//! The `command` service manager (Owner decisions A-6 / A-10, contract K-6,
//! plan WU-6): start / stop / status / health are operator-supplied programs
//! run as argv (never through a shell) by a runner owned by this module.
//!
//! Safety-relevant rules, all fail-closed:
//! - `status` is read strictly: exit 0 and stdout exactly `running` or
//!   `stopped` (one trailing newline allowed). Any other result — another exit
//!   code, a signal, a timeout, oversized or malformed output, a spawn or trust
//!   failure — is `Unavailable`, never `Stopped` (a broken script must not
//!   claim a stopped service).
//! - A `Stopped` status is not believed after Mikagami has started the
//!   service until Mikagami's own `stop` succeeded afterwards ("started and
//!   not yet proven stopped" is Unknown). A start that timed out or returned
//!   early while the service comes up later therefore cannot be read as zero
//!   resource.
//! - Each action runs in its own process group, and Mikagami owes that group's
//!   cleanup until the group is *proven* empty. When the leader exits or the
//!   deadline passes (TERM, 2 s, KILL on timeout), the leader is observed
//!   without being reaped, the whole group is KILLed while the leader's pid
//!   still pins the group id against reuse, the KILL result is checked, the
//!   leader is reaped, and a signal-0 census must find the group empty
//!   (`ESRCH`). Reaping the leader alone proves nothing about its children.
//!   So `start` must detach a long-running service from its group (`setsid`,
//!   `systemd-run`).
//! - Anything short of that proof (a KILL that cannot be confirmed, members
//!   still present, an undecidable census, a leader that cannot be reaped)
//!   leaves the responsibility in a dedicated slot (not shared with any other
//!   backend): the action has no result (`status` is `Unavailable`, `start`
//!   and `stop` are errors, a `stop` earns no credit and the stopped state
//!   stays unproven), and every later action is refused until the slot is
//!   discharged. An unreaped leader is re-KILLed on each retry; once the
//!   leader is reaped only the harmless signal-0 census is used again,
//!   because the group id may by then belong to someone else. Nothing waits
//!   without bound: every call returns, and an unresolvable slot keeps the
//!   backend failing closed.
//! - The pin is only trusted while it is observed. If the leader is no longer
//!   our child (`ECHILD`: something else reaped it), the group id may belong
//!   to a stranger, so no TERM / KILL is sent from then on; the cleanup stays
//!   owed as a census-only responsibility and the action has no result. The
//!   same holds on every path, retries included. This does not close the
//!   instant between the observation and the signal; production never reaps
//!   a child it did not wait for (no `SIGCHLD` ignore, no `waitpid(-1)`, no
//!   subreaper), which is the assumption the guard backs up.
//! - The reap of an exited leader never blocks: `try_wait` is polled for a
//!   short budget. Its answer decides the status and the responsibility
//!   separately. `Ok(Some)`: the status is the leader's. `ECHILD`: someone
//!   else reaped it; no status is invented (`LeaderLost`), the group was
//!   already killed while the pin held, and only the census is used from
//!   then on. `Ok(None)` or any other error: the leader stays owed, unreaped
//!   and pinned, with no status. Only the census (`ESRCH`) ever proves a group
//!   empty. The instant between the exit observation and `try_wait` is not
//!   closed: a leader reaped elsewhere whose pid was reused by another child
//!   of this process that has already exited would lend its status to this
//!   leader. That needs an external reaper and a pid wrap within microseconds;
//!   the `SIGCHLD` check below removes the one external reaper this process
//!   could inherit.
//! - `SIGCHLD` must let this process wait for its children. The disposition
//!   is read (never changed) when the backend is built, so the daemon does
//!   not start under `SIG_IGN` or `SA_NOCLDWAIT` (the kernel would discard
//!   every child's status), or under a handler function (not known to leave
//!   children alone), and again right before every spawn. The setting is
//!   process-wide, so this is a snapshot: a change after the check is not
//!   prevented. It is detected as `ECHILD` on the leader, which ends as a
//!   lost pin with no signal sent, and the next action is refused by the
//!   check. Nothing in this crate or its dependencies touches `SIGCHLD`
//!   (an architecture guard keeps it so); the operational contract is that
//!   nothing in the process may change it after startup.
//! - What a refused `SIGCHLD` state forbids (Owner ruling FH-2): every NEW
//!   spawn, and nothing more. It does not cancel a cleanup that was already
//!   owed. `Runner::run` therefore first discharges the pending cleanup
//!   (`clear_pending`, deliberately ahead of the `SIGCHLD` check; moving it
//!   behind the check would strand the responsibility), and only then checks
//!   the setting. That cleanup obeys the same ownership rules as on every
//!   other path: a signal goes only to the pending group, only while its
//!   leader is observed as our unreaped child (pinned), never after the pin is
//!   lost (census only), and the group counts as gone only on `ESRCH`. If it
//!   cannot be finished, `run` returns `PendingBlocked`: nothing is spawned
//!   and the responsibility is kept. Once nothing is owed, a refused setting
//!   gives `SigchldRefused` with no spawn and no signal at all; no signal can
//!   reach a process of a command this call would have started, because none
//!   is started. So "refused" means no new spawn and no signal to anything
//!   that is not already owed; it does not mean that the call sends no signal.
//!   The ruling does not widen the single-reaper assumption above (no
//!   external reaper, the `SIGCHLD` setting is only read).
//! - An action's timeout is bounded (`config::ACTION_TIMEOUT_CEILING_SEC`) and its
//!   deadline is computed with `checked_add` before anything is spawned; an
//!   out-of-range timeout is refused, never clamped, and spawns nothing.
//! - A pipe that cannot be made non-blocking is never read (a silent child
//!   would hold a blocking read past the deadline); the run goes straight to
//!   the deadline cleanup.
//! - The executable is checked before every spawn: absolute, normalized, no
//!   symlink at the final component, a regular file owned by root, not
//!   group/world writable, executable, and every ancestor directory a
//!   non-symlink owned by root and not group/world writable.
//!
//! No helper thread: the runner is a single-threaded poll loop.

use super::{ActionDiagnostic, RawHealthObservation, RawServiceObservation};
use crate::config::ACTION_TIMEOUT_CEILING_SEC;
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Fixed environment (`env_clear` + these only).
const SERVICE_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
const MAX_CAPTURED_OUTPUT: usize = 4096;
const READ_CHUNK: usize = 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const TERM_GRACE: Duration = Duration::from_secs(2);
const KILL_GRACE: Duration = Duration::from_secs(2);
/// How long a retried cleanup waits for the census after its kill (the kernel
/// and init need a moment to reap the killed members). Short: the retry runs
/// ahead of every later action.
const RETRY_CENSUS_BUDGET: Duration = Duration::from_millis(200);

mod sys {
    //! Manual `extern "C"` for the non-reaping exit query, the group signal
    //! and the non-blocking pipe flag. Verified only for Linux and macOS on
    //! x86_64 / aarch64; any other target fails to build instead of
    //! misreading `siginfo_t`.
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
        "command_service: manual FFI values are verified only for Linux and macOS on x86_64/aarch64"
    );

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    mod constants {
        pub const WNOWAIT: i32 = 0x0100_0000;
        pub const O_NONBLOCK: i32 = 0o4000;
        pub const O_NOFOLLOW: i32 = libc::O_NOFOLLOW;
        pub const ELOOP: i32 = 40;
        /// `si_pid` follows `si_signo`, `si_errno`, `si_code` and padding.
        pub const SI_PID_OFFSET: usize = 16;
        pub const SIGCHLD: i32 = 17;
        pub const SA_NOCLDWAIT: i32 = 2;
        /// `struct sigaction` (glibc / musl): the handler word comes first,
        /// then the 128-byte mask, then `sa_flags`.
        pub const SA_FLAGS_OFFSET: usize = 136;

        const _: () = assert!(
            SIGCHLD == libc::SIGCHLD
                && SA_NOCLDWAIT == libc::SA_NOCLDWAIT
                && libc::SIG_DFL == 0
                && libc::SIG_IGN == 1
                && std::mem::offset_of!(libc::sigaction, sa_sigaction) == 0
                && std::mem::offset_of!(libc::sigaction, sa_flags) == SA_FLAGS_OFFSET
                && std::mem::size_of::<libc::sigaction>()
                    <= std::mem::size_of::<super::SigAction>()
        );

        const _: () = assert!(
            WNOWAIT == libc::WNOWAIT
                && O_NONBLOCK == libc::O_NONBLOCK
                && ELOOP == libc::ELOOP
                && super::P_PID as libc::idtype_t == libc::P_PID
                && super::WEXITED == libc::WEXITED
                && super::WNOHANG == libc::WNOHANG
                && super::F_GETFL == libc::F_GETFL
                && super::F_SETFL == libc::F_SETFL
                && super::SIGTERM == libc::SIGTERM
                && super::SIGKILL == libc::SIGKILL
                && super::EPERM == libc::EPERM
                && super::ESRCH == libc::ESRCH
                && super::EINTR == libc::EINTR
                && super::ECHILD == libc::ECHILD
                && std::mem::size_of::<libc::siginfo_t>() == 128
                && std::mem::size_of::<libc::siginfo_t>() <= std::mem::size_of::<super::SigInfo>()
        );
    }

    #[cfg(all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    mod constants {
        pub const WNOWAIT: i32 = 0x20;
        pub const O_NONBLOCK: i32 = 0x4;
        pub const O_NOFOLLOW: i32 = 0x100;
        pub const ELOOP: i32 = 62;
        pub const SI_PID_OFFSET: usize = 12;
        pub const SIGCHLD: i32 = 20;
        pub const SA_NOCLDWAIT: i32 = 0x20;
        /// Darwin `struct sigaction`: the handler word, a 32-bit mask, then
        /// `sa_flags`.
        pub const SA_FLAGS_OFFSET: usize = 12;
    }

    pub use constants::{ELOOP, O_NOFOLLOW, O_NONBLOCK};
    pub use constants::{SA_FLAGS_OFFSET, SA_NOCLDWAIT, SIGCHLD};
    use constants::{SI_PID_OFFSET, WNOWAIT};

    pub const SIGTERM: i32 = 15;
    pub const SIGKILL: i32 = 9;
    const EPERM: i32 = 1;
    const ESRCH: i32 = 3;
    pub const EINTR: i32 = 4;
    pub const ECHILD: i32 = 10;
    const P_PID: i32 = 1;
    const WEXITED: i32 = 4;
    const WNOHANG: i32 = 1;
    const F_GETFL: i32 = 3;
    const F_SETFL: i32 = 4;

    /// Large enough for `siginfo_t` on both targets (128 / 104 bytes).
    #[repr(C, align(8))]
    struct SigInfo([u8; 128]);

    /// Large enough for `struct sigaction` on both targets (152 / 16 bytes).
    #[repr(C, align(8))]
    pub struct SigAction(pub [u8; 256]);

    /// `SIG_DFL` / `SIG_IGN` as the handler word (identical on both targets).
    pub const SIG_DFL: usize = 0;
    pub const SIG_IGN: usize = 1;

    unsafe extern "C" {
        fn killpg(pgrp: i32, sig: i32) -> i32;
        fn sigaction(signal: i32, action: *const SigAction, previous: *mut SigAction) -> i32;
        fn waitid(idtype: i32, id: u32, infop: *mut SigInfo, options: i32) -> i32;
        fn fcntl(fd: i32, command: i32, ...) -> i32;
    }

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    /// One signal to a whole process group; never waits. A group id of 0 or 1
    /// (or one that does not fit) is refused.
    ///
    /// Callers send TERM / KILL only while the group leader is still an
    /// unreaped child: an unreaped leader keeps its pid, and with it the group
    /// id, from being recycled, so the signal cannot reach a stranger.
    ///
    /// Linux answers `0` for a group whose only member is that exited,
    /// unreaped leader (and `ESRCH`, read as "nothing left to signal", for a
    /// group with no member at all). Darwin answers `EPERM` for the zombie-only
    /// group (the host the unit tests also run on); that one case is read as
    /// delivered there. Production is Linux.
    pub fn signal_group(pgid: u32, signal: i32) -> Result<(), i32> {
        let Ok(pgid) = i32::try_from(pgid) else {
            return Err(9);
        };
        if pgid <= 1 {
            return Err(9);
        }
        // SAFETY: plain syscall with integer arguments.
        if unsafe { killpg(pgid, signal) } == 0 {
            return Ok(());
        }
        let error = errno();
        // `ESRCH`: no process is left in the group to signal. That is not a
        // failure to kill; what proves the group gone is the census after the
        // leader is reaped, never this return value.
        if error == ESRCH || (cfg!(target_os = "macos") && error == EPERM) {
            return Ok(());
        }
        Err(error)
    }

    /// What a signal-0 census of a process group found.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum GroupProbe {
        /// No process (not even an unreaped zombie) is in the group.
        Empty,
        /// At least one process, living or zombie, is still in the group.
        Present,
        /// The census itself failed; nothing is known.
        Unknown(i32),
    }

    /// What `killpg(pgid, 0)` answered, as a census result. `ESRCH` is the only
    /// answer that proves the group empty: `EPERM` means a process exists in
    /// the group (one this user may not signal, or, on Darwin, a zombie-only
    /// group), and any other errno decides nothing.
    pub fn classify_census(answer: Result<(), i32>) -> GroupProbe {
        match answer {
            Ok(()) => GroupProbe::Present,
            Err(ESRCH) => GroupProbe::Empty,
            Err(EPERM) => GroupProbe::Present,
            Err(other) => GroupProbe::Unknown(other),
        }
    }

    /// Signal 0 to a process group: delivers nothing, so it is safe at any
    /// time, also when the leader has already been reaped. `ESRCH` is the only
    /// proof that the group is empty; a recycled group id can only make the
    /// answer `Present` (never `Empty`), which keeps the caller fail-closed.
    pub fn group_probe(pgid: u32) -> GroupProbe {
        let Ok(pgid) = i32::try_from(pgid) else {
            return GroupProbe::Unknown(9);
        };
        if pgid <= 1 {
            return GroupProbe::Unknown(9);
        }
        // SAFETY: plain syscall with integer arguments.
        let answer = if unsafe { killpg(pgid, 0) } == 0 {
            Ok(())
        } else {
            Err(errno())
        };
        classify_census(answer)
    }

    /// `waitid(P_PID, pid, WEXITED | WNOWAIT | WNOHANG)`: observes the leader's
    /// exit without reaping it, so its pid (and therefore the group id) cannot
    /// be recycled before the group has been signalled.
    ///
    /// `Err(ECHILD)` means the pid is no longer our child: it was reaped (or
    /// auto-reaped) elsewhere and no longer pins the group id.
    pub fn leader_exited_without_reaping(pid: u32) -> Result<bool, i32> {
        let mut info = SigInfo([0; 128]);
        // SAFETY: `info` is a properly sized and aligned buffer for siginfo_t.
        if unsafe { waitid(P_PID, pid, &mut info, WEXITED | WNOWAIT | WNOHANG) } != 0 {
            return Err(errno());
        }
        let bytes = &info.0[SI_PID_OFFSET..SI_PID_OFFSET + 4];
        let reported = i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        Ok(reported != 0)
    }

    /// How this process currently treats `SIGCHLD`, as far as it decides
    /// whether a child is kept for `wait`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SigchldState {
        /// `SIG_DFL` without `SA_NOCLDWAIT`: a finished child stays until it
        /// is waited for.
        Default,
        /// `SIG_IGN`: the kernel discards every child's exit status.
        Ignored,
        /// `SA_NOCLDWAIT`: the same, requested through the flag.
        NoChildWait,
        /// A handler function. What it does is unknown, so it is not trusted.
        Handler,
    }

    /// Classify a `SIGCHLD` handler word and its flags. A pure function, so
    /// every state is covered without touching the process-wide setting.
    pub fn classify_sigchld(handler: usize, flags: i32) -> SigchldState {
        if handler == SIG_IGN {
            SigchldState::Ignored
        } else if flags & SA_NOCLDWAIT != 0 {
            SigchldState::NoChildWait
        } else if handler == SIG_DFL {
            SigchldState::Default
        } else {
            SigchldState::Handler
        }
    }

    /// Read (never change) the current `SIGCHLD` disposition: `sigaction`
    /// with a null new action. The setting is shared by the whole process, so
    /// the answer is a snapshot.
    pub fn sigchld_state() -> Result<SigchldState, i32> {
        let mut current = SigAction([0; 256]);
        // SAFETY: a null new action only queries; `current` is a properly
        // sized and aligned buffer for `struct sigaction`.
        if unsafe { sigaction(SIGCHLD, std::ptr::null(), &mut current) } != 0 {
            return Err(errno());
        }
        let mut word = [0u8; std::mem::size_of::<usize>()];
        word.copy_from_slice(&current.0[..std::mem::size_of::<usize>()]);
        let flags = &current.0[SA_FLAGS_OFFSET..SA_FLAGS_OFFSET + 4];
        Ok(classify_sigchld(
            usize::from_ne_bytes(word),
            i32::from_ne_bytes([flags[0], flags[1], flags[2], flags[3]]),
        ))
    }

    pub fn set_nonblocking(fd: i32) -> Result<(), i32> {
        // SAFETY: plain fcntl on a descriptor owned by the caller.
        let flags = unsafe { fcntl(fd, F_GETFL) };
        if flags < 0 {
            return Err(errno());
        }
        // SAFETY: as above.
        if unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) } < 0 {
            return Err(errno());
        }
        Ok(())
    }
}

// ---- executable trust ---------------------------------------------------------

/// Why an executable is not trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecutableRefusal {
    EmptyArgv,
    NotAbsolute,
    NotNormalized,
    SymlinkFinalComponent,
    Open(i32),
    NotRegularFile,
    NotOwnedByTrustedUser,
    GroupOrWorldWritable,
    NotExecutable,
    AncestorUnreadable(i32),
    AncestorNotDirectory,
    AncestorNotTrusted,
    AncestorGroupOrWorldWritable,
}

impl std::fmt::Display for ExecutableRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::EmptyArgv => "empty command",
            Self::NotAbsolute => "path is not absolute",
            Self::NotNormalized => "path is not normalized",
            Self::SymlinkFinalComponent => "path is a symbolic link",
            Self::Open(_) => "path cannot be opened",
            Self::NotRegularFile => "path is not a regular file",
            Self::NotOwnedByTrustedUser => "file is not owned by root",
            Self::GroupOrWorldWritable => "file is group or world writable",
            Self::NotExecutable => "file is not executable",
            Self::AncestorUnreadable(_) => "a parent directory cannot be read",
            Self::AncestorNotDirectory => "a parent is not a directory",
            Self::AncestorNotTrusted => "a parent directory is not owned by root",
            Self::AncestorGroupOrWorldWritable => "a parent directory is group or world writable",
        })
    }
}

/// Who may own a trusted program, and whether its parent directories are
/// walked. Production is `PRODUCTION` (root, ancestors checked); a test runs
/// as an ordinary user in a scratch directory under `/tmp`-like parents, so it
/// names that user and skips only the ancestor walk (the ancestor rule is
/// proven separately on synthetic metadata).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TrustPolicy {
    pub(crate) uid: u32,
    pub(crate) check_ancestors: bool,
}

impl TrustPolicy {
    pub(crate) const PRODUCTION: Self = Self {
        uid: 0,
        check_ancestors: true,
    };

    #[cfg(test)]
    pub(crate) fn for_test_user() -> Self {
        let uid = fs::metadata(std::env::temp_dir())
            .map(|metadata| metadata.uid())
            .unwrap_or(0);
        Self {
            uid,
            check_ancestors: false,
        }
    }
}

/// File rule: a regular file owned by the trusted user, not group/world
/// writable, executable.
fn file_verdict(
    is_file: bool,
    owner: u32,
    mode: u32,
    trusted_uid: u32,
) -> Result<(), ExecutableRefusal> {
    if !is_file {
        return Err(ExecutableRefusal::NotRegularFile);
    }
    if owner != trusted_uid {
        return Err(ExecutableRefusal::NotOwnedByTrustedUser);
    }
    if mode & 0o022 != 0 {
        return Err(ExecutableRefusal::GroupOrWorldWritable);
    }
    if mode & 0o111 == 0 {
        return Err(ExecutableRefusal::NotExecutable);
    }
    Ok(())
}

/// Ancestor rule: a real directory owned by root (or the trusted user) and
/// not group/world writable (a sticky world-writable `/tmp` is refused too).
fn ancestor_verdict(
    is_dir: bool,
    owner: u32,
    mode: u32,
    trusted_uid: u32,
) -> Result<(), ExecutableRefusal> {
    if !is_dir {
        return Err(ExecutableRefusal::AncestorNotDirectory);
    }
    if owner != 0 && owner != trusted_uid {
        return Err(ExecutableRefusal::AncestorNotTrusted);
    }
    if mode & 0o022 != 0 {
        return Err(ExecutableRefusal::AncestorGroupOrWorldWritable);
    }
    Ok(())
}

/// The single trust check for service and health programs (Owner decision
/// A-7).
pub(crate) fn verify_trusted_executable(
    executable: &str,
    policy: TrustPolicy,
) -> Result<(), ExecutableRefusal> {
    if executable.is_empty() {
        return Err(ExecutableRefusal::EmptyArgv);
    }
    let path = Path::new(executable);
    if !path.is_absolute() {
        return Err(ExecutableRefusal::NotAbsolute);
    }
    // `Path::components` silently drops `.` segments and doubled slashes, so
    // those are rejected on the text.
    if executable.contains("//")
        || executable.contains("/./")
        || executable.ends_with("/.")
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(ExecutableRefusal::NotNormalized);
    }
    let linked = fs::symlink_metadata(path)
        .map_err(|error| ExecutableRefusal::Open(error.raw_os_error().unwrap_or(0)))?;
    if linked.file_type().is_symlink() {
        return Err(ExecutableRefusal::SymlinkFinalComponent);
    }
    if !linked.is_file() {
        return Err(ExecutableRefusal::NotRegularFile);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(sys::O_NOFOLLOW | sys::O_NONBLOCK)
        .open(path)
        .map_err(|error| match error.raw_os_error() {
            Some(sys::ELOOP) => ExecutableRefusal::SymlinkFinalComponent,
            errno => ExecutableRefusal::Open(errno.unwrap_or(0)),
        })?;
    let metadata = file
        .metadata()
        .map_err(|error| ExecutableRefusal::Open(error.raw_os_error().unwrap_or(0)))?;
    file_verdict(
        metadata.is_file(),
        metadata.uid(),
        metadata.mode(),
        policy.uid,
    )?;
    if !policy.check_ancestors {
        return Ok(());
    }
    let mut ancestor = path.parent();
    while let Some(directory) = ancestor {
        let metadata = fs::symlink_metadata(directory).map_err(|error| {
            ExecutableRefusal::AncestorUnreadable(error.raw_os_error().unwrap_or(0))
        })?;
        ancestor_verdict(
            metadata.is_dir(),
            metadata.uid(),
            metadata.mode(),
            policy.uid,
        )?;
        ancestor = directory.parent();
    }
    Ok(())
}

// ---- the bounded runner ---------------------------------------------------------

/// A process group's leader that still has to be reaped.
#[derive(Debug)]
struct Leader {
    child: Child,
    pgid: u32,
}

/// The outcome of cleaning up after an exited leader.
struct Settled {
    /// The leader's exit status, when it was reaped.
    status: Option<std::process::ExitStatus>,
    /// The signal-0 census found the whole group empty.
    proven: bool,
    /// The leader was no longer our child when it was to be reaped (`ECHILD`):
    /// someone else reaped it, so its status is unknown and was not guessed.
    pin_lost: bool,
}

/// What one non-blocking reap attempt of an exited leader said.
#[derive(Debug)]
enum Reaped {
    /// Reaped by us; this is the leader's own status.
    Status(std::process::ExitStatus),
    /// `ECHILD`: the pid is not our child any more.
    PinLost,
    /// Still ours and not reaped (not reapable yet, or the query failed).
    /// The leader stays unreaped and pinned.
    NotReaped,
}

/// Cleanup that Mikagami still owes for one action's process group. The slot
/// holds at most one; every later action is refused until it is discharged.
///
/// The group id is the leader's pid. While the leader is an unreaped child its
/// pid cannot be recycled, so only then are TERM / KILL sent. After the leader
/// is reaped the group id may be reused by an unrelated process, so only the
/// harmless signal-0 census is ever used again.
#[derive(Debug)]
enum Responsibility {
    /// The leader is not reaped yet (still running, or exited but the group
    /// kill could not be confirmed). Signals are safe.
    Leader(Leader),
    /// Census only, never a signal: the leader is gone from our hands (reaped
    /// by us after a confirmed group kill, or reaped by someone else, which
    /// ends the pin) and the group was not yet found empty.
    Group { pgid: u32 },
}

/// How one run ended.
#[derive(Debug, PartialEq, Eq)]
enum RunEnd {
    /// The leader exited; `code` is `None` when it died of a signal.
    Exited {
        code: Option<i32>,
        stdout: Vec<u8>,
        overflow: bool,
    },
    TimedOut {
        cleaned: bool,
    },
    /// The leader exited but the group could not be proven empty, or the
    /// leader could not be reaped yet: the run has no result, and the cleanup
    /// responsibility is still held.
    CleanupUncertain,
    /// The leader was reaped by someone else, so its pid no longer pins the
    /// group id: no signal is sent after that, the exit status is unknown
    /// (never guessed), and the census-only responsibility is held until the
    /// census finds the group empty (possibly already, when the loss was seen
    /// at the final reap).
    LeaderLost,
    /// The timeout is out of range or its deadline cannot be represented;
    /// nothing was spawned.
    InvalidTimeout,
    /// `SIGCHLD` is not in a state that lets a child be waited for; nothing
    /// was spawned.
    SigchldRefused(SigchldRefusal),
    Refused(ExecutableRefusal),
    SpawnFailed,
    /// An earlier group is not yet proven gone; nothing is spawned.
    PendingBlocked,
}

/// Why the process-wide `SIGCHLD` setting forbids running a service command.
///
/// This runner learns that a command ended, and that its pid still pins the
/// process group, only by waiting for its own child. If `SIGCHLD` is ignored
/// (inherited from the launcher, for instance) or `SA_NOCLDWAIT` is set, the
/// kernel discards every child's status: each action would end as a lost
/// leader and the backend would never work. A handler function is refused
/// because nothing proves it leaves children alone. The setting is never
/// changed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SigchldRefusal {
    Ignored,
    NoChildWait,
    Handler,
    Unreadable(i32),
}

impl std::fmt::Display for SigchldRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ignored => formatter.write_str(
                "SIGCHLD is ignored (SIG_IGN, probably inherited from the process that started \
                 mikagami); the command service manager cannot wait for its commands. Start \
                 mikagami with the default SIGCHLD disposition",
            ),
            Self::NoChildWait => formatter.write_str(
                "SIGCHLD has SA_NOCLDWAIT set; the command service manager cannot wait for \
                 its commands",
            ),
            Self::Handler => formatter.write_str(
                "a SIGCHLD handler is installed; it is not known to leave children alone, so \
                 the command service manager refuses to run",
            ),
            Self::Unreadable(errno) => write!(
                formatter,
                "the SIGCHLD disposition cannot be read (os error {errno}); the command \
                 service manager refuses to run"
            ),
        }
    }
}

/// `Ok` only for the default disposition. Anything else, including a failure
/// to read it, is a refusal.
fn check_sigchld(probe: SigchldProbe) -> Result<(), SigchldRefusal> {
    match probe() {
        Ok(sys::SigchldState::Default) => Ok(()),
        Ok(sys::SigchldState::Ignored) => Err(SigchldRefusal::Ignored),
        Ok(sys::SigchldState::NoChildWait) => Err(SigchldRefusal::NoChildWait),
        Ok(sys::SigchldState::Handler) => Err(SigchldRefusal::Handler),
        Err(errno) => Err(SigchldRefusal::Unreadable(errno)),
    }
}

impl RunEnd {
    /// The action's process group may still hold a live process.
    fn cleanup_uncertain(&self) -> bool {
        matches!(
            self,
            Self::CleanupUncertain | Self::LeaderLost | Self::TimedOut { cleaned: false }
        )
    }
}

struct Capture {
    bytes: Vec<u8>,
    overflow: bool,
    open: bool,
}

impl Capture {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            overflow: false,
            open: true,
        }
    }

    /// Read what is available without blocking. Surplus output is discarded
    /// (and remembered) so a chatty child can never fill the pipe and stall.
    fn drain(&mut self, source: &mut impl Read, keep: bool) {
        let mut chunk = [0u8; READ_CHUNK];
        // A bounded number of reads per pass keeps the loop responsive.
        for _ in 0..64 {
            if !self.open {
                return;
            }
            match source.read(&mut chunk) {
                Ok(0) => {
                    self.open = false;
                    return;
                }
                Ok(read) => {
                    if keep {
                        let room = MAX_CAPTURED_OUTPUT.saturating_sub(self.bytes.len());
                        if read > room {
                            self.overflow = true;
                        }
                        self.bytes.extend_from_slice(&chunk[..read.min(room)]);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => {
                    self.open = false;
                    return;
                }
            }
        }
    }
}

type ExitProbe = fn(u32) -> Result<bool, i32>;
type GroupSignal = fn(u32, i32) -> Result<(), i32>;
type GroupCensus = fn(u32) -> sys::GroupProbe;
type NonblockingSetter = fn(i32) -> Result<(), i32>;
type LeaderReaper = fn(&mut Leader) -> std::io::Result<Option<std::process::ExitStatus>>;
type SigchldProbe = fn() -> Result<sys::SigchldState, i32>;

/// What one exit query said about a leader we still hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeaderState {
    /// Exited, not reaped by us: the pid still pins the group id.
    Exited,
    /// Not exited yet (or a transient `EINTR`): the pid is still ours.
    Running,
    /// `ECHILD`: the pid is no longer our child. The group id is unpinned.
    PinLost,
    /// The query failed for another reason; the pin is presumed intact (a
    /// reaped leader answers `ECHILD`) but the exit cannot be observed.
    Unobservable,
}

/// How a bounded wait for the leader's exit ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wait {
    Exited,
    Pending,
    PinLost,
}

/// The runner and its one pending cleanup slot.
#[derive(Debug)]
struct Runner {
    trust: TrustPolicy,
    pending: Option<Responsibility>,
    exit_probe: ExitProbe,
    signal: GroupSignal,
    census: GroupCensus,
    set_nonblocking: NonblockingSetter,
    sigchld: SigchldProbe,
    reaper: LeaderReaper,
}

impl Runner {
    fn new(trust: TrustPolicy) -> Self {
        Self {
            trust,
            pending: None,
            exit_probe: sys::leader_exited_without_reaping,
            signal: sys::signal_group,
            census: sys::group_probe,
            set_nonblocking: sys::set_nonblocking,
            sigchld: sys::sigchld_state,
            reaper: |leader| leader.child.try_wait(),
        }
    }

    /// Classify one exit query for a leader we hold.
    fn observe_leader(&self, leader: &Leader) -> LeaderState {
        match (self.exit_probe)(leader.child.id()) {
            Ok(true) => LeaderState::Exited,
            Ok(false) => LeaderState::Running,
            Err(sys::ECHILD) => LeaderState::PinLost,
            Err(sys::EINTR) => LeaderState::Running,
            Err(_) => LeaderState::Unobservable,
        }
    }

    /// The leader is no longer our child, so its pid no longer pins the group
    /// id: the id may already belong to an unrelated group and must never
    /// receive TERM / KILL again. The cleanup stays owed as a census-only
    /// responsibility; `true` only when the census proves the group empty now.
    fn hold_unpinned(&mut self, leader: Leader) -> bool {
        let pgid = leader.pgid;
        // Dropping a `Child` neither signals nor waits.
        drop(leader);
        self.settle_group(pgid, Duration::ZERO)
    }

    /// Discharge the pending cleanup if it can be proven done now. `true`
    /// when nothing is owed. Never waits.
    fn clear_pending(&mut self) -> bool {
        match self.pending.take() {
            None => true,
            Some(Responsibility::Group { pgid }) => self.settle_group(pgid, Duration::ZERO),
            Some(Responsibility::Leader(leader)) => {
                // The pin is checked before any signal: a leader that was
                // reaped elsewhere no longer protects the group id.
                if self.observe_leader(&leader) == LeaderState::PinLost {
                    return self.hold_unpinned(leader);
                }
                let _ = (self.signal)(leader.pgid, sys::SIGKILL);
                match self.observe_leader(&leader) {
                    LeaderState::Exited => {
                        self.settle_exited_leader(leader, RETRY_CENSUS_BUDGET)
                            .proven
                    }
                    LeaderState::PinLost => self.hold_unpinned(leader),
                    LeaderState::Running | LeaderState::Unobservable => {
                        self.pending = Some(Responsibility::Leader(leader));
                        false
                    }
                }
            }
        }
    }

    /// The leader's exit has been observed and it is still unreaped. Kill
    /// whatever is left in its group (the result is checked: a kill that
    /// cannot be confirmed keeps the leader unreaped, and with it the pinned
    /// group id, for a later retry), reap it without blocking, then require
    /// the census to find the group empty. `proven` is `true` only with that
    /// proof; otherwise the matching responsibility is parked.
    ///
    /// The reap never waits without bound, and its answer is read like this:
    /// - `Ok(Some(status))`: reaped by us; the status is the leader's.
    /// - `Ok(None)`: the pid is still our child but cannot be reaped yet. The
    ///   leader stays parked (unreaped, pinned) for a retry; no status.
    /// - `ECHILD`: someone else reaped it, the pin is gone. The group was
    ///   already killed while the pin held; from here only the census is
    ///   used, and no status is invented.
    /// - any other error: nothing is known about the leader. It stays parked
    ///   like `Ok(None)`; a later signal is sent only after the pin has been
    ///   observed again.
    fn settle_exited_leader(&mut self, mut leader: Leader, census_budget: Duration) -> Settled {
        if (self.signal)(leader.pgid, sys::SIGKILL).is_err() {
            self.pending = Some(Responsibility::Leader(leader));
            return Settled {
                status: None,
                proven: false,
                pin_lost: false,
            };
        }
        match self.reap_exited_leader(&mut leader, census_budget) {
            Reaped::Status(status) => {
                let proven = self.settle_group(leader.pgid, census_budget);
                Settled {
                    status: Some(status),
                    proven,
                    pin_lost: false,
                }
            }
            Reaped::PinLost => {
                let pgid = leader.pgid;
                // Dropping a `Child` neither signals nor waits.
                drop(leader);
                let proven = self.settle_group(pgid, census_budget);
                Settled {
                    status: None,
                    proven,
                    pin_lost: true,
                }
            }
            Reaped::NotReaped => {
                self.pending = Some(Responsibility::Leader(leader));
                Settled {
                    status: None,
                    proven: false,
                    pin_lost: false,
                }
            }
        }
    }

    /// Reap an exited leader without blocking: `try_wait` polled until the
    /// budget ends. The exit was observed a moment ago, so one attempt
    /// normally succeeds.
    fn reap_exited_leader(&self, leader: &mut Leader, budget: Duration) -> Reaped {
        let deadline = Instant::now() + budget;
        loop {
            match (self.reaper)(leader) {
                Ok(Some(status)) => return Reaped::Status(status),
                Ok(None) => {}
                Err(error) if error.raw_os_error() == Some(sys::ECHILD) => {
                    return Reaped::PinLost;
                }
                Err(_) => return Reaped::NotReaped,
            }
            let now = Instant::now();
            if now >= deadline {
                return Reaped::NotReaped;
            }
            std::thread::sleep(POLL_INTERVAL.min(deadline - now));
        }
    }

    /// Poll the signal-0 census until the group is empty or the budget ends.
    fn settle_group(&mut self, pgid: u32, budget: Duration) -> bool {
        let deadline = Instant::now() + budget;
        loop {
            if (self.census)(pgid) == sys::GroupProbe::Empty {
                self.pending = None;
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                self.pending = Some(Responsibility::Group { pgid });
                return false;
            }
            std::thread::sleep(POLL_INTERVAL.min(deadline - now));
        }
    }

    /// Order (FH-2, see the module docs): (1) discharge what is already owed,
    /// which may signal the pending group under the pin rules, (2) trust check,
    /// (3) deadline arithmetic, (4) the `SIGCHLD` check, (5) the one spawn.
    /// Steps 2-5 only ever concern a NEW command; a refusal at any of them
    /// spawns nothing and signals nothing. Step 1 stays first: it is the only
    /// place an owed cleanup can make progress, so a refused setting must not
    /// be able to skip it.
    fn run(
        &mut self,
        argv: &[String],
        action: &str,
        timeout: Duration,
        keep_stdout: bool,
    ) -> RunEnd {
        if !self.clear_pending() {
            return RunEnd::PendingBlocked;
        }
        let Some((program, arguments)) = argv.split_first() else {
            return RunEnd::Refused(ExecutableRefusal::EmptyArgv);
        };
        if let Err(refusal) = verify_trusted_executable(program, self.trust) {
            return RunEnd::Refused(refusal);
        }
        // The only fallible deadline arithmetic, done before anything exists
        // that would have to be cleaned up. The clock starts here, so the
        // spawn itself counts against the timeout.
        let Some(deadline) = Instant::now().checked_add(timeout) else {
            return RunEnd::InvalidTimeout;
        };
        // Checked right before every spawn, not only at startup: the setting
        // is process-wide and anything in the process may change it later. A
        // change after this check is not prevented (see the module docs); it
        // makes the leader unobservable (`ECHILD`), which ends as a lost pin
        // with no signal sent.
        if let Err(refusal) = check_sigchld(self.sigchld) {
            return RunEnd::SigchldRefused(refusal);
        }
        let mut command = Command::new(OsStr::new(program));
        command
            .args(arguments)
            .env_clear()
            .env("PATH", SERVICE_PATH)
            .env("LANG", "C")
            .env("MIKAGAMI_SERVICE_ACTION", action)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let Ok(mut child) = command.spawn() else {
            return RunEnd::SpawnFailed;
        };
        let pgid = child.id();
        let mut stdout = child.stdout.take();
        let mut stderr = child.stderr.take();
        let leader = Leader { child, pgid };
        // Both pipes are set up even if the first fails, so the failure is
        // known before anything is read.
        let mut nonblocking = true;
        if let Some(pipe) = &stdout {
            nonblocking &= (self.set_nonblocking)(pipe.as_raw_fd()).is_ok();
        }
        if let Some(pipe) = &stderr {
            nonblocking &= (self.set_nonblocking)(pipe.as_raw_fd()).is_ok();
        }
        let mut out = Capture::new();
        let mut err = Capture::new();
        // A pipe that could not be made non-blocking is never read: a silent
        // child would hold a blocking read past the deadline. It goes straight
        // to the deadline cleanup.
        let mut timed_out = !nonblocking;
        loop {
            if timed_out {
                break;
            }
            if let Some(pipe) = stdout.as_mut() {
                out.drain(pipe, keep_stdout);
            }
            if let Some(pipe) = stderr.as_mut() {
                err.drain(pipe, false);
            }
            match self.observe_leader(&leader) {
                LeaderState::Exited => break,
                LeaderState::Running => {}
                // Reaped elsewhere: the group id is unpinned, nothing is
                // signalled and the run has no result.
                LeaderState::PinLost => {
                    self.hold_unpinned(leader);
                    return RunEnd::LeaderLost;
                }
                // An unusable exit query is treated like a timeout: the group
                // is killed and the leader reaped below.
                LeaderState::Unobservable => timed_out = true,
            }
            let now = Instant::now();
            if now >= deadline {
                timed_out = true;
                break;
            }
            std::thread::sleep(POLL_INTERVAL.min(deadline - now));
        }
        if !timed_out {
            // The leader exited (still unreaped). Drain what it wrote, then
            // kill what it left in its group while its pid still pins the
            // group id, reap it, and require the group to be proven empty.
            if let Some(pipe) = stdout.as_mut() {
                out.drain(pipe, keep_stdout);
            }
            let settled = self.settle_exited_leader(leader, KILL_GRACE);
            if settled.pin_lost {
                // Reaped by someone else: the status is unknown, so the run
                // has no result, whatever the census found.
                return RunEnd::LeaderLost;
            }
            return match settled.status {
                Some(status) if settled.proven => RunEnd::Exited {
                    code: status.code(),
                    stdout: out.bytes,
                    overflow: out.overflow,
                },
                // Without the proof (or without a reaped status) the run has
                // no result and the responsibility stays held.
                _ => RunEnd::CleanupUncertain,
            };
        }
        // Deadline: TERM, grace, KILL, grace, then reap or park. The pin is
        // confirmed right before the first signal (the loop above may not have
        // queried the leader at all), and again by every wait.
        if self.observe_leader(&leader) == LeaderState::PinLost {
            self.hold_unpinned(leader);
            return RunEnd::LeaderLost;
        }
        let term_sent = (self.signal)(leader.pgid, sys::SIGTERM).is_ok();
        if term_sent {
            match self.wait_for_exit(&leader, TERM_GRACE) {
                Wait::Exited => return self.finish_timed_out(leader),
                Wait::PinLost => {
                    self.hold_unpinned(leader);
                    return RunEnd::LeaderLost;
                }
                Wait::Pending => {}
            }
        }
        let kill_sent = (self.signal)(leader.pgid, sys::SIGKILL).is_ok();
        // A kill that was not delivered gains nothing from waiting.
        let grace = if kill_sent {
            KILL_GRACE
        } else {
            Duration::ZERO
        };
        match self.wait_for_exit(&leader, grace) {
            Wait::Exited => return self.finish_timed_out(leader),
            Wait::PinLost => {
                self.hold_unpinned(leader);
                return RunEnd::LeaderLost;
            }
            Wait::Pending => {}
        }
        self.pending = Some(Responsibility::Leader(leader));
        RunEnd::TimedOut { cleaned: false }
    }

    fn finish_timed_out(&mut self, leader: Leader) -> RunEnd {
        RunEnd::TimedOut {
            cleaned: self.settle_exited_leader(leader, KILL_GRACE).proven,
        }
    }

    /// Wait up to `grace` for the leader to exit. A lost pin ends the wait at
    /// once: nothing more may be signalled.
    fn wait_for_exit(&self, leader: &Leader, grace: Duration) -> Wait {
        let deadline = Instant::now() + grace;
        loop {
            match self.observe_leader(leader) {
                LeaderState::Exited => return Wait::Exited,
                LeaderState::PinLost => return Wait::PinLost,
                LeaderState::Running | LeaderState::Unobservable => {}
            }
            let now = Instant::now();
            if now >= deadline {
                return Wait::Pending;
            }
            std::thread::sleep(POLL_INTERVAL.min(deadline - now));
        }
    }
}

// ---- the backend ------------------------------------------------------------------

/// The `command` service backend. The name avoids the word the fencing guards
/// count: this is a separate runner from the fencing backend's.
#[derive(Debug)]
pub(crate) struct ExternalServiceBackend {
    start: Vec<String>,
    stop: Vec<String>,
    status: Vec<String>,
    health: Vec<String>,
    start_timeout: Duration,
    stop_timeout: Duration,
    health_timeout: Duration,
    runner: Runner,
    /// Mikagami started the service and has not yet seen its own `stop`
    /// succeed (a late start is not excluded until then).
    unproven_stopped: bool,
    /// A `stop` exited 0 since the last `start`.
    stop_succeeded_since_start: bool,
}

/// Construction failures (the daemon does not start).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExternalServiceError(pub(crate) String);

impl std::fmt::Display for ExternalServiceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ExternalServiceError {}

impl ExternalServiceBackend {
    /// Production constructor: executables must be root-owned.
    pub(crate) fn new(
        start: Vec<String>,
        stop: Vec<String>,
        status: Vec<String>,
        health: Vec<String>,
        start_timeout: Duration,
        stop_timeout: Duration,
        health_timeout: Duration,
    ) -> Result<Self, ExternalServiceError> {
        Self::with_policy(
            start,
            stop,
            status,
            health,
            start_timeout,
            stop_timeout,
            health_timeout,
            TrustPolicy::PRODUCTION,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn with_policy(
        start: Vec<String>,
        stop: Vec<String>,
        status: Vec<String>,
        health: Vec<String>,
        start_timeout: Duration,
        stop_timeout: Duration,
        health_timeout: Duration,
        trust: TrustPolicy,
    ) -> Result<Self, ExternalServiceError> {
        for (label, argv) in [
            ("service.start", &start),
            ("service.stop", &stop),
            ("service.status", &status),
            ("health.command", &health),
        ] {
            let Some(program) = argv.first() else {
                return Err(ExternalServiceError(format!(
                    "{label} must contain a program"
                )));
            };
            if argv
                .iter()
                .any(|element| element.is_empty() || element.chars().any(char::is_control))
            {
                return Err(ExternalServiceError(format!(
                    "{label} must not contain empty or control-character elements"
                )));
            }
            if let Err(refusal) = verify_trusted_executable(program, trust) {
                return Err(ExternalServiceError(format!(
                    "{label}[0] {program} is not a trusted executable: {refusal}"
                )));
            }
        }
        for (label, timeout) in [
            ("start timeout", start_timeout),
            ("stop timeout", stop_timeout),
            ("health timeout", health_timeout),
        ] {
            if timeout.is_zero() {
                return Err(ExternalServiceError(format!(
                    "{label} must be greater than zero"
                )));
            }
            if timeout > Duration::from_secs(ACTION_TIMEOUT_CEILING_SEC) {
                return Err(ExternalServiceError(format!(
                    "{label} must not exceed {ACTION_TIMEOUT_CEILING_SEC} seconds"
                )));
            }
        }
        // The daemon does not start with a SIGCHLD setting under which no
        // command could be waited for (checked again before every spawn).
        check_sigchld(sys::sigchld_state)
            .map_err(|refusal| ExternalServiceError(refusal.to_string()))?;
        Ok(Self {
            start,
            stop,
            status,
            health,
            start_timeout,
            stop_timeout,
            health_timeout,
            runner: Runner::new(trust),
            unproven_stopped: false,
            stop_succeeded_since_start: false,
        })
    }

    fn query_timeout(&self) -> Duration {
        self.start_timeout.min(self.stop_timeout)
    }

    fn diagnostic(end: &RunEnd) -> ActionDiagnostic {
        match end {
            RunEnd::Exited { code: Some(0), .. } => ActionDiagnostic::Success,
            RunEnd::Exited { .. } => ActionDiagnostic::Error("service command failed".into()),
            RunEnd::TimedOut { cleaned: true } => ActionDiagnostic::Timeout,
            RunEnd::TimedOut { cleaned: false } | RunEnd::CleanupUncertain => {
                ActionDiagnostic::Error("service command cleanup is uncertain".into())
            }
            RunEnd::LeaderLost => ActionDiagnostic::Error(
                "service command leader was lost; cleanup is uncertain".into(),
            ),
            RunEnd::InvalidTimeout => {
                ActionDiagnostic::Error("service command timeout is out of range".into())
            }
            RunEnd::SigchldRefused(refusal) => {
                ActionDiagnostic::Error(format!("service command cannot run: {refusal}"))
            }
            RunEnd::Refused(_) => {
                ActionDiagnostic::Error("service command executable is not trusted".into())
            }
            RunEnd::SpawnFailed => {
                ActionDiagnostic::Error("service command could not start".into())
            }
            RunEnd::PendingBlocked => ActionDiagnostic::Error(
                "an earlier service command could not be reaped; nothing is spawned".into(),
            ),
        }
    }

    /// The strict `status` grammar.
    fn classify_status(end: &RunEnd) -> RawServiceObservation {
        match end {
            RunEnd::Exited {
                code: Some(0),
                stdout,
                overflow: false,
            } => {
                let text = stdout.strip_suffix(b"\n").unwrap_or(stdout);
                match text {
                    b"running" => RawServiceObservation::Running,
                    b"stopped" => RawServiceObservation::Stopped,
                    _ => RawServiceObservation::Unavailable,
                }
            }
            _ => RawServiceObservation::Unavailable,
        }
    }
}

impl super::sealed::ServiceBackend for ExternalServiceBackend {}

impl super::ServiceBackend for ExternalServiceBackend {
    fn request_service_start(&mut self) -> ActionDiagnostic {
        // From this call on a late start cannot be excluded, whatever the
        // command reports.
        self.unproven_stopped = true;
        self.stop_succeeded_since_start = false;
        let argv = self.start.clone();
        let end = self.runner.run(&argv, "start", self.start_timeout, false);
        // A start whose group is not proven gone leaves its leftovers able to
        // act later; the taint set above stays (it is only ever cleared by a
        // successful stop of a proven-empty group), and no result is Success.
        Self::diagnostic(&end)
    }

    fn observe_service(&mut self) -> RawServiceObservation {
        let argv = self.status.clone();
        let end = self.runner.run(&argv, "status", self.query_timeout(), true);
        match Self::classify_status(&end) {
            RawServiceObservation::Stopped if self.unproven_stopped => {
                if self.stop_succeeded_since_start {
                    self.unproven_stopped = false;
                    self.stop_succeeded_since_start = false;
                    RawServiceObservation::Stopped
                } else {
                    RawServiceObservation::Unavailable
                }
            }
            observation => observation,
        }
    }

    fn request_service_stop(&mut self) -> ActionDiagnostic {
        let argv = self.stop.clone();
        let end = self.runner.run(&argv, "stop", self.stop_timeout, false);
        if end.cleanup_uncertain() {
            // The stop's own group may still hold a process that can start
            // the service again: the stopped state is unproven from here on,
            // and no earlier stop success counts.
            self.unproven_stopped = true;
            self.stop_succeeded_since_start = false;
        } else if self.unproven_stopped {
            self.stop_succeeded_since_start = matches!(end, RunEnd::Exited { code: Some(0), .. });
        }
        Self::diagnostic(&end)
    }

    fn observe_health(&mut self) -> RawHealthObservation {
        let argv = self.health.clone();
        match self.runner.run(&argv, "health", self.health_timeout, false) {
            RunEnd::Exited { code: Some(0), .. } => RawHealthObservation::Healthy,
            RunEnd::Exited { .. } => RawHealthObservation::Unhealthy,
            _ => RawHealthObservation::Unavailable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::ServiceBackend;
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn policy() -> TrustPolicy {
        TrustPolicy::for_test_user()
    }

    struct Dir(PathBuf);

    impl Dir {
        fn new(tag: &str) -> Self {
            let path = fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!(
                    "mikagami-cmd-{tag}-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::SeqCst)
                ));
            fs::create_dir_all(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }

        /// Write an executable script and run it once, without its body, so
        /// the OS's first-execution vetting of a new file (slow on a loaded
        /// Mac, where concurrent new-script executions queue) is paid here and
        /// not inside a deadline a test asserts on. The guard line returns
        /// before the body when `MKM_TEST_WARMUP` is set, which only this
        /// warm-up run sets (the runner clears the environment, so no real run
        /// ever sees it).
        fn script(&self, name: &str, body: &str) -> String {
            let path = self.0.join(name);
            fs::write(
                &path,
                format!("#!/bin/sh\n[ -n \"$MKM_TEST_WARMUP\" ] && exit 0\n{body}\n"),
            )
            .unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            let warmed = Command::new(&path)
                .env("MKM_TEST_WARMUP", "1")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            assert!(warmed.success(), "the warm-up of {} failed", path.display());
            path.to_string_lossy().into_owned()
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A generous step budget for the tests that expect their commands to
    /// finish: a loaded host can take seconds to start a script. Tests that
    /// expect a timeout choose their own, short, deadline.
    fn backend(dir: &Dir, start: &str, stop: &str, status: &str) -> ExternalServiceBackend {
        backend_with_timeouts(dir, start, stop, status, Duration::from_secs(20))
    }

    fn backend_with_timeouts(
        dir: &Dir,
        start: &str,
        stop: &str,
        status: &str,
        timeout: Duration,
    ) -> ExternalServiceBackend {
        let start = dir.script("start", start);
        let stop = dir.script("stop", stop);
        let status = dir.script("status", status);
        let health = dir.script("health", "exit 0");
        ExternalServiceBackend::with_policy(
            vec![start],
            vec![stop],
            vec![status],
            vec![health],
            timeout,
            timeout,
            timeout,
            policy(),
        )
        .unwrap()
    }

    // ---- status grammar (CM-6) ---------------------------------------------------

    #[test]
    fn status_reads_only_running_and_stopped() {
        for (script, expected) in [
            ("echo running", RawServiceObservation::Running),
            ("printf running", RawServiceObservation::Running),
            ("echo stopped", RawServiceObservation::Stopped),
            ("printf stopped", RawServiceObservation::Stopped),
            ("echo Running", RawServiceObservation::Unavailable),
            ("echo 'running '", RawServiceObservation::Unavailable),
            ("printf 'running\\n\\n'", RawServiceObservation::Unavailable),
            (
                "printf 'stopped\\nextra\\n'",
                RawServiceObservation::Unavailable,
            ),
            ("echo inactive", RawServiceObservation::Unavailable),
            ("exit 0", RawServiceObservation::Unavailable),
            ("echo running; exit 1", RawServiceObservation::Unavailable),
            ("echo stopped; exit 3", RawServiceObservation::Unavailable),
            (
                "echo stopped; kill -9 $$",
                RawServiceObservation::Unavailable,
            ),
        ] {
            let dir = Dir::new("status");
            let mut backend = backend(&dir, "exit 0", "exit 0", script);
            assert_eq!(backend.observe_service(), expected, "{script}");
        }
    }

    #[test]
    fn oversized_status_output_is_unavailable_and_does_not_stall() {
        let dir = Dir::new("big");
        let mut backend = backend(
            &dir,
            "exit 0",
            "exit 0",
            "i=0; while [ $i -lt 2000 ]; do echo running-running-running; i=$((i+1)); done",
        );
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable
        );
    }

    #[test]
    fn a_status_command_that_cannot_run_is_never_stopped() {
        let dir = Dir::new("missing");
        let mut backend = backend(&dir, "exit 0", "exit 0", "echo stopped");
        fs::remove_file(&backend.status[0]).unwrap();
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable
        );
    }

    #[test]
    fn status_timeout_is_unavailable() {
        let dir = Dir::new("status-timeout");
        let mut backend = backend_with_timeouts(
            &dir,
            "exit 0",
            "exit 0",
            "sleep 30; echo stopped",
            Duration::from_secs(1),
        );
        let started = Instant::now();
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable
        );
        assert!(started.elapsed() < Duration::from_secs(6));
    }

    // ---- start / stop results are advisory (CM-5) ------------------------------

    #[test]
    fn start_and_stop_diagnostics_follow_the_exit_status() {
        let dir = Dir::new("diag");
        let mut ok = backend(&dir, "exit 0", "exit 0", "echo running");
        assert_eq!(ok.request_service_start(), ActionDiagnostic::Success);
        assert_eq!(ok.request_service_stop(), ActionDiagnostic::Success);
        let dir = Dir::new("diag-fail");
        let mut failing = backend(&dir, "exit 4", "exit 5", "echo running");
        assert!(matches!(
            failing.request_service_start(),
            ActionDiagnostic::Error(_)
        ));
        assert!(matches!(
            failing.request_service_stop(),
            ActionDiagnostic::Error(_)
        ));
    }

    #[test]
    fn the_environment_is_cleared_and_fixed() {
        let dir = Dir::new("env");
        let out = dir.0.join("env.txt");
        let mut backend = backend(
            &dir,
            &format!("env > '{}'", out.display()),
            "exit 0",
            "echo running",
        );
        unsafe { std::env::set_var("MIKAGAMI_TEST_LEAK", "1") };
        assert_eq!(backend.request_service_start(), ActionDiagnostic::Success);
        let text = fs::read_to_string(&out).unwrap();
        assert!(text.contains("MIKAGAMI_SERVICE_ACTION=start"), "{text}");
        assert!(
            text.contains("PATH=/usr/sbin:/usr/bin:/sbin:/bin"),
            "{text}"
        );
        assert!(text.contains("LANG=C"), "{text}");
        assert!(!text.contains("MIKAGAMI_TEST_LEAK"), "{text}");
    }

    #[test]
    fn arguments_are_not_interpreted_by_a_shell() {
        let dir = Dir::new("argv");
        let marker = dir.0.join("marker");
        let program = dir.script("args", "echo \"$1\" > \"$2\"");
        let mut backend = ExternalServiceBackend::with_policy(
            vec![
                program,
                "a b; touch /nonexistent-mikagami $(id)".into(),
                marker.display().to_string(),
            ],
            vec![dir.script("stop", "exit 0")],
            vec![dir.script("status", "echo stopped")],
            vec![dir.script("health", "exit 0")],
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
            policy(),
        )
        .unwrap();
        assert_eq!(backend.request_service_start(), ActionDiagnostic::Success);
        assert_eq!(
            fs::read_to_string(&marker).unwrap(),
            "a b; touch /nonexistent-mikagami $(id)\n"
        );
    }

    // ---- process groups (CM-4 / CM-7) -------------------------------------------

    fn alive(pid: i32) -> bool {
        Command::new("/bin/kill")
            .args(["-0", &pid.to_string()])
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    fn read_pid(path: &Path) -> i32 {
        for _ in 0..200 {
            if let Ok(text) = fs::read_to_string(path) {
                if let Ok(pid) = text.trim().parse() {
                    return pid;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("no pid in {}", path.display());
    }

    fn wait_dead(pid: i32) -> bool {
        for _ in 0..300 {
            if !alive(pid) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    /// Run a script once with `warm` as its only argument (it exits at once
    /// on that argument). The first exec of a freshly written script can take
    /// seconds on a loaded host, where the OS vets it while its neighbours do
    /// the same; a test with a short deadline warms its script first so the
    /// deadline measures the script and not the host.
    fn warm_exec(script: &Path) {
        assert!(Command::new(script).arg("warm").status().unwrap().success());
    }

    #[test]
    fn a_timed_out_start_kills_its_whole_group() {
        let dir = Dir::new("timeout");
        let pidfile = dir.0.join("child.pid");
        let mut backend = backend_with_timeouts(
            &dir,
            &format!(
                "[ \"$1\" = warm ] && exit 0\nsleep 60 &\necho $! > '{}'\nwait",
                pidfile.display()
            ),
            "exit 0",
            "echo stopped",
            Duration::from_secs(1),
        );
        warm_exec(&dir.0.join("start"));
        assert_eq!(backend.request_service_start(), ActionDiagnostic::Timeout);
        let child = read_pid(&pidfile);
        assert!(wait_dead(child), "the grandchild survived the group kill");
    }

    #[test]
    fn leftovers_in_the_group_are_killed_when_the_leader_exits() {
        let dir = Dir::new("leftover");
        let pidfile = dir.0.join("child.pid");
        let mut backend = backend(
            &dir,
            &format!("sleep 60 &\necho $! > '{}'\nexit 0", pidfile.display()),
            "exit 0",
            "echo running",
        );
        assert_eq!(backend.request_service_start(), ActionDiagnostic::Success);
        let child = read_pid(&pidfile);
        assert!(
            wait_dead(child),
            "a process left in the action's group must not outlive the action"
        );
    }

    #[test]
    fn a_detached_service_survives_the_action_by_contract() {
        let dir = Dir::new("detached");
        let pidfile = dir.0.join("svc.pid");
        // `perl` calls setsid so the service leaves the action's group. The
        // action must not return before that has happened (the runner kills
        // whatever is still in the group when the leader exits).
        let mut backend = backend(
            &dir,
            &format!(
                "perl -MPOSIX -e 'POSIX::setsid(); exec \"/bin/sleep\", \"60\"' &\necho $! > '{}'\nsleep 1\nexit 0",
                pidfile.display()
            ),
            "exit 0",
            "echo running",
        );
        assert_eq!(backend.request_service_start(), ActionDiagnostic::Success);
        let service = read_pid(&pidfile);
        std::thread::sleep(Duration::from_millis(200));
        assert!(alive(service), "a setsid'ed service must survive");
        let _ = Command::new("/bin/kill").arg(service.to_string()).status();
        assert!(wait_dead(service));
    }

    // ---- "started, not yet proven stopped" is Unknown (K-6) -----------------------

    #[test]
    fn stopped_is_not_believed_after_a_start_until_our_stop_succeeded() {
        let dir = Dir::new("taint");
        // A start that returns at once while the service "comes up later":
        // the status script still says stopped.
        let mut backend = backend(&dir, "exit 0", "exit 0", "echo stopped");
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Stopped,
            "before any start"
        );
        assert_eq!(backend.request_service_start(), ActionDiagnostic::Success);
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable,
            "stopped right after our start is not trusted"
        );
        assert_eq!(backend.request_service_stop(), ActionDiagnostic::Success);
        assert_eq!(backend.observe_service(), RawServiceObservation::Stopped);
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Stopped,
            "the proof is consumed only once the state is proven"
        );
    }

    #[test]
    fn a_failed_or_timed_out_start_is_also_unproven_and_a_failed_stop_keeps_it_unknown() {
        let dir = Dir::new("taint2");
        let mut backend = backend_with_timeouts(
            &dir,
            "sleep 30",
            "exit 9",
            "echo stopped",
            Duration::from_secs(1),
        );
        assert_eq!(backend.request_service_start(), ActionDiagnostic::Timeout);
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable
        );
        // `exit 9` is an error; under heavy load the 1 s step deadline may
        // fire first. Either way the stop did not succeed.
        assert!(matches!(
            backend.request_service_stop(),
            ActionDiagnostic::Error(_) | ActionDiagnostic::Timeout
        ));
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable,
            "a stop that failed proves nothing"
        );
    }

    #[test]
    fn running_is_reported_as_is_after_a_start() {
        let dir = Dir::new("running");
        let mut backend = backend(&dir, "exit 0", "exit 0", "echo running");
        assert_eq!(backend.request_service_start(), ActionDiagnostic::Success);
        assert_eq!(backend.observe_service(), RawServiceObservation::Running);
    }

    // ---- health (A-7) ---------------------------------------------------------------

    #[test]
    fn health_maps_exit_status_and_failures() {
        for (body, expected) in [
            ("exit 0", RawHealthObservation::Healthy),
            ("exit 1", RawHealthObservation::Unhealthy),
            ("kill -9 $$", RawHealthObservation::Unhealthy),
        ] {
            let dir = Dir::new("health");
            let mut backend = backend(&dir, "exit 0", "exit 0", "echo running");
            backend.health = vec![dir.script("h", body)];
            assert_eq!(backend.observe_health(), expected, "{body}");
        }
        let dir = Dir::new("health-timeout");
        let mut backend = backend_with_timeouts(
            &dir,
            "exit 0",
            "exit 0",
            "echo running",
            Duration::from_secs(1),
        );
        backend.health = vec![dir.script("h", "sleep 30")];
        assert_eq!(backend.observe_health(), RawHealthObservation::Unavailable);
    }

    // ---- trust (CM-2) -------------------------------------------------------------------

    #[test]
    fn untrusted_executables_are_refused_at_construction_and_at_every_spawn() {
        let dir = Dir::new("trust");
        let good = dir.script("good", "exit 0");
        let build = |program: &str, policy: TrustPolicy| {
            ExternalServiceBackend::with_policy(
                vec![program.to_string()],
                vec![good.clone()],
                vec![good.clone()],
                vec![good.clone()],
                Duration::from_secs(5),
                Duration::from_secs(5),
                Duration::from_secs(5),
                policy,
            )
        };
        let ok = policy();
        assert!(build(&good, ok).is_ok());
        // owner is not the trusted user (stands in for "not root")
        let other = TrustPolicy {
            uid: ok.uid + 1,
            ..ok
        };
        assert!(
            build(&good, other)
                .unwrap_err()
                .0
                .contains("not owned by root")
        );
        // the production policy refuses a user-owned file
        if ok.uid != 0 {
            assert!(build(&good, TrustPolicy::PRODUCTION).is_err());
        }
        // group-writable
        let writable = dir.script("writable", "exit 0");
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(
            build(&writable, ok)
                .unwrap_err()
                .0
                .contains("group or world writable")
        );
        // not executable
        let plain = dir.script("plain", "exit 0");
        fs::set_permissions(&plain, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(build(&plain, ok).unwrap_err().0.contains("not executable"));
        // symlink as the final component
        let link = dir.0.join("link");
        std::os::unix::fs::symlink(&good, &link).unwrap();
        assert!(
            build(link.to_str().unwrap(), ok)
                .unwrap_err()
                .0
                .contains("symbolic link")
        );
        // relative and non-normalized paths
        assert!(build("good", ok).is_err());
        let dotted = format!("{}/./good", dir.0.display());
        assert!(build(&dotted, ok).unwrap_err().0.contains("not normalized"));
        // a directory is not a regular file
        assert!(build(dir.0.to_str().unwrap(), ok).is_err());
        // swapped after construction: the spawn-time check refuses it
        let mut backend = backend(&dir, "exit 0", "exit 0", "echo stopped");
        fs::set_permissions(&backend.status[0], fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable
        );
        assert!(matches!(
            backend.request_service_stop(),
            ActionDiagnostic::Success
        ));
        fs::set_permissions(&backend.stop[0], fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            backend.request_service_stop(),
            ActionDiagnostic::Error(_)
        ));
    }

    /// The ancestor rule on synthetic metadata (the real walk depends on the
    /// parents of the scratch directory, which differ between hosts).
    #[test]
    fn the_ancestor_rule_refuses_untrusted_parents() {
        // (is_dir, owner, mode, expected)
        for (is_dir, owner, mode, trusted, expected) in [
            (true, 0, 0o755, 0, Ok(())),
            (true, 0, 0o700, 0, Ok(())),
            (
                true,
                0,
                0o775,
                0,
                Err(ExecutableRefusal::AncestorGroupOrWorldWritable),
            ),
            (
                true,
                0,
                0o777,
                0,
                Err(ExecutableRefusal::AncestorGroupOrWorldWritable),
            ),
            // a sticky world-writable directory such as /tmp is still refused
            (
                true,
                0,
                0o1777,
                0,
                Err(ExecutableRefusal::AncestorGroupOrWorldWritable),
            ),
            (
                true,
                1000,
                0o755,
                0,
                Err(ExecutableRefusal::AncestorNotTrusted),
            ),
            (
                false,
                0,
                0o755,
                0,
                Err(ExecutableRefusal::AncestorNotDirectory),
            ),
            (true, 1000, 0o755, 1000, Ok(())),
        ] {
            assert_eq!(
                ancestor_verdict(is_dir, owner, mode, trusted),
                expected,
                "{is_dir} {owner} {mode:o} {trusted}"
            );
        }
        for (is_file, owner, mode, expected) in [
            (true, 0, 0o755, Ok(())),
            (true, 0, 0o555, Ok(())),
            (
                true,
                1000,
                0o755,
                Err(ExecutableRefusal::NotOwnedByTrustedUser),
            ),
            (true, 0, 0o775, Err(ExecutableRefusal::GroupOrWorldWritable)),
            (true, 0, 0o757, Err(ExecutableRefusal::GroupOrWorldWritable)),
            (true, 0, 0o644, Err(ExecutableRefusal::NotExecutable)),
            (false, 0, 0o755, Err(ExecutableRefusal::NotRegularFile)),
        ] {
            assert_eq!(
                file_verdict(is_file, owner, mode, 0),
                expected,
                "{is_file} {owner} {mode:o}"
            );
        }
        assert!(TrustPolicy::PRODUCTION.check_ancestors);
        assert_eq!(TrustPolicy::PRODUCTION.uid, 0);
    }

    #[test]
    fn configuration_with_empty_or_control_elements_is_refused() {
        let dir = Dir::new("elements");
        let good = dir.script("good", "exit 0");
        for element in ["", "a\u{1}b"] {
            let result = ExternalServiceBackend::with_policy(
                vec![good.clone(), element.to_string()],
                vec![good.clone()],
                vec![good.clone()],
                vec![good.clone()],
                Duration::from_secs(5),
                Duration::from_secs(5),
                Duration::from_secs(5),
                policy(),
            );
            assert!(result.is_err(), "{element:?}");
        }
    }

    // ---- an unreapable leader blocks every later spawn (CM-4) -----------------------

    #[test]
    fn a_leader_that_cannot_be_reaped_blocks_all_later_actions() {
        let dir = Dir::new("pending");
        // Every script that really runs leaves a mark, so "nothing is spawned"
        // is observed and not inferred from elapsed time. `warm` exits before
        // the mark: the first exec of a fresh script (slow on a loaded Mac) is
        // paid in `warm_exec`, outside every deadline the test asserts on.
        let mark = |name: &str| dir.0.join(format!("ran-{name}"));
        let guarded = |name: &str, body: &str| {
            format!(
                "[ \"$1\" = warm ] && exit 0\ntouch '{}'\n{body}",
                mark(name).display()
            )
        };
        let mut backend = ExternalServiceBackend::with_policy(
            vec![dir.script("start", &guarded("start", "sleep 30"))],
            vec![dir.script("stop", &guarded("stop", "exit 0"))],
            vec![dir.script("status", &guarded("status", "echo running"))],
            vec![dir.script("health", &guarded("health", "exit 0"))],
            Duration::from_secs(1),
            Duration::from_secs(20),
            Duration::from_secs(20),
            policy(),
        )
        .unwrap();
        for name in ["start", "stop", "status", "health"] {
            warm_exec(&dir.0.join(name));
            assert!(!mark(name).exists(), "the warm-up must not run the body");
        }
        // The exit probe never reports an exit: the leader looks unreapable.
        backend.runner.exit_probe = |_| Ok(false);
        assert!(matches!(
            backend.request_service_start(),
            ActionDiagnostic::Error(message) if message.contains("cleanup is uncertain")
        ));
        assert!(
            eventually(|| mark("start").exists()),
            "the start command really ran"
        );
        assert!(backend.runner.pending.is_some());
        let started = Instant::now();
        assert!(matches!(
            backend.request_service_stop(),
            ActionDiagnostic::Error(_)
        ));
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable
        );
        assert_eq!(backend.observe_health(), RawHealthObservation::Unavailable);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "no spawn, no wait"
        );
        for name in ["stop", "status", "health"] {
            assert!(!mark(name).exists(), "{name} was spawned while owed");
        }
        assert!(
            backend.runner.pending.is_some(),
            "the refusals must not discharge the responsibility"
        );
        // Once the leader really is gone, the slot clears and work resumes.
        backend.runner.exit_probe = sys::leader_exited_without_reaping;
        let deadline = Instant::now() + Duration::from_secs(5);
        while backend.runner.pending.is_some() && Instant::now() < deadline {
            let _ = backend.request_service_stop();
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(backend.runner.pending.is_none(), "the slot never cleared");
        assert_eq!(backend.request_service_stop(), ActionDiagnostic::Success);
        assert!(mark("stop").exists(), "positive control: stop ran");
    }

    // ---- group cleanup responsibility (F15-M2) ---------------------------------------

    thread_local! {
        /// `(signal, leader still unreaped)` for every signal the runner sent.
        static SIGNALS: std::cell::RefCell<Vec<(i32, bool)>> =
            const { std::cell::RefCell::new(Vec::new()) };
        static NONBLOCK_CALLS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        static CENSUS_CALLS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    }

    fn failing_signal(_: u32, _: i32) -> Result<(), i32> {
        Err(1)
    }

    /// Delivers for real and records whether the leader was still unreaped,
    /// that is whether the group id was still pinned, at that moment.
    fn recording_signal(pgid: u32, signal: i32) -> Result<(), i32> {
        let pinned = sys::leader_exited_without_reaping(pgid).is_ok();
        SIGNALS.with(|signals| signals.borrow_mut().push((signal, pinned)));
        sys::signal_group(pgid, signal)
    }

    fn census_present(_: u32) -> sys::GroupProbe {
        sys::GroupProbe::Present
    }

    fn census_unknown(_: u32) -> sys::GroupProbe {
        sys::GroupProbe::Unknown(5)
    }

    /// Reports a surviving member twice, then the real census.
    fn census_present_twice(pgid: u32) -> sys::GroupProbe {
        let call = CENSUS_CALLS.with(|calls| {
            calls.set(calls.get() + 1);
            calls.get()
        });
        if call <= 2 {
            sys::GroupProbe::Present
        } else {
            sys::group_probe(pgid)
        }
    }

    fn nonblocking_fails_everywhere(_: i32) -> Result<(), i32> {
        Err(5)
    }

    fn nonblocking_fails_first(fd: i32) -> Result<(), i32> {
        let call = NONBLOCK_CALLS.with(|calls| {
            calls.set(calls.get() + 1);
            calls.get()
        });
        if call == 1 {
            Err(5)
        } else {
            sys::set_nonblocking(fd)
        }
    }

    fn nonblocking_fails_second(fd: i32) -> Result<(), i32> {
        let call = NONBLOCK_CALLS.with(|calls| {
            calls.set(calls.get() + 1);
            calls.get()
        });
        if call == 2 {
            Err(5)
        } else {
            sys::set_nonblocking(fd)
        }
    }

    /// Short start / status deadline, generous stop / health deadline (a
    /// freshly written script can stall for a moment on a loaded host).
    fn backend_with_short_start(
        dir: &Dir,
        start: &str,
        stop: &str,
        status: &str,
        start_timeout: Duration,
    ) -> ExternalServiceBackend {
        ExternalServiceBackend::with_policy(
            vec![dir.script("start", start)],
            vec![dir.script("stop", stop)],
            vec![dir.script("status", status)],
            vec![dir.script("health", "exit 0")],
            start_timeout,
            Duration::from_secs(10),
            Duration::from_secs(10),
            policy(),
        )
        .unwrap()
    }

    fn kill_group_if_alive(pgid: u32) {
        let _ = sys::signal_group(pgid, sys::SIGKILL);
    }

    fn pending_pgid(backend: &ExternalServiceBackend) -> u32 {
        match backend.runner.pending.as_ref().expect("a responsibility") {
            Responsibility::Leader(leader) => leader.pgid,
            Responsibility::Group { pgid } => *pgid,
        }
    }

    /// Independent audit counterexample (F15-M2): a group kill that fails must
    /// not let the status read as stopped. The leftover is a real child of the
    /// action's own group.
    #[test]
    fn independent_audit_signal_failure_must_not_trust_stopped() {
        let dir = Dir::new("audit-group-error");
        let pidfile = dir.0.join("child.pid");
        let body = format!(
            "sleep 2 &\necho $! > '{}'\necho stopped\nexit 0",
            pidfile.display()
        );
        let mut backend = backend(&dir, "exit 0", "exit 0", &body);
        backend.runner.signal = failing_signal;
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable,
            "a group that could not be killed is not a Stopped proof"
        );
        let child = read_pid(&pidfile);
        let pgid = pending_pgid(&backend);
        assert!(alive(child), "the injected failure left the child running");
        // The responsibility is held: nothing runs, nothing is believed.
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable
        );
        assert!(matches!(
            backend.request_service_stop(),
            ActionDiagnostic::Error(message) if message.contains("could not be reaped")
        ));
        assert_eq!(backend.observe_health(), RawHealthObservation::Unavailable);
        // Once the group can be signalled again the child is killed and work
        // resumes.
        backend.runner.signal = sys::signal_group;
        assert_eq!(backend.observe_service(), RawServiceObservation::Stopped);
        assert!(wait_dead(child), "the retried cleanup must kill the group");
        assert!(backend.runner.pending.is_none());
        kill_group_if_alive(pgid);
    }

    /// Independent audit counterexample (F15-M2), strengthened: while the
    /// kill keeps failing, a same-group child that can still activate the
    /// service keeps every answer at Unavailable / Error, including after the
    /// activation has happened.
    #[test]
    fn independent_audit_failed_kill_allows_late_start_after_stopped() {
        let dir = Dir::new("audit-late-start");
        let marker = dir.0.join("activated");
        let start = format!("(sleep 0.6; touch '{}') &\nexit 0", marker.display());
        let status = format!(
            "if test -e '{}'; then echo running; else echo stopped; fi",
            marker.display()
        );
        let mut backend = backend(&dir, &start, "exit 0", &status);
        backend.runner.signal = failing_signal;
        let diagnostic = backend.request_service_start();
        assert!(
            matches!(&diagnostic, ActionDiagnostic::Error(message) if message.contains("cleanup is uncertain")),
            "a start whose group could not be killed is never Success: {diagnostic:?}"
        );
        let pgid = pending_pgid(&backend);
        assert!(matches!(
            backend.request_service_stop(),
            ActionDiagnostic::Error(_)
        ));
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable
        );
        assert!(
            eventually(|| marker.exists()),
            "the leftover child did activate"
        );
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable,
            "stopped (or anything) is not believed while the cleanup is owed"
        );
        // Discharged once the group can be signalled: the activation really
        // happened, so the truthful answer is Running.
        backend.runner.signal = sys::signal_group;
        assert_eq!(backend.observe_service(), RawServiceObservation::Running);
        kill_group_if_alive(pgid);
    }

    /// The same counterexample with the signal restored before the next
    /// action: the retried cleanup kills the leftover child before it can
    /// activate, and the stopped state is believed only after that.
    #[test]
    fn a_retried_group_kill_stops_the_late_start_before_stopped_is_believed() {
        let dir = Dir::new("audit-late-start-retried");
        let marker = dir.0.join("activated");
        let start = format!("(sleep 0.6; touch '{}') &\nexit 0", marker.display());
        let status = format!(
            "if test -e '{}'; then echo running; else echo stopped; fi",
            marker.display()
        );
        let mut backend = backend(&dir, &start, "exit 0", &status);
        backend.runner.signal = failing_signal;
        assert!(matches!(
            backend.request_service_start(),
            ActionDiagnostic::Error(_)
        ));
        backend.runner.signal = sys::signal_group;
        assert_eq!(backend.request_service_stop(), ActionDiagnostic::Success);
        assert_eq!(backend.observe_service(), RawServiceObservation::Stopped);
        std::thread::sleep(Duration::from_millis(900));
        assert!(!marker.exists(), "the leftover child was killed in time");
    }

    #[test]
    fn a_confirmed_kill_but_a_surviving_member_parks_a_census_only_responsibility() {
        let dir = Dir::new("group-state");
        let pidfile = dir.0.join("child.pid");
        let body = format!("sleep 5 &\necho $! > '{}'\necho stopped", pidfile.display());
        let mut backend = backend(&dir, "exit 0", "exit 0", &body);
        backend.runner.signal = recording_signal;
        backend.runner.census = census_present;
        SIGNALS.with(|signals| signals.borrow_mut().clear());
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable,
            "members were still present"
        );
        let pgid = pending_pgid(&backend);
        assert!(matches!(
            backend.runner.pending,
            Some(Responsibility::Group { .. })
        ));
        // Every signal sent so far went out while the leader pinned the id.
        SIGNALS.with(|signals| {
            let signals = signals.borrow();
            assert!(!signals.is_empty());
            assert!(signals.iter().all(|(_, pinned)| *pinned), "{signals:?}");
        });
        // From now on: refused, and not one more signal (the id is unpinned).
        let sent = SIGNALS.with(|signals| signals.borrow().len());
        let started = Instant::now();
        for _ in 0..3 {
            assert_eq!(
                backend.observe_service(),
                RawServiceObservation::Unavailable
            );
            assert!(matches!(
                backend.request_service_stop(),
                ActionDiagnostic::Error(_)
            ));
            assert_eq!(backend.observe_health(), RawHealthObservation::Unavailable);
        }
        assert_eq!(SIGNALS.with(|signals| signals.borrow().len()), sent);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "no spawn, no wait"
        );
        assert!(matches!(
            backend.runner.pending,
            Some(Responsibility::Group { pgid: held }) if held == pgid
        ));
        // An undecidable census is not an empty group either.
        backend.runner.census = census_unknown;
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable
        );
        assert!(backend.runner.pending.is_some());
        assert_eq!(SIGNALS.with(|signals| signals.borrow().len()), sent);
        // The real census finds it empty and discharges the responsibility.
        backend.runner.census = sys::group_probe;
        assert_eq!(backend.observe_service(), RawServiceObservation::Stopped);
        assert!(backend.runner.pending.is_none());
    }

    #[test]
    fn a_member_that_is_reaped_a_moment_later_does_not_fail_the_action() {
        let dir = Dir::new("census-wait");
        let mut backend = backend(&dir, "exit 0", "exit 0", "echo stopped");
        // The bound below is on the census wait, not on the host's first exec
        // of a new script.
        warm_exec(&dir.0.join("status"));
        backend.runner.census = census_present_twice;
        CENSUS_CALLS.with(|calls| calls.set(0));
        let started = Instant::now();
        assert_eq!(backend.observe_service(), RawServiceObservation::Stopped);
        assert_eq!(
            CENSUS_CALLS.with(|calls| calls.get()),
            3,
            "two sightings of a dying member, then the proof"
        );
        assert!(started.elapsed() < TERM_GRACE);
        assert!(backend.runner.pending.is_none());
    }

    #[test]
    fn only_a_pinned_group_id_ever_receives_a_destructive_signal() {
        let dir = Dir::new("pinned");
        let mut backend = backend_with_short_start(
            &dir,
            "sleep 30",
            "exit 0",
            "sleep 30",
            Duration::from_secs(1),
        );
        backend.runner.signal = recording_signal;
        SIGNALS.with(|signals| signals.borrow_mut().clear());
        assert_eq!(backend.request_service_start(), ActionDiagnostic::Timeout);
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable
        );
        assert_eq!(backend.request_service_stop(), ActionDiagnostic::Success);
        SIGNALS.with(|signals| {
            let signals = signals.borrow();
            assert!(signals.iter().any(|(signal, _)| *signal == sys::SIGTERM));
            assert!(signals.iter().any(|(signal, _)| *signal == sys::SIGKILL));
            assert!(
                signals.iter().all(|(_, pinned)| *pinned),
                "a signal went to a group id whose leader was already reaped: {signals:?}"
            );
        });
    }

    #[test]
    fn a_stop_with_an_uncertain_cleanup_does_not_prove_stopped() {
        let dir = Dir::new("stop-uncertain");
        let mut backend = backend(&dir, "exit 0", "exit 0", "echo stopped");
        assert_eq!(backend.request_service_start(), ActionDiagnostic::Success);
        backend.runner.census = census_present;
        assert!(matches!(
            backend.request_service_stop(),
            ActionDiagnostic::Error(message) if message.contains("cleanup is uncertain")
        ));
        backend.runner.census = sys::group_probe;
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable,
            "the stop's group was not proven gone, so it does not count"
        );
        assert_eq!(backend.request_service_stop(), ActionDiagnostic::Success);
        assert_eq!(backend.observe_service(), RawServiceObservation::Stopped);
    }

    #[test]
    fn a_stop_with_an_uncertain_cleanup_taints_even_without_an_earlier_start() {
        let dir = Dir::new("stop-uncertain-fresh");
        let mut backend = backend(&dir, "exit 0", "exit 0", "echo stopped");
        backend.runner.census = census_present;
        assert!(matches!(
            backend.request_service_stop(),
            ActionDiagnostic::Error(_)
        ));
        backend.runner.census = sys::group_probe;
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable
        );
        assert_eq!(backend.request_service_stop(), ActionDiagnostic::Success);
        assert_eq!(backend.observe_service(), RawServiceObservation::Stopped);
    }

    #[test]
    fn an_unconfirmed_kill_after_a_normal_exit_keeps_the_leader_unreaped() {
        let dir = Dir::new("kill-after-exit");
        let mut backend = backend(&dir, "exit 0", "exit 0", "echo running");
        backend.runner.signal = failing_signal;
        assert!(matches!(
            backend.request_service_start(),
            ActionDiagnostic::Error(_)
        ));
        let Some(Responsibility::Leader(leader)) = backend.runner.pending.as_ref() else {
            panic!("the unreaped leader must be held");
        };
        // Still a zombie child: its pid, and so the group id, is pinned.
        assert!(sys::leader_exited_without_reaping(leader.child.id()).unwrap());
        let pgid = leader.pgid;
        backend.runner.signal = sys::signal_group;
        assert_eq!(backend.observe_service(), RawServiceObservation::Running);
        assert!(backend.runner.pending.is_none());
        assert_eq!(sys::group_probe(pgid), sys::GroupProbe::Empty);
    }

    #[test]
    fn a_timeout_with_a_failed_term_still_ends_in_a_bounded_kill() {
        fn term_fails_kill_works(pgid: u32, signal: i32) -> Result<(), i32> {
            if signal == sys::SIGTERM {
                Err(1)
            } else {
                sys::signal_group(pgid, signal)
            }
        }
        let dir = Dir::new("term-fails");
        let mut backend = backend_with_timeouts(
            &dir,
            "sleep 30",
            "exit 0",
            "echo stopped",
            Duration::from_millis(200),
        );
        backend.runner.signal = term_fails_kill_works;
        let started = Instant::now();
        assert_eq!(backend.request_service_start(), ActionDiagnostic::Timeout);
        assert!(
            started.elapsed() < TERM_GRACE,
            "a TERM that was not delivered is not waited on"
        );
        assert!(backend.runner.pending.is_none());
    }

    #[test]
    fn a_timeout_whose_group_is_not_proven_empty_is_not_a_clean_timeout() {
        let dir = Dir::new("timeout-census");
        let mut backend = backend_with_short_start(
            &dir,
            "sleep 30",
            "exit 0",
            "echo stopped",
            Duration::from_millis(200),
        );
        backend.runner.census = census_present;
        assert!(matches!(
            backend.request_service_start(),
            ActionDiagnostic::Error(message) if message.contains("cleanup is uncertain")
        ));
        let pgid = pending_pgid(&backend);
        assert!(matches!(
            backend.runner.pending,
            Some(Responsibility::Group { .. })
        ));
        // The same group, once the census can prove it empty, is discharged.
        backend.runner.census = sys::group_probe;
        assert_eq!(backend.request_service_stop(), ActionDiagnostic::Success);
        assert!(backend.runner.pending.is_none());
        assert_eq!(sys::group_probe(pgid), sys::GroupProbe::Empty);
    }

    #[test]
    fn a_timeout_whose_kill_cannot_be_confirmed_holds_the_leader_without_waiting() {
        let dir = Dir::new("timeout-kill-fails");
        let mut backend = backend_with_timeouts(
            &dir,
            "sleep 30",
            "exit 0",
            "echo stopped",
            Duration::from_millis(200),
        );
        backend.runner.signal = failing_signal;
        let started = Instant::now();
        assert!(matches!(
            backend.request_service_start(),
            ActionDiagnostic::Error(message) if message.contains("cleanup is uncertain")
        ));
        assert!(
            started.elapsed() < TERM_GRACE,
            "an undeliverable kill is not waited on"
        );
        let pgid = pending_pgid(&backend);
        assert!(matches!(
            backend.runner.pending,
            Some(Responsibility::Leader(_))
        ));
        backend.runner.signal = sys::signal_group;
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable
        );
        for _ in 0..50 {
            if backend.runner.pending.is_none() {
                break;
            }
            let _ = backend.request_service_stop();
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(backend.runner.pending.is_none());
        assert_eq!(sys::group_probe(pgid), sys::GroupProbe::Empty);
    }

    #[test]
    fn the_census_distinguishes_empty_present_and_undecidable() {
        let dir = Dir::new("census");
        let mut child = Command::new(dir.script("c", "sleep 30"))
            .process_group(0)
            .spawn()
            .unwrap();
        let pgid = child.id();
        assert_eq!(sys::group_probe(pgid), sys::GroupProbe::Present);
        sys::signal_group(pgid, sys::SIGKILL).unwrap();
        let _ = child.wait();
        for _ in 0..200 {
            if sys::group_probe(pgid) == sys::GroupProbe::Empty {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(sys::group_probe(pgid), sys::GroupProbe::Empty);
        // A signal to a group nobody is left in is "nothing to signal", not a
        // failed kill (signal 0 only: the id is unpinned here).
        assert_eq!(sys::signal_group(pgid, 0), Ok(()));
        for refused in [0, 1] {
            assert_eq!(sys::group_probe(refused), sys::GroupProbe::Unknown(9));
            assert_eq!(sys::signal_group(refused, sys::SIGKILL), Err(9));
        }
        assert_eq!(
            sys::group_probe(u32::MAX),
            sys::GroupProbe::Unknown(9),
            "an id that does not fit is never a census"
        );
    }

    // ---- non-blocking setup failures (F15-M3) ------------------------------------------

    /// Independent audit counterexample (F15-M3): a pipe that cannot be made
    /// non-blocking is never read, so a silent child cannot hold the runner
    /// past its deadline. Stdout only, stderr only and both.
    #[test]
    fn independent_audit_nonblock_error_must_not_block_before_timeout() {
        let setters: [(&str, NonblockingSetter); 3] = [
            ("both", nonblocking_fails_everywhere),
            ("stdout only", nonblocking_fails_first),
            ("stderr only", nonblocking_fails_second),
        ];
        for (label, setter) in setters {
            let dir = Dir::new("audit-nonblock-error");
            let script = dir.script("silent", "sleep 2");
            let mut runner = Runner::new(policy());
            runner.set_nonblocking = setter;
            NONBLOCK_CALLS.with(|calls| calls.set(0));
            let started = Instant::now();
            let result = runner.run(&[script], "status", Duration::from_millis(20), true);
            let elapsed = started.elapsed();
            assert_eq!(
                result,
                RunEnd::TimedOut { cleaned: true },
                "{label}: the group is killed and proven gone"
            );
            assert!(
                elapsed < Duration::from_millis(500),
                "{label}: blocking pipe read defeated the 20 ms timeout: {elapsed:?}"
            );
            assert!(runner.pending.is_none(), "{label}");
        }
    }

    #[test]
    fn a_status_whose_pipe_cannot_be_made_non_blocking_is_unavailable_not_stopped() {
        let dir = Dir::new("nonblock-status");
        let mut backend = backend(&dir, "exit 0", "exit 0", "echo stopped");
        backend.runner.set_nonblocking = nonblocking_fails_second;
        NONBLOCK_CALLS.with(|calls| calls.set(0));
        let started = Instant::now();
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable
        );
        assert!(started.elapsed() < TERM_GRACE);
    }

    #[test]
    fn a_setup_failure_with_an_unkillable_group_is_bounded_and_holds_the_leader() {
        let dir = Dir::new("nonblock-and-kill");
        let script = dir.script("silent", "sleep 30");
        let mut runner = Runner::new(policy());
        runner.set_nonblocking = nonblocking_fails_everywhere;
        runner.signal = failing_signal;
        let started = Instant::now();
        assert_eq!(
            runner.run(&[script.clone()], "status", Duration::from_millis(20), true),
            RunEnd::TimedOut { cleaned: false }
        );
        assert!(started.elapsed() < Duration::from_millis(500));
        let pgid = match runner.pending.as_ref() {
            Some(Responsibility::Leader(leader)) => leader.pgid,
            other => panic!("the leader must be held: {other:?}"),
        };
        // The next action is refused instead of spawning on top of it.
        assert_eq!(
            runner.run(&[script], "status", Duration::from_millis(20), true),
            RunEnd::PendingBlocked
        );
        kill_group_if_alive(pgid);
    }

    #[test]
    fn a_setup_failure_with_a_child_that_never_exits_ends_within_the_grace_periods() {
        let dir = Dir::new("nonblock-never-exits");
        let script = dir.script("silent", "sleep 30");
        let mut runner = Runner::new(policy());
        runner.set_nonblocking = nonblocking_fails_everywhere;
        runner.exit_probe = |_| Ok(false);
        let started = Instant::now();
        assert_eq!(
            runner.run(&[script], "status", Duration::from_millis(20), true),
            RunEnd::TimedOut { cleaned: false }
        );
        assert!(
            started.elapsed() < TERM_GRACE + KILL_GRACE + Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
        let pgid = match runner.pending.as_ref() {
            Some(Responsibility::Leader(leader)) => leader.pgid,
            other => panic!("the leader must be held: {other:?}"),
        };
        kill_group_if_alive(pgid);
        runner.exit_probe = sys::leader_exited_without_reaping;
        for _ in 0..50 {
            if runner.clear_pending() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(runner.pending.is_none());
    }

    // ---- timeout range and the pre-spawn deadline (N-1) ----------------------------------

    #[test]
    fn construction_refuses_a_timeout_outside_the_range() {
        let dir = Dir::new("timeout-range");
        let argv = |name: &str| vec![dir.script(name, "exit 0")];
        let build = |start: Duration, stop: Duration, health: Duration| {
            ExternalServiceBackend::with_policy(
                argv("start"),
                argv("stop"),
                argv("status"),
                argv("health"),
                start,
                stop,
                health,
                policy(),
            )
        };
        let normal = Duration::from_secs(30);
        let max = Duration::from_secs(ACTION_TIMEOUT_CEILING_SEC);
        // Smallest, ordinary and largest accepted values, and the boundary.
        for accepted in [Duration::from_nanos(1), Duration::from_secs(1), normal, max] {
            assert!(build(accepted, accepted, accepted).is_ok(), "{accepted:?}");
        }
        for refused in [
            max + Duration::from_nanos(1),
            max + Duration::from_secs(1),
            Duration::from_secs(u64::MAX),
            Duration::MAX,
        ] {
            for (label, built) in [
                ("start", build(refused, normal, normal)),
                ("stop", build(normal, refused, normal)),
                ("health", build(normal, normal, refused)),
            ] {
                let error = built.expect_err(&format!("{label} {refused:?}")).0;
                assert!(
                    error.contains(&format!(
                        "must not exceed {ACTION_TIMEOUT_CEILING_SEC} seconds"
                    )),
                    "{label} {refused:?}: {error}"
                );
            }
        }
        assert!(build(Duration::ZERO, normal, normal).is_err());
    }

    /// N-1: an unrepresentable deadline is refused before anything is spawned.
    /// Before the fix `Instant::now() + timeout` ran after the spawn and
    /// panicked, leaving a live group with no recorded responsibility.
    #[test]
    fn an_unrepresentable_deadline_is_refused_before_anything_is_spawned() {
        let dir = Dir::new("deadline-overflow");
        let marker = dir.0.join("spawned");
        let script = dir.script(
            "probe",
            &format!(
                "[ \"$1\" = warm ] && exit 0\ntouch '{}'\nsleep 5",
                marker.display()
            ),
        );
        // Warmed, so a spawn would leave its mark within moments.
        warm_exec(Path::new(&script));
        for timeout in [Duration::MAX, Duration::from_secs(u64::MAX)] {
            let mut runner = Runner::new(policy());
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                runner.run(&[script.clone()], "start", timeout, false)
            }));
            assert_eq!(
                result.expect("an overflowing deadline must not panic"),
                RunEnd::InvalidTimeout,
                "{timeout:?}"
            );
            assert!(runner.pending.is_none(), "{timeout:?}: nothing was spawned");
            // A command that had been spawned would have run by now; wait for
            // it for up to 1.5 s (a correct runner never gets here late).
            for _ in 0..150 {
                assert!(!marker.exists(), "{timeout:?}: the command must not run");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        // The same runner still serves a representable timeout.
        let mut runner = Runner::new(policy());
        assert!(matches!(
            runner.run(
                &[dir.script("ok", "exit 0")],
                "start",
                Duration::from_secs(20),
                false
            ),
            RunEnd::Exited { code: Some(0), .. }
        ));
    }

    /// N-1 on every path (start / stop / status / health): the refusal is an
    /// error or `Unavailable`, never a believed result, and spawns nothing.
    #[test]
    fn every_action_path_refuses_an_unrepresentable_timeout_without_spawning() {
        let dir = Dir::new("deadline-paths");
        let marker = dir.0.join("spawned");
        let touch = format!("touch '{}'", marker.display());
        let mut backend = backend(
            &dir,
            &format!("{touch}\nexit 0"),
            &format!("{touch}\nexit 0"),
            &format!("{touch}\necho stopped"),
        );
        backend.health = vec![dir.script("health-touch", &format!("{touch}\nexit 0"))];
        backend.start_timeout = Duration::MAX;
        backend.stop_timeout = Duration::MAX;
        backend.health_timeout = Duration::MAX;
        let out_of_range = |diagnostic: ActionDiagnostic| matches!(&diagnostic, ActionDiagnostic::Error(message) if message.contains("out of range"));
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable
        );
        assert_eq!(backend.observe_health(), RawHealthObservation::Unavailable);
        assert!(out_of_range(backend.request_service_stop()));
        assert!(out_of_range(backend.request_service_start()));
        assert!(backend.runner.pending.is_none());
        std::thread::sleep(Duration::from_millis(100));
        assert!(!marker.exists(), "no command may have been spawned");
        // A refused start still counts as "started": stopped stays unproven.
        backend.start_timeout = Duration::from_secs(5);
        backend.stop_timeout = Duration::from_secs(5);
        backend.health_timeout = Duration::from_secs(5);
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable
        );
        assert_eq!(backend.request_service_stop(), ActionDiagnostic::Success);
        assert_eq!(backend.observe_service(), RawServiceObservation::Stopped);
        assert_eq!(backend.observe_health(), RawHealthObservation::Healthy);
        assert!(marker.exists(), "valid timeouts run the commands");
    }

    // ---- a leader reaped elsewhere no longer pins its group id (N-2) --------------------

    /// Poll `done` for up to 30 s: these tests wait for processes on a host
    /// that may be loaded, and only a result, never a duration, is asserted.
    fn eventually(mut done: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if done() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// The pid a script wrote, waiting up to 30 s for the script to start.
    fn read_pid_patiently(path: &Path) -> i32 {
        let mut pid = None;
        assert!(
            eventually(|| {
                pid = fs::read_to_string(path)
                    .ok()
                    .and_then(|text| text.trim().parse().ok());
                pid.is_some()
            }),
            "no pid in {}",
            path.display()
        );
        pid.unwrap()
    }

    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    }

    /// `kill(pid, 0)` without a helper process: these tests poll, and a
    /// process spawned per poll would load the host they are measured on.
    fn pid_alive(pid: i32) -> bool {
        // SAFETY: signal 0 delivers nothing.
        unsafe { kill(pid, 0) == 0 }
    }

    #[derive(Clone, Copy)]
    enum Probe {
        Running,
        Interrupted,
        Invalid,
        /// `ECHILD` once, though the leader is in fact still alive: the
        /// loss must be final even if a later query would look healthy.
        LostOnce,
        ExternalReap,
    }

    thread_local! {
        static PROBES: std::cell::RefCell<std::collections::VecDeque<Probe>> =
            const { std::cell::RefCell::new(std::collections::VecDeque::new()) };
        /// `reap_elsewhere` waits for this file (the group's other member
        /// has started) before it takes the leader away.
        static MEMBER_STARTED: std::cell::RefCell<Option<PathBuf>> =
            const { std::cell::RefCell::new(None) };
    }

    fn queue_probes(steps: &[Probe]) {
        PROBES.with(|probes| {
            let mut probes = probes.borrow_mut();
            probes.clear();
            probes.extend(steps.iter().copied());
        });
    }

    /// Something other than the runner kills and reaps the leader process
    /// alone: the kernel then answers `ECHILD` to every later exit query, and
    /// the group's other members keep the group id in use.
    fn reap_elsewhere(pid: u32) {
        if let Some(file) = MEMBER_STARTED.with(|file| file.borrow().clone()) {
            read_pid_patiently(&file);
        }
        let pid = i32::try_from(pid).unwrap();
        let mut status = 0;
        // SAFETY: plain syscalls on a pid of a child of this test process.
        unsafe {
            kill(pid, sys::SIGKILL);
            waitpid(pid, &mut status, 0);
        }
    }

    /// The scripted exit query: queued answers first, then the real one.
    fn scripted_probe(pid: u32) -> Result<bool, i32> {
        match PROBES.with(|probes| probes.borrow_mut().pop_front()) {
            Some(Probe::Running) => Ok(false),
            Some(Probe::Interrupted) => Err(sys::EINTR),
            Some(Probe::Invalid) => Err(22),
            Some(Probe::LostOnce) => Err(sys::ECHILD),
            Some(Probe::ExternalReap) => {
                reap_elsewhere(pid);
                sys::leader_exited_without_reaping(pid)
            }
            None => sys::leader_exited_without_reaping(pid),
        }
    }

    /// Records `(signal, group id still pinned)` and delivers nothing, so a
    /// signal that would have hit the group's surviving members is visible
    /// without harming them. TERM is reported as undeliverable on request.
    fn muted_signal(pgid: u32, signal: i32) -> Result<(), i32> {
        let pinned = sys::leader_exited_without_reaping(pgid).is_ok();
        SIGNALS.with(|signals| signals.borrow_mut().push((signal, pinned)));
        Ok(())
    }

    fn muted_signal_term_fails(pgid: u32, signal: i32) -> Result<(), i32> {
        muted_signal(pgid, signal)?;
        if signal == sys::SIGTERM {
            Err(1)
        } else {
            Ok(())
        }
    }

    fn sent_signals() -> Vec<(i32, bool)> {
        SIGNALS.with(|signals| signals.borrow().clone())
    }

    /// The scripts of a lost-pin test, written once and reused by every case
    /// of that test: the first exec of a freshly written script is slow on a
    /// loaded host, and this module's tests run side by side.
    struct LostPinScripts {
        dir: Dir,
        /// A leader that stays up with one more member in its group; `$1`
        /// receives the member's pid once it runs.
        holder: String,
        /// Touches the marker `$1`.
        late: String,
    }

    impl LostPinScripts {
        fn new(tag: &str) -> Self {
            let dir = Dir::new(tag);
            let holder = dir.script("holder", "sleep 30 &\necho $! > \"$1\"\nsleep 30");
            let late = dir.script("late", "touch \"$1\"");
            Self { dir, holder, late }
        }

        /// The holder's argv for one case; the pid file is where the case
        /// finds the group's other member.
        fn holder_for(&self, label: &str) -> (Vec<String>, PathBuf) {
            let member = self.dir.0.join(format!("member-{label}.pid"));
            MEMBER_STARTED.with(|file| *file.borrow_mut() = Some(member.clone()));
            (
                vec![self.holder.clone(), member.display().to_string()],
                member,
            )
        }
    }

    /// The group is only held by the surviving members now: kill it (it is in
    /// use, so this is the test's own cleanup) and let the runner discharge.
    fn finish_lost_group(runner: &mut Runner, pgid: u32, member: i32) {
        assert!(
            pid_alive(member),
            "a lost pin must not cost a stranger its life"
        );
        kill_group_if_alive(pgid);
        assert!(eventually(|| !pid_alive(member)));
        assert!(
            eventually(|| runner.clear_pending()),
            "the proven-empty group discharges"
        );
        assert!(runner.pending.is_none());
    }

    fn assert_lost_pin_is_held(
        runner: &mut Runner,
        label: &str,
        scripts: &LostPinScripts,
        member: &Path,
    ) {
        let pgid = pending_pgid_of(runner);
        assert!(
            matches!(runner.pending, Some(Responsibility::Group { .. })),
            "{label}: census-only responsibility, not {:?}",
            runner.pending
        );
        let before = sent_signals();
        // Every later action is refused, nothing is spawned, nothing signalled.
        let marker = scripts.dir.0.join(format!("late-ran-{label}"));
        let late = vec![scripts.late.clone(), marker.display().to_string()];
        for _ in 0..3 {
            assert!(!runner.clear_pending(), "{label}: group id still in use");
            assert_eq!(
                runner.run(&late, "start", Duration::from_secs(5), false),
                RunEnd::PendingBlocked,
                "{label}"
            );
        }
        assert!(!marker.exists(), "{label}: a later spawn was allowed");
        assert_eq!(
            sent_signals(),
            before,
            "{label}: a signal followed the loss"
        );
        let member_pid = read_pid_patiently(member);
        finish_lost_group(runner, pgid, member_pid);
        // Discharged by proof; with the real hooks back, work resumes.
        runner.exit_probe = sys::leader_exited_without_reaping;
        runner.signal = sys::signal_group;
        runner.set_nonblocking = sys::set_nonblocking;
        assert!(
            matches!(
                runner.run(&late, "start", Duration::from_secs(5), false),
                RunEnd::Exited { code: Some(0), .. }
            ),
            "{label}"
        );
        assert!(marker.exists(), "{label}");
    }

    fn pending_pgid_of(runner: &Runner) -> u32 {
        match runner.pending.as_ref().expect("a responsibility") {
            Responsibility::Leader(leader) => leader.pgid,
            Responsibility::Group { pgid } => *pgid,
        }
    }

    /// The leader is reaped elsewhere at each point where the runner asks
    /// about it. The group id is then (as far as the runner can know) free
    /// for anyone: its other members stand for the stranger that would own it.
    /// No path may signal after the loss, claim success, or allow a spawn.
    #[test]
    fn a_leader_reaped_elsewhere_is_never_signalled_again_on_any_path() {
        // (label, probe answers, signal, non-blocking setter, signals before the loss)
        type Case = (
            &'static str,
            &'static [Probe],
            GroupSignal,
            NonblockingSetter,
            &'static [i32],
        );
        let cases: [Case; 4] = [
            (
                "run-loop",
                &[Probe::ExternalReap],
                muted_signal,
                sys::set_nonblocking,
                &[],
            ),
            (
                "before-term",
                &[Probe::ExternalReap],
                muted_signal,
                nonblocking_fails_everywhere,
                &[],
            ),
            (
                "during-term-grace",
                &[Probe::Running, Probe::ExternalReap],
                muted_signal,
                nonblocking_fails_everywhere,
                &[sys::SIGTERM],
            ),
            (
                "during-kill-grace",
                &[Probe::Running, Probe::ExternalReap],
                muted_signal_term_fails,
                nonblocking_fails_everywhere,
                &[sys::SIGTERM, sys::SIGKILL],
            ),
        ];
        let scripts = LostPinScripts::new("lost-pin-run");
        for (label, probes, signal, setter, expected) in cases {
            let (argv, member) = scripts.holder_for(label);
            let mut runner = Runner::new(policy());
            runner.exit_probe = scripted_probe;
            runner.signal = signal;
            runner.set_nonblocking = setter;
            SIGNALS.with(|signals| signals.borrow_mut().clear());
            queue_probes(probes);
            assert_eq!(
                runner.run(&argv, "start", Duration::from_millis(20), false),
                RunEnd::LeaderLost,
                "{label}"
            );
            let sent = sent_signals();
            assert_eq!(
                sent.iter().map(|(signal, _)| *signal).collect::<Vec<_>>(),
                expected,
                "{label}"
            );
            assert!(
                sent.iter().all(|(_, pinned)| *pinned),
                "{label}: only pinned signals: {sent:?}"
            );
            assert_lost_pin_is_held(&mut runner, label, &scripts, &member);
        }
    }

    /// A lost pin seen by the run loop is final: no later, healthier-looking
    /// answer brings the group id back (the guard before the deadline TERM is
    /// a second line, not the first). The leader here is really still alive.
    #[test]
    fn a_pin_lost_in_the_run_loop_is_not_forgotten_by_a_later_query() {
        let scripts = LostPinScripts::new("lost-pin-final");
        let (argv, member) = scripts.holder_for("final");
        let mut runner = Runner::new(policy());
        runner.exit_probe = scripted_probe;
        runner.signal = muted_signal;
        SIGNALS.with(|signals| signals.borrow_mut().clear());
        queue_probes(&[Probe::LostOnce]);
        assert_eq!(
            runner.run(&argv, "start", Duration::from_secs(30), false),
            RunEnd::LeaderLost
        );
        assert!(sent_signals().is_empty(), "{:?}", sent_signals());
        let pgid = pending_pgid_of(&runner);
        let member_pid = read_pid_patiently(&member);
        // Test cleanup: the leader is still ours in fact; collect it too.
        kill_group_if_alive(pgid);
        let mut status = 0;
        // SAFETY: plain syscall on the pid of this test's own child.
        unsafe { waitpid(i32::try_from(pgid).unwrap(), &mut status, 0) };
        assert!(eventually(|| !pid_alive(member_pid)));
        assert!(eventually(|| runner.clear_pending()));
    }

    /// The retry (`clear_pending`) checks the pin before it kills.
    #[test]
    fn a_retried_cleanup_whose_leader_was_reaped_elsewhere_does_not_kill() {
        // (label, answers to the retry's queries, signals the retry may send)
        let cases: [(&str, &[Probe], &[i32]); 2] = [
            ("before-the-kill", &[Probe::ExternalReap], &[]),
            (
                "after-the-kill",
                &[Probe::Running, Probe::ExternalReap],
                &[sys::SIGKILL],
            ),
        ];
        let scripts = LostPinScripts::new("lost-pin-retry");
        for (label, probes, expected) in cases {
            let (argv, member) = scripts.holder_for(label);
            let mut runner = Runner::new(policy());
            runner.exit_probe = scripted_probe;
            runner.signal = failing_signal;
            queue_probes(&[]);
            assert_eq!(
                runner.run(&argv, "start", Duration::from_millis(20), false),
                RunEnd::TimedOut { cleaned: false },
                "{label}: the kill could not be confirmed, the leader is held"
            );
            assert!(matches!(runner.pending, Some(Responsibility::Leader(_))));
            runner.signal = muted_signal;
            SIGNALS.with(|signals| signals.borrow_mut().clear());
            queue_probes(probes);
            assert!(!runner.clear_pending(), "{label}");
            assert_eq!(
                sent_signals()
                    .iter()
                    .map(|(signal, _)| *signal)
                    .collect::<Vec<_>>(),
                expected,
                "{label}"
            );
            assert!(sent_signals().iter().all(|(_, pinned)| *pinned), "{label}");
            assert_lost_pin_is_held(&mut runner, label, &scripts, &member);
        }
    }

    /// Backend level: a status whose leader is reaped elsewhere is never
    /// `Stopped`, the survivor of its group is not killed, and later actions
    /// wait for the census proof.
    #[test]
    fn a_status_whose_leader_was_reaped_elsewhere_is_unavailable_and_blocks_later_actions() {
        let dir = Dir::new("lost-pin-status");
        let member = dir.0.join("member.pid");
        let status = format!(
            "sleep 30 &\necho $! > '{}'\necho stopped\nexit 0",
            member.display()
        );
        let mut backend = backend(&dir, "exit 0", "exit 0", &status);
        MEMBER_STARTED.with(|file| *file.borrow_mut() = Some(member.clone()));
        backend.runner.exit_probe = scripted_probe;
        backend.runner.signal = recording_signal;
        SIGNALS.with(|signals| signals.borrow_mut().clear());
        queue_probes(&[Probe::ExternalReap]);
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable,
            "a status that lost its leader is not a Stopped proof"
        );
        let pgid = pending_pgid(&backend);
        let member_pid = read_pid_patiently(&member);
        assert!(matches!(
            backend.runner.pending,
            Some(Responsibility::Group { .. })
        ));
        for _ in 0..2 {
            assert_eq!(
                backend.observe_service(),
                RawServiceObservation::Unavailable
            );
            assert!(matches!(
                backend.request_service_start(),
                ActionDiagnostic::Error(message) if message.contains("could not be reaped")
            ));
            assert!(matches!(
                backend.request_service_stop(),
                ActionDiagnostic::Error(_)
            ));
            assert_eq!(backend.observe_health(), RawHealthObservation::Unavailable);
        }
        assert!(sent_signals().is_empty(), "{:?}", sent_signals());
        assert!(
            pid_alive(member_pid),
            "the stranger's process was signalled"
        );
        kill_group_if_alive(pgid);
        assert!(eventually(|| !pid_alive(member_pid)));
        backend.runner.exit_probe = sys::leader_exited_without_reaping;
        assert!(eventually(|| backend.runner.clear_pending()));
        assert!(backend.runner.pending.is_none());
        // The refused start above means a late start is not excluded: stopped
        // is believed again only after a stop of ours succeeded.
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable
        );
        assert_eq!(backend.request_service_stop(), ActionDiagnostic::Success);
        assert_eq!(backend.observe_service(), RawServiceObservation::Stopped);
    }

    /// A stop that lost its leader taints the stopped state like any other
    /// stop with an uncertain cleanup.
    #[test]
    fn a_stop_whose_leader_was_reaped_elsewhere_does_not_prove_stopped() {
        let dir = Dir::new("lost-pin-stop");
        let member = dir.0.join("member.pid");
        let stop = format!("sleep 30 &\necho $! > '{}'\nexit 0", member.display());
        let mut backend = backend(&dir, "exit 0", &stop, "echo stopped");
        MEMBER_STARTED.with(|file| *file.borrow_mut() = Some(member.clone()));
        backend.runner.exit_probe = scripted_probe;
        queue_probes(&[Probe::ExternalReap]);
        let diagnostic = backend.request_service_stop();
        assert!(
            matches!(&diagnostic, ActionDiagnostic::Error(message) if message.contains("cleanup is uncertain")),
            "{diagnostic:?}"
        );
        let pgid = pending_pgid(&backend);
        let member_pid = read_pid_patiently(&member);
        kill_group_if_alive(pgid);
        assert!(eventually(|| !pid_alive(member_pid)));
        backend.runner.exit_probe = sys::leader_exited_without_reaping;
        assert!(eventually(|| backend.runner.clear_pending()));
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable,
            "the stop's group was never seen to end: the stopped state is unproven"
        );
    }

    /// Only `ECHILD` is a lost pin. A transient interrupt is retried.
    #[test]
    fn an_interrupted_exit_query_is_retried_not_read_as_a_timeout() {
        let dir = Dir::new("probe-eintr");
        let mut backend = backend(&dir, "exit 0", "exit 0", "echo running");
        backend.runner.exit_probe = scripted_probe;
        queue_probes(&[Probe::Interrupted, Probe::Interrupted]);
        assert_eq!(backend.observe_service(), RawServiceObservation::Running);
        assert!(backend.runner.pending.is_none());
    }

    /// R-CS-15: an exit query that fails for another reason is a timeout —
    /// the group is still killed, the leader reaped, the answer is a clean
    /// `Timeout`, never the exit of a command that was only cut short.
    #[test]
    fn an_unusable_exit_query_ends_in_a_cleaned_timeout() {
        let dir = Dir::new("probe-invalid");
        let mut runner = Runner::new(policy());
        runner.exit_probe = scripted_probe;
        runner.signal = recording_signal;
        SIGNALS.with(|signals| signals.borrow_mut().clear());
        queue_probes(&[Probe::Invalid]);
        let started = Instant::now();
        assert_eq!(
            runner.run(
                &[dir.script("slow", "sleep 30")],
                "start",
                Duration::from_secs(40),
                false
            ),
            RunEnd::TimedOut { cleaned: true }
        );
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "the deadline was not waited for: {:?}",
            started.elapsed()
        );
        assert!(runner.pending.is_none());
        let sent = sent_signals();
        assert!(sent.iter().any(|(signal, _)| *signal == sys::SIGTERM));
        assert!(sent.iter().all(|(_, pinned)| *pinned), "{sent:?}");
    }

    /// A leader whose exit cannot be observed is still ours (its pin is
    /// intact): signals are allowed, the leader stays owed, and it is not
    /// mistaken for a lost one.
    #[test]
    fn an_unobservable_leader_stays_owed_as_a_leader() {
        let dir = Dir::new("probe-unobservable");
        let mut runner = Runner::new(policy());
        runner.exit_probe = |_| Err(22);
        runner.signal = recording_signal;
        SIGNALS.with(|signals| signals.borrow_mut().clear());
        assert_eq!(
            runner.run(
                &[dir.script("slow", "sleep 30")],
                "start",
                Duration::from_millis(20),
                false
            ),
            RunEnd::TimedOut { cleaned: false }
        );
        let pgid = match runner.pending.as_ref() {
            Some(Responsibility::Leader(leader)) => leader.pgid,
            other => panic!("the leader must be held: {other:?}"),
        };
        assert!(sent_signals().iter().all(|(_, pinned)| *pinned));
        kill_group_if_alive(pgid);
        runner.exit_probe = sys::leader_exited_without_reaping;
        assert!(eventually(|| runner.clear_pending()));
        assert!(runner.pending.is_none());
    }

    // ---- the census reads only ESRCH as empty (R-CS-12) ----------------------------------

    #[test]
    fn only_esrch_proves_a_group_empty() {
        const EPERM: i32 = 1;
        const ESRCH: i32 = 3;
        assert_eq!(sys::classify_census(Ok(())), sys::GroupProbe::Present);
        assert_eq!(sys::classify_census(Err(ESRCH)), sys::GroupProbe::Empty);
        assert_eq!(
            sys::classify_census(Err(EPERM)),
            sys::GroupProbe::Present,
            "a group this user may not signal is not an empty group"
        );
        for other in [4, 9, 10, 22, 0] {
            assert_eq!(
                sys::classify_census(Err(other)),
                sys::GroupProbe::Unknown(other)
            );
        }
    }

    /// The real kernel answer for a group whose only member is an exited,
    /// unreaped leader: `0` on Linux, `EPERM` on Darwin. Either way it is
    /// `Present`; only the reaped, member-less group is `Empty`.
    #[test]
    fn a_group_whose_only_member_is_an_unreaped_zombie_is_not_empty() {
        let dir = Dir::new("zombie-census");
        let mut child = Command::new(dir.script("quick", "exit 0"))
            .process_group(0)
            .spawn()
            .unwrap();
        let pgid = child.id();
        assert!(eventually(
            || sys::leader_exited_without_reaping(pgid) == Ok(true)
        ));
        assert_eq!(sys::group_probe(pgid), sys::GroupProbe::Present);
        child.wait().unwrap();
        assert!(eventually(
            || sys::group_probe(pgid) == sys::GroupProbe::Empty
        ));
    }

    // ---- NF-3: the exited leader is reaped without blocking -----------------------------

    #[derive(Clone, Copy)]
    enum Reap {
        /// Something else reaps the leader first; then the real `try_wait`
        /// answers (`ECHILD`).
        ExternalThenReal,
        /// `ECHILD`, although the leader is in fact still ours.
        Echild,
        /// `Ok(None)`: not reapable (yet).
        NotYet,
        /// Any other error from the reap.
        Failed(i32),
    }

    thread_local! {
        static REAPS: std::cell::RefCell<std::collections::VecDeque<Reap>> =
            const { std::cell::RefCell::new(std::collections::VecDeque::new()) };
        static REAP_CALLS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    }

    fn queue_reaps(steps: &[Reap]) {
        REAP_CALLS.with(|calls| calls.set(0));
        REAPS.with(|reaps| {
            let mut reaps = reaps.borrow_mut();
            reaps.clear();
            reaps.extend(steps.iter().copied());
        });
    }

    /// The scripted reap: queued answers first, then the real `try_wait`.
    fn scripted_reaper(leader: &mut Leader) -> std::io::Result<Option<std::process::ExitStatus>> {
        REAP_CALLS.with(|calls| calls.set(calls.get() + 1));
        match REAPS.with(|reaps| reaps.borrow_mut().pop_front()) {
            Some(Reap::ExternalThenReal) => {
                reap_elsewhere(leader.pgid);
                leader.child.try_wait()
            }
            Some(Reap::Echild) => Err(std::io::Error::from_raw_os_error(sys::ECHILD)),
            Some(Reap::NotYet) => Ok(None),
            Some(Reap::Failed(errno)) => Err(std::io::Error::from_raw_os_error(errno)),
            None => leader.child.try_wait(),
        }
    }

    /// A leader that leaves one member in its group (`$1` receives that
    /// member's pid) and exits 3; and one that just exits 3. Both are warmed,
    /// so no deadline in these tests measures a first exec.
    struct ExitingLeaders {
        scripts: LostPinScripts,
        leaves_member: String,
        plain: String,
    }

    impl ExitingLeaders {
        fn new(tag: &str) -> Self {
            let scripts = LostPinScripts::new(tag);
            let leaves_member = scripts.dir.script(
                "leaves-member",
                "[ \"$1\" = warm ] && exit 0\nsleep 30 &\necho $! > \"$1\"\nexit 3",
            );
            let plain = scripts
                .dir
                .script("plain", "[ \"$1\" = warm ] && exit 0\nexit 3");
            warm_exec(Path::new(&leaves_member));
            warm_exec(Path::new(&plain));
            // `late` takes a marker path, so it is warmed with one inside the
            // case's own directory (a bare `warm` argument would be a path
            // relative to the working directory).
            let warm_mark = scripts.dir.0.join("late-warm-mark");
            assert!(
                Command::new(&scripts.late)
                    .arg(&warm_mark)
                    .status()
                    .unwrap()
                    .success()
            );
            Self {
                scripts,
                leaves_member,
                plain,
            }
        }

        fn with_member(&self, label: &str) -> (Vec<String>, PathBuf) {
            let (_, member) = self.scripts.holder_for(label);
            (
                vec![self.leaves_member.clone(), member.display().to_string()],
                member,
            )
        }

        fn runner(&self, signal: GroupSignal, reaps: &[Reap]) -> Runner {
            let mut runner = Runner::new(policy());
            runner.exit_probe = sys::leader_exited_without_reaping;
            runner.signal = signal;
            runner.reaper = scripted_reaper;
            SIGNALS.with(|signals| signals.borrow_mut().clear());
            queue_reaps(reaps);
            runner
        }
    }

    /// The group was KILLed while the pin held; afterwards only the census is
    /// used. Exactly one signal, pinned, was sent.
    fn assert_only_the_pinned_kill(label: &str) {
        let sent = sent_signals();
        assert_eq!(
            sent.iter().map(|(signal, _)| *signal).collect::<Vec<_>>(),
            [sys::SIGKILL],
            "{label}: {sent:?}"
        );
        assert!(sent.iter().all(|(_, pinned)| *pinned), "{label}: {sent:?}");
    }

    /// The leader exits on its own, then something else reaps it before the
    /// runner does (real `ECHILD`, and a synthetic one on a leader that is
    /// still ours). No status is invented (the leader exited 3), nothing is
    /// signalled after the loss, the census-only responsibility stays, and
    /// later work is refused until the group is proven empty.
    #[test]
    fn a_leader_reaped_elsewhere_just_before_the_reap_has_no_status_and_owes_the_census() {
        let leaders = ExitingLeaders::new("nf3-before-reap");
        for (label, reap) in [
            ("external-reap", Reap::ExternalThenReal),
            ("echild-on-our-child", Reap::Echild),
        ] {
            let (argv, member) = leaders.with_member(label);
            let mut runner = leaders.runner(muted_signal, &[reap]);
            let end = runner.run(&argv, "start", Duration::from_secs(30), false);
            assert_eq!(end, RunEnd::LeaderLost, "{label}: no status was reaped");
            assert!(
                !matches!(end, RunEnd::Exited { .. }),
                "{label}: someone else's status was adopted"
            );
            assert_only_the_pinned_kill(label);
            assert_eq!(REAP_CALLS.with(|calls| calls.get()), 1, "{label}");
            if matches!(reap, Reap::Echild) {
                // Test cleanup: the leader really was still ours, and the
                // runner (rightly) let go of it unreaped; collect the zombie so
                // the census can find the group empty at the end.
                let mut status = 0;
                let pgid = i32::try_from(pending_pgid_of(&runner)).unwrap();
                // SAFETY: plain syscall on the pid of this test's own child.
                unsafe { waitpid(pgid, &mut status, 0) };
            }
            assert_lost_pin_is_held(&mut runner, label, &leaders.scripts, &member);
        }
    }

    /// `Ok(None)` from the reap: the leader is still ours but cannot be reaped.
    /// It is bounded (no wait without limit), keeps the leader unreaped and
    /// pinned, adopts no status, and later work is refused. When the reap
    /// works again the retry discharges the responsibility.
    #[test]
    fn a_reap_that_is_not_ready_is_bounded_and_keeps_the_leader_owed() {
        let leaders = ExitingLeaders::new("nf3-not-yet");
        let (argv, member) = leaders.with_member("not-yet");
        let mut runner = leaders.runner(muted_signal, &[Reap::NotYet; 400]);
        let started = Instant::now();
        let end = runner.run(&argv, "start", Duration::from_secs(30), false);
        assert_eq!(end, RunEnd::CleanupUncertain);
        assert!(
            started.elapsed() < KILL_GRACE + Duration::from_secs(10),
            "the reap must not wait without bound"
        );
        assert!(
            REAP_CALLS.with(|calls| calls.get()) > 1,
            "the reap is retried within its budget"
        );
        assert!(matches!(runner.pending, Some(Responsibility::Leader(_))));
        assert_only_the_pinned_kill("not-yet");
        // Refused, nothing spawned, no further signal while the leader is owed
        // but not yet observed gone.
        let marker = leaders.scripts.dir.0.join("not-yet-late");
        let late = vec![leaders.scripts.late.clone(), marker.display().to_string()];
        queue_reaps(&[Reap::NotYet; 400]);
        assert!(!runner.clear_pending());
        assert_eq!(
            runner.run(&late, "start", Duration::from_secs(5), false),
            RunEnd::PendingBlocked
        );
        assert!(!marker.exists());
        // The reap works again: the leader is reaped by us, the member keeps
        // the group non-empty, so the census-only responsibility remains.
        queue_reaps(&[]);
        assert!(!runner.clear_pending());
        assert!(matches!(runner.pending, Some(Responsibility::Group { .. })));
        let pgid = pending_pgid_of(&runner);
        finish_lost_group(&mut runner, pgid, read_pid_patiently(&member));
    }

    /// Any other reap error says nothing about the leader: it stays owed as a
    /// leader, no status is adopted, and no signal follows the failure.
    #[test]
    fn a_reap_error_keeps_the_leader_owed_and_sends_nothing_more() {
        let leaders = ExitingLeaders::new("nf3-reap-error");
        for errno in [22, 5, 4] {
            let label = format!("errno-{errno}");
            let (argv, member) = leaders.with_member(&label);
            let mut runner = leaders.runner(muted_signal, &[Reap::Failed(errno)]);
            let end = runner.run(&argv, "start", Duration::from_secs(30), false);
            assert_eq!(end, RunEnd::CleanupUncertain, "{label}");
            assert!(
                matches!(runner.pending, Some(Responsibility::Leader(_))),
                "{label}: {:?}",
                runner.pending
            );
            assert_only_the_pinned_kill(&label);
            // Later work is refused while the leader is owed.
            let marker = leaders.scripts.dir.0.join(format!("late-{label}"));
            let late = vec![leaders.scripts.late.clone(), marker.display().to_string()];
            queue_reaps(&[Reap::Failed(errno)]);
            assert_eq!(
                runner.run(&late, "start", Duration::from_secs(5), false),
                RunEnd::PendingBlocked,
                "{label}"
            );
            assert!(!marker.exists(), "{label}");
            // With a working reap the retry finishes it; the member stands for
            // a survivor that keeps the group id in use until it is gone.
            queue_reaps(&[]);
            assert!(!runner.clear_pending(), "{label}: the member is alive");
            assert!(matches!(runner.pending, Some(Responsibility::Group { .. })));
            let pgid = pending_pgid_of(&runner);
            finish_lost_group(&mut runner, pgid, read_pid_patiently(&member));
        }
    }

    /// The normal path keeps working: the status is the leader's own, the
    /// responsibility is discharged by the census, and exactly one pinned KILL
    /// was sent.
    #[test]
    fn a_normally_reaped_leader_reports_its_own_status() {
        let leaders = ExitingLeaders::new("nf3-normal");
        let mut runner = leaders.runner(recording_signal, &[]);
        let argv = vec![leaders.plain.clone()];
        let end = runner.run(&argv, "start", Duration::from_secs(30), false);
        assert!(
            matches!(end, RunEnd::Exited { code: Some(3), .. }),
            "{end:?}"
        );
        assert!(runner.pending.is_none());
        assert_only_the_pinned_kill("normal");
        assert_eq!(REAP_CALLS.with(|calls| calls.get()), 1);
    }

    /// After a lost pin the census decides: `Empty` discharges (the result
    /// stays "no result", never a status), `Present` and `Unknown` keep the
    /// census-only responsibility.
    #[test]
    fn after_a_lost_pin_the_census_alone_decides_and_the_result_stays_lost() {
        let leaders = ExitingLeaders::new("nf3-census");
        let argv = vec![leaders.plain.clone()];
        // Empty (real census, no member left): discharged, still LeaderLost.
        let mut runner = leaders.runner(recording_signal, &[Reap::ExternalThenReal]);
        assert_eq!(
            runner.run(&argv, "start", Duration::from_secs(30), false),
            RunEnd::LeaderLost
        );
        assert!(runner.pending.is_none(), "the empty group is discharged");
        assert_only_the_pinned_kill("census-empty");
        // The slot is free again: the next action runs.
        runner.reaper = |leader| leader.child.try_wait();
        assert!(matches!(
            runner.run(&argv, "start", Duration::from_secs(30), false),
            RunEnd::Exited { code: Some(3), .. }
        ));
        // Present / Unknown: owed, census only.
        for (label, census) in [
            ("census-present", census_present as GroupCensus),
            ("census-unknown", census_unknown as GroupCensus),
        ] {
            let mut runner = leaders.runner(recording_signal, &[Reap::ExternalThenReal]);
            runner.census = census;
            assert_eq!(
                runner.run(&argv, "start", Duration::from_secs(30), false),
                RunEnd::LeaderLost,
                "{label}"
            );
            assert!(
                matches!(runner.pending, Some(Responsibility::Group { .. })),
                "{label}"
            );
            assert_only_the_pinned_kill(label);
            let before = sent_signals();
            assert!(!runner.clear_pending(), "{label}");
            assert_eq!(sent_signals(), before, "{label}: the retry must not signal");
            runner.census = sys::group_probe;
            assert!(runner.clear_pending(), "{label}: now provably empty");
        }
    }

    /// The deadline path: the group is TERM/KILLed while pinned, the leader is
    /// then reaped elsewhere. The clean timeout needs the census proof, not a
    /// status; with a surviving member it is not clean.
    #[test]
    fn a_leader_reaped_elsewhere_after_the_deadline_kill_is_clean_only_if_the_census_says_so() {
        let leaders = ExitingLeaders::new("nf3-deadline");
        let sleeper = leaders
            .scripts
            .dir
            .script("sleeper", "[ \"$1\" = warm ] && exit 0\nsleep 30");
        warm_exec(Path::new(&sleeper));
        let argv = vec![sleeper];
        let mut runner = leaders.runner(recording_signal, &[Reap::ExternalThenReal]);
        let end = runner.run(&argv, "start", Duration::from_millis(100), false);
        assert_eq!(end, RunEnd::TimedOut { cleaned: true }, "census Empty");
        assert!(runner.pending.is_none());
        assert!(sent_signals().iter().all(|(_, pinned)| *pinned));
        let mut runner = leaders.runner(recording_signal, &[Reap::ExternalThenReal]);
        runner.census = census_present;
        let end = runner.run(&argv, "start", Duration::from_millis(100), false);
        assert_eq!(end, RunEnd::TimedOut { cleaned: false }, "census Present");
        assert!(matches!(runner.pending, Some(Responsibility::Group { .. })));
        assert!(sent_signals().iter().all(|(_, pinned)| *pinned));
        let before = sent_signals();
        assert!(!runner.clear_pending());
        assert_eq!(sent_signals(), before, "no signal after the loss");
        runner.census = sys::group_probe;
        assert!(runner.clear_pending());
    }

    /// Backend level: a `stop` whose leader was reaped elsewhere at the reap
    /// earns no credit, `status` stays unavailable, and nothing later is
    /// spawned while the group is owed.
    #[test]
    fn a_stop_whose_leader_is_lost_at_the_reap_does_not_prove_stopped() {
        let dir = Dir::new("nf3-backend");
        let mark = dir.0.join("status-ran");
        let mut backend = ExternalServiceBackend::with_policy(
            vec![dir.script("start", "[ \"$1\" = warm ] && exit 0\nexit 0")],
            vec![dir.script("stop", "[ \"$1\" = warm ] && exit 0\nsleep 30 &\nexit 0")],
            vec![dir.script(
                "status",
                &format!(
                    "[ \"$1\" = warm ] && exit 0\ntouch '{}'\necho stopped",
                    mark.display()
                ),
            )],
            vec![dir.script("health", "exit 0")],
            Duration::from_secs(20),
            Duration::from_secs(20),
            Duration::from_secs(20),
            policy(),
        )
        .unwrap();
        for name in ["start", "stop", "status", "health"] {
            warm_exec(&dir.0.join(name));
        }
        assert_eq!(backend.request_service_start(), ActionDiagnostic::Success);
        SIGNALS.with(|signals| signals.borrow_mut().clear());
        queue_reaps(&[Reap::ExternalThenReal]);
        backend.runner.reaper = scripted_reaper;
        backend.runner.signal = muted_signal;
        assert!(matches!(
            backend.request_service_stop(),
            ActionDiagnostic::Error(message) if message.contains("cleanup is uncertain")
        ));
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable
        );
        assert!(!mark.exists(), "nothing is spawned while the group is owed");
        assert!(backend.unproven_stopped && !backend.stop_succeeded_since_start);
        // Test cleanup: the stop's background sleeper is the group's survivor.
        let pgid = pending_pgid(&backend);
        kill_group_if_alive(pgid);
        backend.runner.signal = sys::signal_group;
        assert!(eventually(|| backend.runner.clear_pending()));
        // Still not stopped until a stop succeeds and the status then agrees.
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable
        );
    }

    // ---- NF-2: SIGCHLD must let this process wait for its children --------------------

    #[test]
    fn sigchld_dispositions_are_classified_without_touching_the_process() {
        use sys::SigchldState::{Default, Handler, Ignored, NoChildWait};
        let handler = 0x1000_usize;
        for (word, flags, expected) in [
            (sys::SIG_DFL, 0, Default),
            (sys::SIG_IGN, 0, Ignored),
            (sys::SIG_DFL, sys::SA_NOCLDWAIT, NoChildWait),
            (handler, 0, Handler),
            (handler, sys::SA_NOCLDWAIT, NoChildWait),
            (sys::SIG_IGN, sys::SA_NOCLDWAIT, Ignored),
            // unrelated flag bits do not matter
            (sys::SIG_DFL, 0x4000_0000 & !sys::SA_NOCLDWAIT, Default),
        ] {
            assert_eq!(
                sys::classify_sigchld(word, flags),
                expected,
                "{word} {flags}"
            );
        }
    }

    fn sigchld_default() -> Result<sys::SigchldState, i32> {
        Ok(sys::SigchldState::Default)
    }

    fn sigchld_ignored() -> Result<sys::SigchldState, i32> {
        Ok(sys::SigchldState::Ignored)
    }

    fn sigchld_nocldwait() -> Result<sys::SigchldState, i32> {
        Ok(sys::SigchldState::NoChildWait)
    }

    fn sigchld_handler() -> Result<sys::SigchldState, i32> {
        Ok(sys::SigchldState::Handler)
    }

    fn sigchld_unreadable() -> Result<sys::SigchldState, i32> {
        Err(14)
    }

    #[test]
    fn only_the_default_sigchld_disposition_is_accepted() {
        assert_eq!(check_sigchld(sigchld_default), Ok(()));
        assert_eq!(check_sigchld(sigchld_ignored), Err(SigchldRefusal::Ignored));
        assert_eq!(
            check_sigchld(sigchld_nocldwait),
            Err(SigchldRefusal::NoChildWait)
        );
        assert_eq!(check_sigchld(sigchld_handler), Err(SigchldRefusal::Handler));
        assert_eq!(
            check_sigchld(sigchld_unreadable),
            Err(SigchldRefusal::Unreadable(14))
        );
        // The reasons are explicit.
        for (refusal, needle) in [
            (SigchldRefusal::Ignored, "SIG_IGN"),
            (SigchldRefusal::NoChildWait, "SA_NOCLDWAIT"),
            (SigchldRefusal::Handler, "handler"),
            (SigchldRefusal::Unreadable(14), "os error 14"),
        ] {
            let text = refusal.to_string();
            assert!(text.contains("SIGCHLD") && text.contains(needle), "{text}");
        }
    }

    /// Every action path refuses, with the reason, and spawns nothing (each
    /// script leaves a mark when it really runs; the warm-up does not).
    #[test]
    fn a_refused_sigchld_state_spawns_nothing_on_any_action() {
        type Probe = fn() -> Result<sys::SigchldState, i32>;
        let cases: [(&str, Probe, &str); 4] = [
            ("ignored", sigchld_ignored, "SIG_IGN"),
            ("nocldwait", sigchld_nocldwait, "SA_NOCLDWAIT"),
            ("handler", sigchld_handler, "handler"),
            ("unreadable", sigchld_unreadable, "os error 14"),
        ];
        let dir = Dir::new("nf2-refuse");
        let mark = |name: &str| dir.0.join(format!("ran-{name}"));
        let body = |name: &str, tail: &str| {
            format!(
                "[ \"$1\" = warm ] && exit 0\ntouch '{}'\n{tail}",
                mark(name).display()
            )
        };
        let mut backend = ExternalServiceBackend::with_policy(
            vec![dir.script("start", &body("start", "exit 0"))],
            vec![dir.script("stop", &body("stop", "exit 0"))],
            vec![dir.script("status", &body("status", "echo running"))],
            vec![dir.script("health", &body("health", "exit 0"))],
            Duration::from_secs(20),
            Duration::from_secs(20),
            Duration::from_secs(20),
            policy(),
        )
        .unwrap();
        for name in ["start", "stop", "status", "health"] {
            warm_exec(&dir.0.join(name));
        }
        for (label, probe, needle) in cases {
            backend.runner.sigchld = probe;
            for diagnostic in [
                backend.request_service_start(),
                backend.request_service_stop(),
            ] {
                assert!(
                    matches!(&diagnostic, ActionDiagnostic::Error(message)
                        if message.contains("SIGCHLD") && message.contains(needle)),
                    "{label}: {diagnostic:?}"
                );
            }
            assert_eq!(
                backend.observe_service(),
                RawServiceObservation::Unavailable,
                "{label}"
            );
            assert_eq!(
                backend.observe_health(),
                RawHealthObservation::Unavailable,
                "{label}"
            );
            for name in ["start", "stop", "status", "health"] {
                assert!(!mark(name).exists(), "{label}: {name} was spawned");
            }
            assert!(backend.runner.pending.is_none(), "{label}: nothing is owed");
        }
        // Positive control: the default disposition runs every action.
        backend.runner.sigchld = sigchld_default;
        assert_eq!(backend.request_service_start(), ActionDiagnostic::Success);
        assert_eq!(backend.request_service_stop(), ActionDiagnostic::Success);
        assert_eq!(backend.observe_service(), RawServiceObservation::Running);
        assert_eq!(backend.observe_health(), RawHealthObservation::Healthy);
        for name in ["start", "stop", "status", "health"] {
            assert!(mark(name).exists(), "positive control: {name} ran");
        }
    }

    #[test]
    fn this_process_has_the_default_sigchld_disposition_and_commands_run() {
        // The test process itself, not a child: nothing in the suite changes
        // SIGCHLD in-process (those tests run in isolated child processes).
        assert_eq!(sys::sigchld_state(), Ok(sys::SigchldState::Default));
        let dir = Dir::new("nf2-default");
        let mut backend = backend(&dir, "exit 0", "exit 0", "echo running");
        assert_eq!(backend.request_service_start(), ActionDiagnostic::Success);
        assert_eq!(backend.observe_service(), RawServiceObservation::Running);
    }

    unsafe extern "C" {
        fn sigaction(
            signal: i32,
            action: *const sys::SigAction,
            previous: *mut sys::SigAction,
        ) -> i32;
    }

    extern "C" fn sigchld_noop(_: i32) {}

    /// Change the (process-wide) SIGCHLD disposition. ONLY for use inside the
    /// isolated child process of `sigchld_isolated_child`.
    fn set_sigchld_in_child_process(handler: usize, flags: i32) {
        let mut action = sys::SigAction([0; 256]);
        action.0[..std::mem::size_of::<usize>()].copy_from_slice(&handler.to_ne_bytes());
        action.0[sys::SA_FLAGS_OFFSET..sys::SA_FLAGS_OFFSET + 4]
            .copy_from_slice(&flags.to_ne_bytes());
        // SAFETY: a properly sized and aligned action; no previous action asked.
        let result = unsafe { sigaction(sys::SIGCHLD, &action, std::ptr::null_mut()) };
        assert_eq!(result, 0, "sigaction failed");
    }

    fn flipping_probe() -> Result<sys::SigchldState, i32> {
        // Reports the default state, then the setting changes: the window
        // between the check and the spawn.
        set_sigchld_in_child_process(sys::SIG_IGN, 0);
        Ok(sys::SigchldState::Default)
    }

    const SIGCHLD_CASE_ENV: &str = "MKM_TEST_SIGCHLD_CASE";
    const SIGCHLD_CASE_TEST: &str =
        "resource_executor::command_service::tests::sigchld_isolated_child";

    /// Does nothing unless the parent test below started this binary for one
    /// case. The case changes the process-wide SIGCHLD setting, so it only ever
    /// runs in that child.
    #[test]
    fn sigchld_isolated_child() {
        let Ok(case) = std::env::var(SIGCHLD_CASE_ENV) else {
            return;
        };
        let dir = Dir::new(&format!("nf2-child-{case}"));
        let mark = |name: &str| dir.0.join(format!("ran-{name}"));
        let body = |name: &str, tail: &str| {
            format!(
                "[ \"$1\" = warm ] && exit 0\ntouch '{}'\n{tail}",
                mark(name).display()
            )
        };
        // Every script is written (and warmed up, which waits for a child)
        // before the SIGCHLD setting is changed: with it ignored, waiting for
        // any child fails.
        let start = dir.script("start", &body("start", "exit 0"));
        let stop = dir.script("stop", &body("stop", "exit 0"));
        let status = dir.script("status", &body("status", "echo running"));
        let health = dir.script("health", &body("health", "exit 0"));
        let race = dir.script("race", "exit 0");
        let build = || {
            ExternalServiceBackend::with_policy(
                vec![start.clone()],
                vec![stop.clone()],
                vec![status.clone()],
                vec![health.clone()],
                Duration::from_secs(20),
                Duration::from_secs(20),
                Duration::from_secs(20),
                policy(),
            )
        };
        let mut backend = build().unwrap();
        let (word, flags, state, needle) = match case.as_str() {
            "default" => (sys::SIG_DFL, 0, sys::SigchldState::Default, ""),
            "ignored" => (sys::SIG_IGN, 0, sys::SigchldState::Ignored, "SIG_IGN"),
            "nocldwait" => (
                sys::SIG_DFL,
                sys::SA_NOCLDWAIT,
                sys::SigchldState::NoChildWait,
                "SA_NOCLDWAIT",
            ),
            "handler" => (
                sigchld_noop as extern "C" fn(i32) as usize,
                0,
                sys::SigchldState::Handler,
                "handler",
            ),
            "race" => {
                // The check passes, then SIGCHLD becomes SIG_IGN before the
                // child exits: the kernel reaps it, the pin is lost, and the
                // runner signals nothing. Fail-closed, not prevented.
                backend.runner.sigchld = flipping_probe;
                backend.runner.signal = recording_signal;
                let end = backend
                    .runner
                    .run(&[race], "start", Duration::from_secs(20), false);
                assert_eq!(end, RunEnd::LeaderLost);
                assert!(sent_signals().is_empty(), "{:?}", sent_signals());
                assert_eq!(sys::sigchld_state(), Ok(sys::SigchldState::Ignored));
                // The next action is refused by the check, not run.
                backend.runner.sigchld = sys::sigchld_state;
                assert!(matches!(
                    backend.request_service_start(),
                    ActionDiagnostic::Error(message) if message.contains("SIG_IGN")
                ));
                assert!(!mark("start").exists());
                println!("SIGCHLD-CASE-OK {case}");
                return;
            }
            other => panic!("unknown case {other}"),
        };
        set_sigchld_in_child_process(word, flags);
        assert_eq!(sys::sigchld_state(), Ok(state));
        if case == "default" {
            assert!(build().is_ok());
            assert_eq!(backend.request_service_start(), ActionDiagnostic::Success);
            assert_eq!(backend.request_service_stop(), ActionDiagnostic::Success);
            assert_eq!(backend.observe_service(), RawServiceObservation::Running);
            assert_eq!(backend.observe_health(), RawHealthObservation::Healthy);
        } else {
            // Daemon start: construction refuses, with the reason.
            let error = build().unwrap_err().to_string();
            assert!(
                error.contains("SIGCHLD") && error.contains(needle),
                "{error}"
            );
            // A backend that was built earlier refuses at every spawn.
            for diagnostic in [
                backend.request_service_start(),
                backend.request_service_stop(),
            ] {
                assert!(
                    matches!(&diagnostic, ActionDiagnostic::Error(message)
                        if message.contains("SIGCHLD") && message.contains(needle)),
                    "{diagnostic:?}"
                );
            }
            assert_eq!(
                backend.observe_service(),
                RawServiceObservation::Unavailable
            );
            assert_eq!(backend.observe_health(), RawHealthObservation::Unavailable);
            for name in ["start", "stop", "status", "health"] {
                assert!(!mark(name).exists(), "{name} was spawned");
            }
            assert!(backend.runner.pending.is_none());
        }
        println!("SIGCHLD-CASE-OK {case}");
    }

    /// Runs each SIGCHLD case in a fresh child process (this test binary,
    /// filtered to the one test above), so the process-wide setting is never
    /// changed in the process that runs the other tests.
    #[test]
    fn sigchld_states_are_handled_in_isolated_child_processes() {
        let exe = std::env::current_exe().unwrap();
        for case in ["default", "ignored", "nocldwait", "handler", "race"] {
            let output = Command::new(&exe)
                .args([
                    "--exact",
                    SIGCHLD_CASE_TEST,
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(SIGCHLD_CASE_ENV, case)
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                output.status.success(),
                "{case}: {}\n{stdout}\n{stderr}",
                output.status
            );
            assert!(
                stdout.contains(&format!("SIGCHLD-CASE-OK {case}")),
                "{case}: the case did not run\n{stdout}\n{stderr}"
            );
        }
    }

    /// The production reap (no test hook) must not wait for a leader that is
    /// still running: this is the case a recycled pid, now owned by a live
    /// stranger child, would present. A blocking `wait` would hold the daemon
    /// until the stranger exits and then return the stranger's status; the
    /// watchdog frees a blocked reap after 3 s so a regression fails the
    /// assertions instead of hanging the suite.
    #[test]
    fn the_production_reap_does_not_block_on_a_live_child() {
        let dir = Dir::new("nf3-live");
        let sleeper = dir.script("sleeper", "[ \"$1\" = warm ] && exit 0\nexec sleep 20");
        warm_exec(Path::new(&sleeper));
        let child = Command::new(&sleeper).process_group(0).spawn().unwrap();
        let pid = child.id();
        let mut leader = Leader { child, pgid: pid };
        let reap = Runner::new(policy()).reaper;
        let watchdog = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(3));
            kill_group_if_alive(pid);
        });
        let started = Instant::now();
        let answer = reap(&mut leader);
        let waited = started.elapsed();
        watchdog.join().unwrap();
        assert!(
            matches!(answer, Ok(None)),
            "a live child has no status to give: {answer:?}"
        );
        assert!(
            waited < Duration::from_secs(2),
            "the reap blocked for {waited:?}"
        );
        // Test cleanup: the watchdog killed it; collect it.
        assert!(leader.child.wait().is_ok());
    }

    // ---- FH-2: a refused SIGCHLD state forbids NEW spawns, not the cleanup already owed --

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Event {
        /// A group signal the runner sent, and whether the group id was pinned.
        Signal {
            pgid: u32,
            signal: i32,
            pinned: bool,
        },
        /// The `SIGCHLD` check ran.
        SigchldChecked,
    }

    thread_local! {
        static EVENTS: std::cell::RefCell<Vec<Event>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }

    fn clear_events() {
        EVENTS.with(|events| events.borrow_mut().clear());
    }

    fn events() -> Vec<Event> {
        EVENTS.with(|events| events.borrow().clone())
    }

    fn signals_of(events: &[Event]) -> Vec<(u32, i32, bool)> {
        events
            .iter()
            .filter_map(|event| match event {
                Event::Signal {
                    pgid,
                    signal,
                    pinned,
                } => Some((*pgid, *signal, *pinned)),
                Event::SigchldChecked => None,
            })
            .collect()
    }

    /// Delivers for real and logs the signal with its group id and the pin.
    fn logging_signal(pgid: u32, signal: i32) -> Result<(), i32> {
        let pinned = sys::leader_exited_without_reaping(pgid).is_ok();
        EVENTS.with(|events| {
            events.borrow_mut().push(Event::Signal {
                pgid,
                signal,
                pinned,
            })
        });
        sys::signal_group(pgid, signal)
    }

    /// Logs and delivers nothing (the leader stands for a stranger's group).
    fn logging_muted_signal(pgid: u32, signal: i32) -> Result<(), i32> {
        let pinned = sys::leader_exited_without_reaping(pgid).is_ok();
        EVENTS.with(|events| {
            events.borrow_mut().push(Event::Signal {
                pgid,
                signal,
                pinned,
            })
        });
        Ok(())
    }

    /// Logs the attempt, then fails: a kill that cannot be confirmed.
    fn logging_failing_signal(pgid: u32, signal: i32) -> Result<(), i32> {
        let _ = logging_muted_signal(pgid, signal);
        Err(1)
    }

    macro_rules! logged_probe {
        ($name:ident, $answer:expr) => {
            fn $name() -> Result<sys::SigchldState, i32> {
                EVENTS.with(|events| events.borrow_mut().push(Event::SigchldChecked));
                $answer
            }
        };
    }

    logged_probe!(logged_default, Ok(sys::SigchldState::Default));
    logged_probe!(logged_ignored, Ok(sys::SigchldState::Ignored));
    logged_probe!(logged_nocldwait, Ok(sys::SigchldState::NoChildWait));
    logged_probe!(logged_handler, Ok(sys::SigchldState::Handler));
    logged_probe!(logged_unreadable, Err(14));

    type LoggedProbe = fn() -> Result<sys::SigchldState, i32>;

    fn refused_states() -> [(&'static str, LoggedProbe, SigchldRefusal); 4] {
        [
            ("ignored", logged_ignored, SigchldRefusal::Ignored),
            ("nocldwait", logged_nocldwait, SigchldRefusal::NoChildWait),
            ("handler", logged_handler, SigchldRefusal::Handler),
            (
                "unreadable",
                logged_unreadable,
                SigchldRefusal::Unreadable(14),
            ),
        ]
    }

    /// A real child in its own group that has exited and is not reaped: the
    /// cleanup the runner owes (`Responsibility::Leader`).
    fn exited_leader(dir: &Dir, name: &str) -> Leader {
        let script = dir.script(name, "exit 0");
        let child = Command::new(&script)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        assert!(
            eventually(|| sys::leader_exited_without_reaping(pid) == Ok(true)),
            "the owed leader never exited"
        );
        Leader { child, pgid: pid }
    }

    /// A real child in its own group that is still running.
    fn running_leader(dir: &Dir, name: &str) -> Leader {
        let script = dir.script(name, "exec sleep 60");
        let child = Command::new(&script)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        Leader { child, pgid: pid }
    }

    /// A script that leaves a mark when it really runs (the warm-up does not),
    /// as the argv of a NEW command.
    fn marking_argv(dir: &Dir, label: &str) -> (Vec<String>, PathBuf) {
        let mark = dir.0.join(format!("new-command-{label}"));
        let script = dir.script("mark", "touch \"$1\"");
        (vec![script, mark.display().to_string()], mark)
    }

    fn runner_with(signal: GroupSignal, probe: LoggedProbe) -> Runner {
        let mut runner = Runner::new(policy());
        runner.signal = signal;
        runner.sigchld = probe;
        clear_events();
        runner
    }

    const RUN: Duration = Duration::from_secs(20);

    /// Case 1 (nothing owed): a refused state spawns nothing and signals
    /// nothing, for every refusal kind, on repeated calls.
    #[test]
    fn fh2_nothing_owed_and_a_refused_sigchld_neither_spawns_nor_signals() {
        let dir = Dir::new("fh2-case1");
        let (argv, mark) = marking_argv(&dir, "case1");
        for (label, probe, refusal) in refused_states() {
            let mut runner = runner_with(logging_signal, probe);
            for _ in 0..3 {
                assert_eq!(
                    runner.run(&argv, "start", RUN, false),
                    RunEnd::SigchldRefused(refusal),
                    "{label}"
                );
            }
            assert!(!mark.exists(), "{label}: a command was spawned");
            assert!(runner.pending.is_none(), "{label}: nothing is owed");
            assert_eq!(
                events(),
                vec![Event::SigchldChecked; 3],
                "{label}: only the check ran, no signal"
            );
        }
    }

    /// Cases 2 and 3 (cleanup owed, then finished): the owed cleanup runs and
    /// signals ONLY its own pinned group, before the check; the refusal then
    /// spawns nothing and signals nothing, and stays that way afterwards.
    #[test]
    fn fh2_an_owed_cleanup_runs_before_a_refusal_and_then_nothing_new_starts() {
        let dir = Dir::new("fh2-case23");
        let (argv, mark) = marking_argv(&dir, "case23");
        for (label, probe, refusal) in refused_states() {
            let mut runner = runner_with(logging_signal, probe);
            let leader = exited_leader(&dir, &format!("owed-{label}"));
            let owed = leader.pgid;
            runner.pending = Some(Responsibility::Leader(leader));
            assert_eq!(
                runner.run(&argv, "start", RUN, false),
                RunEnd::SigchldRefused(refusal),
                "{label}: the cleanup finished, then the refusal"
            );
            let first = events();
            let signals = signals_of(&first);
            assert!(
                !signals.is_empty() && signals.len() <= 2,
                "{label}: the cleanup kills its own group: {signals:?}"
            );
            assert!(
                signals.iter().all(|&(pgid, signal, pinned)| pgid == owed
                    && signal == sys::SIGKILL
                    && pinned),
                "{label}: only pinned KILLs to the owed group: {signals:?}"
            );
            assert_eq!(
                first.last(),
                Some(&Event::SigchldChecked),
                "{label}: the cleanup precedes the check, which ends the call"
            );
            assert_eq!(
                first
                    .iter()
                    .filter(|event| **event == Event::SigchldChecked)
                    .count(),
                1,
                "{label}"
            );
            assert!(
                runner.pending.is_none(),
                "{label}: discharged by the census"
            );
            assert!(!mark.exists(), "{label}: a new command was spawned");

            // Case 3: the cleanup is finished and the state is still refused.
            for _ in 0..2 {
                assert_eq!(
                    runner.run(&argv, "start", RUN, false),
                    RunEnd::SigchldRefused(refusal),
                    "{label}"
                );
            }
            let later = events();
            assert_eq!(
                signals_of(&later),
                signals,
                "{label}: no signal after the cleanup was finished"
            );
            assert_eq!(
                later.len(),
                first.len() + 2,
                "{label}: two more checks only"
            );
            assert!(!mark.exists(), "{label}");
        }
    }

    /// Case 4 (the cleanup cannot be finished): the responsibility is kept and
    /// every later command is refused as `PendingBlocked`, whatever the
    /// `SIGCHLD` state, without the check even running; a signal that cannot
    /// be confirmed keeps the leader, a census that finds members keeps the
    /// group; only a finished cleanup lets work (or the refusal) through.
    #[test]
    fn fh2_an_unfinished_cleanup_keeps_the_responsibility_and_blocks_every_spawn() {
        let dir = Dir::new("fh2-case4");
        let (argv, mark) = marking_argv(&dir, "case4");

        // (a) the kill cannot be confirmed: the exited leader stays owed.
        for (label, probe) in [
            ("refused", logged_ignored as LoggedProbe),
            ("default", logged_default),
        ] {
            let mut runner = runner_with(logging_failing_signal, probe);
            let leader = exited_leader(&dir, &format!("unconfirmed-{label}"));
            let owed = leader.pgid;
            runner.pending = Some(Responsibility::Leader(leader));
            for _ in 0..3 {
                assert_eq!(
                    runner.run(&argv, "start", RUN, false),
                    RunEnd::PendingBlocked,
                    "{label}"
                );
                assert!(
                    matches!(&runner.pending, Some(Responsibility::Leader(l)) if l.pgid == owed),
                    "{label}: the responsibility is kept"
                );
            }
            assert!(
                !mark.exists(),
                "{label}: a spawn followed an unfinished cleanup"
            );
            let log = events();
            assert!(
                !log.contains(&Event::SigchldChecked),
                "{label}: the check is never reached while a cleanup is owed"
            );
            assert!(
                signals_of(&log).iter().all(|&(pgid, ..)| pgid == owed),
                "{label}: signals only to the owed group"
            );
            // The kill works again: the cleanup finishes, then the state decides.
            runner.signal = logging_signal;
            let expected = if label == "refused" {
                RunEnd::SigchldRefused(SigchldRefusal::Ignored)
            } else {
                RunEnd::Exited {
                    code: Some(0),
                    stdout: Vec::new(),
                    overflow: false,
                }
            };
            assert_eq!(runner.run(&argv, "start", RUN, false), expected, "{label}");
            assert_eq!(mark.exists(), label == "default", "{label}");
            let _ = fs::remove_file(&mark);
        }

        // (b) the leader is reaped but the census finds the group not empty:
        // census-only responsibility, no signal at all afterwards.
        let mut runner = runner_with(logging_signal, logged_ignored);
        runner.census = census_present;
        runner.pending = Some(Responsibility::Leader(exited_leader(&dir, "census")));
        assert_eq!(
            runner.run(&argv, "start", RUN, false),
            RunEnd::PendingBlocked
        );
        assert!(matches!(runner.pending, Some(Responsibility::Group { .. })));
        let after_reap = events();
        for probe in [logged_ignored as LoggedProbe, logged_default] {
            runner.sigchld = probe;
            assert_eq!(
                runner.run(&argv, "start", RUN, false),
                RunEnd::PendingBlocked
            );
        }
        assert_eq!(
            events(),
            after_reap,
            "no signal and no check after the reap"
        );
        assert!(!mark.exists());
        // The census can prove the group empty again: the refusal now applies.
        runner.census = sys::group_probe;
        runner.sigchld = logged_ignored;
        assert_eq!(
            runner.run(&argv, "start", RUN, false),
            RunEnd::SigchldRefused(SigchldRefusal::Ignored)
        );
        assert!(runner.pending.is_none());
        assert!(!mark.exists());
    }

    /// Case 5 (the pin is lost): the leader is no longer our child, so its group
    /// id may belong to a stranger. Under a refused state and under the default
    /// one, nothing is signalled, the cleanup stays owed as a census-only
    /// responsibility, and nothing is spawned. The "stranger" (a live process
    /// of the old group) survives.
    #[test]
    fn fh2_a_lost_pin_sends_no_signal_to_the_old_group_under_any_sigchld_state() {
        fn pin_lost(_: u32) -> Result<bool, i32> {
            Err(sys::ECHILD)
        }
        let dir = Dir::new("fh2-case5");
        let (argv, mark) = marking_argv(&dir, "case5");
        for (label, probe) in [
            ("refused", logged_ignored as LoggedProbe),
            ("default", logged_default),
        ] {
            let mut runner = runner_with(logging_signal, probe);
            runner.exit_probe = pin_lost;
            let leader = running_leader(&dir, &format!("stranger-{label}"));
            let old_group = leader.pgid;
            let stranger = i32::try_from(old_group).unwrap();
            runner.pending = Some(Responsibility::Leader(leader));
            for _ in 0..3 {
                assert_eq!(
                    runner.run(&argv, "start", RUN, false),
                    RunEnd::PendingBlocked,
                    "{label}"
                );
                assert!(
                    matches!(&runner.pending, Some(Responsibility::Group { pgid }) if *pgid == old_group),
                    "{label}: census-only responsibility"
                );
            }
            assert!(
                events().is_empty(),
                "{label}: no signal, no check: {:?}",
                events()
            );
            assert!(!mark.exists(), "{label}: a spawn followed a lost pin");
            assert!(
                pid_alive(stranger),
                "{label}: the old group's process was hit"
            );
            // Test cleanup: the process is in fact still our child.
            kill_group_if_alive(old_group);
            let mut status = 0;
            // SAFETY: plain syscall on the pid of this test's own child.
            unsafe { waitpid(stranger, &mut status, 0) };
            assert!(eventually(|| runner.clear_pending()), "{label}");
        }
    }

    /// Case 6 (the state returns to the default): normal work resumes, but only
    /// once nothing is owed; the cleanup that was owed is finished first (its
    /// signals all precede the check and the new spawn), and the new command
    /// then gets its own, separate, signals.
    #[test]
    fn fh2_a_restored_default_runs_commands_only_after_the_owed_cleanup() {
        let dir = Dir::new("fh2-case6");
        let (argv, mark) = marking_argv(&dir, "case6");
        let mut runner = runner_with(logging_signal, logged_ignored);
        assert_eq!(
            runner.run(&argv, "start", RUN, false),
            RunEnd::SigchldRefused(SigchldRefusal::Ignored)
        );
        assert!(!mark.exists());

        let leader = exited_leader(&dir, "owed-before-default");
        let owed = leader.pgid;
        runner.pending = Some(Responsibility::Leader(leader));
        clear_events();
        runner.sigchld = logged_default;
        assert!(matches!(
            runner.run(&argv, "start", RUN, false),
            RunEnd::Exited { code: Some(0), .. }
        ));
        assert!(mark.exists(), "the default state runs the command");
        assert!(runner.pending.is_none());
        let log = events();
        let check = log
            .iter()
            .position(|event| *event == Event::SigchldChecked)
            .expect("the check ran");
        let cleanup: Vec<_> = log[..check]
            .iter()
            .filter(|event| matches!(event, Event::Signal { pgid, .. } if *pgid == owed))
            .collect();
        assert!(
            !cleanup.is_empty(),
            "the owed cleanup signalled before the check"
        );
        assert!(
            log[..check]
                .iter()
                .all(|event| matches!(event, Event::Signal { pgid, .. } if *pgid == owed)),
            "before the check only the owed group is signalled: {log:?}"
        );
        assert!(
            log[check + 1..]
                .iter()
                .all(|event| matches!(event, Event::Signal { pgid, .. } if *pgid != owed)),
            "after the check only the new command's own group is signalled: {log:?}"
        );

        // Refused again: no spawn, no signal.
        let _ = fs::remove_file(&mark);
        runner.sigchld = logged_nocldwait;
        clear_events();
        assert_eq!(
            runner.run(&argv, "start", RUN, false),
            RunEnd::SigchldRefused(SigchldRefusal::NoChildWait)
        );
        assert_eq!(events(), vec![Event::SigchldChecked]);
        assert!(!mark.exists());
    }

    /// Source shape of the FH-2 order: the owed cleanup is discharged before
    /// the `SIGCHLD` check, and the check precedes the one spawn.
    #[test]
    fn fh2_the_order_of_run_is_cleanup_then_check_then_spawn() {
        let source = include_str!("command_service.rs");
        let production = &source[..source.find("#[cfg(test)]\nmod tests").unwrap()];
        let start = production.find("    fn run(").unwrap();
        let run = &production[start..];
        let at = |needle: &str| run.find(needle).unwrap_or_else(|| panic!("{needle}"));
        assert!(at("self.clear_pending()") < at("check_sigchld(self.sigchld)"));
        assert!(at("check_sigchld(self.sigchld)") < at("command.spawn()"));
        assert!(at("PendingBlocked") < at("SigchldRefused"));
    }
}
