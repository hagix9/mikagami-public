//! Stage 14 bounded command-process backend (Design Revision 5 §16.2-§16.7,
//! S14-FR-01, S14-R3-01; Phase 14.5, DC-14.5-01 Option 1).
//!
//! One fencing action step or verify poll step runs one external process
//! under a single absolute deadline set computed once at step start
//! (§16.6.1): Execution, TERM, KILL, then non-blocking Finalization, with the
//! function returning by `return_deadline`. The step is single-threaded: both
//! read ends are non-blocking and are drained alternately with a non-reaping
//! leader-exit query in `POLL_SLICE` sub-waits (§16.6.3). A leader that
//! cannot be reaped by `return_deadline` moves into the single pending-reap
//! slot (§16.7), and every spawn is refused while that slot is occupied.
//!
//! Runtime edges: `LinuxNodeRuntime` owns one backend and drives only its
//! pending-reap slot (Phase 14.6). `[fencing]` configuration is validated
//! here and trust-checked at daemon startup (Phase 14.7). No production code
//! runs a step yet. The backend owns no lifecycle, fencing, authority,
//! or promotion state, performs no durable write, and a step outcome is only
//! provenance (§16.4) or a verify classification (§17.1): it never confirms
//! anything by itself.

#![allow(dead_code)]

use crate::config::{FencingBackendKind, FencingConfig};
use crate::fencing::{ActionOutcome, IncidentId, InconclusiveKind};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Component, Path};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The existing 10 ms child-poll interval; the longest sub-wait (§16.6.1).
pub const POLL_SLICE: Duration = Duration::from_millis(10);
pub const TERM_GRACE: Duration = Duration::from_secs(2);
pub const KILL_REAP_GRACE: Duration = Duration::from_secs(2);
/// One per step, measured from `hard_deadline` (§16.6.7).
pub const FINALIZATION_RETURN_ALLOWANCE: Duration = Duration::from_millis(500);
/// G-2 contract R4.1 §5.1: the route-handoff step has its own, shorter deadline set (the fencing
/// step values above are unchanged). Execution `E` = 2.0 s, then TERM 0.25 s, KILL/reap 0.5 s and
/// finalization 0.25 s, so a route step returns within `S` = 3.0 s. There is no configuration for
/// these values: they are part of the lease-renewal safety budget and are never lengthened.
pub const ROUTE_EXECUTION: Duration = Duration::from_millis(2_000);
pub const ROUTE_TERM_GRACE: Duration = Duration::from_millis(250);
pub const ROUTE_KILL_REAP_GRACE: Duration = Duration::from_millis(500);
pub const ROUTE_FINALIZATION_RETURN_ALLOWANCE: Duration = Duration::from_millis(250);
/// `S`: the latest return of a route step after its start (the route handoff's own constant).
pub const ROUTE_STEP_RETURN_BUDGET: Duration = crate::route_handoff::RH_STEP_RETURN_BUDGET;
const _: () = assert!(
    ROUTE_EXECUTION.as_millis()
        + ROUTE_TERM_GRACE.as_millis()
        + ROUTE_KILL_REAP_GRACE.as_millis()
        + ROUTE_FINALIZATION_RETURN_ALLOWANCE.as_millis()
        == ROUTE_STEP_RETURN_BUDGET.as_millis()
);
/// Stored stdout bytes; further bytes are drained and discarded (§16.3).
pub const STDOUT_CAPTURE_LIMIT: usize = 4 * 1024;
pub const MAX_FENCE_TIMEOUT_SEC: u64 = 60;
pub const MAX_VERIFY_TIMEOUT_SEC: u64 = 30;
/// §16.1: `verify_polls` is an integer in 1..=60.
pub const MAX_VERIFY_POLLS: u64 = 60;
/// The only inherited-looking variable besides `LANG` and the four
/// `MIKAGAMI_*` values (§16.3).
pub const FENCE_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

const READ_CHUNK: usize = 8 * 1024;
const MAX_READS_PER_PASS: usize = 64;

mod sys {
    //! Manual production `extern "C"` for the non-reaping exit query, the
    //! group signal, and the non-blocking pipe flag (§16.3; the `tcp.rs`
    //! idiom). No new crate.

    // The manual values and the `siginfo_t` layout below are verified only
    // for these targets. Pointer width is not an ABI selector (mips64,
    // sparc64, and alpha use other values), so every other target fails to
    // build instead of misreading `siginfo_t` or passing wrong flags.
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
        "fencing_backend: manual FFI values are verified only for Linux and macOS on x86_64/aarch64"
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
        pub const EBADF: i32 = 9;
        /// `si_pid` follows `si_signo`, `si_errno`, `si_code`, and padding.
        pub const SI_PID_OFFSET: usize = 16;

        // Build-time cross-check against the target's own `libc` values.
        const _: () = assert!(
            WNOWAIT == libc::WNOWAIT
                && O_NONBLOCK == libc::O_NONBLOCK
                && ELOOP == libc::ELOOP
                && EBADF == libc::EBADF
                && super::P_PID as libc::idtype_t == libc::P_PID
                && super::WEXITED == libc::WEXITED
                && super::WNOHANG == libc::WNOHANG
                && super::F_GETFL == libc::F_GETFL
                && super::F_SETFL == libc::F_SETFL
                && super::SIGTERM == libc::SIGTERM
                && super::SIGKILL == libc::SIGKILL
                && std::mem::size_of::<libc::siginfo_t>() == 128
                && std::mem::align_of::<libc::siginfo_t>() == 8
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
        pub const EBADF: i32 = 9;
        pub const SI_PID_OFFSET: usize = 12;
    }

    pub(super) use constants::SI_PID_OFFSET;
    use constants::WNOWAIT;
    pub use constants::{EBADF, ELOOP, O_NOFOLLOW, O_NONBLOCK};

    pub const SIGTERM: i32 = 15;
    pub const SIGKILL: i32 = 9;
    const P_PID: i32 = 1;
    const WEXITED: i32 = 4;
    const WNOHANG: i32 = 1;
    const F_GETFL: i32 = 3;
    const F_SETFL: i32 = 4;

    /// Large enough for `siginfo_t` on both targets (128 / 104 bytes).
    #[repr(C, align(8))]
    struct SigInfo([u8; 128]);

    unsafe extern "C" {
        fn killpg(pgrp: i32, sig: i32) -> i32;
        fn waitid(idtype: i32, id: u32, infop: *mut SigInfo, options: i32) -> i32;
        fn fcntl(fd: i32, command: i32, ...) -> i32;
    }

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    /// `killpg(pgid, signal)`; one signal send, never a wait.
    pub fn signal_group(pgid: u32, signal: i32) -> Result<(), i32> {
        let Ok(pgid) = i32::try_from(pgid) else {
            return Err(EBADF);
        };
        if pgid <= 1 {
            return Err(EBADF);
        }
        if unsafe { killpg(pgid, signal) } == 0 {
            Ok(())
        } else {
            Err(errno())
        }
    }

    /// `waitid(P_PID, pid, WEXITED | WNOWAIT | WNOHANG)`: observes leader
    /// exit without reaping, so the pid (and pgid) cannot be recycled.
    pub fn leader_exited_without_reaping(pid: u32) -> Result<bool, i32> {
        let mut info = SigInfo([0; 128]);
        let options = WEXITED | WNOWAIT | WNOHANG;
        if unsafe { waitid(P_PID, pid, &mut info, options) } != 0 {
            return Err(errno());
        }
        let bytes = &info.0[SI_PID_OFFSET..SI_PID_OFFSET + 4];
        let reported = i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        Ok(reported != 0)
    }

    pub fn set_nonblocking(fd: i32) -> Result<(), i32> {
        let flags = unsafe { fcntl(fd, F_GETFL) };
        if flags < 0 {
            return Err(errno());
        }
        if unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) } < 0 {
            return Err(errno());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepKind {
    Action,
    Verify,
    /// G-2 route handoff (`route-check`, `route-observe`, `route-assign`): the RH-only deadline
    /// set, at most one Compute API call per step.
    Route,
}

/// A step timeout within the §16.5 maxima (`fence_timeout_sec` 1..=60,
/// `verify_timeout_sec` 1..=30). There is no unbounded or zero timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepTimeout {
    kind: StepKind,
    duration: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeoutOutOfRange {
    pub kind: StepKind,
    pub seconds: u64,
    pub maximum: u64,
}

impl StepTimeout {
    pub fn fence(seconds: u64) -> Result<Self, TimeoutOutOfRange> {
        Self::bounded(StepKind::Action, seconds, MAX_FENCE_TIMEOUT_SEC)
    }

    pub fn verify(seconds: u64) -> Result<Self, TimeoutOutOfRange> {
        Self::bounded(StepKind::Verify, seconds, MAX_VERIFY_TIMEOUT_SEC)
    }

    /// The fixed G-2 route-step execution timeout (`ROUTE_EXECUTION`); not configurable.
    pub const fn route() -> StepTimeout {
        Self {
            kind: StepKind::Route,
            duration: ROUTE_EXECUTION,
        }
    }

    fn bounded(kind: StepKind, seconds: u64, maximum: u64) -> Result<Self, TimeoutOutOfRange> {
        if !(1..=maximum).contains(&seconds) {
            return Err(TimeoutOutOfRange {
                kind,
                seconds,
                maximum,
            });
        }
        Ok(Self {
            kind,
            duration: Duration::from_secs(seconds),
        })
    }

    pub fn kind(&self) -> StepKind {
        self.kind
    }

    pub fn duration(&self) -> Duration {
        self.duration
    }
}

/// The four absolute deadlines of §16.6.1, computed once before spawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepDeadlines {
    pub step_started_at: Instant,
    pub execution_deadline: Instant,
    pub term_deadline: Instant,
    pub hard_deadline: Instant,
    pub return_deadline: Instant,
}

impl StepDeadlines {
    /// `None` if any `checked_add` overflows: the step then never spawns.
    pub fn compute(step_started_at: Instant, timeout: Duration) -> Option<Self> {
        Self::compute_with(
            step_started_at,
            timeout,
            TERM_GRACE,
            KILL_REAP_GRACE,
            FINALIZATION_RETURN_ALLOWANCE,
        )
    }

    /// The deadline set of a step of `kind`: the G-2 route step uses its own shorter graces
    /// (contract R4.1 §5.1), every fencing step the §16.6.1 values.
    pub fn compute_for(
        kind: StepKind,
        step_started_at: Instant,
        timeout: Duration,
    ) -> Option<Self> {
        match kind {
            StepKind::Action | StepKind::Verify => Self::compute(step_started_at, timeout),
            StepKind::Route => Self::compute_with(
                step_started_at,
                timeout,
                ROUTE_TERM_GRACE,
                ROUTE_KILL_REAP_GRACE,
                ROUTE_FINALIZATION_RETURN_ALLOWANCE,
            ),
        }
    }

    fn compute_with(
        step_started_at: Instant,
        timeout: Duration,
        term_grace: Duration,
        kill_reap_grace: Duration,
        finalization: Duration,
    ) -> Option<Self> {
        let execution_deadline = step_started_at.checked_add(timeout)?;
        let term_deadline = execution_deadline.checked_add(term_grace)?;
        let hard_deadline = term_deadline.checked_add(kill_reap_grace)?;
        let return_deadline = hard_deadline.checked_add(finalization)?;
        Some(Self {
            step_started_at,
            execution_deadline,
            term_deadline,
            hard_deadline,
            return_deadline,
        })
    }
}

/// Provenance of the step's incident and attempt (§12.2), copied into the
/// environment and, if the leader is retained, into `PendingReap`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepIdentity {
    pub incident_seq: u64,
    pub incident_id: IncidentId,
    pub attempt_token: u64,
}

/// One action or verify step: the configured argv (never a shell line), its
/// bounded timeout, and the values placed in the allowlisted environment.
#[derive(Debug, Clone)]
pub struct StepRequest<'a> {
    pub argv: &'a [String],
    pub timeout: StepTimeout,
    pub identity: StepIdentity,
    pub cluster: &'a str,
    pub target_node: &'a str,
}

/// §16.2 refusal reasons. Any refusal means no spawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustRefusal {
    EmptyArgv,
    NotAbsolute,
    NotNormalized,
    SymlinkFinalComponent,
    Open(i32),
    NotRegularFile,
    NotRootOwned,
    GroupOrWorldWritable,
    NotExecutable,
    AncestorUnreadable(i32),
    AncestorNotDirectory,
    AncestorNotRootOwned,
    AncestorGroupOrWorldWritable,
}

/// §16.2: absolute path, final component opened with `O_NOFOLLOW` as a
/// regular file owned by uid 0, not group/world-writable, executable, and
/// every ancestor directory owned by uid 0 and not group/world-writable. An
/// ancestor that is a symlink is not a directory and is refused.
///
/// Every call is non-blocking (§16.6.1): the final component's type is
/// checked with `lstat` before anything opens it, so a FIFO, device, socket,
/// or directory is refused without an `open`. The open itself adds
/// `O_NONBLOCK`, so a path swapped to a special file after the `lstat`
/// still cannot block it.
pub fn check_executable_trust(executable: &str) -> Result<(), TrustRefusal> {
    let path = Path::new(executable);
    if !path.is_absolute() {
        return Err(TrustRefusal::NotAbsolute);
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(TrustRefusal::NotNormalized);
    }
    let linked = fs::symlink_metadata(path)
        .map_err(|error| TrustRefusal::Open(error.raw_os_error().unwrap_or(0)))?;
    if linked.file_type().is_symlink() {
        return Err(TrustRefusal::SymlinkFinalComponent);
    }
    if !linked.is_file() {
        return Err(TrustRefusal::NotRegularFile);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(sys::O_NOFOLLOW | sys::O_NONBLOCK)
        .open(path)
        .map_err(|error| match error.raw_os_error() {
            Some(sys::ELOOP) => TrustRefusal::SymlinkFinalComponent,
            errno => TrustRefusal::Open(errno.unwrap_or(0)),
        })?;
    let metadata = file
        .metadata()
        .map_err(|error| TrustRefusal::Open(error.raw_os_error().unwrap_or(0)))?;
    check_file_metadata(metadata.is_file(), metadata.uid(), metadata.mode())?;
    let mut ancestor = path.parent();
    while let Some(directory) = ancestor {
        let metadata = fs::symlink_metadata(directory)
            .map_err(|error| TrustRefusal::AncestorUnreadable(error.raw_os_error().unwrap_or(0)))?;
        check_ancestor_metadata(metadata.is_dir(), metadata.uid(), metadata.mode())?;
        ancestor = directory.parent();
    }
    Ok(())
}

fn check_file_metadata(is_file: bool, uid: u32, mode: u32) -> Result<(), TrustRefusal> {
    if !is_file {
        return Err(TrustRefusal::NotRegularFile);
    }
    if uid != 0 {
        return Err(TrustRefusal::NotRootOwned);
    }
    if mode & 0o022 != 0 {
        return Err(TrustRefusal::GroupOrWorldWritable);
    }
    if mode & 0o111 == 0 {
        return Err(TrustRefusal::NotExecutable);
    }
    Ok(())
}

fn check_ancestor_metadata(is_dir: bool, uid: u32, mode: u32) -> Result<(), TrustRefusal> {
    if !is_dir {
        return Err(TrustRefusal::AncestorNotDirectory);
    }
    if uid != 0 {
        return Err(TrustRefusal::AncestorNotRootOwned);
    }
    if mode & 0o022 != 0 {
        return Err(TrustRefusal::AncestorGroupOrWorldWritable);
    }
    Ok(())
}

/// v0.7 G-2: `[route] helper` at daemon startup, with the same §16.2 check every spawn uses
/// (`run_step` re-checks it before each route step). Its only caller is the runtime owner's
/// constructor on the daemon startup path.
pub fn trust_route_helper(executable: &str) -> Result<(), String> {
    check_executable_trust(executable).map_err(|refusal| {
        format!("route.helper {executable} is not a trusted executable: {refusal:?}")
    })
}

/// Stage 14 Design Revision 5 §16.1 / §16.2 / §16.5: validated `[fencing]`
/// settings (Phase 14.7, DC-14.7-01 Option 1).
///
/// Holding settings runs nothing. No production code passes them to
/// `run_step`: `backend = "command"` is validated and trust-checked at daemon
/// startup, but this build executes no fence or verify command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FencingSettings {
    /// An absent `[fencing]` section or `backend = "none"` (§16.1).
    None,
    Command(CommandFencing),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandFencing {
    pub fence: Vec<String>,
    pub verify: Vec<String>,
    pub fence_timeout: StepTimeout,
    pub verify_timeout: StepTimeout,
    pub verify_polls: u64,
}

/// A §16.1 / §16.2 startup refusal. The daemon does not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FencingStartupError {
    Invalid(Vec<String>),
    Untrusted {
        field: &'static str,
        executable: String,
        refusal: TrustRefusal,
    },
}

impl fmt::Display for FencingStartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(errors) => {
                formatter.write_str("invalid [fencing] configuration")?;
                for error in errors {
                    write!(formatter, "; {error}")?;
                }
                Ok(())
            }
            Self::Untrusted {
                field,
                executable,
                refusal,
            } => write!(
                formatter,
                "fencing.{field}[0] {executable} is not a trusted executable: {refusal:?}"
            ),
        }
    }
}

impl FencingSettings {
    /// The only `[fencing]` validator (§16.1, §16.5); config validation
    /// reports its errors. Timeouts are checked by the `StepTimeout`
    /// constructors, so the configured range and the step range are one rule.
    pub fn from_config(section: Option<&FencingConfig>) -> Result<Self, Vec<String>> {
        let Some(section) = section else {
            return Ok(Self::None);
        };
        let mut errors = Vec::new();
        let fence_timeout = configured_timeout(
            "fence_timeout_sec",
            section.fence_timeout_sec,
            StepTimeout::fence,
            &mut errors,
        );
        let verify_timeout = configured_timeout(
            "verify_timeout_sec",
            section.verify_timeout_sec,
            StepTimeout::verify,
            &mut errors,
        );
        let verify_polls = match section.verify_polls {
            Some(polls) if !(1..=MAX_VERIFY_POLLS).contains(&polls) => {
                errors.push(format!(
                    "fencing.verify_polls must be between 1 and {MAX_VERIFY_POLLS}"
                ));
                None
            }
            polls => polls,
        };
        match section.backend {
            FencingBackendKind::None => {
                for (field, argv) in [("fence", &section.fence), ("verify", &section.verify)] {
                    if argv.is_some() {
                        errors.push(format!("fencing.{field} is not valid for backend \"none\""));
                    }
                }
                if errors.is_empty() {
                    Ok(Self::None)
                } else {
                    Err(errors)
                }
            }
            FencingBackendKind::Command => {
                let fence = configured_argv("fence", &section.fence, &mut errors);
                let verify = configured_argv("verify", &section.verify, &mut errors);
                for (field, missing) in [
                    ("fence_timeout_sec", section.fence_timeout_sec.is_none()),
                    ("verify_timeout_sec", section.verify_timeout_sec.is_none()),
                    ("verify_polls", section.verify_polls.is_none()),
                ] {
                    if missing {
                        errors.push(format!(
                            "fencing.{field} is required for backend \"command\""
                        ));
                    }
                }
                match (fence, verify, fence_timeout, verify_timeout, verify_polls) {
                    (
                        Some(fence),
                        Some(verify),
                        Some(fence_timeout),
                        Some(verify_timeout),
                        Some(verify_polls),
                    ) if errors.is_empty() => Ok(Self::Command(CommandFencing {
                        fence,
                        verify,
                        fence_timeout,
                        verify_timeout,
                        verify_polls,
                    })),
                    _ => Err(errors),
                }
            }
        }
    }

    /// §16.2 at daemon startup: validate, then trust-check `fence[0]` and
    /// `verify[0]` with the check every spawn uses. Backend `none` has no
    /// executable and checks nothing. Its only caller is the runtime owner's
    /// constructor on the daemon startup path.
    pub fn startup(section: Option<&FencingConfig>) -> Result<Self, FencingStartupError> {
        Self::startup_with(section, check_executable_trust)
    }

    fn startup_with(
        section: Option<&FencingConfig>,
        mut trust: impl FnMut(&str) -> Result<(), TrustRefusal>,
    ) -> Result<Self, FencingStartupError> {
        let settings = Self::from_config(section).map_err(FencingStartupError::Invalid)?;
        if let Self::Command(command) = &settings {
            for (field, argv) in [("fence", &command.fence), ("verify", &command.verify)] {
                trust(&argv[0]).map_err(|refusal| FencingStartupError::Untrusted {
                    field,
                    executable: argv[0].clone(),
                    refusal,
                })?;
            }
        }
        Ok(settings)
    }

    /// The configured backend `B` of §13.2.
    pub fn backend(&self) -> crate::fencing::FencingBackend {
        match self {
            Self::None => crate::fencing::FencingBackend::None,
            Self::Command(_) => crate::fencing::FencingBackend::Command,
        }
    }

    /// The command settings when `B = command`.
    pub fn command(&self) -> Option<&CommandFencing> {
        match self {
            Self::None => None,
            Self::Command(command) => Some(command),
        }
    }

    /// The one startup diagnostic for the Phase 14.9 transitional state:
    /// fence and verify commands run only for an operator-requested incident,
    /// and this build never lets an attempt past the fencing gate.
    pub fn startup_notice(&self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Command(_) => Some(
                "fencing: backend \"command\" validated and trusted at startup; fence and \
                 verify commands run only for an operator-requested incident, and this build \
                 never lets an activation attempt past the fencing gate",
            ),
        }
    }
}

fn configured_timeout(
    field: &str,
    seconds: Option<u64>,
    bounded: fn(u64) -> Result<StepTimeout, TimeoutOutOfRange>,
    errors: &mut Vec<String>,
) -> Option<StepTimeout> {
    match seconds.map(bounded)? {
        Ok(timeout) => Some(timeout),
        Err(range) => {
            errors.push(format!(
                "fencing.{field} must be between 1 and {} seconds",
                range.maximum
            ));
            None
        }
    }
}

fn configured_argv(
    field: &str,
    argv: &Option<Vec<String>>,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let Some(argv) = argv else {
        errors.push(format!(
            "fencing.{field} is required for backend \"command\""
        ));
        return None;
    };
    match argv.first() {
        Some(program) if !program.is_empty() && Path::new(program).is_absolute() => {
            return Some(argv.clone());
        }
        Some(program) if !program.is_empty() => {
            errors.push(format!("fencing.{field}[0] must be an absolute path"));
        }
        _ => errors.push(format!("fencing.{field} must contain a program")),
    }
    None
}

/// What the step hands the driver to spawn: argv verbatim plus the exact
/// §16.3 environment allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnPlan<'a> {
    pub argv: &'a [String],
    pub environment: [(&'static str, String); 6],
}

impl<'a> SpawnPlan<'a> {
    /// `pub(crate)` only so the two-node helper-binding tests can read the exact environment.
    pub(crate) fn new(request: &StepRequest<'a>) -> Self {
        Self {
            argv: request.argv,
            environment: [
                ("PATH", FENCE_PATH.to_string()),
                ("LANG", "C".to_string()),
                ("MIKAGAMI_CLUSTER", request.cluster.to_string()),
                ("MIKAGAMI_FENCE_TARGET", request.target_node.to_string()),
                (
                    "MIKAGAMI_FENCE_INCIDENT",
                    request.identity.incident_id.as_str().to_string(),
                ),
                (
                    "MIKAGAMI_FENCE_ATTEMPT",
                    request.identity.attempt_token.to_string(),
                ),
            ],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupSignal {
    Term,
    Kill,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadResult {
    Data(usize),
    /// Would block or interrupted: retried within the active deadline.
    Retry,
    Eof,
    Error(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaderStatus {
    Code(i32),
    Signal(i32),
}

/// Result of one non-blocking (`WNOHANG`) reap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReapResult {
    Exited(LeaderStatus),
    NotExited,
    Interrupted,
    Error(i32),
}

/// The process and clock primitives of one step. Every method is
/// non-blocking except `sleep`, whose duration the step bounds by
/// `min(POLL_SLICE, active_phase_deadline - now)`. There is no blocking wait,
/// reader thread, or join. The production driver is `SystemProcessDriver`;
/// tests substitute a fake with a controllable clock (§34.21 FR01-08).
pub trait ProcessDriver {
    type Leader;

    fn now(&self) -> Instant;
    fn sleep(&mut self, duration: Duration);
    fn check_trust(&mut self, executable: &str) -> Result<(), TrustRefusal>;
    fn spawn(&mut self, plan: &SpawnPlan<'_>) -> Result<Self::Leader, i32>;
    fn leader_pid(&self, leader: &Self::Leader) -> u32;
    fn set_nonblocking(&mut self, leader: &mut Self::Leader, stream: Stream) -> Result<(), i32>;
    fn read(&mut self, leader: &mut Self::Leader, stream: Stream, buffer: &mut [u8]) -> ReadResult;
    /// Non-reaping exit observation (`WNOWAIT | WNOHANG`).
    fn leader_exited(&mut self, leader: &Self::Leader) -> Result<bool, i32>;
    fn signal_group(&mut self, pgid: u32, signal: GroupSignal) -> Result<(), i32>;
    fn close_read_end(&mut self, leader: &mut Self::Leader, stream: Stream);
    /// One non-blocking reap (`WNOHANG`); never waits.
    fn try_reap(&mut self, leader: &mut Self::Leader) -> ReapResult;
}

/// Real processes: `std::process::Command` with no shell, `env_clear`,
/// `process_group(0)`, stdin `/dev/null`, and both output pipes.
#[derive(Debug, Default)]
pub struct SystemProcessDriver;

impl ProcessDriver for SystemProcessDriver {
    type Leader = Child;

    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }

    fn check_trust(&mut self, executable: &str) -> Result<(), TrustRefusal> {
        check_executable_trust(executable)
    }

    fn spawn(&mut self, plan: &SpawnPlan<'_>) -> Result<Child, i32> {
        let Some((program, arguments)) = plan.argv.split_first() else {
            return Err(sys::EBADF);
        };
        let mut command = Command::new(program);
        command.args(arguments).env_clear();
        for (name, value) in &plan.environment {
            command.env(name, value);
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .map_err(|error| error.raw_os_error().unwrap_or(0))
    }

    fn leader_pid(&self, leader: &Child) -> u32 {
        leader.id()
    }

    fn set_nonblocking(&mut self, leader: &mut Child, stream: Stream) -> Result<(), i32> {
        let fd = match stream {
            Stream::Stdout => leader.stdout.as_ref().map(|pipe| pipe.as_raw_fd()),
            Stream::Stderr => leader.stderr.as_ref().map(|pipe| pipe.as_raw_fd()),
        };
        sys::set_nonblocking(fd.ok_or(sys::EBADF)?)
    }

    fn read(&mut self, leader: &mut Child, stream: Stream, buffer: &mut [u8]) -> ReadResult {
        let result = match stream {
            Stream::Stdout => leader.stdout.as_mut().map(|pipe| pipe.read(buffer)),
            Stream::Stderr => leader.stderr.as_mut().map(|pipe| pipe.read(buffer)),
        };
        match result {
            None => ReadResult::Error(sys::EBADF),
            Some(Ok(0)) => ReadResult::Eof,
            Some(Ok(count)) => ReadResult::Data(count),
            Some(Err(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                ReadResult::Retry
            }
            Some(Err(error)) => ReadResult::Error(error.raw_os_error().unwrap_or(0)),
        }
    }

    fn leader_exited(&mut self, leader: &Child) -> Result<bool, i32> {
        sys::leader_exited_without_reaping(leader.id())
    }

    fn signal_group(&mut self, pgid: u32, signal: GroupSignal) -> Result<(), i32> {
        let signal = match signal {
            GroupSignal::Term => sys::SIGTERM,
            GroupSignal::Kill => sys::SIGKILL,
        };
        sys::signal_group(pgid, signal)
    }

    fn close_read_end(&mut self, leader: &mut Child, stream: Stream) {
        match stream {
            Stream::Stdout => drop(leader.stdout.take()),
            Stream::Stderr => drop(leader.stderr.take()),
        }
    }

    fn try_reap(&mut self, leader: &mut Child) -> ReapResult {
        match leader.try_wait() {
            Ok(Some(status)) => match (status.code(), status.signal()) {
                (Some(code), _) => ReapResult::Exited(LeaderStatus::Code(code)),
                (None, Some(signal)) => ReapResult::Exited(LeaderStatus::Signal(signal)),
                (None, None) => ReapResult::Error(0),
            },
            Ok(None) => ReapResult::NotExited,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => ReapResult::Interrupted,
            Err(error) => ReapResult::Error(error.raw_os_error().unwrap_or(0)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    Isolated,
    NotIsolated,
    Inconclusive(InconclusiveKind),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepOutcome {
    Action(ActionOutcome),
    Verify(VerifyOutcome),
    Route(RouteOutcome),
}

/// What a G-2 route step returned. Only `Output` carries the helper's answer (exit 0, resolved
/// before the execution deadline, no integrity fault, no overflow); the caller parses it with a
/// fixed grammar. Everything else is inconclusive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteOutcome {
    Output(Vec<u8>),
    NonzeroExit(i32),
    Inconclusive(InconclusiveKind),
}

/// Why a step produced no child (all classified `spawn-failed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnFailure {
    PendingReapOccupied,
    DeadlineOverflow,
    Trust(TrustRefusal),
    Spawn(i32),
}

/// Internal diagnostic reasons (§16.6.5). Never persisted, never on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepReason {
    LeaderExitPipeHeld,
    DescendantCleanupTimeout,
    GroupStateUnknown,
    ReaderError,
    ReaderDeadline,
    ReapFailed,
    EscapedHolder,
    ReturnDeadlineReached,
    PendingReapOccupied,
}

/// Ordered: a step only ever advances Execution → TERM → KILL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StepPhase {
    Execution,
    Term,
    Kill,
}

/// Result of the Finalization group `SIGKILL` (§16.7.2 `final_kill`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalKill {
    Sent,
    GroupStateUnknown,
}

/// Instants recorded by the step owner, for tests and the caller's log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepTimeline {
    pub term_signal_at: Option<Instant>,
    pub kill_signal_at: Option<Instant>,
    pub leader_exit_observed_at: Option<Instant>,
    pub resolved_at: Option<Instant>,
    pub last_wait_end: Option<Instant>,
    pub finalization_at: Instant,
}

/// What one step returns. The caller maps `outcome` onto the existing
/// fencing transitions and logs after the step returns (§16.6.6, §28).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepReport {
    pub kind: StepKind,
    /// The §16.7.4 gate's own §16.7.5 poll, so the caller can log a slot
    /// cleared (or still occupied) at step entry (§16.7.8).
    pub gate_poll: PendingReapPoll,
    pub outcome: StepOutcome,
    pub success_eligible: bool,
    pub spawn_failure: Option<SpawnFailure>,
    pub deadlines: Option<StepDeadlines>,
    pub timeline: Option<StepTimeline>,
    pub pid: Option<u32>,
    pub leader_status: Option<LeaderStatus>,
    pub final_kill: Option<FinalKill>,
    pub retained: bool,
    pub reasons: Vec<StepReason>,
    pub stdout: Vec<u8>,
    pub stdout_overflow: bool,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub returned_at: Instant,
}

impl StepReport {
    fn no_child(
        kind: StepKind,
        gate_poll: PendingReapPoll,
        failure: SpawnFailure,
        returned_at: Instant,
    ) -> Self {
        let outcome = match kind {
            StepKind::Action => StepOutcome::Action(ActionOutcome::SpawnFailed),
            StepKind::Verify => {
                StepOutcome::Verify(VerifyOutcome::Inconclusive(InconclusiveKind::SpawnFailed))
            }
            StepKind::Route => {
                StepOutcome::Route(RouteOutcome::Inconclusive(InconclusiveKind::SpawnFailed))
            }
        };
        let reasons = if failure == SpawnFailure::PendingReapOccupied {
            vec![StepReason::PendingReapOccupied]
        } else {
            Vec::new()
        };
        Self {
            kind,
            gate_poll,
            outcome,
            success_eligible: false,
            spawn_failure: Some(failure),
            deadlines: None,
            timeline: None,
            pid: None,
            leader_status: None,
            final_kill: None,
            retained: false,
            reasons,
            stdout: Vec::new(),
            stdout_overflow: false,
            stdout_bytes: 0,
            stderr_bytes: 0,
            returned_at,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionReason {
    ReapFailed,
    ReturnDeadlineReached,
}

/// The latest §16.7.5 poll result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastPoll {
    None,
    NotReaped,
    Interrupted,
    Error(i32),
}

/// The retained unreaped leader (§16.7.2). In memory only: never cloned,
/// copied, serialized, persisted, or dropped while occupied.
#[derive(Debug)]
pub struct PendingReap<L> {
    child: L,
    pid: u32,
    pgid: u32,
    step_kind: StepKind,
    incident_seq: u64,
    incident_id: IncidentId,
    attempt_token: u64,
    step_started_at: Instant,
    hard_deadline: Instant,
    retained_at: Instant,
    final_kill: FinalKill,
    reason: RetentionReason,
    polls: u64,
    last_poll: LastPoll,
}

/// Read-only copy of the §16.7.2 provenance, without the `Child`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingReapView {
    pub pid: u32,
    pub pgid: u32,
    pub step_kind: StepKind,
    pub incident_seq: u64,
    pub incident_id: IncidentId,
    pub attempt_token: u64,
    pub step_started_at: Instant,
    pub hard_deadline: Instant,
    pub retained_at: Instant,
    pub final_kill: FinalKill,
    pub reason: RetentionReason,
    pub polls: u64,
    pub last_poll: LastPoll,
}

impl PendingReapView {
    pub fn age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.retained_at)
    }

    /// The §16.7.8 fields of one pending-reap log line. Only provenance is
    /// logged: never argv, environment, output, or the incident UUID.
    pub fn log_fields(&self, pending_present: bool, now: Instant) -> String {
        format!(
            "pending_present={pending_present} kind={:?} incident_seq={} attempt_token={} pid={} age_ms={} last_poll={:?}",
            self.step_kind,
            self.incident_seq,
            self.attempt_token,
            self.pid,
            self.age(now).as_millis(),
            self.last_poll,
        )
    }
}

impl<L> PendingReap<L> {
    fn view(&self) -> PendingReapView {
        PendingReapView {
            pid: self.pid,
            pgid: self.pgid,
            step_kind: self.step_kind,
            incident_seq: self.incident_seq,
            incident_id: self.incident_id.clone(),
            attempt_token: self.attempt_token,
            step_started_at: self.step_started_at,
            hard_deadline: self.hard_deadline,
            retained_at: self.retained_at,
            final_kill: self.final_kill,
            reason: self.reason,
            polls: self.polls,
            last_poll: self.last_poll,
        }
    }
}

/// One §16.7.5 poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingReapPoll {
    Empty,
    Reaped {
        view: PendingReapView,
        status: LeaderStatus,
    },
    NotReaped,
    Interrupted,
    /// `transitioned` is true when the errno differs from the previous poll
    /// result (one WARN per distinct transition, §28).
    Error {
        errno: i32,
        transitioned: bool,
    },
}

/// §16.7.3 invariant violation: the slot was occupied at transfer. The
/// existing leader stays in the slot; the rejected one is handed back, never
/// stored and never silently dropped. The daemon integration maps this to the
/// class-D `DaemonError::ObservationInvariant` (`LoopExit::Fatal`).
#[derive(Debug)]
pub struct PendingReapInvariantViolation<L> {
    pub existing_pid: u32,
    pub rejected: PendingReap<L>,
}

impl<L> PendingReapInvariantViolation<L> {
    /// §16.7.3 fail-closed mapping into the existing class-D path: a runtime
    /// step caller returns this message as its error, which the daemon maps
    /// to `DaemonError::ObservationInvariant` and the loop to
    /// `LoopExit::Fatal`. Only the violation is consumed; the occupied slot
    /// keeps its leader. The rejected handle is released with neither a
    /// signal nor a wait (`Child` has no killing or waiting `Drop`, §16.7.8)
    /// on the way to that fatal exit.
    pub fn into_observation_invariant(self) -> String {
        let Self {
            existing_pid,
            rejected,
        } = self;
        let message = format!(
            "pending_reap invariant violation: transfer into an occupied slot refused (existing pid {existing_pid}; rejected pid {} kind {:?} incident_seq {} attempt_token {})",
            rejected.pid, rejected.step_kind, rejected.incident_seq, rejected.attempt_token,
        );
        drop(rejected);
        message
    }
}

/// One §16.7.8 shutdown poll: whether the slot is empty afterwards, plus the
/// §28 lines to log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShutdownPendingReap {
    pub slot_empty: bool,
    pub log_lines: Vec<String>,
}

/// The bounded-process backend: the driver plus the single pending-reap slot
/// (§16.7.1). Accessed only through `&mut`; not `Clone`.
#[derive(Debug)]
pub struct CommandBackend<D: ProcessDriver = SystemProcessDriver> {
    driver: D,
    pending_reap: Option<PendingReap<D::Leader>>,
}

impl CommandBackend<SystemProcessDriver> {
    pub fn system() -> Self {
        Self::new(SystemProcessDriver)
    }
}

impl<D: ProcessDriver> CommandBackend<D> {
    pub fn new(driver: D) -> Self {
        Self {
            driver,
            pending_reap: None,
        }
    }

    /// Read-only diagnostics (§16.7.8). Offers no mutable control.
    pub fn pending_reap_diagnostics(&self) -> Option<PendingReapView> {
        self.pending_reap.as_ref().map(PendingReap::view)
    }

    /// §16.7.5: if occupied, exactly one non-blocking reap. Never waits,
    /// sleeps, signals, or retries. Only an exit status empties the slot.
    pub fn poll_pending_reap(&mut self) -> PendingReapPoll {
        let Some(pending) = self.pending_reap.as_mut() else {
            return PendingReapPoll::Empty;
        };
        pending.polls = pending.polls.saturating_add(1);
        match self.driver.try_reap(&mut pending.child) {
            ReapResult::Exited(status) => match self.pending_reap.take() {
                Some(reaped) => PendingReapPoll::Reaped {
                    view: reaped.view(),
                    status,
                },
                None => PendingReapPoll::Empty,
            },
            ReapResult::NotExited => {
                pending.last_poll = LastPoll::NotReaped;
                PendingReapPoll::NotReaped
            }
            ReapResult::Interrupted => {
                pending.last_poll = LastPoll::Interrupted;
                PendingReapPoll::Interrupted
            }
            ReapResult::Error(errno) => {
                let transitioned = pending.last_poll != LastPoll::Error(errno);
                pending.last_poll = LastPoll::Error(errno);
                PendingReapPoll::Error {
                    errno,
                    transitioned,
                }
            }
        }
    }

    /// The §16.7.5 ordinary foreground poll: exactly one `poll_pending_reap`,
    /// returning the §28 line to log, if any. The runtime owner calls it as
    /// the first Stage 14 operation of every ordinary iteration. It samples
    /// no clock unless a line is produced (the age is diagnostic only).
    pub fn foreground_pending_reap(&mut self) -> Option<String> {
        let poll = self.poll_pending_reap();
        self.poll_log_line(&poll)
    }

    /// The §16.7.8 shutdown poll: exactly one `poll_pending_reap`, then
    /// whether the slot is empty. An occupied slot is never clean; its WARN
    /// names `pending_reap_occupied` and the retained leader's provenance.
    pub fn shutdown_pending_reap(&mut self) -> ShutdownPendingReap {
        let poll = self.poll_pending_reap();
        let mut log_lines: Vec<String> = self.poll_log_line(&poll).into_iter().collect();
        let retained = self.pending_reap_diagnostics();
        if let Some(view) = &retained {
            log_lines.push(format!(
                "WARN shutdown requires cleanup: pending_reap_occupied; the retained fencing leader is not reaped, so shutdown cannot be clean ({})",
                view.log_fields(true, self.driver.now())
            ));
        }
        ShutdownPendingReap {
            slot_empty: retained.is_none(),
            log_lines,
        }
    }

    /// §28: INFO when a poll clears the slot and WARN on each distinct errno
    /// transition. Not-yet-exited, EINTR and repeated errors are per-iteration
    /// DEBUG events and are not logged.
    fn poll_log_line(&self, poll: &PendingReapPoll) -> Option<String> {
        match poll {
            PendingReapPoll::Reaped { view, status } => Some(format!(
                "INFO pending_reap cleared: leader reaped with {status:?} ({})",
                view.log_fields(false, self.driver.now())
            )),
            PendingReapPoll::Error {
                errno,
                transitioned: true,
            } => self.pending_reap_diagnostics().map(|view| {
                format!(
                    "WARN pending_reap poll error errno {errno}; the slot stays occupied ({})",
                    view.log_fields(true, self.driver.now())
                )
            }),
            _ => None,
        }
    }

    /// §16.7.8 / §28 lines for one finished step, for the step caller to log:
    /// the gate's own pending-reap poll line, a refusal while the slot is
    /// occupied, and the transfer of an unreapable leader into the slot.
    pub fn step_log_lines(&self, report: &StepReport) -> Vec<String> {
        let mut lines: Vec<String> = self.poll_log_line(&report.gate_poll).into_iter().collect();
        let retained = self.pending_reap_diagnostics();
        if report.spawn_failure == Some(SpawnFailure::PendingReapOccupied)
            && let Some(view) = &retained
        {
            lines.push(format!(
                "WARN fencing step refused: pending_reap_occupied; no process was spawned ({})",
                view.log_fields(true, self.driver.now())
            ));
        }
        if report.retained
            && let Some(view) = &retained
        {
            lines.push(format!(
                "WARN fencing step leader not reapable by its return deadline; retained in the pending-reap slot ({})",
                view.log_fields(true, self.driver.now())
            ));
        }
        lines
    }

    /// One bounded action or verify step (§16.6). Returns by
    /// `return_deadline`; `Err` only for the §16.7.3 invariant violation.
    pub fn run_step(
        &mut self,
        request: &StepRequest<'_>,
    ) -> Result<StepReport, PendingReapInvariantViolation<D::Leader>> {
        let kind = request.timeout.kind();
        // §16.7.4 spawn gate: one poll, then no spawn while occupied. No
        // deadline is computed and nothing waits.
        let gate_poll = self.poll_pending_reap();
        if self.pending_reap.is_some() {
            let now = self.driver.now();
            return Ok(StepReport::no_child(
                kind,
                gate_poll,
                SpawnFailure::PendingReapOccupied,
                now,
            ));
        }
        // §16.6.1: sampled immediately before the pre-spawn trust check.
        let step_started_at = self.driver.now();
        let Some(deadlines) =
            StepDeadlines::compute_for(kind, step_started_at, request.timeout.duration())
        else {
            return Ok(StepReport::no_child(
                kind,
                gate_poll,
                SpawnFailure::DeadlineOverflow,
                step_started_at,
            ));
        };
        let trust = match request.argv.first() {
            Some(executable) => self.driver.check_trust(executable),
            None => Err(TrustRefusal::EmptyArgv),
        };
        if let Err(refusal) = trust {
            let now = self.driver.now();
            return Ok(StepReport::no_child(
                kind,
                gate_poll,
                SpawnFailure::Trust(refusal),
                now,
            ));
        }
        let mut leader = match self.driver.spawn(&SpawnPlan::new(request)) {
            Ok(leader) => leader,
            Err(errno) => {
                let now = self.driver.now();
                return Ok(StepReport::no_child(
                    kind,
                    gate_poll,
                    SpawnFailure::Spawn(errno),
                    now,
                ));
            }
        };
        let mut observation = Observation::default();
        for stream in [Stream::Stdout, Stream::Stderr] {
            if let Err(errno) = self.driver.set_nonblocking(&mut leader, stream) {
                observation.stream_mut(stream).error = Some(errno);
                observation.reasons.push(StepReason::ReaderError);
            }
        }
        observation.execute(&mut self.driver, &mut leader, &deadlines);
        self.finalize(leader, request, gate_poll, deadlines, observation)
    }

    /// Finalization (§16.6.3, §16.6.6): non-blocking only, each operation at
    /// most once, in order.
    fn finalize(
        &mut self,
        mut leader: D::Leader,
        request: &StepRequest<'_>,
        gate_poll: PendingReapPoll,
        deadlines: StepDeadlines,
        mut observation: Observation,
    ) -> Result<StepReport, PendingReapInvariantViolation<D::Leader>> {
        let pid = self.driver.leader_pid(&leader);
        let finalization_at = self.driver.now();
        // (1) Final group SIGKILL in every outcome, while the leader is still
        // unreaped (pgid-reuse safety, §16.6.4).
        let final_kill = match self.driver.signal_group(pid, GroupSignal::Kill) {
            Ok(()) => FinalKill::Sent,
            Err(_) => {
                observation.group_state_unknown = true;
                FinalKill::GroupStateUnknown
            }
        };
        // (2) Forced closure of both read ends.
        self.driver.close_read_end(&mut leader, Stream::Stdout);
        self.driver.close_read_end(&mut leader, Stream::Stderr);
        // (3) Non-blocking reap unless the return deadline has been reached;
        // otherwise transfer into the pending-reap slot.
        let reap = if self.driver.now() >= deadlines.return_deadline {
            None
        } else {
            Some(self.driver.try_reap(&mut leader))
        };
        let leader_status = match reap {
            Some(ReapResult::Exited(status)) => Some(status),
            _ => None,
        };
        let mut retained = false;
        if leader_status.is_none() {
            let reason = if reap.is_none() {
                RetentionReason::ReturnDeadlineReached
            } else {
                RetentionReason::ReapFailed
            };
            let retained_at = self.driver.now();
            self.transfer(PendingReap {
                child: leader,
                pid,
                pgid: pid,
                step_kind: request.timeout.kind(),
                incident_seq: request.identity.incident_seq,
                incident_id: request.identity.incident_id.clone(),
                attempt_token: request.identity.attempt_token,
                step_started_at: deadlines.step_started_at,
                hard_deadline: deadlines.hard_deadline,
                retained_at,
                final_kill,
                reason,
                polls: 0,
                last_poll: LastPoll::None,
            })?;
            retained = true;
            observation.reasons.push(match reason {
                RetentionReason::ReapFailed => StepReason::ReapFailed,
                RetentionReason::ReturnDeadlineReached => StepReason::ReturnDeadlineReached,
            });
        }
        // (4) Deterministic classification.
        if observation.group_state_unknown {
            observation.reasons.push(StepReason::GroupStateUnknown);
        }
        let (outcome, success_eligible) = classify(
            request.timeout.kind(),
            &observation,
            &deadlines,
            leader_status,
        );
        Ok(StepReport {
            kind: request.timeout.kind(),
            gate_poll,
            outcome,
            success_eligible,
            spawn_failure: None,
            deadlines: Some(deadlines),
            timeline: Some(StepTimeline {
                term_signal_at: observation.term_signal_at,
                kill_signal_at: observation.kill_signal_at,
                leader_exit_observed_at: observation.leader_exit_observed_at,
                resolved_at: observation.resolved_at,
                last_wait_end: observation.last_wait_end,
                finalization_at,
            }),
            pid: Some(pid),
            leader_status,
            final_kill: Some(final_kill),
            retained,
            reasons: observation.reasons,
            stdout: observation.captured,
            stdout_overflow: observation.overflow,
            stdout_bytes: observation.stdout.bytes,
            stderr_bytes: observation.stderr.bytes,
            returned_at: self.driver.now(),
        })
    }

    /// §16.7.3 transfer: the only writer of the slot. Requires an empty slot;
    /// an occupied slot is kept and the new leader is handed back.
    fn transfer(
        &mut self,
        pending: PendingReap<D::Leader>,
    ) -> Result<(), PendingReapInvariantViolation<D::Leader>> {
        if let Some(existing) = &self.pending_reap {
            return Err(PendingReapInvariantViolation {
                existing_pid: existing.pid,
                rejected: pending,
            });
        }
        self.pending_reap = Some(pending);
        Ok(())
    }
}

#[derive(Debug, Default)]
struct StreamState {
    eof: bool,
    error: Option<i32>,
    bytes: u64,
}

#[derive(Debug, Default)]
struct Observation {
    stdout: StreamState,
    stderr: StreamState,
    captured: Vec<u8>,
    overflow: bool,
    leader_exited: bool,
    exit_query_error: Option<i32>,
    group_state_unknown: bool,
    term_signal_at: Option<Instant>,
    kill_signal_at: Option<Instant>,
    leader_exit_observed_at: Option<Instant>,
    resolved_at: Option<Instant>,
    last_wait_end: Option<Instant>,
    reasons: Vec<StepReason>,
}

impl Observation {
    fn stream_mut(&mut self, stream: Stream) -> &mut StreamState {
        match stream {
            Stream::Stdout => &mut self.stdout,
            Stream::Stderr => &mut self.stderr,
        }
    }

    fn read_error(&self) -> bool {
        self.stdout.error.is_some() || self.stderr.error.is_some()
    }

    fn resolved(&self) -> bool {
        self.leader_exited && self.stdout.eof && self.stderr.eof
    }

    /// Execution, TERM, and KILL phases (§16.6.3). Returns at resolution or
    /// at `hard_deadline`; no deadline is recomputed and no requested wait
    /// ends after `hard_deadline`.
    ///
    /// The absolute deadlines dominate the phase state: each clock sample
    /// first checks `hard_deadline` (after which only Finalization runs,
    /// §16.6.6), then selects the phase that contains `now`. A late wake
    /// never replays an escalation whose phase has already passed: a wake at
    /// or after `hard_deadline` sends no TERM/KILL here, and a wake inside
    /// the KILL phase sends only the KILL.
    fn execute<D: ProcessDriver>(
        &mut self,
        driver: &mut D,
        leader: &mut D::Leader,
        deadlines: &StepDeadlines,
    ) {
        let pgid = driver.leader_pid(leader);
        let mut phase = StepPhase::Execution;
        loop {
            let now = driver.now();
            if now >= deadlines.hard_deadline {
                if phase == StepPhase::Execution && self.leader_exited {
                    self.reasons.push(StepReason::LeaderExitPipeHeld);
                }
                self.reasons.push(StepReason::ReaderDeadline);
                if !self.leader_exited {
                    self.reasons.push(StepReason::DescendantCleanupTimeout);
                } else if !self.group_state_unknown {
                    self.reasons.push(StepReason::EscapedHolder);
                }
                return;
            }
            let current = if now >= deadlines.term_deadline {
                StepPhase::Kill
            } else if now >= deadlines.execution_deadline {
                StepPhase::Term
            } else {
                StepPhase::Execution
            };
            if current > phase {
                if phase == StepPhase::Execution && self.leader_exited {
                    self.reasons.push(StepReason::LeaderExitPipeHeld);
                }
                phase = current;
                let signal = if phase == StepPhase::Term {
                    self.term_signal_at = Some(now);
                    GroupSignal::Term
                } else {
                    self.kill_signal_at = Some(now);
                    GroupSignal::Kill
                };
                if driver.signal_group(pgid, signal).is_err() {
                    self.group_state_unknown = true;
                }
            }
            self.drain(driver, leader, Stream::Stdout, deadlines.hard_deadline);
            self.drain(driver, leader, Stream::Stderr, deadlines.hard_deadline);
            if !self.leader_exited && driver.now() < deadlines.hard_deadline {
                match driver.leader_exited(leader) {
                    Ok(true) => {
                        self.leader_exited = true;
                        self.leader_exit_observed_at = Some(driver.now());
                    }
                    Ok(false) => {}
                    Err(errno) => self.exit_query_error = Some(errno),
                }
            }
            if self.resolved() {
                self.resolved_at = Some(driver.now());
                return;
            }
            let phase_deadline = match phase {
                StepPhase::Execution => deadlines.execution_deadline,
                StepPhase::Term => deadlines.term_deadline,
                StepPhase::Kill => deadlines.hard_deadline,
            };
            let now = driver.now();
            if now < phase_deadline {
                let wait = POLL_SLICE.min(phase_deadline - now);
                self.last_wait_end = Some(now + wait);
                driver.sleep(wait);
            }
        }
    }

    /// Bounded non-blocking draining of one stream. The capture limit is not
    /// a drain deadline: past 4 KiB, stdout is drained and discarded.
    fn drain<D: ProcessDriver>(
        &mut self,
        driver: &mut D,
        leader: &mut D::Leader,
        stream: Stream,
        hard_deadline: Instant,
    ) {
        let mut buffer = [0_u8; READ_CHUNK];
        for _ in 0..MAX_READS_PER_PASS {
            let state = self.stream_mut(stream);
            if state.eof || state.error.is_some() || driver.now() >= hard_deadline {
                return;
            }
            match driver.read(leader, stream, &mut buffer) {
                ReadResult::Data(count) => {
                    let count = count.min(buffer.len());
                    self.stream_mut(stream).bytes += count as u64;
                    if stream == Stream::Stdout {
                        let room = STDOUT_CAPTURE_LIMIT - self.captured.len();
                        self.captured.extend_from_slice(&buffer[..count.min(room)]);
                        if count > room {
                            self.overflow = true;
                        }
                    }
                }
                ReadResult::Retry => return,
                ReadResult::Eof => {
                    self.stream_mut(stream).eof = true;
                    return;
                }
                ReadResult::Error(errno) => {
                    self.stream_mut(stream).error = Some(errno);
                    self.reasons.push(StepReason::ReaderError);
                    return;
                }
            }
        }
    }
}

/// Deterministic classification (§16.4, §16.6.5, §17.1). Success-eligible iff
/// resolved before `execution_deadline`, the group state is known, the
/// leader was reaped with a status, and no read or exit-query error occurred.
fn classify(
    kind: StepKind,
    observation: &Observation,
    deadlines: &StepDeadlines,
    leader_status: Option<LeaderStatus>,
) -> (StepOutcome, bool) {
    let integrity_fault = observation.group_state_unknown
        || observation.read_error()
        || observation.exit_query_error.is_some()
        || leader_status.is_none();
    let resolved_before =
        |deadline: Instant| observation.resolved_at.is_some_and(|at| at < deadline);
    let success_status =
        leader_status.filter(|_| !integrity_fault && resolved_before(deadlines.execution_deadline));
    let outcome = match (kind, success_status) {
        (StepKind::Action, Some(LeaderStatus::Code(0))) => {
            StepOutcome::Action(ActionOutcome::ReportedSuccess)
        }
        (StepKind::Action, Some(LeaderStatus::Code(_))) => {
            StepOutcome::Action(ActionOutcome::ReportedFailure)
        }
        (StepKind::Action, Some(LeaderStatus::Signal(_))) => {
            StepOutcome::Action(ActionOutcome::Signal)
        }
        (StepKind::Action, None) => StepOutcome::Action(ActionOutcome::TimedOut),
        (StepKind::Verify, Some(status)) => StepOutcome::Verify(classify_verify(
            status,
            &observation.captured,
            observation.overflow,
        )),
        (StepKind::Verify, None) => {
            let kind = if !integrity_fault && resolved_before(deadlines.hard_deadline) {
                InconclusiveKind::Timeout
            } else {
                InconclusiveKind::Integrity
            };
            StepOutcome::Verify(VerifyOutcome::Inconclusive(kind))
        }
        (StepKind::Route, Some(LeaderStatus::Code(0))) if observation.overflow => {
            StepOutcome::Route(RouteOutcome::Inconclusive(InconclusiveKind::OutputOverflow))
        }
        (StepKind::Route, Some(LeaderStatus::Code(0))) => {
            StepOutcome::Route(RouteOutcome::Output(observation.captured.clone()))
        }
        (StepKind::Route, Some(LeaderStatus::Code(code))) => {
            StepOutcome::Route(RouteOutcome::NonzeroExit(code))
        }
        (StepKind::Route, Some(LeaderStatus::Signal(_))) => {
            StepOutcome::Route(RouteOutcome::Inconclusive(InconclusiveKind::Signal))
        }
        (StepKind::Route, None) => {
            let kind = if !integrity_fault && resolved_before(deadlines.hard_deadline) {
                InconclusiveKind::Timeout
            } else {
                InconclusiveKind::Integrity
            };
            StepOutcome::Route(RouteOutcome::Inconclusive(kind))
        }
    };
    (outcome, success_status.is_some())
}

/// The exact §17.1 grammar, applied only to a success-eligible step's
/// EOF-complete stdout.
fn classify_verify(status: LeaderStatus, stdout: &[u8], overflow: bool) -> VerifyOutcome {
    match status {
        LeaderStatus::Signal(_) => VerifyOutcome::Inconclusive(InconclusiveKind::Signal),
        LeaderStatus::Code(code) if code != 0 => {
            VerifyOutcome::Inconclusive(InconclusiveKind::NonzeroExit)
        }
        LeaderStatus::Code(_) if overflow => {
            VerifyOutcome::Inconclusive(InconclusiveKind::OutputOverflow)
        }
        LeaderStatus::Code(_) => match stdout {
            b"isolated" | b"isolated\n" => VerifyOutcome::Isolated,
            b"not-isolated" | b"not-isolated\n" => VerifyOutcome::NotIsolated,
            _ => VerifyOutcome::Inconclusive(InconclusiveKind::MalformedOutput),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::{HashSet, VecDeque};
    use std::path::PathBuf;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;

    // ---------------------------------------------------------------------
    // Fake process driver with a controllable clock (§34.21 FR01-08,
    // §34.22 driver).
    // ---------------------------------------------------------------------

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Op {
        Trust,
        Spawn(u32),
        Sleep {
            at: Instant,
            end: Instant,
        },
        Read {
            stream: Stream,
            at: Instant,
        },
        ExitQuery {
            at: Instant,
        },
        Signal {
            pgid: u32,
            signal: GroupSignal,
            at: Instant,
        },
        Close {
            stream: Stream,
            at: Instant,
        },
        Reap {
            pid: u32,
            at: Instant,
        },
    }

    impl Op {
        fn at(&self) -> Option<Instant> {
            match *self {
                Op::Trust | Op::Spawn(_) => None,
                Op::Sleep { at, .. }
                | Op::Read { at, .. }
                | Op::ExitQuery { at }
                | Op::Signal { at, .. }
                | Op::Close { at, .. }
                | Op::Reap { at, .. } => Some(at),
            }
        }
    }

    type DropLog = Rc<RefCell<Vec<(u32, bool)>>>;

    /// A fake leader handle. Dropping it while unreaped is recorded so tests
    /// can prove a retained handle is never dropped (§34.22).
    #[derive(Debug)]
    struct FakeLeader {
        pid: u32,
        reaped: bool,
        drops: DropLog,
    }

    impl Drop for FakeLeader {
        fn drop(&mut self) {
            self.drops.borrow_mut().push((self.pid, self.reaped));
        }
    }

    #[derive(Debug, Clone)]
    struct Script {
        trust: Result<(), TrustRefusal>,
        spawn_error: Option<i32>,
        leader_exit_after: Option<Duration>,
        stdout_eof_after: Option<Duration>,
        stderr_eof_after: Option<Duration>,
        stdout: Vec<u8>,
        status: LeaderStatus,
        honors_signals: bool,
        unreapable: bool,
        read_error: Option<Stream>,
        signal_cost: Duration,
        close_cost: Duration,
        reap_cost: Duration,
        late_wake: Option<(Instant, Duration)>,
    }

    impl Script {
        /// Leader and both pipes finish after `after`; exit 0.
        fn finishes_after(after: Duration, stdout: &[u8]) -> Self {
            Self {
                trust: Ok(()),
                spawn_error: None,
                leader_exit_after: Some(after),
                stdout_eof_after: Some(after),
                stderr_eof_after: Some(after),
                stdout: stdout.to_vec(),
                status: LeaderStatus::Code(0),
                honors_signals: true,
                unreapable: false,
                read_error: None,
                signal_cost: Duration::ZERO,
                close_cost: Duration::ZERO,
                reap_cost: Duration::ZERO,
                late_wake: None,
            }
        }

        /// A leader in uninterruptible sleep: it never exits, ignores every
        /// signal, holds both pipes, and is unreapable until released.
        fn unreapable() -> Self {
            Self {
                leader_exit_after: None,
                stdout_eof_after: None,
                stderr_eof_after: None,
                honors_signals: false,
                unreapable: true,
                ..Self::finishes_after(Duration::ZERO, b"")
            }
        }
    }

    #[derive(Debug)]
    struct FakeDriver {
        base: Instant,
        now: Instant,
        script: Script,
        ops: Vec<Op>,
        spawns: u32,
        next_pid: u32,
        exit_at: Option<Instant>,
        stdout_eof_at: Option<Instant>,
        stderr_eof_at: Option<Instant>,
        stdout_pending: VecDeque<u8>,
        released: HashSet<u32>,
        reap_script: VecDeque<ReapResult>,
        /// Injected non-reaping exit-query results, consumed first.
        exit_query_script: VecDeque<Result<bool, i32>>,
        /// A persistent exit-query error once the script is empty.
        exit_query_error: Option<i32>,
        environment: Vec<(String, String)>,
        drops: DropLog,
    }

    impl FakeDriver {
        fn new(script: Script) -> Self {
            let base = Instant::now();
            Self {
                base,
                now: base,
                script,
                ops: Vec::new(),
                spawns: 0,
                next_pid: 4000,
                exit_at: None,
                stdout_eof_at: None,
                stderr_eof_at: None,
                stdout_pending: VecDeque::new(),
                released: HashSet::new(),
                reap_script: VecDeque::new(),
                exit_query_script: VecDeque::new(),
                exit_query_error: None,
                environment: Vec::new(),
                drops: Rc::new(RefCell::new(Vec::new())),
            }
        }

        fn advance(&mut self, by: Duration) {
            self.now += by;
        }

        fn unreaped_drops(&self) -> Vec<u32> {
            self.drops
                .borrow()
                .iter()
                .filter(|(_, reaped)| !reaped)
                .map(|(pid, _)| *pid)
                .collect()
        }
    }

    fn reached(at: Option<Instant>, now: Instant) -> bool {
        at.is_some_and(|at| at <= now)
    }

    impl ProcessDriver for FakeDriver {
        type Leader = FakeLeader;

        fn now(&self) -> Instant {
            self.now
        }

        fn sleep(&mut self, duration: Duration) {
            assert!(
                duration > Duration::ZERO && duration <= POLL_SLICE,
                "every sub-wait is bounded by POLL_SLICE: {duration:?}"
            );
            let end = self.now + duration;
            self.ops.push(Op::Sleep { at: self.now, end });
            self.now = match self.script.late_wake {
                Some((target, lateness)) if target == end => end + lateness,
                _ => end,
            };
        }

        fn check_trust(&mut self, _executable: &str) -> Result<(), TrustRefusal> {
            self.ops.push(Op::Trust);
            self.script.trust
        }

        fn spawn(&mut self, plan: &SpawnPlan<'_>) -> Result<FakeLeader, i32> {
            if let Some(errno) = self.script.spawn_error {
                return Err(errno);
            }
            self.spawns += 1;
            let pid = self.next_pid;
            self.next_pid += 1;
            self.ops.push(Op::Spawn(pid));
            self.environment = plan
                .environment
                .iter()
                .map(|(name, value)| (name.to_string(), value.clone()))
                .collect();
            let now = self.now;
            self.exit_at = self.script.leader_exit_after.map(|after| now + after);
            self.stdout_eof_at = self.script.stdout_eof_after.map(|after| now + after);
            self.stderr_eof_at = self.script.stderr_eof_after.map(|after| now + after);
            self.stdout_pending = self.script.stdout.iter().copied().collect();
            Ok(FakeLeader {
                pid,
                reaped: false,
                drops: Rc::clone(&self.drops),
            })
        }

        fn leader_pid(&self, leader: &FakeLeader) -> u32 {
            leader.pid
        }

        fn set_nonblocking(&mut self, _: &mut FakeLeader, _: Stream) -> Result<(), i32> {
            Ok(())
        }

        fn read(&mut self, _: &mut FakeLeader, stream: Stream, buffer: &mut [u8]) -> ReadResult {
            self.ops.push(Op::Read {
                stream,
                at: self.now,
            });
            if self.script.read_error == Some(stream) {
                return ReadResult::Error(5);
            }
            if stream == Stream::Stdout && !self.stdout_pending.is_empty() {
                let count = buffer.len().min(self.stdout_pending.len());
                for slot in buffer.iter_mut().take(count) {
                    *slot = self.stdout_pending.pop_front().unwrap_or(0);
                }
                return ReadResult::Data(count);
            }
            let eof_at = match stream {
                Stream::Stdout => self.stdout_eof_at,
                Stream::Stderr => self.stderr_eof_at,
            };
            if reached(eof_at, self.now) {
                ReadResult::Eof
            } else {
                ReadResult::Retry
            }
        }

        fn leader_exited(&mut self, _: &FakeLeader) -> Result<bool, i32> {
            self.ops.push(Op::ExitQuery { at: self.now });
            if let Some(scripted) = self.exit_query_script.pop_front() {
                return scripted;
            }
            if let Some(errno) = self.exit_query_error {
                return Err(errno);
            }
            Ok(reached(self.exit_at, self.now))
        }

        fn signal_group(&mut self, pgid: u32, signal: GroupSignal) -> Result<(), i32> {
            self.ops.push(Op::Signal {
                pgid,
                signal,
                at: self.now,
            });
            let cost = self.script.signal_cost;
            self.advance(cost);
            if self.script.honors_signals {
                let now = self.now;
                self.exit_at = Some(self.exit_at.map_or(now, |at| at.min(now)));
                self.stdout_eof_at = Some(self.stdout_eof_at.map_or(now, |at| at.min(now)));
                self.stderr_eof_at = Some(self.stderr_eof_at.map_or(now, |at| at.min(now)));
            }
            Ok(())
        }

        fn close_read_end(&mut self, _: &mut FakeLeader, stream: Stream) {
            self.ops.push(Op::Close {
                stream,
                at: self.now,
            });
            let cost = self.script.close_cost;
            self.advance(cost);
        }

        fn try_reap(&mut self, leader: &mut FakeLeader) -> ReapResult {
            self.ops.push(Op::Reap {
                pid: leader.pid,
                at: self.now,
            });
            let cost = self.script.reap_cost;
            self.advance(cost);
            let result = if let Some(scripted) = self.reap_script.pop_front() {
                scripted
            } else if self.released.contains(&leader.pid) {
                ReapResult::Exited(LeaderStatus::Signal(9))
            } else if self.script.unreapable || !reached(self.exit_at, self.now) {
                ReapResult::NotExited
            } else {
                ReapResult::Exited(self.script.status)
            };
            if matches!(result, ReapResult::Exited(_)) {
                leader.reaped = true;
            }
            result
        }
    }

    const INCIDENT_ID: &str = "5f0c6a8e-3c1b-4c55-9a47-2f6f5e1d9b10";

    fn identity() -> StepIdentity {
        StepIdentity {
            incident_seq: 7,
            incident_id: IncidentId::new(INCIDENT_ID),
            attempt_token: 3,
        }
    }

    fn request(argv: &[String], timeout: StepTimeout) -> StepRequest<'_> {
        StepRequest {
            argv,
            timeout,
            identity: identity(),
            cluster: "cluster-a",
            target_node: "node-b",
        }
    }

    fn fake_argv() -> Vec<String> {
        vec![
            "/usr/lib/mikagami/fence".to_string(),
            "--target".to_string(),
        ]
    }

    fn fake(script: Script) -> CommandBackend<FakeDriver> {
        CommandBackend::new(FakeDriver::new(script))
    }

    fn timeout(kind: StepKind, seconds: u64) -> StepTimeout {
        match kind {
            StepKind::Action => StepTimeout::fence(seconds).unwrap(),
            StepKind::Verify => StepTimeout::verify(seconds).unwrap(),
            StepKind::Route => StepTimeout::route(),
        }
    }

    fn not_success(kind: StepKind) -> StepOutcome {
        match kind {
            StepKind::Action => StepOutcome::Action(ActionOutcome::TimedOut),
            StepKind::Verify => {
                StepOutcome::Verify(VerifyOutcome::Inconclusive(InconclusiveKind::Integrity))
            }
            StepKind::Route => {
                StepOutcome::Route(RouteOutcome::Inconclusive(InconclusiveKind::Integrity))
            }
        }
    }

    fn spawn_failed(kind: StepKind) -> StepOutcome {
        match kind {
            StepKind::Action => StepOutcome::Action(ActionOutcome::SpawnFailed),
            StepKind::Verify => {
                StepOutcome::Verify(VerifyOutcome::Inconclusive(InconclusiveKind::SpawnFailed))
            }
            StepKind::Route => {
                StepOutcome::Route(RouteOutcome::Inconclusive(InconclusiveKind::SpawnFailed))
            }
        }
    }

    fn signals(ops: &[Op]) -> Vec<(GroupSignal, Instant)> {
        ops.iter()
            .filter_map(|op| match *op {
                Op::Signal { signal, at, .. } => Some((signal, at)),
                _ => None,
            })
            .collect()
    }

    fn count(ops: &[Op], predicate: impl Fn(&Op) -> bool) -> usize {
        ops.iter().filter(|op| predicate(op)).count()
    }

    /// Common FR01 phase assertions: deadlines equal the step-start values,
    /// no sub-wait ends after its phase deadline or `hard_deadline`, no
    /// drain/exit query/sleep at or after `hard_deadline`, return by
    /// `return_deadline`.
    fn assert_bounded(report: &StepReport, ops: &[Op], start: Instant, step_timeout: Duration) {
        assert_ops_bounded(report, ops, start, step_timeout);
        assert!(report.returned_at <= report.deadlines.unwrap().return_deadline);
    }

    /// `assert_bounded` without the return bound, for a wake that the test
    /// places after `return_deadline` itself (§16.6.7: the step then runs
    /// only the mandatory calls and returns at once).
    fn assert_ops_bounded(report: &StepReport, ops: &[Op], start: Instant, step_timeout: Duration) {
        let deadlines = report.deadlines.expect("spawned step has deadlines");
        assert_eq!(Some(deadlines), StepDeadlines::compute(start, step_timeout));
        for op in ops {
            match *op {
                Op::Sleep { at, end } => {
                    assert!(end <= deadlines.hard_deadline, "wait beyond hard_deadline");
                    for phase_end in [deadlines.execution_deadline, deadlines.term_deadline] {
                        assert!(at >= phase_end || end <= phase_end, "wait crosses a phase");
                    }
                    assert!(at < deadlines.hard_deadline);
                }
                Op::Read { at, .. } | Op::ExitQuery { at } => {
                    assert!(at < deadlines.hard_deadline, "drain after hard_deadline")
                }
                _ => {}
            }
        }
    }

    #[test]
    fn stage14_5_timeout_maxima_are_enforced() {
        assert!(StepTimeout::fence(0).is_err());
        assert_eq!(
            StepTimeout::fence(60).unwrap().duration(),
            Duration::from_secs(60)
        );
        assert_eq!(
            StepTimeout::fence(61),
            Err(TimeoutOutOfRange {
                kind: StepKind::Action,
                seconds: 61,
                maximum: 60
            })
        );
        assert!(StepTimeout::verify(0).is_err());
        assert_eq!(StepTimeout::verify(30).unwrap().kind(), StepKind::Verify);
        assert!(StepTimeout::verify(31).is_err());
    }

    #[test]
    fn stage14_5_deadlines_are_checked_and_computed_once() {
        let start = Instant::now();
        let deadlines = StepDeadlines::compute(start, Duration::from_secs(60)).unwrap();
        assert_eq!(deadlines.hard_deadline - start, Duration::from_secs(64));
        assert_eq!(
            deadlines.return_deadline - start,
            Duration::from_millis(64_500)
        );
        let verify = StepDeadlines::compute(start, Duration::from_secs(30)).unwrap();
        assert_eq!(verify.hard_deadline - start, Duration::from_secs(34));
        assert_eq!(
            verify.return_deadline - start,
            Duration::from_millis(34_500)
        );
        assert_eq!(StepDeadlines::compute(start, Duration::MAX), None);

        // Overflow at step level: no trust check, no spawn, spawn-failed.
        for kind in [StepKind::Action, StepKind::Verify] {
            let mut backend = fake(Script::finishes_after(Duration::ZERO, b""));
            let argv = fake_argv();
            let overflowing = StepTimeout {
                kind,
                duration: Duration::MAX,
            };
            let report = backend.run_step(&request(&argv, overflowing)).unwrap();
            assert_eq!(report.outcome, spawn_failed(kind));
            assert_eq!(report.spawn_failure, Some(SpawnFailure::DeadlineOverflow));
            assert!(backend.driver.ops.is_empty());
            assert_eq!(backend.driver.spawns, 0);
        }
    }

    #[test]
    fn stage14_5_trust_and_spawn_failures_never_spawn() {
        for kind in [StepKind::Action, StepKind::Verify] {
            let mut script = Script::finishes_after(Duration::ZERO, b"");
            script.trust = Err(TrustRefusal::NotRootOwned);
            let mut backend = fake(script);
            let argv = fake_argv();
            let report = backend.run_step(&request(&argv, timeout(kind, 5))).unwrap();
            assert_eq!(report.outcome, spawn_failed(kind));
            assert_eq!(
                report.spawn_failure,
                Some(SpawnFailure::Trust(TrustRefusal::NotRootOwned))
            );
            assert_eq!(backend.driver.ops, vec![Op::Trust]);
            assert_eq!(backend.driver.spawns, 0);

            let mut backend = fake(Script::finishes_after(Duration::ZERO, b""));
            let report = backend.run_step(&request(&[], timeout(kind, 5))).unwrap();
            assert_eq!(
                report.spawn_failure,
                Some(SpawnFailure::Trust(TrustRefusal::EmptyArgv))
            );
            assert!(backend.driver.ops.is_empty());

            let mut script = Script::finishes_after(Duration::ZERO, b"");
            script.spawn_error = Some(2);
            let mut backend = fake(script);
            let report = backend.run_step(&request(&argv, timeout(kind, 5))).unwrap();
            assert_eq!(report.outcome, spawn_failed(kind));
            assert_eq!(report.spawn_failure, Some(SpawnFailure::Spawn(2)));
            assert!(report.pid.is_none());
        }
    }

    #[test]
    fn stage14_5_spawn_plan_is_the_exact_environment_allowlist() {
        let mut backend = fake(Script::finishes_after(Duration::ZERO, b""));
        let argv = fake_argv();
        backend
            .run_step(&request(&argv, timeout(StepKind::Action, 5)))
            .unwrap();
        let expected: Vec<(String, String)> = [
            ("PATH", FENCE_PATH),
            ("LANG", "C"),
            ("MIKAGAMI_CLUSTER", "cluster-a"),
            ("MIKAGAMI_FENCE_TARGET", "node-b"),
            ("MIKAGAMI_FENCE_INCIDENT", INCIDENT_ID),
            ("MIKAGAMI_FENCE_ATTEMPT", "3"),
        ]
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
        assert_eq!(backend.driver.environment, expected);
    }

    #[test]
    fn stage14_5_resolved_step_is_success_eligible_and_still_group_killed() {
        for (kind, expected) in [
            (
                StepKind::Action,
                StepOutcome::Action(ActionOutcome::ReportedSuccess),
            ),
            (
                StepKind::Verify,
                StepOutcome::Verify(VerifyOutcome::Isolated),
            ),
        ] {
            let mut backend = fake(Script::finishes_after(
                Duration::from_secs(1),
                b"isolated\n",
            ));
            let start = backend.driver.base;
            let argv = fake_argv();
            let report = backend.run_step(&request(&argv, timeout(kind, 5))).unwrap();
            assert_eq!(report.outcome, expected);
            assert!(report.success_eligible);
            assert_eq!(report.gate_poll, PendingReapPoll::Empty);
            assert_eq!(report.final_kill, Some(FinalKill::Sent));
            let ops = &backend.driver.ops;
            assert_bounded(&report, ops, start, Duration::from_secs(5));
            // Only the Finalization SIGKILL, and it precedes the reap.
            assert_eq!(signals(ops).len(), 1);
            let kill = ops.iter().position(|op| matches!(op, Op::Signal { .. }));
            let reap = ops.iter().position(|op| matches!(op, Op::Reap { .. }));
            assert!(kill < reap);
            assert!(!report.retained);
            assert!(backend.pending_reap_diagnostics().is_none());
        }
    }

    /// FR01-08: the leader exits at `execution_deadline - 1 s` while a pipe is
    /// held; deadlines never move; TERM/KILL/Finalization at exactly the
    /// step-start instants; no sub-wait beyond `hard_deadline`.
    /// v0.7 G-2 (contract R4.1 §5.1): the route step's own deadline set returns within 3.0 s
    /// even when the helper ignores TERM and holds its pipes, and the fencing kinds keep their
    /// §16.6.1 graces.
    #[test]
    fn g2_route_step_deadlines_return_within_the_budget() {
        let start = Instant::now();
        let route = StepDeadlines::compute_for(StepKind::Route, start, ROUTE_EXECUTION).unwrap();
        assert_eq!(
            route.execution_deadline - start,
            Duration::from_millis(2_000)
        );
        assert_eq!(route.term_deadline - start, Duration::from_millis(2_250));
        assert_eq!(route.hard_deadline - start, Duration::from_millis(2_750));
        assert_eq!(route.return_deadline - start, ROUTE_STEP_RETURN_BUDGET);
        for kind in [StepKind::Action, StepKind::Verify] {
            assert_eq!(
                StepDeadlines::compute_for(kind, start, Duration::from_secs(1)),
                StepDeadlines::compute(start, Duration::from_secs(1))
            );
        }
        let mut script = Script::finishes_after(Duration::from_secs(9), b"own all\n");
        script.stdout_eof_after = None;
        script.honors_signals = false;
        let mut backend = fake(script);
        let begin = backend.driver.base;
        let argv = fake_argv();
        let report = backend
            .run_step(&request(&argv, StepTimeout::route()))
            .unwrap();
        assert!(report.returned_at - begin <= ROUTE_STEP_RETURN_BUDGET);
        assert_eq!(
            report.outcome,
            StepOutcome::Route(RouteOutcome::Inconclusive(InconclusiveKind::Integrity))
        );
        assert!(!report.success_eligible);
    }

    #[test]
    fn g2_route_step_classification() {
        let argv = fake_argv();
        let mut backend = fake(Script::finishes_after(
            Duration::from_millis(100),
            b"op done-ok\n",
        ));
        let report = backend
            .run_step(&request(&argv, StepTimeout::route()))
            .unwrap();
        assert_eq!(
            report.outcome,
            StepOutcome::Route(RouteOutcome::Output(b"op done-ok\n".to_vec()))
        );
        let mut script = Script::finishes_after(Duration::from_millis(100), b"");
        script.status = LeaderStatus::Code(2);
        let mut backend = fake(script);
        let report = backend
            .run_step(&request(&argv, StepTimeout::route()))
            .unwrap();
        assert_eq!(
            report.outcome,
            StepOutcome::Route(RouteOutcome::NonzeroExit(2))
        );
        let mut script = Script::finishes_after(Duration::from_millis(100), b"");
        script.status = LeaderStatus::Signal(9);
        let mut backend = fake(script);
        let report = backend
            .run_step(&request(&argv, StepTimeout::route()))
            .unwrap();
        assert_eq!(
            report.outcome,
            StepOutcome::Route(RouteOutcome::Inconclusive(InconclusiveKind::Signal))
        );
        let big = vec![b'x'; STDOUT_CAPTURE_LIMIT + 1];
        let mut backend = fake(Script::finishes_after(Duration::from_millis(100), &big));
        let report = backend
            .run_step(&request(&argv, StepTimeout::route()))
            .unwrap();
        assert_eq!(
            report.outcome,
            StepOutcome::Route(RouteOutcome::Inconclusive(InconclusiveKind::OutputOverflow))
        );
        // A route step past the execution deadline is never an answer.
        let mut late = Script::finishes_after(Duration::from_millis(2_100), b"own all\n");
        late.honors_signals = false;
        let mut backend = fake(late);
        let report = backend
            .run_step(&request(&argv, StepTimeout::route()))
            .unwrap();
        assert!(!matches!(
            report.outcome,
            StepOutcome::Route(RouteOutcome::Output(_))
        ));
    }

    #[test]
    fn g2_route_step_shares_the_pending_reap_gate() {
        let argv = fake_argv();
        let mut backend = fake(Script::unreapable());
        let _ = backend
            .run_step(&request(&argv, timeout(StepKind::Verify, 1)))
            .unwrap();
        assert!(backend.pending_reap_diagnostics().is_some());
        backend.driver.script = Script::finishes_after(Duration::ZERO, b"own all\n");
        let spawned_before = backend.driver.ops.len();
        let report = backend
            .run_step(&request(&argv, StepTimeout::route()))
            .unwrap();
        assert_eq!(
            report.spawn_failure,
            Some(SpawnFailure::PendingReapOccupied)
        );
        assert_eq!(
            report.outcome,
            StepOutcome::Route(RouteOutcome::Inconclusive(InconclusiveKind::SpawnFailed))
        );
        assert!(
            backend.driver.ops[spawned_before..]
                .iter()
                .all(|op| !matches!(op, Op::Spawn(_)))
        );
    }

    #[test]
    fn stage14_5_fr01_08_fixed_deadlines_and_phase_instants() {
        for kind in [StepKind::Action, StepKind::Verify] {
            let mut script = Script::finishes_after(Duration::from_secs(9), b"isolated\n");
            script.stdout_eof_after = None;
            script.stderr_eof_after = Some(Duration::ZERO);
            script.honors_signals = false;
            let mut backend = fake(script);
            let start = backend.driver.base;
            let argv = fake_argv();
            let report = backend
                .run_step(&request(&argv, timeout(kind, 10)))
                .unwrap();
            let deadlines = report.deadlines.unwrap();
            let ops = backend.driver.ops.clone();
            assert_bounded(&report, &ops, start, Duration::from_secs(10));
            assert_eq!(
                signals(&ops),
                vec![
                    (GroupSignal::Term, deadlines.execution_deadline),
                    (GroupSignal::Kill, deadlines.term_deadline),
                    (GroupSignal::Kill, deadlines.hard_deadline),
                ]
            );
            let timeline = report.timeline.unwrap();
            assert_eq!(timeline.term_signal_at, Some(deadlines.execution_deadline));
            assert_eq!(timeline.kill_signal_at, Some(deadlines.term_deadline));
            assert_eq!(timeline.finalization_at, deadlines.hard_deadline);
            assert_eq!(timeline.last_wait_end, Some(deadlines.hard_deadline));
            assert_eq!(
                timeline.leader_exit_observed_at,
                Some(deadlines.execution_deadline - Duration::from_secs(1))
            );
            assert_eq!(timeline.resolved_at, None);
            assert_eq!(report.outcome, not_success(kind));
            assert!(!report.success_eligible);
            for reason in [
                StepReason::LeaderExitPipeHeld,
                StepReason::ReaderDeadline,
                StepReason::EscapedHolder,
            ] {
                assert!(report.reasons.contains(&reason), "{reason:?}");
            }
            // The exited leader was reaped in Finalization, not retained.
            assert_eq!(report.leader_status, Some(LeaderStatus::Code(0)));
            assert!(!report.retained);
        }
    }

    /// FR01-01 shape at the maximum timeouts (60/30 s) on the fake clock: the
    /// leader exits 0 immediately with `isolated`; a descendant holds stdout,
    /// stderr, or both until the group TERM (MF-50: each stream is bounded
    /// identically).
    #[test]
    fn stage14_5_fr01_01_fake_clock_at_maximum_timeouts() {
        for (kind, seconds, expected) in [
            (
                StepKind::Action,
                60,
                StepOutcome::Action(ActionOutcome::TimedOut),
            ),
            (
                StepKind::Verify,
                30,
                StepOutcome::Verify(VerifyOutcome::Inconclusive(InconclusiveKind::Timeout)),
            ),
        ] {
            for (stdout_held, stderr_held) in [(true, false), (false, true), (true, true)] {
                let mut script = Script::finishes_after(Duration::ZERO, b"isolated\n");
                if stdout_held {
                    script.stdout_eof_after = None;
                }
                if stderr_held {
                    script.stderr_eof_after = None;
                }
                let mut backend = fake(script);
                let start = backend.driver.base;
                let argv = fake_argv();
                let report = backend
                    .run_step(&request(&argv, timeout(kind, seconds)))
                    .unwrap();
                let deadlines = report.deadlines.unwrap();
                assert_bounded(
                    &report,
                    &backend.driver.ops,
                    start,
                    Duration::from_secs(seconds),
                );
                assert_eq!(
                    deadlines.hard_deadline - start,
                    Duration::from_secs(seconds + 4)
                );
                assert_eq!(
                    deadlines.return_deadline - start,
                    Duration::from_millis(seconds * 1000 + 4500)
                );
                assert!(report.returned_at >= deadlines.execution_deadline);
                assert_eq!(report.outcome, expected);
                assert!(!report.success_eligible);
                assert!(report.reasons.contains(&StepReason::LeaderExitPipeHeld));
            }
        }
    }

    /// FR01-10 (a): the final sub-wait wakes at `hard_deadline + 300 ms`;
    /// each Finalization operation costs 10 ms; the reap is attempted, fails,
    /// and the leader is retained; return at `hard_deadline + 340 ms`.
    #[test]
    fn stage14_5_fr01_10a_late_wake_inside_the_allowance() {
        for kind in [StepKind::Action, StepKind::Verify] {
            let mut backend = fake(Script::unreapable());
            let start = backend.driver.base;
            let hard = start + Duration::from_secs(6);
            backend.driver.script.late_wake = Some((hard, Duration::from_millis(300)));
            backend.driver.script.signal_cost = Duration::from_millis(10);
            backend.driver.script.close_cost = Duration::from_millis(10);
            backend.driver.script.reap_cost = Duration::from_millis(10);
            let argv = fake_argv();
            let report = backend.run_step(&request(&argv, timeout(kind, 2))).unwrap();
            let deadlines = report.deadlines.unwrap();
            assert_eq!(deadlines.hard_deadline, hard);
            let ops = backend.driver.ops.clone();
            assert_bounded(&report, &ops, start, Duration::from_secs(2));
            let after: Vec<Op> = ops
                .iter()
                .copied()
                .filter(|op| op.at().is_some_and(|at| at >= hard))
                .collect();
            let ms = |value: u64| hard + Duration::from_millis(value);
            let pid = report.pid.unwrap();
            assert_eq!(
                after,
                vec![
                    Op::Signal {
                        pgid: pid,
                        signal: GroupSignal::Kill,
                        at: ms(300)
                    },
                    Op::Close {
                        stream: Stream::Stdout,
                        at: ms(310)
                    },
                    Op::Close {
                        stream: Stream::Stderr,
                        at: ms(320)
                    },
                    Op::Reap { pid, at: ms(330) },
                ]
            );
            assert_eq!(report.returned_at, ms(340));
            assert!(report.returned_at <= deadlines.return_deadline);
            assert_eq!(report.outcome, not_success(kind));
            assert!(report.retained);
            let view = backend.pending_reap_diagnostics().unwrap();
            assert_eq!(view.reason, RetentionReason::ReapFailed);
            assert_eq!(view.retained_at, ms(340));
            assert!(report.reasons.contains(&StepReason::ReapFailed));
        }
    }

    /// FR01-10 (b): the wake is at exactly `return_deadline`; `killpg` and
    /// both `close` run; the reap is skipped; return at exactly
    /// `return_deadline`.
    #[test]
    fn stage14_5_fr01_10b_wake_at_return_deadline_skips_the_reap() {
        for kind in [StepKind::Action, StepKind::Verify] {
            let mut backend = fake(Script::unreapable());
            let start = backend.driver.base;
            let hard = start + Duration::from_secs(6);
            backend.driver.script.late_wake = Some((hard, FINALIZATION_RETURN_ALLOWANCE));
            backend.driver.script.reap_cost = Duration::from_millis(100);
            let argv = fake_argv();
            let report = backend.run_step(&request(&argv, timeout(kind, 2))).unwrap();
            let deadlines = report.deadlines.unwrap();
            let ops = backend.driver.ops.clone();
            assert_bounded(&report, &ops, start, Duration::from_secs(2));
            let pid = report.pid.unwrap();
            let after: Vec<Op> = ops
                .iter()
                .copied()
                .filter(|op| op.at().is_some_and(|at| at >= hard))
                .collect();
            let at = deadlines.return_deadline;
            assert_eq!(
                after,
                vec![
                    Op::Signal {
                        pgid: pid,
                        signal: GroupSignal::Kill,
                        at
                    },
                    Op::Close {
                        stream: Stream::Stdout,
                        at
                    },
                    Op::Close {
                        stream: Stream::Stderr,
                        at
                    },
                ]
            );
            assert_eq!(count(&ops, |op| matches!(op, Op::Reap { .. })), 0);
            assert_eq!(report.returned_at, deadlines.return_deadline);
            assert_eq!(report.outcome, not_success(kind));
            assert!(report.retained);
            assert!(report.reasons.contains(&StepReason::ReturnDeadlineReached));
            assert_eq!(
                backend.pending_reap_diagnostics().unwrap().reason,
                RetentionReason::ReturnDeadlineReached
            );
        }
    }

    #[test]
    fn stage14_5_fr01_07_fake_read_error_is_not_success_eligible() {
        for kind in [StepKind::Action, StepKind::Verify] {
            let mut script = Script::finishes_after(Duration::from_millis(100), b"isolated\n");
            script.read_error = Some(Stream::Stderr);
            let mut backend = fake(script);
            let start = backend.driver.base;
            let argv = fake_argv();
            let report = backend.run_step(&request(&argv, timeout(kind, 2))).unwrap();
            assert_bounded(&report, &backend.driver.ops, start, Duration::from_secs(2));
            assert_eq!(report.outcome, not_success(kind));
            assert!(report.reasons.contains(&StepReason::ReaderError));
            // The errored stream is never read again.
            let stderr_reads = count(&backend.driver.ops, |op| {
                matches!(
                    op,
                    Op::Read {
                        stream: Stream::Stderr,
                        ..
                    }
                )
            });
            assert_eq!(stderr_reads, 1);
        }
    }

    /// Retains an unreapable leader (PR-01 setup) and returns the backend.
    fn retained(kind: StepKind) -> (CommandBackend<FakeDriver>, StepReport) {
        let mut backend = fake(Script::unreapable());
        let argv = fake_argv();
        let report = backend.run_step(&request(&argv, timeout(kind, 2))).unwrap();
        (backend, report)
    }

    /// PR-01: an unreapable leader at `hard_deadline` is transferred with the
    /// step's provenance after exactly one Finalization group SIGKILL.
    #[test]
    fn stage14_5_pr01_unreapable_leader_is_retained_with_provenance() {
        for kind in [StepKind::Action, StepKind::Verify] {
            let (backend, report) = retained(kind);
            let deadlines = report.deadlines.unwrap();
            assert!(report.returned_at <= deadlines.return_deadline);
            assert_eq!(report.outcome, not_success(kind));
            assert!(report.retained);
            let pid = report.pid.unwrap();
            let view = backend.pending_reap_diagnostics().unwrap();
            assert_eq!(view.pid, pid);
            assert_eq!(view.pgid, pid);
            assert_eq!(view.step_kind, kind);
            assert_eq!(view.incident_seq, 7);
            assert_eq!(view.incident_id, IncidentId::new(INCIDENT_ID));
            assert_eq!(view.attempt_token, 3);
            assert_eq!(view.step_started_at, deadlines.step_started_at);
            assert_eq!(view.hard_deadline, deadlines.hard_deadline);
            assert_eq!(view.final_kill, FinalKill::Sent);
            assert_eq!(view.polls, 0);
            assert_eq!(view.last_poll, LastPoll::None);
            let ops = &backend.driver.ops;
            let finalization_kills: Vec<_> = signals(ops)
                .into_iter()
                .filter(|(signal, at)| {
                    *signal == GroupSignal::Kill && *at >= deadlines.hard_deadline
                })
                .collect();
            assert_eq!(finalization_kills.len(), 1);
            let last_signal = ops.iter().rposition(|op| matches!(op, Op::Signal { .. }));
            let reap = ops.iter().rposition(|op| matches!(op, Op::Reap { .. }));
            assert!(last_signal < reap);
            assert!(backend.driver.unreaped_drops().is_empty());
        }
    }

    /// Stage 14 Phase 14.9: the lines the step caller logs for a finished
    /// step (§16.7.8). A leader transferred into the slot and a later step
    /// refused while it is occupied each yield exactly one WARN line that
    /// names the slot; they are diagnostics only.
    #[test]
    fn stage14_9_step_log_lines_name_retention_and_refusal() {
        let (mut backend, report) = retained(StepKind::Action);
        let lines = backend.step_log_lines(&report);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].starts_with(
            "WARN fencing step leader not reapable by its return deadline; retained in the pending-reap slot ("
        ));
        let argv = fake_argv();
        let refused = backend
            .run_step(&request(&argv, timeout(StepKind::Verify, 5)))
            .unwrap();
        let lines = backend.step_log_lines(&refused);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].starts_with(
            "WARN fencing step refused: pending_reap_occupied; no process was spawned ("
        ));
    }

    /// PR-02 / PR-03: while occupied, every verify poll and every action
    /// attempt is refused before any deadline or spawn, as `spawn-failed`
    /// with reason `pending_reap_occupied`.
    #[test]
    fn stage14_5_pr02_pr03_occupied_slot_refuses_every_spawn() {
        for (kind, iterations) in [(StepKind::Verify, 60), (StepKind::Action, 10)] {
            let (mut backend, report) = retained(StepKind::Action);
            let pid = report.pid.unwrap();
            let before = backend.driver.ops.len();
            let argv = fake_argv();
            for _ in 0..iterations {
                let refused = backend.run_step(&request(&argv, timeout(kind, 5))).unwrap();
                assert_eq!(refused.outcome, spawn_failed(kind));
                assert_eq!(
                    refused.spawn_failure,
                    Some(SpawnFailure::PendingReapOccupied)
                );
                assert_eq!(refused.reasons, vec![StepReason::PendingReapOccupied]);
                assert_eq!(refused.gate_poll, PendingReapPoll::NotReaped);
                assert_eq!(refused.deadlines, None);
                assert_eq!(refused.pid, None);
            }
            assert_eq!(backend.driver.spawns, 1, "no spawn after the transfer");
            let new_ops = &backend.driver.ops[before..];
            assert_eq!(new_ops.len(), iterations, "exactly one gate poll each");
            assert!(new_ops.iter().all(|op| *op
                == Op::Reap {
                    pid,
                    at: backend.driver.now
                }));
            assert_eq!(backend.pending_reap_diagnostics().unwrap().pid, pid);
            assert_eq!(
                backend.pending_reap_diagnostics().unwrap().polls,
                iterations as u64
            );
        }
    }

    /// PR-04: each poll is exactly one non-blocking reap; EINTR and errors
    /// leave the slot and are not retried; no signal after the transfer.
    #[test]
    fn stage14_5_pr04_polls_are_single_nonblocking_and_signal_free() {
        let (mut backend, report) = retained(StepKind::Verify);
        let pid = report.pid.unwrap();
        let before = backend.driver.ops.len();
        for iteration in 0..100 {
            if iteration == 50 {
                backend
                    .driver
                    .reap_script
                    .push_back(ReapResult::Interrupted);
            }
            let before = backend.driver.ops.len();
            let poll = backend.poll_pending_reap();
            assert_eq!(backend.driver.ops.len(), before + 1);
            let expected = if iteration == 50 {
                PendingReapPoll::Interrupted
            } else {
                PendingReapPoll::NotReaped
            };
            assert_eq!(poll, expected);
            let view = backend.pending_reap_diagnostics().unwrap();
            assert_eq!(view.pid, pid);
            let last = if iteration == 50 {
                LastPoll::Interrupted
            } else {
                LastPoll::NotReaped
            };
            assert_eq!(view.last_poll, last);
        }
        for (errno, transitioned) in [(10, true), (10, false), (4, true), (10, true)] {
            backend
                .driver
                .reap_script
                .push_back(ReapResult::Error(errno));
            assert_eq!(
                backend.poll_pending_reap(),
                PendingReapPoll::Error {
                    errno,
                    transitioned
                }
            );
            assert_eq!(
                backend.pending_reap_diagnostics().unwrap().last_poll,
                LastPoll::Error(errno)
            );
        }
        assert_eq!(backend.pending_reap_diagnostics().unwrap().polls, 104);
        // Only reaps since the transfer: no signal, sleep, read, or spawn.
        let ops = &backend.driver.ops[before..];
        assert_eq!(ops.len(), 104);
        assert!(
            ops.iter()
                .all(|op| matches!(op, Op::Reap { pid: reaped, .. } if *reaped == pid))
        );
        assert!(backend.driver.unreaped_drops().is_empty());
    }

    /// PR-05: once released, the next poll reaps and clears exactly that
    /// slot; the next step passes the gate and spawns exactly one child.
    #[test]
    fn stage14_5_pr05_later_reap_clears_the_slot_then_one_spawn() {
        let (mut backend, report) = retained(StepKind::Action);
        let pid = report.pid.unwrap();
        for _ in 0..36 {
            assert_eq!(backend.poll_pending_reap(), PendingReapPoll::NotReaped);
        }
        backend.driver.released.insert(pid);
        match backend.poll_pending_reap() {
            PendingReapPoll::Reaped { view, status } => {
                assert_eq!(view.pid, pid);
                assert_eq!(view.polls, 37);
                assert_eq!(status, LeaderStatus::Signal(9));
            }
            other => panic!("expected reap, got {other:?}"),
        }
        assert!(backend.pending_reap_diagnostics().is_none());
        assert_eq!(backend.poll_pending_reap(), PendingReapPoll::Empty);
        assert!(backend.driver.unreaped_drops().is_empty());

        backend.driver.script = Script::finishes_after(Duration::from_millis(50), b"isolated\n");
        let argv = fake_argv();
        let next = backend
            .run_step(&request(&argv, timeout(StepKind::Verify, 5)))
            .unwrap();
        assert_eq!(backend.driver.spawns, 2);
        assert_eq!(next.outcome, StepOutcome::Verify(VerifyOutcome::Isolated));
        assert_ne!(next.pid, Some(pid));
    }

    /// PR-05 gate variant: a step whose gate poll finds the leader reaped
    /// clears the slot and spawns in the same call.
    #[test]
    fn stage14_5_gate_poll_that_reaps_permits_the_spawn() {
        let (mut backend, report) = retained(StepKind::Verify);
        backend.driver.released.insert(report.pid.unwrap());
        backend.driver.script = Script::finishes_after(Duration::ZERO, b"");
        let argv = fake_argv();
        let before = backend.driver.ops.len();
        let next = backend
            .run_step(&request(&argv, timeout(StepKind::Action, 5)))
            .unwrap();
        let ops = &backend.driver.ops[before..];
        match &next.gate_poll {
            PendingReapPoll::Reaped { view, .. } => assert_eq!(Some(view.pid), report.pid),
            other => panic!("gate poll must report the reap: {other:?}"),
        }
        assert!(matches!(ops[0], Op::Reap { .. }));
        assert_eq!(ops[1], Op::Trust);
        assert!(matches!(ops[2], Op::Spawn(_)));
        assert_eq!(
            next.outcome,
            StepOutcome::Action(ActionOutcome::ReportedSuccess)
        );
    }

    /// PR-06: permanently unreapable, 1,000 iterations of polls and refused
    /// steps: at most one leader, no spawn, handle never dropped or replaced,
    /// no sleep, no signal.
    #[test]
    fn stage14_5_pr06_permanently_unreapable_never_grows() {
        let (mut backend, report) = retained(StepKind::Action);
        let pid = report.pid.unwrap();
        let before = backend.driver.ops.len();
        let argv = fake_argv();
        for iteration in 0..1000 {
            assert_eq!(backend.poll_pending_reap(), PendingReapPoll::NotReaped);
            let kind = if iteration % 2 == 0 {
                StepKind::Action
            } else {
                StepKind::Verify
            };
            let refused = backend
                .run_step(&request(&argv, timeout(kind, 30)))
                .unwrap();
            assert_eq!(refused.outcome, spawn_failed(kind));
            assert_eq!(backend.pending_reap_diagnostics().unwrap().pid, pid);
        }
        assert_eq!(backend.driver.spawns, 1);
        let ops = &backend.driver.ops[before..];
        assert_eq!(ops.len(), 2000);
        assert!(
            ops.iter()
                .all(|op| matches!(op, Op::Reap { pid: reaped, .. } if *reaped == pid))
        );
        assert!(backend.driver.unreaped_drops().is_empty());
    }

    /// PR-08: the accessor returns the provenance, tracks polls, and is a
    /// copy with no mutable control.
    #[test]
    fn stage14_5_pr08_diagnostics_view_is_a_read_only_copy() {
        let (mut backend, _) = retained(StepKind::Verify);
        let mut view = backend.pending_reap_diagnostics().unwrap();
        view.polls = 999;
        view.pid = 1;
        let fresh = backend.pending_reap_diagnostics().unwrap();
        assert_ne!(fresh.pid, 1);
        assert_eq!(fresh.polls, 0);
        backend.poll_pending_reap();
        let polled = backend.pending_reap_diagnostics().unwrap();
        assert_eq!(polled.polls, 1);
        assert_eq!(polled.last_poll, LastPoll::NotReaped);
        let later = polled.retained_at + Duration::from_secs(90);
        assert_eq!(polled.age(later), Duration::from_secs(90));
        assert_eq!(
            polled.age(polled.retained_at - Duration::from_secs(1)),
            Duration::ZERO
        );
    }

    /// PR-09: the transfer primitive with an already occupied slot keeps the
    /// existing handle and hands the new one back as the invariant error.
    #[test]
    fn stage14_5_pr09_transfer_into_occupied_slot_is_an_invariant_error() {
        let (mut backend, report) = retained(StepKind::Action);
        let existing = report.pid.unwrap();
        let now = backend.driver.now;
        let intruder = PendingReap {
            child: FakeLeader {
                pid: 9999,
                reaped: false,
                drops: Rc::clone(&backend.driver.drops),
            },
            pid: 9999,
            pgid: 9999,
            step_kind: StepKind::Verify,
            incident_seq: 8,
            incident_id: IncidentId::new(INCIDENT_ID),
            attempt_token: 4,
            step_started_at: now,
            hard_deadline: now,
            retained_at: now,
            final_kill: FinalKill::Sent,
            reason: RetentionReason::ReapFailed,
            polls: 0,
            last_poll: LastPoll::None,
        };
        let mut violation = backend.transfer(intruder).unwrap_err();
        assert_eq!(violation.existing_pid, existing);
        assert_eq!(violation.rejected.pid, 9999);
        assert_eq!(backend.pending_reap_diagnostics().unwrap().pid, existing);
        assert!(backend.driver.unreaped_drops().is_empty());
        violation.rejected.child.reaped = true;
    }

    #[test]
    fn stage14_5_verify_grammar_is_exact() {
        let exit0 = LeaderStatus::Code(0);
        assert_eq!(
            classify_verify(exit0, b"isolated", false),
            VerifyOutcome::Isolated
        );
        assert_eq!(
            classify_verify(exit0, b"isolated\n", false),
            VerifyOutcome::Isolated
        );
        assert_eq!(
            classify_verify(exit0, b"not-isolated", false),
            VerifyOutcome::NotIsolated
        );
        assert_eq!(
            classify_verify(exit0, b"not-isolated\n", false),
            VerifyOutcome::NotIsolated
        );
        for malformed in [
            &b""[..],
            b"Isolated",
            b" isolated",
            b"isolated\r\n",
            b"isolated\nisolated\n",
            b"isolated trailing",
            b"isolated\n\n",
        ] {
            assert_eq!(
                classify_verify(exit0, malformed, false),
                VerifyOutcome::Inconclusive(InconclusiveKind::MalformedOutput),
                "{malformed:?}"
            );
        }
        assert_eq!(
            classify_verify(exit0, b"isolated", true),
            VerifyOutcome::Inconclusive(InconclusiveKind::OutputOverflow)
        );
        assert_eq!(
            classify_verify(LeaderStatus::Code(1), b"isolated", false),
            VerifyOutcome::Inconclusive(InconclusiveKind::NonzeroExit)
        );
        assert_eq!(
            classify_verify(LeaderStatus::Signal(15), b"isolated", false),
            VerifyOutcome::Inconclusive(InconclusiveKind::Signal)
        );
    }

    #[test]
    fn stage14_5_trust_metadata_rules() {
        assert_eq!(check_file_metadata(true, 0, 0o100755), Ok(()));
        assert_eq!(
            check_file_metadata(false, 0, 0o040755),
            Err(TrustRefusal::NotRegularFile)
        );
        assert_eq!(
            check_file_metadata(true, 1000, 0o100755),
            Err(TrustRefusal::NotRootOwned)
        );
        assert_eq!(
            check_file_metadata(true, 0, 0o100775),
            Err(TrustRefusal::GroupOrWorldWritable)
        );
        assert_eq!(
            check_file_metadata(true, 0, 0o100757),
            Err(TrustRefusal::GroupOrWorldWritable)
        );
        assert_eq!(
            check_file_metadata(true, 0, 0o100644),
            Err(TrustRefusal::NotExecutable)
        );
        assert_eq!(check_ancestor_metadata(true, 0, 0o040755), Ok(()));
        assert_eq!(
            check_ancestor_metadata(false, 0, 0o120777),
            Err(TrustRefusal::AncestorNotDirectory)
        );
        assert_eq!(
            check_ancestor_metadata(true, 1000, 0o040755),
            Err(TrustRefusal::AncestorNotRootOwned)
        );
        assert_eq!(
            check_ancestor_metadata(true, 0, 0o040775),
            Err(TrustRefusal::AncestorGroupOrWorldWritable)
        );
        assert_eq!(
            check_ancestor_metadata(true, 0, 0o041777),
            Err(TrustRefusal::AncestorGroupOrWorldWritable)
        );
    }

    // ---------------------------------------------------------------------
    // Real processes (§34.6, §34.21). Helpers run through a trusted
    // root-owned interpreter; argv is passed verbatim (no shell is added by
    // the backend; the test chooses the interpreter as argv[0]).
    //
    // Tests whose success path needs a successful Finalization `killpg` on a
    // group whose only remaining member is the unreaped (zombie) leader are
    // Linux-only (§34.6 "Linux real processes"): Linux delivers to that
    // group, while macOS returns EPERM, which the step correctly classifies
    // as `group_state_unknown` (fail closed).
    // ---------------------------------------------------------------------

    unsafe extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }

    const ESRCH: i32 = 3;
    #[cfg(target_os = "linux")]
    const MIB: u64 = 1024 * 1024;

    fn trusted(candidates: &[&str]) -> String {
        candidates
            .iter()
            .find(|candidate| check_executable_trust(candidate).is_ok())
            .unwrap_or_else(|| panic!("no trusted executable among {candidates:?}"))
            .to_string()
    }

    fn bash() -> String {
        trusted(&["/usr/bin/bash", "/bin/bash"])
    }

    fn script(body: &str, arguments: &[&str]) -> Vec<String> {
        let mut argv = vec![
            bash(),
            "-c".to_string(),
            body.to_string(),
            "helper".to_string(),
        ];
        argv.extend(arguments.iter().map(|argument| argument.to_string()));
        argv
    }

    fn temp_path(tag: &str) -> PathBuf {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        std::env::temp_dir().join(format!(
            "mikagami-fb-{}-{tag}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ))
    }

    fn read_pid(path: &Path) -> u32 {
        let pid = fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
            .trim()
            .parse()
            .unwrap();
        let _ = fs::remove_file(path);
        pid
    }

    #[cfg(target_os = "linux")]
    fn alive(pid: u32) -> bool {
        let result = unsafe { kill(pid as i32, 0) };
        result == 0 || io::Error::last_os_error().raw_os_error() != Some(ESRCH)
    }

    #[cfg(target_os = "linux")]
    fn gone_within(pid: u32, limit: Duration) -> bool {
        let until = Instant::now() + limit;
        while Instant::now() < until {
            if !alive(pid) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        !alive(pid)
    }

    /// Real driver with ordering instrumentation and optional injected
    /// `killpg` / stderr read errors (FR01-05, FR01-06, FR01-07).
    #[derive(Debug, Default)]
    struct Instrumented {
        inner: SystemProcessDriver,
        log: Vec<&'static str>,
        signal_error: bool,
        stderr_error_once: bool,
    }

    impl ProcessDriver for Instrumented {
        type Leader = Child;

        fn now(&self) -> Instant {
            self.inner.now()
        }

        fn sleep(&mut self, duration: Duration) {
            self.inner.sleep(duration)
        }

        fn check_trust(&mut self, executable: &str) -> Result<(), TrustRefusal> {
            self.log.push("trust");
            self.inner.check_trust(executable)
        }

        fn spawn(&mut self, plan: &SpawnPlan<'_>) -> Result<Child, i32> {
            self.log.push("spawn");
            self.inner.spawn(plan)
        }

        fn leader_pid(&self, leader: &Child) -> u32 {
            self.inner.leader_pid(leader)
        }

        fn set_nonblocking(&mut self, leader: &mut Child, stream: Stream) -> Result<(), i32> {
            self.inner.set_nonblocking(leader, stream)
        }

        fn read(&mut self, leader: &mut Child, stream: Stream, buffer: &mut [u8]) -> ReadResult {
            if stream == Stream::Stderr && self.stderr_error_once {
                self.stderr_error_once = false;
                return ReadResult::Error(5);
            }
            self.inner.read(leader, stream, buffer)
        }

        fn leader_exited(&mut self, leader: &Child) -> Result<bool, i32> {
            self.inner.leader_exited(leader)
        }

        fn signal_group(&mut self, pgid: u32, signal: GroupSignal) -> Result<(), i32> {
            self.log.push("signal");
            let result = self.inner.signal_group(pgid, signal);
            if self.signal_error { Err(1) } else { result }
        }

        fn close_read_end(&mut self, leader: &mut Child, stream: Stream) {
            self.inner.close_read_end(leader, stream)
        }

        fn try_reap(&mut self, leader: &mut Child) -> ReapResult {
            self.log.push("reap");
            self.inner.try_reap(leader)
        }
    }

    /// Runs one real step on its own thread under the emergency watchdog
    /// (`hard_deadline + 5 s`, a hang detector only). Returns the report, the
    /// instant `run_step` returned, and the driver.
    fn run_real<D>(driver: D, argv: Vec<String>, step: StepTimeout) -> (StepReport, Instant, D)
    where
        D: ProcessDriver<Leader = Child> + Send + 'static,
    {
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let mut backend = CommandBackend::new(driver);
            let report = backend.run_step(&request(&argv, step));
            let returned = Instant::now();
            let report = report.expect("no invariant violation");
            assert!(backend.pending_reap_diagnostics().is_none() || report.retained);
            let _ = sender.send((report, returned, backend.driver));
        });
        let watchdog = step.duration() + TERM_GRACE + KILL_REAP_GRACE + Duration::from_secs(5);
        receiver
            .recv_timeout(watchdog)
            .expect("emergency watchdog: the step did not return")
    }

    fn run_system(argv: Vec<String>, step: StepTimeout) -> (StepReport, Instant) {
        let (report, returned, _) = run_real(SystemProcessDriver, argv, step);
        (report, returned)
    }

    fn timed_out(kind: StepKind) -> StepOutcome {
        match kind {
            StepKind::Action => StepOutcome::Action(ActionOutcome::TimedOut),
            StepKind::Verify => {
                StepOutcome::Verify(VerifyOutcome::Inconclusive(InconclusiveKind::Timeout))
            }
            StepKind::Route => {
                StepOutcome::Route(RouteOutcome::Inconclusive(InconclusiveKind::Timeout))
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn success(kind: StepKind) -> StepOutcome {
        match kind {
            StepKind::Action => StepOutcome::Action(ActionOutcome::ReportedSuccess),
            StepKind::Verify => StepOutcome::Verify(VerifyOutcome::Isolated),
            StepKind::Route => StepOutcome::Route(RouteOutcome::Output(b"isolated\n".to_vec())),
        }
    }

    const KINDS: [StepKind; 2] = [StepKind::Action, StepKind::Verify];

    #[cfg(target_os = "linux")]
    /// FR01-01 helper: a same-group descendant keeps the selected captured
    /// descriptors open for 600 s; the leader prints `isolated` and exits 0.
    fn holder_script(stream: Stream2) -> &'static str {
        match stream {
            Stream2::Stdout => {
                "sleep 600 2>/dev/null & echo $! > \"$1\"; printf 'isolated\\n'; exit 0"
            }
            Stream2::Stderr => {
                "sleep 600 >/dev/null & echo $! > \"$1\"; printf 'isolated\\n'; exit 0"
            }
            Stream2::Both => "sleep 600 & echo $! > \"$1\"; printf 'isolated\\n'; exit 0",
        }
    }

    #[cfg(target_os = "linux")]
    #[derive(Debug, Clone, Copy)]
    enum Stream2 {
        Stdout,
        Stderr,
        Both,
    }

    #[cfg(target_os = "linux")]
    fn assert_fr01_01(kind: StepKind, stream: Stream2, seconds: u64) -> StepOutcome {
        let pidfile = temp_path("fr0101");
        let argv = script(holder_script(stream), &[pidfile.to_str().unwrap()]);
        let (report, returned) = run_system(argv, timeout(kind, seconds));
        let deadlines = report.deadlines.unwrap();
        let timeline = report.timeline.unwrap();
        assert!(
            returned >= deadlines.execution_deadline,
            "{kind:?}/{stream:?}: returned at leader exit"
        );
        assert!(returned <= deadlines.return_deadline, "{kind:?}/{stream:?}");
        assert!(timeline.last_wait_end.unwrap() <= deadlines.hard_deadline);
        assert!(timeline.term_signal_at.unwrap() >= deadlines.execution_deadline);
        assert!(timeline.finalization_at < deadlines.hard_deadline);
        assert_eq!(report.outcome, timed_out(kind), "{kind:?}/{stream:?}");
        assert!(!report.success_eligible);
        assert!(report.stdout.len() <= STDOUT_CAPTURE_LIMIT);
        assert!(report.reasons.contains(&StepReason::LeaderExitPipeHeld));
        let descendant = read_pid(&pidfile);
        assert!(
            gone_within(descendant, Duration::from_secs(1)),
            "descendant {descendant} survived"
        );
        report.outcome
    }

    #[cfg(target_os = "linux")]
    const STREAMS: [Stream2; 3] = [Stream2::Stdout, Stream2::Stderr, Stream2::Both];

    #[cfg(target_os = "linux")]
    /// FR01-01 at the 2 s CI timeout, every stream x step, 20 repetitions
    /// each with identical results.
    #[test]
    fn stage14_5_fr01_01_real_descendant_holds_pipes_2s() {
        let handles: Vec<_> = KINDS
            .iter()
            .flat_map(|kind| STREAMS.iter().map(move |stream| (*kind, *stream)))
            .map(|(kind, stream)| {
                std::thread::spawn(move || {
                    let outcomes: HashSet<String> = (0..20)
                        .map(|_| format!("{:?}", assert_fr01_01(kind, stream, 2)))
                        .collect();
                    assert_eq!(outcomes.len(), 1, "{kind:?}/{stream:?}: {outcomes:?}");
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    /// FR01-01 at the maximum timeouts (60 s action, 30 s verify).
    #[test]
    fn stage14_5_fr01_01_real_descendant_holds_pipes_at_maximum() {
        let handles: Vec<_> = KINDS
            .iter()
            .flat_map(|kind| STREAMS.iter().map(move |stream| (*kind, *stream)))
            .map(|(kind, stream)| {
                let seconds = match kind {
                    StepKind::Action => MAX_FENCE_TIMEOUT_SEC,
                    StepKind::Verify => MAX_VERIFY_TIMEOUT_SEC,
                    StepKind::Route => 2,
                };
                std::thread::spawn(move || assert_fr01_01(kind, stream, seconds))
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    /// FR01-02: the descendant releases the pipes after 1 s; the step is
    /// resolved before `execution_deadline` and success-eligible.
    #[test]
    fn stage14_5_fr01_02_real_descendant_releases_before_deadline() {
        for kind in KINDS {
            let argv = script("sleep 1 & printf 'isolated\\n'; exit 0", &[]);
            let (report, _) = run_system(argv, timeout(kind, 5));
            let deadlines = report.deadlines.unwrap();
            let resolved = report.timeline.unwrap().resolved_at.unwrap();
            assert!(resolved - deadlines.step_started_at >= Duration::from_millis(900));
            assert!(resolved < deadlines.execution_deadline);
            assert!(report.success_eligible, "{report:?}");
            assert_eq!(report.outcome, success(kind));
            assert_eq!(report.final_kill, Some(FinalKill::Sent));
        }
    }

    #[cfg(target_os = "linux")]
    /// FR01-03: a descendant escapes via `setsid` and holds stdout: forced
    /// closure at `hard_deadline`, return by `return_deadline`, never success.
    #[test]
    fn stage14_5_fr01_03_real_escaped_holder() {
        let handles: Vec<_> = KINDS
            .iter()
            .map(|kind| {
                let kind = *kind;
                std::thread::spawn(move || {
                    let pidfile = temp_path("fr0103");
                    let argv = script(
                        "perl -MPOSIX -e 'POSIX::setsid() or die; sleep 12' 2>/dev/null & \
                         echo $! > \"$1\"; exit 0",
                        &[pidfile.to_str().unwrap()],
                    );
                    let (report, returned) = run_system(argv, timeout(kind, 2));
                    let escaped = read_pid(&pidfile);
                    unsafe { kill(escaped as i32, 9) };
                    let deadlines = report.deadlines.unwrap();
                    assert!(returned >= deadlines.hard_deadline);
                    assert!(returned <= deadlines.return_deadline);
                    assert_eq!(report.outcome, not_success(kind));
                    assert!(report.reasons.contains(&StepReason::EscapedHolder));
                    assert!(!report.retained);
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    /// FR01-04: a descendant floods 1 MiB to stdout and holds it; at most
    /// 4 KiB is stored, draining continues, and the step is bounded.
    #[test]
    fn stage14_5_fr01_04_real_flood_and_hold() {
        for kind in KINDS {
            let pidfile = temp_path("fr0104");
            let argv = script(
                "(head -c 1048576 /dev/zero; exec sleep 600) 2>/dev/null & \
                 echo $! > \"$1\"; exit 0",
                &[pidfile.to_str().unwrap()],
            );
            let (report, returned) = run_system(argv, timeout(kind, 2));
            assert!(returned <= report.deadlines.unwrap().return_deadline);
            assert_eq!(report.stdout.len(), STDOUT_CAPTURE_LIMIT);
            assert!(report.stdout_overflow);
            assert_eq!(report.stdout_bytes, MIB);
            assert_eq!(report.outcome, timed_out(kind));
            assert!(gone_within(read_pid(&pidfile), Duration::from_secs(1)));
        }
    }

    fn process_state(pid: u32) -> Option<char> {
        #[cfg(target_os = "linux")]
        {
            let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            stat.rsplit_once(") ")?.1.chars().next()
        }
        #[cfg(not(target_os = "linux"))]
        {
            let output = Command::new("/bin/ps")
                .args(["-o", "stat=", "-p", &pid.to_string()])
                .output()
                .ok()?;
            String::from_utf8_lossy(&output.stdout)
                .trim()
                .chars()
                .next()
        }
    }

    /// FR01-05: while the step drains after leader exit the leader is an
    /// unreaped zombie, and every group signal precedes the single reap.
    #[test]
    fn stage14_5_fr01_05_real_leader_stays_unreaped_until_final_kill() {
        let pidfile = temp_path("fr0105");
        let watched = pidfile.clone();
        let watcher = std::thread::spawn(move || {
            let until = Instant::now() + Duration::from_secs(2);
            while !watched.exists() && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(5));
            }
            std::thread::sleep(Duration::from_millis(500));
            process_state(read_pid(&watched))
        });
        let argv = script(
            "echo $$ > \"$1\"; sleep 600 & exit 0",
            &[pidfile.to_str().unwrap()],
        );
        let (report, _, driver) =
            run_real(Instrumented::default(), argv, timeout(StepKind::Action, 2));
        assert_eq!(watcher.join().unwrap(), Some('Z'));
        assert_eq!(driver.log.last(), Some(&"reap"));
        assert_eq!(
            driver.log.iter().filter(|entry| **entry == "reap").count(),
            1
        );
        assert!(
            driver
                .log
                .iter()
                .filter(|entry| **entry == "signal")
                .count()
                >= 2
        );
        assert_eq!(report.outcome, timed_out(StepKind::Action));
    }

    /// FR01-06: an injected `killpg` error means `group_state_unknown`.
    #[test]
    fn stage14_5_fr01_06_real_injected_killpg_error() {
        for kind in KINDS {
            let driver = Instrumented {
                signal_error: true,
                ..Instrumented::default()
            };
            let argv = script("printf 'isolated\\n'; exit 0", &[]);
            let (report, _, _) = run_real(driver, argv, timeout(kind, 2));
            assert_eq!(report.final_kill, Some(FinalKill::GroupStateUnknown));
            assert!(report.reasons.contains(&StepReason::GroupStateUnknown));
            assert!(!report.success_eligible);
            assert_eq!(report.outcome, not_success(kind));
        }
    }

    /// FR01-07: an injected read error on stderr is never success-eligible.
    #[test]
    fn stage14_5_fr01_07_real_injected_stderr_read_error() {
        let handles: Vec<_> = KINDS
            .iter()
            .map(|kind| {
                let kind = *kind;
                std::thread::spawn(move || {
                    let driver = Instrumented {
                        stderr_error_once: true,
                        ..Instrumented::default()
                    };
                    let argv = script("printf 'isolated\\n'; exit 0", &[]);
                    let (report, returned, _) = run_real(driver, argv, timeout(kind, 2));
                    assert!(returned <= report.deadlines.unwrap().return_deadline);
                    assert!(report.reasons.contains(&StepReason::ReaderError));
                    assert!(!report.success_eligible);
                    assert_eq!(report.outcome, not_success(kind));
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    /// FR01-09: a background descendant that closed its pipes does not block
    /// resolution, and the Finalization group SIGKILL kills it.
    #[test]
    fn stage14_5_fr01_09_real_final_group_kill_on_success() {
        for kind in KINDS {
            let pidfile = temp_path("fr0109");
            let argv = script(
                "sleep 600 >/dev/null 2>&1 & echo $! > \"$1\"; printf 'isolated\\n'; exit 0",
                &[pidfile.to_str().unwrap()],
            );
            let (report, _) = run_system(argv, timeout(kind, 2));
            assert!(report.success_eligible);
            assert_eq!(report.outcome, success(kind));
            let background = read_pid(&pidfile);
            assert!(gone_within(background, Duration::from_secs(1)));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stage14_5_real_verify_grammar_and_exit_classes() {
        let cases: [(&str, VerifyOutcome); 10] = [
            ("isolated", VerifyOutcome::Isolated),
            ("isolated\n", VerifyOutcome::Isolated),
            ("not-isolated", VerifyOutcome::NotIsolated),
            ("not-isolated\n", VerifyOutcome::NotIsolated),
            (
                "",
                VerifyOutcome::Inconclusive(InconclusiveKind::MalformedOutput),
            ),
            (
                "Isolated",
                VerifyOutcome::Inconclusive(InconclusiveKind::MalformedOutput),
            ),
            (
                " isolated",
                VerifyOutcome::Inconclusive(InconclusiveKind::MalformedOutput),
            ),
            (
                "isolated\r\n",
                VerifyOutcome::Inconclusive(InconclusiveKind::MalformedOutput),
            ),
            (
                "isolated\nisolated\n",
                VerifyOutcome::Inconclusive(InconclusiveKind::MalformedOutput),
            ),
            (
                "isolated trailing",
                VerifyOutcome::Inconclusive(InconclusiveKind::MalformedOutput),
            ),
        ];
        for (stdout, expected) in cases {
            let argv = script("printf '%s' \"$1\"", &[stdout]);
            let (report, _) = run_system(argv, timeout(StepKind::Verify, 2));
            assert_eq!(report.outcome, StepOutcome::Verify(expected), "{stdout:?}");
            assert_eq!(report.stdout, stdout.as_bytes());
        }
        for (body, action, verify) in [
            (
                "printf 'isolated\\n'; exit 3",
                ActionOutcome::ReportedFailure,
                InconclusiveKind::NonzeroExit,
            ),
            (
                "printf 'isolated\\n'; kill -KILL $$",
                ActionOutcome::Signal,
                InconclusiveKind::Signal,
            ),
        ] {
            let (report, _) = run_system(script(body, &[]), timeout(StepKind::Action, 2));
            assert_eq!(report.outcome, StepOutcome::Action(action), "{body}");
            let (report, _) = run_system(script(body, &[]), timeout(StepKind::Verify, 2));
            assert_eq!(
                report.outcome,
                StepOutcome::Verify(VerifyOutcome::Inconclusive(verify)),
                "{body}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    /// Timeout with TERM honored, and with TERM ignored (KILL at
    /// `term_deadline`).
    #[test]
    fn stage14_5_real_timeout_term_then_kill() {
        let handles: Vec<_> = KINDS
            .iter()
            .flat_map(|kind| [(*kind, false), (*kind, true)])
            .map(|(kind, ignore_term)| {
                std::thread::spawn(move || {
                    let body = if ignore_term {
                        "trap '' TERM; exec sleep 600"
                    } else {
                        "exec sleep 600"
                    };
                    let (report, returned) = run_system(script(body, &[]), timeout(kind, 2));
                    let deadlines = report.deadlines.unwrap();
                    let timeline = report.timeline.unwrap();
                    assert!(returned <= deadlines.return_deadline);
                    assert_eq!(report.outcome, timed_out(kind));
                    let resolved = timeline.resolved_at.unwrap();
                    if ignore_term {
                        assert!(timeline.kill_signal_at.unwrap() >= deadlines.term_deadline);
                        assert!(resolved >= deadlines.term_deadline);
                        assert_eq!(report.leader_status, Some(LeaderStatus::Signal(9)));
                    } else {
                        assert_eq!(timeline.kill_signal_at, None);
                        assert!(resolved < deadlines.term_deadline);
                        assert_eq!(report.leader_status, Some(LeaderStatus::Signal(15)));
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stage14_5_real_output_overflow_and_stderr_flood_are_bounded() {
        let (report, _) = run_system(
            script("head -c 1048576 /dev/zero; exit 0", &[]),
            timeout(StepKind::Verify, 5),
        );
        assert!(report.success_eligible);
        assert_eq!(
            report.outcome,
            StepOutcome::Verify(VerifyOutcome::Inconclusive(
                InconclusiveKind::OutputOverflow
            ))
        );
        assert_eq!(report.stdout.len(), STDOUT_CAPTURE_LIMIT);
        assert_eq!(report.stdout_bytes, MIB);
        let (report, _) = run_system(
            script("head -c 1048576 /dev/zero; exit 0", &[]),
            timeout(StepKind::Action, 5),
        );
        assert_eq!(report.outcome, success(StepKind::Action));

        let (report, _) = run_system(
            script("head -c 1048576 /dev/zero >&2; printf 'isolated\\n'", &[]),
            timeout(StepKind::Verify, 5),
        );
        assert_eq!(report.outcome, success(StepKind::Verify));
        assert_eq!(report.stderr_bytes, MIB);
        assert_eq!(report.stdout, b"isolated\n");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stage14_5_real_environment_is_exactly_the_allowlist() {
        let argv = vec![trusted(&["/usr/bin/env"])];
        let (report, _) = run_system(argv, timeout(StepKind::Action, 5));
        assert_eq!(report.outcome, success(StepKind::Action));
        let mut lines: Vec<String> = String::from_utf8(report.stdout)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        lines.sort();
        let mut expected = vec![
            format!("PATH={FENCE_PATH}"),
            "LANG=C".to_string(),
            "MIKAGAMI_CLUSTER=cluster-a".to_string(),
            "MIKAGAMI_FENCE_TARGET=node-b".to_string(),
            format!("MIKAGAMI_FENCE_INCIDENT={INCIDENT_ID}"),
            "MIKAGAMI_FENCE_ATTEMPT=3".to_string(),
        ];
        expected.sort();
        assert_eq!(lines, expected);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stage14_5_real_no_shell_argument_is_literal() {
        let marker = temp_path("noshell");
        let argument = format!("a;touch {}", marker.display());
        let argv = vec![trusted(&["/usr/bin/echo", "/bin/echo"]), argument.clone()];
        let (report, _) = run_system(argv, timeout(StepKind::Action, 5));
        assert_eq!(report.outcome, success(StepKind::Action));
        assert_eq!(report.stdout, format!("{argument}\n").into_bytes());
        assert!(!marker.exists());
    }

    #[test]
    fn stage14_5_real_executable_trust_check() {
        assert_eq!(check_executable_trust(&bash()), Ok(()));
        assert_eq!(
            check_executable_trust("usr/bin/env"),
            Err(TrustRefusal::NotAbsolute)
        );
        assert_eq!(
            check_executable_trust("/usr/bin/../bin/env"),
            Err(TrustRefusal::NotNormalized)
        );
        assert_eq!(
            check_executable_trust("/nonexistent-mikagami/fence"),
            Err(TrustRefusal::Open(2))
        );
        assert_eq!(
            check_executable_trust("/usr/bin"),
            Err(TrustRefusal::NotRegularFile)
        );
        if fs::symlink_metadata("/bin")
            .unwrap()
            .file_type()
            .is_symlink()
        {
            // A symlinked ancestor is not a directory (Ubuntu's /bin): the
            // final component `env` is a regular root-owned file, so only the
            // ancestor rule refuses it. (`/bin/sh` would already fail on its
            // own symlinked final component.)
            assert_eq!(check_executable_trust("/usr/bin/env"), Ok(()));
            assert_eq!(
                check_executable_trust("/bin/env"),
                Err(TrustRefusal::AncestorNotDirectory)
            );
            if fs::symlink_metadata("/usr/bin/sh")
                .is_ok_and(|metadata| metadata.file_type().is_symlink())
            {
                assert_eq!(
                    check_executable_trust("/bin/sh"),
                    Err(TrustRefusal::SymlinkFinalComponent)
                );
            }
        }

        let link = temp_path("link");
        std::os::unix::fs::symlink(trusted(&["/usr/bin/env"]), &link).unwrap();
        let refused = check_executable_trust(link.to_str().unwrap());
        fs::remove_file(&link).unwrap();
        assert_eq!(refused, Err(TrustRefusal::SymlinkFinalComponent));

        let own = temp_path("own");
        fs::write(&own, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&own, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let owner = fs::metadata(&own).unwrap().uid();
        let refused = check_executable_trust(own.to_str().unwrap());
        let (report, _) = run_system(
            vec![own.display().to_string()],
            timeout(StepKind::Verify, 2),
        );
        fs::remove_file(&own).unwrap();
        assert!(refused.is_err());
        if owner != 0 {
            assert_eq!(refused, Err(TrustRefusal::NotRootOwned));
        }
        assert_eq!(report.outcome, spawn_failed(StepKind::Verify));
        assert_eq!(
            report.spawn_failure,
            Some(SpawnFailure::Trust(refused.unwrap_err()))
        );
        assert_eq!(report.pid, None);
    }

    // ---------------------------------------------------------------------
    // Phase 14.5 remediation regressions (F14.5-01 .. F14.5-04).
    // ---------------------------------------------------------------------

    /// Runs `check` on its own thread under a 2 s watchdog. On a hang (the
    /// F14.5-01 regression: a blocking `open` of the FIFO) the FIFO is given
    /// a non-blocking writer so the blocked thread is released, then the test
    /// fails; the suite itself never hangs.
    fn within_fifo_watchdog<T: Send + 'static>(
        fifo: &Path,
        check: impl FnOnce() -> T + Send + 'static,
    ) -> (T, Duration) {
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let started = Instant::now();
            let value = check();
            let _ = sender.send((value, started.elapsed()));
        });
        match receiver.recv_timeout(Duration::from_secs(2)) {
            Ok(result) => result,
            Err(_) => {
                for _ in 0..40 {
                    let writer = OpenOptions::new()
                        .write(true)
                        .custom_flags(sys::O_NONBLOCK)
                        .open(fifo);
                    if writer.is_ok() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                let _ = fs::remove_file(fifo);
                panic!("trust check blocked on the FIFO {}", fifo.display());
            }
        }
    }

    /// F14.5-01: a FIFO at `argv[0]` is refused promptly as a non-regular
    /// file. No FIFO writer or reader exists at any point, and the step
    /// never reaches spawn.
    #[test]
    fn stage14_5_fifo_argv0_is_refused_promptly_and_never_spawns() {
        use std::os::unix::fs::FileTypeExt;
        let fifo = temp_path("fifo");
        let made = Command::new("/usr/bin/mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo");
        assert!(made.success());
        assert!(fs::symlink_metadata(&fifo).unwrap().file_type().is_fifo());
        let path = fifo.display().to_string();

        let checked = path.clone();
        let (refusal, elapsed) =
            within_fifo_watchdog(&fifo, move || check_executable_trust(&checked));
        assert_eq!(refusal, Err(TrustRefusal::NotRegularFile));
        assert!(elapsed < Duration::from_millis(500), "{elapsed:?}");

        for kind in KINDS {
            let argv = vec![path.clone()];
            let ((report, driver), elapsed) = within_fifo_watchdog(&fifo, move || {
                let mut backend = CommandBackend::new(Instrumented::default());
                let report = backend
                    .run_step(&request(&argv, timeout(kind, 1)))
                    .expect("no invariant violation");
                (report, backend.driver)
            });
            assert!(elapsed < Duration::from_millis(500), "{elapsed:?}");
            assert_eq!(report.outcome, spawn_failed(kind));
            assert_eq!(
                report.spawn_failure,
                Some(SpawnFailure::Trust(TrustRefusal::NotRegularFile))
            );
            assert_eq!(report.pid, None);
            assert!(report.timeline.is_none());
            // Trust ran; spawn, signal, and reap never did.
            assert_eq!(driver.log, vec!["trust"]);
        }
        fs::remove_file(&fifo).unwrap();
    }

    /// F14.5-01: other non-regular targets (a character device, a socket,
    /// and a directory) are refused as non-regular files before any open,
    /// and a step naming one never spawns.
    #[test]
    fn stage14_5_non_regular_targets_are_refused_before_open() {
        let socket = temp_path("sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let socket_path = socket.display().to_string();
        for target in ["/dev/null", socket_path.as_str(), "/usr/bin"] {
            let started = Instant::now();
            assert_eq!(
                check_executable_trust(target),
                Err(TrustRefusal::NotRegularFile),
                "{target}"
            );
            assert!(started.elapsed() < Duration::from_millis(500));
            let argv = vec![target.to_string()];
            let (report, _, driver) =
                run_real(Instrumented::default(), argv, timeout(StepKind::Verify, 1));
            assert_eq!(report.outcome, spawn_failed(StepKind::Verify), "{target}");
            assert_eq!(
                report.spawn_failure,
                Some(SpawnFailure::Trust(TrustRefusal::NotRegularFile))
            );
            assert_eq!(driver.log, vec!["trust"], "{target}");
        }
        drop(listener);
        fs::remove_file(&socket).unwrap();
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Held {
        /// The leader never exits and holds both pipes; it ignores signals
        /// and is unreapable (§34.22 driver).
        AlivePipesOpen,
        /// The leader never exits; both pipes are closed; signals ignored.
        AlivePipesClosed,
        /// The leader exited 0 at once; a descendant holds both pipes.
        ExitedPipesOpen,
        /// The leader is alive and holds both pipes, but honors signals.
        AliveHonorsSignals,
    }

    fn held_script(held: Held) -> Script {
        let mut script = Script::finishes_after(Duration::ZERO, b"isolated\n");
        match held {
            Held::AlivePipesOpen => return Script::unreapable(),
            Held::AlivePipesClosed => {
                script.leader_exit_after = None;
                script.honors_signals = false;
            }
            Held::ExitedPipesOpen => {
                script.stdout_eof_after = None;
                script.stderr_eof_after = None;
                script.honors_signals = false;
            }
            Held::AliveHonorsSignals => {
                script.leader_exit_after = None;
                script.stdout_eof_after = None;
                script.stderr_eof_after = None;
            }
        }
        script
    }

    /// One step with a 2 s timeout (E = +2 s, TE = +4 s, H = +6 s,
    /// R = +6.5 s) whose sub-wait ending at `from` (after start) wakes at
    /// `to` (after start) instead.
    fn late_wake_step(
        kind: StepKind,
        held: Held,
        from: Duration,
        to: Duration,
    ) -> (CommandBackend<FakeDriver>, StepReport) {
        let mut backend = fake(held_script(held));
        let start = backend.driver.base;
        backend.driver.script.late_wake = Some((start + from, to - from));
        let argv = fake_argv();
        let report = backend
            .run_step(&request(&argv, timeout(kind, 2)))
            .expect("no invariant violation");
        assert_ops_bounded(&report, &backend.driver.ops, start, Duration::from_secs(2));
        let deadlines = report.deadlines.unwrap();
        let wake = start + to;
        if wake <= deadlines.return_deadline {
            assert!(report.returned_at <= deadlines.return_deadline);
        } else {
            assert_eq!(
                report.returned_at, wake,
                "returns at once after a late wake"
            );
        }
        assert!(backend.driver.unreaped_drops().is_empty());
        (backend, report)
    }

    /// F14.5-02: a late wake from the Execution, TERM, or KILL phase lands
    /// at `hard_deadline - ε`, `hard_deadline`, `hard_deadline + ε`,
    /// `return_deadline`, or `return_deadline + ε`. The absolute deadlines
    /// alone select the behavior: no escalation whose phase has passed is
    /// replayed, and at or after `hard_deadline` exactly the §16.6.6
    /// operations run (one killpg, two closes, one WNOHANG reap unless
    /// `now ≥ return_deadline`), with no TERM, no drain, no exit query, no
    /// sleep, and no deadline change.
    #[test]
    fn stage14_5_late_wake_matrix_follows_absolute_deadlines() {
        let s = Duration::from_secs;
        let ms = Duration::from_millis;
        let epsilon = ms(1);
        let (e, te, h, r) = (s(2), s(4), s(6), ms(6500));
        let origins = [
            (StepPhase::Execution, s(1)),
            (StepPhase::Term, s(3)),
            (StepPhase::Kill, s(5)),
        ];
        let targets = [h - epsilon, h, h + epsilon, r, r + epsilon];
        let helds = [
            Held::AlivePipesOpen,
            Held::AlivePipesClosed,
            Held::ExitedPipesOpen,
            Held::AliveHonorsSignals,
        ];
        let mut cases = 0;
        for kind in KINDS {
            for (origin, from) in origins {
                for to in targets {
                    for held in helds {
                        // A signal-honoring leader resolves at the on-time
                        // TERM, so only the Execution origin sleeps into a
                        // late wake.
                        if held == Held::AliveHonorsSignals && origin != StepPhase::Execution {
                            continue;
                        }
                        cases += 1;
                        let label = format!("{kind:?}/{origin:?}/+{to:?}/{held:?}");
                        let (backend, report) = late_wake_step(kind, held, from, to);
                        let deadlines = report.deadlines.unwrap();
                        let start = deadlines.step_started_at;
                        let at = |offset: Duration| start + offset;
                        let ops = &backend.driver.ops;
                        let pid = report.pid.unwrap();

                        // Escalations the step legitimately entered on time,
                        // before the wake.
                        let mut expected = Vec::new();
                        if origin >= StepPhase::Term {
                            expected.push((GroupSignal::Term, at(e)));
                        }
                        if origin == StepPhase::Kill {
                            expected.push((GroupSignal::Kill, at(te)));
                        }
                        // Before `hard_deadline`, the wake enters only the
                        // phase that contains it: the KILL phase.
                        if to < h && origin < StepPhase::Kill {
                            expected.push((GroupSignal::Kill, at(to)));
                        }
                        // The single Finalization group SIGKILL.
                        let resolved_at_wake =
                            to < h && held == Held::AliveHonorsSignals && origin < StepPhase::Kill;
                        let finalization = if resolved_at_wake {
                            at(to)
                        } else {
                            at(to.max(h))
                        };
                        expected.push((GroupSignal::Kill, finalization));
                        assert_eq!(signals(ops), expected, "{label}");

                        let hard = deadlines.hard_deadline;
                        let after: Vec<Op> = ops
                            .iter()
                            .copied()
                            .filter(|op| op.at().is_some_and(|instant| instant >= hard))
                            .collect();
                        if to >= h {
                            // Exactly the §16.6.6 sequence, each once.
                            let mut permitted = vec![
                                Op::Signal {
                                    pgid: pid,
                                    signal: GroupSignal::Kill,
                                    at: at(to),
                                },
                                Op::Close {
                                    stream: Stream::Stdout,
                                    at: at(to),
                                },
                                Op::Close {
                                    stream: Stream::Stderr,
                                    at: at(to),
                                },
                            ];
                            if to < r {
                                permitted.push(Op::Reap { pid, at: at(to) });
                            }
                            assert_eq!(after, permitted, "{label}");
                            assert_eq!(report.returned_at, at(to), "{label}");
                            assert_eq!(report.timeline.unwrap().finalization_at, at(to));
                        } else if !resolved_at_wake {
                            // Finalization on time at `hard_deadline`.
                            assert_eq!(
                                after,
                                vec![
                                    Op::Signal {
                                        pgid: pid,
                                        signal: GroupSignal::Kill,
                                        at: hard,
                                    },
                                    Op::Close {
                                        stream: Stream::Stdout,
                                        at: hard,
                                    },
                                    Op::Close {
                                        stream: Stream::Stderr,
                                        at: hard,
                                    },
                                    Op::Reap { pid, at: hard },
                                ],
                                "{label}"
                            );
                            assert_eq!(report.returned_at, hard, "{label}");
                        } else {
                            assert!(after.is_empty(), "{label}");
                            assert_eq!(report.returned_at, at(to), "{label}");
                        }
                        let killpg_after_hard = count(&after, |op| matches!(op, Op::Signal { .. }));
                        assert!(killpg_after_hard <= 1, "{label}");
                        assert_eq!(
                            count(&after, |op| matches!(
                                op,
                                Op::Signal {
                                    signal: GroupSignal::Term,
                                    ..
                                }
                            )),
                            0,
                            "{label}: TERM after hard_deadline"
                        );
                        assert_eq!(
                            count(&after, |op| matches!(
                                op,
                                Op::Read { .. } | Op::ExitQuery { .. } | Op::Sleep { .. }
                            )),
                            0,
                            "{label}: drain, exit query, or wait after hard_deadline"
                        );
                        let reaps = count(ops, |op| matches!(op, Op::Reap { .. }));
                        assert_eq!(reaps, usize::from(to < r), "{label}: reaps");
                        let last_signal =
                            ops.iter().rposition(|op| matches!(op, Op::Signal { .. }));
                        if let Some(reap) = ops.iter().position(|op| matches!(op, Op::Reap { .. }))
                        {
                            assert!(last_signal < Some(reap), "{label}: reap before final kill");
                        }
                        // Never success; the leader is reaped or retained.
                        assert!(!report.success_eligible, "{label}");
                        assert_ne!(
                            report.outcome,
                            StepOutcome::Action(ActionOutcome::ReportedSuccess)
                        );
                        assert_ne!(report.outcome, StepOutcome::Verify(VerifyOutcome::Isolated));
                        if report.retained {
                            let view = backend.pending_reap_diagnostics().unwrap();
                            assert_eq!(view.pid, pid);
                            let reason = if to < r {
                                RetentionReason::ReapFailed
                            } else {
                                RetentionReason::ReturnDeadlineReached
                            };
                            assert_eq!(view.reason, reason, "{label}");
                        } else {
                            assert!(report.leader_status.is_some(), "{label}");
                            assert!(backend.pending_reap_diagnostics().is_none());
                        }
                    }
                }
            }
        }
        assert_eq!(cases, 2 * 5 * (3 * 3 + 1));
    }

    /// F14.5-02, the exact boundaries without a late wake: a wake exactly at
    /// `execution_deadline` and `term_deadline` sends one phase-entry signal
    /// each, and a Finalization reached exactly at `hard_deadline` sends only
    /// its own SIGKILL.
    #[test]
    fn stage14_5_on_time_boundaries_send_each_signal_once() {
        for kind in KINDS {
            let (backend, report) = late_wake_step(
                kind,
                Held::AlivePipesOpen,
                Duration::from_secs(1),
                Duration::from_secs(1),
            );
            let deadlines = report.deadlines.unwrap();
            assert_eq!(
                signals(&backend.driver.ops),
                vec![
                    (GroupSignal::Term, deadlines.execution_deadline),
                    (GroupSignal::Kill, deadlines.term_deadline),
                    (GroupSignal::Kill, deadlines.hard_deadline),
                ]
            );
            assert_eq!(report.returned_at, deadlines.hard_deadline);
        }
    }

    /// F14.5-03 (M13): an error from the non-reaping exit query is never
    /// leader exit. With a persistent error the step never resolves, runs
    /// the ordinary TERM → KILL → Finalization path, and is never
    /// success-eligible; the leader is still reaped after the final group
    /// SIGKILL or retained in the slot, never dropped.
    #[test]
    fn stage14_5_exit_query_error_is_never_leader_exit() {
        for kind in KINDS {
            for unreapable in [false, true] {
                let mut script = Script::finishes_after(Duration::from_millis(100), b"isolated\n");
                script.unreapable = unreapable;
                let mut backend = fake(script);
                backend.driver.exit_query_error = Some(10);
                let start = backend.driver.base;
                let argv = fake_argv();
                let report = backend
                    .run_step(&request(&argv, timeout(kind, 2)))
                    .expect("no invariant violation");
                let deadlines = report.deadlines.unwrap();
                let ops = backend.driver.ops.clone();
                assert_bounded(&report, &ops, start, Duration::from_secs(2));
                let timeline = report.timeline.unwrap();
                assert_eq!(timeline.leader_exit_observed_at, None);
                assert_eq!(timeline.resolved_at, None);
                assert!(!report.success_eligible);
                assert_eq!(report.outcome, not_success(kind));
                assert_eq!(
                    signals(&ops),
                    vec![
                        (GroupSignal::Term, deadlines.execution_deadline),
                        (GroupSignal::Kill, deadlines.term_deadline),
                        (GroupSignal::Kill, deadlines.hard_deadline),
                    ]
                );
                let last_signal = ops.iter().rposition(|op| matches!(op, Op::Signal { .. }));
                let reap = ops.iter().position(|op| matches!(op, Op::Reap { .. }));
                assert!(last_signal < reap);
                if unreapable {
                    assert!(report.retained);
                    assert_eq!(
                        backend.pending_reap_diagnostics().unwrap().pid,
                        report.pid.unwrap()
                    );
                } else {
                    assert!(!report.retained);
                    assert_eq!(report.leader_status, Some(LeaderStatus::Code(0)));
                }
                assert!(backend.driver.unreaped_drops().is_empty());
            }

            // One interrupted query, then a real exit observation: the step
            // resolves, but the recorded query error still forbids success.
            let mut backend = fake(Script::finishes_after(
                Duration::from_millis(100),
                b"isolated\n",
            ));
            backend.driver.exit_query_script.push_back(Err(4));
            let argv = fake_argv();
            let report = backend
                .run_step(&request(&argv, timeout(kind, 2)))
                .expect("no invariant violation");
            let timeline = report.timeline.unwrap();
            assert!(
                timeline.leader_exit_observed_at.unwrap()
                    >= backend.driver.base + Duration::from_millis(100)
            );
            assert!(timeline.resolved_at.is_some());
            assert!(!report.success_eligible);
            assert_eq!(report.outcome, not_success(kind));
        }
    }

    /// F14.5-03 (M19): a gate poll that returns an error or EINTR while the
    /// slot stays occupied refuses the spawn exactly like `NotReaped`: no
    /// deadline, no trust check, no spawn, the retained handle is kept (same
    /// pid, never dropped or overwritten), and later steps stay refused
    /// until a real reap clears the slot.
    #[test]
    fn stage14_5_gate_poll_error_while_occupied_never_spawns() {
        for kind in KINDS {
            let (mut backend, report) = retained(StepKind::Action);
            let pid = report.pid.unwrap();
            let argv = fake_argv();
            for (injected, expected, last) in [
                (
                    ReapResult::Error(10),
                    PendingReapPoll::Error {
                        errno: 10,
                        transitioned: true,
                    },
                    LastPoll::Error(10),
                ),
                (
                    ReapResult::Error(10),
                    PendingReapPoll::Error {
                        errno: 10,
                        transitioned: false,
                    },
                    LastPoll::Error(10),
                ),
                (
                    ReapResult::Interrupted,
                    PendingReapPoll::Interrupted,
                    LastPoll::Interrupted,
                ),
                (
                    ReapResult::Error(4),
                    PendingReapPoll::Error {
                        errno: 4,
                        transitioned: true,
                    },
                    LastPoll::Error(4),
                ),
                (
                    ReapResult::NotExited,
                    PendingReapPoll::NotReaped,
                    LastPoll::NotReaped,
                ),
            ] {
                backend.driver.reap_script.push_back(injected);
                let before = backend.driver.ops.len();
                let refused = backend
                    .run_step(&request(&argv, timeout(kind, 5)))
                    .expect("a refused step is not an invariant violation");
                assert_eq!(refused.gate_poll, expected);
                assert_eq!(refused.outcome, spawn_failed(kind));
                assert_eq!(
                    refused.spawn_failure,
                    Some(SpawnFailure::PendingReapOccupied)
                );
                assert_eq!(refused.reasons, vec![StepReason::PendingReapOccupied]);
                assert_eq!(refused.deadlines, None);
                assert_eq!(refused.pid, None);
                // Exactly the one gate reap: no trust, spawn, or signal.
                let at = backend.driver.now;
                assert_eq!(backend.driver.ops[before..], [Op::Reap { pid, at }]);
                let view = backend.pending_reap_diagnostics().unwrap();
                assert_eq!(view.pid, pid);
                assert_eq!(view.last_poll, last);
            }
            assert_eq!(backend.driver.spawns, 1, "no spawn after the transfer");
            assert!(backend.driver.unreaped_drops().is_empty());
            // Only a real reap clears the slot; then exactly one spawn.
            backend.driver.released.insert(pid);
            backend.driver.script = Script::finishes_after(Duration::ZERO, b"isolated\n");
            let next = backend
                .run_step(&request(&argv, timeout(kind, 5)))
                .expect("no invariant violation");
            assert!(matches!(next.gate_poll, PendingReapPoll::Reaped { .. }));
            assert_eq!(backend.driver.spawns, 2);
            assert!(backend.driver.unreaped_drops().is_empty());
        }
    }

    /// Real driver whose first sub-wait at or after `oversleep_from` (from
    /// step start) returns only at `wake_at` (from step start): a real late
    /// scheduler wake. Every operation is logged with its instant.
    #[derive(Debug)]
    struct Oversleeping {
        inner: SystemProcessDriver,
        started: std::cell::Cell<Option<Instant>>,
        oversleep_from: Duration,
        wake_at: Duration,
        overslept: bool,
        log: Vec<(&'static str, Instant)>,
    }

    impl Oversleeping {
        fn new(oversleep_from: Duration, wake_at: Duration) -> Self {
            Self {
                inner: SystemProcessDriver,
                started: std::cell::Cell::new(None),
                oversleep_from,
                wake_at,
                overslept: false,
                log: Vec::new(),
            }
        }
    }

    // `Cell` is only touched by the thread that runs the step.
    unsafe impl Send for Oversleeping {}

    impl ProcessDriver for Oversleeping {
        type Leader = Child;

        fn now(&self) -> Instant {
            let now = self.inner.now();
            if self.started.get().is_none() {
                self.started.set(Some(now));
            }
            now
        }

        fn sleep(&mut self, duration: Duration) {
            let now = Instant::now();
            self.log.push(("sleep", now));
            let started = self.started.get().expect("step started");
            if !self.overslept && now >= started + self.oversleep_from {
                self.overslept = true;
                let wake = started + self.wake_at;
                std::thread::sleep(wake.saturating_duration_since(now));
            } else {
                self.inner.sleep(duration);
            }
        }

        fn check_trust(&mut self, executable: &str) -> Result<(), TrustRefusal> {
            self.inner.check_trust(executable)
        }

        fn spawn(&mut self, plan: &SpawnPlan<'_>) -> Result<Child, i32> {
            self.inner.spawn(plan)
        }

        fn leader_pid(&self, leader: &Child) -> u32 {
            self.inner.leader_pid(leader)
        }

        fn set_nonblocking(&mut self, leader: &mut Child, stream: Stream) -> Result<(), i32> {
            self.inner.set_nonblocking(leader, stream)
        }

        fn read(&mut self, leader: &mut Child, stream: Stream, buffer: &mut [u8]) -> ReadResult {
            self.log.push(("read", Instant::now()));
            self.inner.read(leader, stream, buffer)
        }

        fn leader_exited(&mut self, leader: &Child) -> Result<bool, i32> {
            self.log.push(("exit_query", Instant::now()));
            self.inner.leader_exited(leader)
        }

        fn signal_group(&mut self, pgid: u32, signal: GroupSignal) -> Result<(), i32> {
            let name = match signal {
                GroupSignal::Term => "term",
                GroupSignal::Kill => "kill",
            };
            self.log.push((name, Instant::now()));
            self.inner.signal_group(pgid, signal)
        }

        fn close_read_end(&mut self, leader: &mut Child, stream: Stream) {
            self.log.push(("close", Instant::now()));
            self.inner.close_read_end(leader, stream)
        }

        fn try_reap(&mut self, leader: &mut Child) -> ReapResult {
            self.log.push(("reap", Instant::now()));
            self.inner.try_reap(leader)
        }
    }

    /// F14.5-02 with real processes: a TERM-ignoring leader holds both pipes;
    /// the step thread really sleeps through `hard_deadline` (from the
    /// Execution phase, and from the TERM phase after its on-time TERM). On
    /// the wake only the Finalization runs: one group SIGKILL, two closes,
    /// at most one reap; no TERM, read, exit query, or sleep at or after
    /// `hard_deadline`.
    #[test]
    fn stage14_5_real_late_wake_past_hard_deadline_sends_one_kill() {
        let handles: Vec<_> = [Duration::from_millis(500), Duration::from_millis(1500)]
            .into_iter()
            .map(|oversleep_from| {
                std::thread::spawn(move || {
                    let driver = Oversleeping::new(oversleep_from, Duration::from_millis(5200));
                    let argv = script("trap '' TERM; exec sleep 600", &[]);
                    let (sender, receiver) = mpsc::channel();
                    std::thread::spawn(move || {
                        let mut backend = CommandBackend::new(driver);
                        let report = backend
                            .run_step(&request(&argv, timeout(StepKind::Action, 1)))
                            .expect("no invariant violation");
                        let step_log = backend.driver.log.clone();
                        // Release a retained leader (already SIGKILLed) so the
                        // test leaves no zombie: bounded polling, test only.
                        let until = Instant::now() + Duration::from_secs(5);
                        while backend.pending_reap_diagnostics().is_some() && Instant::now() < until
                        {
                            backend.poll_pending_reap();
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        let cleared = backend.pending_reap_diagnostics().is_none();
                        let _ = sender.send((report, cleared, step_log));
                    });
                    let (report, cleared, log) = receiver
                        .recv_timeout(Duration::from_secs(20))
                        .expect("emergency watchdog: the step did not return");
                    let deadlines = report.deadlines.unwrap();
                    let hard = deadlines.hard_deadline;
                    let after: Vec<&str> = log
                        .iter()
                        .filter(|(_, at)| *at >= hard)
                        .map(|(name, _)| *name)
                        .collect();
                    let reaps = after.iter().filter(|name| **name == "reap").count();
                    assert!(reaps <= 1, "{after:?}");
                    assert_eq!(&after[..3], ["kill", "close", "close"], "{after:?}");
                    assert_eq!(after.len(), 3 + reaps, "{after:?}");
                    let before: Vec<&str> = log
                        .iter()
                        .filter(|(name, at)| *at < hard && (*name == "term" || *name == "kill"))
                        .map(|(name, _)| *name)
                        .collect();
                    if oversleep_from >= Duration::from_secs(1) {
                        assert_eq!(before, ["term"], "the on-time TERM only");
                    } else {
                        assert!(before.is_empty(), "{before:?}");
                    }
                    assert!(report.timeline.unwrap().finalization_at >= hard);
                    assert!(!report.success_eligible);
                    assert_eq!(report.outcome, not_success(StepKind::Action));
                    assert!(cleared, "retained leader was never reaped");
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
    }

    /// F14.5-04: the manual `si_pid` offset agrees with the target `libc`
    /// accessor (the numeric values are checked at build time).
    #[cfg(target_os = "linux")]
    #[test]
    fn stage14_5_linux_siginfo_pid_offset_matches_libc() {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::siginfo_t>();
        let bytes = unsafe {
            std::slice::from_raw_parts_mut((&mut info as *mut libc::siginfo_t).cast::<u8>(), size)
        };
        let marker: i32 = 0x1234_5678;
        bytes[sys::SI_PID_OFFSET..sys::SI_PID_OFFSET + 4].copy_from_slice(&marker.to_ne_bytes());
        assert_eq!(unsafe { info.si_pid() }, marker);
    }

    // ---------------------------------------------------------------------
    // Phase 14.6 (DC-14.6-01 Option 1): the runtime-facing pending-reap
    // lifecycle helpers used by the LinuxNodeRuntime owner.
    // ---------------------------------------------------------------------

    fn reap_ops(ops: &[Op]) -> usize {
        count(ops, |op| matches!(op, Op::Reap { .. }))
    }

    /// PR-04 (backend part): every ordinary-iteration poll is exactly one
    /// non-blocking reap, with no signal, sleep, read or spawn. Only the §28
    /// transitions produce a log line, and a line carries provenance but
    /// never argv, environment or the incident UUID.
    #[test]
    fn stage14_6_foreground_poll_is_one_reap_with_section_28_lines() {
        let mut empty = fake(Script::finishes_after(Duration::ZERO, b""));
        for _ in 0..10 {
            assert_eq!(empty.foreground_pending_reap(), None);
        }
        assert!(empty.driver.ops.is_empty(), "an empty slot costs nothing");

        let (mut backend, report) = retained(StepKind::Verify);
        let pid = report.pid.unwrap();
        let before = backend.driver.ops.len();
        for iteration in 0..100 {
            let ops = backend.driver.ops.len();
            assert_eq!(backend.foreground_pending_reap(), None, "{iteration}");
            assert_eq!(backend.driver.ops.len(), ops + 1);
        }
        backend
            .driver
            .reap_script
            .push_back(ReapResult::Interrupted);
        assert_eq!(backend.foreground_pending_reap(), None);
        backend.driver.advance(Duration::from_millis(1500));
        let age = backend
            .pending_reap_diagnostics()
            .unwrap()
            .age(backend.driver.now);
        backend.driver.reap_script.push_back(ReapResult::Error(10));
        let warn = backend
            .foreground_pending_reap()
            .expect("errno transition WARN");
        // The age comes from the driver clock at the moment the line is made.
        assert!(
            warn.contains(&format!("age_ms={} ", age.as_millis())),
            "{warn}"
        );
        backend.driver.reap_script.push_back(ReapResult::Error(10));
        assert_eq!(backend.foreground_pending_reap(), None, "same errno again");
        assert!(warn.starts_with("WARN pending_reap poll error errno 10"));
        for field in [
            "pending_present=true",
            "kind=Verify",
            "incident_seq=7",
            "attempt_token=3",
            &format!("pid={pid}"),
            "age_ms=",
            "last_poll=Error(10)",
        ] {
            assert!(warn.contains(field), "{field}: {warn}");
        }
        for secret in [INCIDENT_ID, "/usr/lib/mikagami/fence", "MIKAGAMI_", "PATH="] {
            assert!(!warn.contains(secret), "{secret}: {warn}");
        }
        assert_eq!(backend.pending_reap_diagnostics().unwrap().pid, pid);

        backend.driver.released.insert(pid);
        let info = backend.foreground_pending_reap().expect("clear INFO");
        assert!(info.starts_with("INFO pending_reap cleared"), "{info}");
        assert!(info.contains("pending_present=false"));
        assert!(backend.pending_reap_diagnostics().is_none());
        assert_eq!(backend.foreground_pending_reap(), None);
        let ops = &backend.driver.ops[before..];
        assert_eq!(ops.len(), 104, "one reap per non-empty poll only");
        assert!(
            ops.iter()
                .all(|op| matches!(op, Op::Reap { pid: reaped, .. } if *reaped == pid))
        );
        assert!(backend.driver.unreaped_drops().is_empty());
    }

    /// PR-07 / G8-C (backend part): the shutdown classification makes exactly
    /// one non-blocking poll and no wait or signal. Empty is clean-eligible;
    /// occupied never is and says why; a leader reapable just before the
    /// shutdown poll clears the slot. A poll error keeps the slot (fail
    /// closed).
    #[test]
    fn stage14_6_shutdown_poll_requires_an_empty_slot() {
        let mut empty = fake(Script::finishes_after(Duration::ZERO, b""));
        assert_eq!(
            empty.shutdown_pending_reap(),
            ShutdownPendingReap {
                slot_empty: true,
                log_lines: Vec::new(),
            }
        );
        assert!(empty.driver.ops.is_empty());

        let (mut backend, report) = retained(StepKind::Action);
        let pid = report.pid.unwrap();
        let before = backend.driver.ops.len();
        let occupied = backend.shutdown_pending_reap();
        assert!(!occupied.slot_empty);
        assert_eq!(occupied.log_lines.len(), 1);
        let warn = &occupied.log_lines[0];
        assert!(
            warn.contains("shutdown requires cleanup: pending_reap_occupied"),
            "{warn}"
        );
        assert!(warn.contains(&format!("pid={pid}")) && warn.contains("kind=Action"));
        assert_eq!(reap_ops(&backend.driver.ops[before..]), 1);
        assert_eq!(
            backend.driver.ops.len(),
            before + 1,
            "no signal, sleep or read"
        );

        backend.driver.reap_script.push_back(ReapResult::Error(10));
        let errored = backend.shutdown_pending_reap();
        assert!(!errored.slot_empty, "an unprovable reap is never clean");
        assert_eq!(errored.log_lines.len(), 2);
        assert_eq!(backend.pending_reap_diagnostics().unwrap().pid, pid);

        backend.driver.released.insert(pid);
        let cleared = backend.shutdown_pending_reap();
        assert!(cleared.slot_empty);
        assert_eq!(cleared.log_lines.len(), 1);
        assert!(cleared.log_lines[0].starts_with("INFO pending_reap cleared"));
        assert_eq!(reap_ops(&backend.driver.ops[before..]), 3);
        assert_eq!(signals(&backend.driver.ops[before..]).len(), 0);
        assert!(backend.driver.unreaped_drops().is_empty());
    }

    /// §16.7.3: the invariant violation maps to the class-D message. The
    /// occupied slot keeps its leader and is never overwritten or cleared;
    /// only the rejected handle is released.
    #[test]
    fn stage14_6_invariant_violation_maps_without_touching_the_slot() {
        let (mut backend, report) = retained(StepKind::Action);
        let existing = report.pid.unwrap();
        let now = backend.driver.now;
        let intruder = PendingReap {
            child: FakeLeader {
                pid: 9999,
                reaped: false,
                drops: Rc::clone(&backend.driver.drops),
            },
            pid: 9999,
            pgid: 9999,
            step_kind: StepKind::Verify,
            incident_seq: 8,
            incident_id: IncidentId::new(INCIDENT_ID),
            attempt_token: 4,
            step_started_at: now,
            hard_deadline: now,
            retained_at: now,
            final_kill: FinalKill::Sent,
            reason: RetentionReason::ReapFailed,
            polls: 0,
            last_poll: LastPoll::None,
        };
        let message = backend
            .transfer(intruder)
            .unwrap_err()
            .into_observation_invariant();
        assert!(
            message.starts_with("pending_reap invariant violation"),
            "{message}"
        );
        assert!(message.contains(&format!("existing pid {existing}")));
        assert!(message.contains("rejected pid 9999"));
        assert!(!message.contains(INCIDENT_ID));
        assert_eq!(backend.pending_reap_diagnostics().unwrap().pid, existing);
        assert_eq!(backend.driver.unreaped_drops(), vec![9999]);
        assert_eq!(backend.driver.spawns, 1);
    }

    fn stage14_7_section(fence: &str, verify: &str) -> FencingConfig {
        FencingConfig {
            backend: FencingBackendKind::Command,
            fence: Some(vec![fence.to_string(), "--off".to_string()]),
            verify: Some(vec![verify.to_string()]),
            fence_timeout_sec: Some(30),
            verify_timeout_sec: Some(10),
            verify_polls: Some(6),
        }
    }

    fn stage14_7_none(fence_timeout_sec: Option<u64>) -> FencingConfig {
        FencingConfig {
            backend: FencingBackendKind::None,
            fence: None,
            verify: None,
            fence_timeout_sec,
            verify_timeout_sec: None,
            verify_polls: None,
        }
    }

    /// Records every trust-checked path and refuses the ones listed.
    fn stage14_7_startup(
        section: Option<&FencingConfig>,
        refuse: &[&str],
    ) -> (Result<FencingSettings, FencingStartupError>, Vec<String>) {
        let mut checked = Vec::new();
        let result = FencingSettings::startup_with(section, |executable| {
            checked.push(executable.to_string());
            if refuse.contains(&executable) {
                Err(TrustRefusal::NotRootOwned)
            } else {
                Ok(())
            }
        });
        (result, checked)
    }

    /// §16.1: backend `none` (absent or explicit) has no executable, so
    /// startup performs no trust check at all.
    #[test]
    fn stage14_7_backend_none_performs_no_trust_check() {
        for section in [
            None,
            Some(stage14_7_none(None)),
            Some(stage14_7_none(Some(60))),
        ] {
            let (result, checked) = stage14_7_startup(section.as_ref(), &[]);
            assert_eq!(result, Ok(FencingSettings::None));
            assert!(checked.is_empty(), "{checked:?}");
        }
    }

    /// §16.2 at startup: `fence[0]` and `verify[0]`, each exactly once.
    #[test]
    fn stage14_7_command_trust_checks_fence_and_verify_argv0() {
        let section = stage14_7_section("/opt/fence", "/opt/verify");
        let (result, checked) = stage14_7_startup(Some(&section), &[]);
        assert_eq!(checked, ["/opt/fence", "/opt/verify"]);
        let Ok(FencingSettings::Command(command)) = result else {
            panic!("expected command settings: {result:?}");
        };
        assert_eq!(command.fence, ["/opt/fence", "--off"]);
        assert_eq!(command.verify, ["/opt/verify"]);
        assert_eq!(command.fence_timeout, StepTimeout::fence(30).unwrap());
        assert_eq!(command.verify_timeout, StepTimeout::verify(10).unwrap());
        assert_eq!(command.verify_polls, 6);
    }

    #[test]
    fn stage14_7_untrusted_fence_or_verify_refuses_startup() {
        let section = stage14_7_section("/opt/fence", "/opt/verify");
        let (result, checked) = stage14_7_startup(Some(&section), &["/opt/fence"]);
        assert_eq!(
            result,
            Err(FencingStartupError::Untrusted {
                field: "fence",
                executable: "/opt/fence".to_string(),
                refusal: TrustRefusal::NotRootOwned,
            })
        );
        assert_eq!(checked, ["/opt/fence"]);
        let (result, checked) = stage14_7_startup(Some(&section), &["/opt/verify"]);
        assert_eq!(
            result,
            Err(FencingStartupError::Untrusted {
                field: "verify",
                executable: "/opt/verify".to_string(),
                refusal: TrustRefusal::NotRootOwned,
            })
        );
        assert_eq!(checked, ["/opt/fence", "/opt/verify"]);
    }

    /// An invalid section is refused before any executable is examined.
    #[test]
    fn stage14_7_invalid_section_refuses_before_trust() {
        let mut section = stage14_7_section("/opt/fence", "/opt/verify");
        section.fence_timeout_sec = Some(MAX_FENCE_TIMEOUT_SEC + 1);
        let (result, checked) = stage14_7_startup(Some(&section), &[]);
        assert!(
            matches!(result, Err(FencingStartupError::Invalid(_))),
            "{result:?}"
        );
        assert!(checked.is_empty());
    }

    /// The production startup entry uses the real §16.2 check.
    #[test]
    fn stage14_7_real_startup_trust_check() {
        let trusted = trusted(&["/usr/bin/true", "/bin/true"]);
        let accepted = FencingSettings::startup(Some(&stage14_7_section(&trusted, &trusted)));
        assert!(
            matches!(accepted, Ok(FencingSettings::Command(_))),
            "{accepted:?}"
        );

        let own = temp_path("stage14-7-own");
        fs::write(&own, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&own, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let own_path = own.display().to_string();
        let expected = check_executable_trust(&own_path).unwrap_err();
        let fence = FencingSettings::startup(Some(&stage14_7_section(&own_path, &trusted)));
        let verify = FencingSettings::startup(Some(&stage14_7_section(&trusted, &own_path)));
        fs::remove_file(&own).unwrap();
        for (field, result) in [("fence", fence), ("verify", verify)] {
            assert_eq!(
                result,
                Err(FencingStartupError::Untrusted {
                    field,
                    executable: own_path.clone(),
                    refusal: expected,
                })
            );
        }
    }

    /// Startup validates and trust-checks only: even an approved executable
    /// is never run (Phase 14.7 is spawn-free).
    #[test]
    fn stage14_7_startup_executes_nothing() {
        let marker = temp_path("stage14-7-marker");
        let script = temp_path("stage14-7-script");
        fs::write(&script, format!("#!/bin/sh\ntouch {}\n", marker.display())).unwrap();
        fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let path = script.display().to_string();
        let (result, checked) = stage14_7_startup(Some(&stage14_7_section(&path, &path)), &[]);
        let real = FencingSettings::startup(Some(&stage14_7_section(&path, &path)));
        std::thread::sleep(Duration::from_millis(50));
        let ran = marker.exists();
        fs::remove_file(&script).unwrap();
        assert!(matches!(result, Ok(FencingSettings::Command(_))));
        assert_eq!(checked.len(), 2);
        assert!(real.is_err());
        assert!(!ran, "startup executed a fencing command");
    }

    /// MF-44 / §16.5: the configured range is exactly the step range, so the
    /// maxima have one meaning.
    #[test]
    fn stage14_7_config_bounds_are_the_step_bounds() {
        for seconds in 0..=MAX_FENCE_TIMEOUT_SEC + 5 {
            let mut section = stage14_7_section("/opt/fence", "/opt/verify");
            section.fence_timeout_sec = Some(seconds);
            assert_eq!(
                FencingSettings::from_config(Some(&section)).is_ok(),
                StepTimeout::fence(seconds).is_ok(),
                "fence_timeout_sec {seconds}"
            );
            section.fence_timeout_sec = Some(30);
            section.verify_timeout_sec = Some(seconds);
            assert_eq!(
                FencingSettings::from_config(Some(&section)).is_ok(),
                StepTimeout::verify(seconds).is_ok(),
                "verify_timeout_sec {seconds}"
            );
            section.verify_timeout_sec = Some(10);
            section.verify_polls = Some(seconds);
            assert_eq!(
                FencingSettings::from_config(Some(&section)).is_ok(),
                (1..=MAX_VERIFY_POLLS).contains(&seconds),
                "verify_polls {seconds}"
            );
        }
        assert_eq!(MAX_FENCE_TIMEOUT_SEC, 60);
        assert_eq!(MAX_VERIFY_TIMEOUT_SEC, 30);
        assert_eq!(MAX_VERIFY_POLLS, 60);
    }

    /// The transitional diagnostic states that command fencing is inactive.
    #[test]
    fn stage14_7_startup_notice_and_refusal_text() {
        assert_eq!(FencingSettings::None.startup_notice(), None);
        let command =
            FencingSettings::from_config(Some(&stage14_7_section("/opt/f", "/opt/v"))).unwrap();
        let notice = command.startup_notice().unwrap();
        assert!(notice.contains("backend \"command\""));
        // Phase 14.9: the steps are reachable, and the text still states the
        // fail-closed gate (no activation attempt passes it in this build).
        assert!(notice.contains("run only for an operator-requested incident"));
        assert!(notice.contains("never lets an activation attempt past the fencing gate"));
        assert!(!notice.contains("does not execute fence or verify commands"));
        let untrusted = FencingStartupError::Untrusted {
            field: "verify",
            executable: "/opt/v".to_string(),
            refusal: TrustRefusal::NotRootOwned,
        };
        assert_eq!(
            untrusted.to_string(),
            "fencing.verify[0] /opt/v is not a trusted executable: NotRootOwned"
        );
        let invalid = FencingStartupError::Invalid(vec!["a".to_string(), "b".to_string()]);
        assert_eq!(invalid.to_string(), "invalid [fencing] configuration; a; b");
    }
}

/// Phase 14.6 test support for the runtime owner's composition tests in other
/// modules: a driver that can only answer reap polls, and a seam that places a
/// leader in the slot through the one transfer writer. Test-only; it sits
/// after `mod tests` so production-source guards never count it.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Debug)]
    pub(crate) struct TestLeader(pub(crate) u32);

    /// Answers only `try_reap` (scripted, else not exited). Every process,
    /// signal, clock-wait or pipe operation panics, so a composition test
    /// fails if the runtime integration ever spawns, signals or waits.
    #[derive(Debug, Default)]
    pub(crate) struct ScriptedReapDriver {
        pub(crate) reaps: VecDeque<ReapResult>,
        pub(crate) reap_calls: u32,
    }

    impl ProcessDriver for ScriptedReapDriver {
        type Leader = TestLeader;

        fn now(&self) -> Instant {
            Instant::now()
        }
        fn sleep(&mut self, _: Duration) {
            panic!("pending-reap runtime integration must never sleep");
        }
        fn check_trust(&mut self, _: &str) -> Result<(), TrustRefusal> {
            panic!("pending-reap runtime integration must never run a step");
        }
        fn spawn(&mut self, _: &SpawnPlan<'_>) -> Result<TestLeader, i32> {
            panic!("pending-reap runtime integration must never spawn");
        }
        fn leader_pid(&self, leader: &TestLeader) -> u32 {
            leader.0
        }
        fn set_nonblocking(&mut self, _: &mut TestLeader, _: Stream) -> Result<(), i32> {
            panic!("pending-reap runtime integration must never touch pipes");
        }
        fn read(&mut self, _: &mut TestLeader, _: Stream, _: &mut [u8]) -> ReadResult {
            panic!("pending-reap runtime integration must never read");
        }
        fn leader_exited(&mut self, _: &TestLeader) -> Result<bool, i32> {
            panic!("pending-reap runtime integration must never query exit");
        }
        fn signal_group(&mut self, _: u32, _: GroupSignal) -> Result<(), i32> {
            panic!("pending-reap runtime integration must never signal");
        }
        fn close_read_end(&mut self, _: &mut TestLeader, _: Stream) {
            panic!("pending-reap runtime integration must never close pipes");
        }
        fn try_reap(&mut self, _: &mut TestLeader) -> ReapResult {
            self.reap_calls += 1;
            self.reaps.pop_front().unwrap_or(ReapResult::NotExited)
        }
    }

    /// Places `leader` in the slot through the only writer (`transfer`).
    pub(crate) fn retain<D: ProcessDriver>(
        backend: &mut CommandBackend<D>,
        leader: D::Leader,
        pid: u32,
    ) -> Result<(), PendingReapInvariantViolation<D::Leader>> {
        let now = Instant::now();
        backend.transfer(PendingReap {
            child: leader,
            pid,
            pgid: pid,
            step_kind: StepKind::Verify,
            incident_seq: 7,
            incident_id: IncidentId::new("5f0c6a8e-3c1b-4c55-9a47-2f6f5e1d9b10"),
            attempt_token: 3,
            step_started_at: now,
            hard_deadline: now,
            retained_at: now,
            final_kill: FinalKill::Sent,
            reason: RetentionReason::ReapFailed,
            polls: 0,
            last_poll: LastPoll::None,
        })
    }

    pub(crate) fn driver<D: ProcessDriver>(backend: &mut CommandBackend<D>) -> &mut D {
        &mut backend.driver
    }
}
