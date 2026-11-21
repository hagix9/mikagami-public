//! Linux systemd service backend.
//!
//! The backend deliberately keeps action diagnostics separate from the
//! machine-readable service and health observations obtained afterwards.
//!
//! Bounded execution (FH-1). One command (`systemctl start|stop|show`, or the
//! health program) is run by the calling thread alone; there is no reader
//! thread. After the spawn, every wait is a non-blocking step: `try_wait`, a
//! read on a non-blocking pipe, `kill`, or a sleep slice no longer than the
//! time left. The call ends at the configured timeout (at most
//! `ACTION_TIMEOUT_CEILING_SEC`, checked with `checked_add` before the spawn)
//! plus the cleanup budgets named below; it never ends in an unbounded
//! `join`, `read` or `wait`.
//! - The child's exit and the completeness of its output are separate facts.
//!   After the exit the pipe is drained until EOF or the same deadline (one
//!   more pass is always made, so data the child already wrote is read). A
//!   pipe still open then is held by a process other than the child; the
//!   output is `unfinished` and `systemctl show` is never read from it.
//! - An exit that is first seen at or after the deadline is a timeout, not a
//!   success (the exit time is unknowable, so a late exit is never promoted).
//! - On the deadline the direct child gets SIGKILL (the systemd backend has no
//!   TERM / grace step) and is reaped by polling `try_wait` for at most
//!   `KILL_REAP_BUDGET`. A child that cannot be reaped in that time, or whose
//!   wait query fails, is not forgotten: it stays as the backend's one owed
//!   child and every later command (action, `show`, health) is refused until
//!   a later call reaps it (one more kill, `RETRY_REAP_BUDGET` of polling,
//!   only while the wait query still says the pid is our unreaped child).
//!   A failed wait query is never followed by a signal: the pid may no longer
//!   be ours. The exception that settles the debt is `ECHILD` (the child is no
//!   longer ours, so it is gone): the slot is cleared, still without a signal
//!   and without turning the uncertain result of that call into a success.
//!   This relies on the fixed deployment premise that nothing else in the
//!   process reaps this backend's children.
//! - The pipe's read end lives only inside the call and is closed when it
//!   returns, so nothing accumulates over repeated timeouts and a late writer
//!   can never reach a later command's output.
//!
//! The bound assumes that the non-blocking calls above return. The spawn
//! itself (fork/exec of a target that blocks) and a child in uninterruptible
//! sleep are outside any bound this process can give; the latter is reported
//! as an uncertain cleanup and keeps the child owed, never as success.

use super::{ActionDiagnostic, RawHealthObservation, RawServiceObservation};
use crate::config::ACTION_TIMEOUT_CEILING_SEC;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_SYSTEMCTL_PATH: &str = "/usr/bin/systemctl";
const MAX_CAPTURED_OUTPUT: usize = 4096;
const READ_BUFFER_SIZE: usize = 1024;
/// Reads per drain pass: keeps a chatty writer from monopolising the loop.
const DRAIN_READS_PER_PASS: usize = 64;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
/// `ECHILD` (the same value on Linux and macOS).
const ECHILD: i32 = 10;
#[cfg(target_os = "linux")]
const _: () = assert!(ECHILD == libc::ECHILD);
/// After the deadline SIGKILL: how long `try_wait` is polled for the reap.
const KILL_REAP_BUDGET: Duration = Duration::from_secs(2);
/// When a later call retries an owed child: how long it polls after one kill.
const RETRY_REAP_BUDGET: Duration = Duration::from_millis(200);

/// `O_NONBLOCK` for the pipe the output is read from. The same two fcntl
/// commands and flag values as the command backend, checked against `libc` on
/// Linux at compile time. No signal, wait or process-group call lives here.
mod pipe {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    compile_error!("systemd_service: the non-blocking flag is verified only for Linux and macOS");

    #[cfg(target_os = "linux")]
    const O_NONBLOCK: i32 = 0o4000;
    #[cfg(target_os = "macos")]
    const O_NONBLOCK: i32 = 0x4;
    const F_GETFL: i32 = 3;
    const F_SETFL: i32 = 4;

    #[cfg(target_os = "linux")]
    const _: () = assert!(
        O_NONBLOCK == libc::O_NONBLOCK && F_GETFL == libc::F_GETFL && F_SETFL == libc::F_SETFL
    );

    unsafe extern "C" {
        fn fcntl(fd: i32, command: i32, ...) -> i32;
    }

    pub fn set_nonblocking(fd: i32) -> Result<(), i32> {
        // SAFETY: plain fcntl on a descriptor owned by the caller.
        let flags = unsafe { fcntl(fd, F_GETFL) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
        }
        // SAFETY: as above.
        if unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) } < 0 {
            return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SystemdServiceConfigError(String);

impl std::fmt::Display for SystemdServiceConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for SystemdServiceConfigError {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Program {
    path: PathBuf,
    arguments: Vec<String>,
}

impl Program {
    fn new(
        path: impl Into<PathBuf>,
        arguments: Vec<String>,
        label: &str,
    ) -> Result<Self, SystemdServiceConfigError> {
        let path = path.into();
        if !path.is_absolute() {
            return Err(SystemdServiceConfigError(format!(
                "{label} path must be absolute"
            )));
        }
        if path.as_os_str().is_empty() {
            return Err(SystemdServiceConfigError(format!(
                "{label} path must not be empty"
            )));
        }
        if arguments.iter().any(|argument| argument.contains('\0')) {
            return Err(SystemdServiceConfigError(format!(
                "{label} arguments must not contain NUL"
            )));
        }
        Ok(Self { path, arguments })
    }
}

/// The OS-facing steps of a command's child handling, as plain function
/// pointers so a test can make each of them fail. Production is `PRODUCTION`.
#[derive(Debug, Clone, Copy)]
struct ChildOps {
    kill: fn(&mut Child) -> std::io::Result<()>,
    try_wait: fn(&mut Child) -> std::io::Result<Option<ExitStatus>>,
    set_nonblocking: fn(i32) -> Result<(), i32>,
    kill_reap_budget: Duration,
    retry_reap_budget: Duration,
}

impl ChildOps {
    const PRODUCTION: Self = Self {
        kill: Child::kill,
        try_wait: Child::try_wait,
        set_nonblocking: pipe::set_nonblocking,
        kill_reap_budget: KILL_REAP_BUDGET,
        retry_reap_budget: RETRY_REAP_BUDGET,
    };
}

/// The one child this backend still owes a reap for. A deadline kill whose
/// reap could not be confirmed, or a failed wait query, parks the child here;
/// no command is spawned while the slot is occupied.
#[derive(Debug)]
struct Children {
    pending: Option<Child>,
    ops: ChildOps,
}

impl Children {
    fn new(ops: ChildOps) -> Self {
        Self { pending: None, ops }
    }

    /// Try to discharge the owed child; `true` when nothing is owed. Bounded
    /// by `retry_reap_budget`. Another kill is sent only while `try_wait`
    /// still reports the child as ours and running (an unreaped child keeps
    /// its pid); after a failed wait query nothing is signalled. `ECHILD` is
    /// the one failure that settles the debt: the pid is no longer our child
    /// (it was reaped by the kernel or by someone else), so there is nothing
    /// left to kill or reap. The slot is cleared without any signal and
    /// without any claim about how the child ended; the call that met the
    /// `ECHILD` keeps its uncertain result. Any other failure keeps the child.
    fn discharge(&mut self) -> bool {
        let ops = self.ops;
        let Some(child) = self.pending.as_mut() else {
            return true;
        };
        let reaped = match (ops.try_wait)(child) {
            Ok(Some(_)) => true,
            Ok(None) => {
                let _ = (ops.kill)(child);
                reap(&ops, child, ops.retry_reap_budget)
            }
            Err(error) if error.raw_os_error() == Some(ECHILD) => true,
            Err(_) => false,
        };
        if reaped {
            self.pending = None;
        }
        reaped
    }
}

#[derive(Debug)]
pub(crate) struct LinuxSystemdServiceBackend {
    unit: String,
    systemctl: Program,
    health: Program,
    start_timeout: Duration,
    stop_timeout: Duration,
    health_timeout: Duration,
    /// Owner decision A-7: the health program gets the same root-owned
    /// executable check as a `command` service program. 0 in production.
    health_trust: super::command_service::TrustPolicy,
    /// The child (of any of the three commands) that is not yet reaped.
    children: Children,
}

impl LinuxSystemdServiceBackend {
    pub(crate) fn new(
        unit: impl Into<String>,
        start_timeout: Duration,
        stop_timeout: Duration,
        health_command: Vec<String>,
        health_timeout: Duration,
    ) -> Result<Self, SystemdServiceConfigError> {
        Self::with_systemctl_path(
            unit,
            PathBuf::from(DEFAULT_SYSTEMCTL_PATH),
            start_timeout,
            stop_timeout,
            health_command,
            health_timeout,
            super::command_service::TrustPolicy::PRODUCTION,
        )
    }

    fn with_systemctl_path(
        unit: impl Into<String>,
        systemctl_path: PathBuf,
        start_timeout: Duration,
        stop_timeout: Duration,
        health_command: Vec<String>,
        health_timeout: Duration,
        health_trust: super::command_service::TrustPolicy,
    ) -> Result<Self, SystemdServiceConfigError> {
        let unit = unit.into();
        validate_unit(&unit)?;
        validate_timeout(start_timeout, "start timeout")?;
        validate_timeout(stop_timeout, "stop timeout")?;
        validate_timeout(health_timeout, "health timeout")?;

        let systemctl = Program::new(systemctl_path, Vec::new(), "systemctl")?;
        let (health_path, health_arguments) = health_command
            .split_first()
            .ok_or_else(|| SystemdServiceConfigError("health command must not be empty".into()))?;
        let health = Program::new(
            PathBuf::from(health_path),
            health_arguments.to_vec(),
            "health command",
        )?;
        validate_executable(&systemctl.path, "systemctl")?;
        if let Some(element) = health_command
            .iter()
            .find(|element| element.is_empty() || element.chars().any(char::is_control))
        {
            let _ = element;
            return Err(SystemdServiceConfigError(
                "health command must not contain empty or control-character elements".into(),
            ));
        }
        verify_health_program(&health.path, health_trust)?;

        Ok(Self {
            unit,
            systemctl,
            health,
            start_timeout,
            stop_timeout,
            health_timeout,
            health_trust,
            children: Children::new(ChildOps::PRODUCTION),
        })
    }

    fn query_timeout(&self) -> Duration {
        self.start_timeout.min(self.stop_timeout)
    }

    fn run_systemctl_action(&mut self, action: &str, timeout: Duration) -> ActionDiagnostic {
        let arguments = [action.to_string(), self.unit.clone()];
        run_action(
            &mut self.children,
            &self.systemctl.path,
            &arguments,
            timeout,
        )
    }

    fn query_service(&mut self) -> RawServiceObservation {
        let arguments = [
            "show".to_string(),
            "--no-pager".to_string(),
            "--no-legend".to_string(),
            "--property=ActiveState,SubState,LoadState".to_string(),
            self.unit.clone(),
        ];
        let timeout = self.query_timeout();
        match run_capture(
            &mut self.children,
            &self.systemctl.path,
            &arguments,
            timeout,
        ) {
            CaptureResult::Exited(status, output) if status.success() => {
                // Output that is cut off, oversized, unreadable or still being
                // written by another process is never a service state.
                if output.is_complete() {
                    classify_properties(&output.bytes)
                } else {
                    RawServiceObservation::Unavailable
                }
            }
            CaptureResult::Exited(_, _)
            | CaptureResult::SpawnFailed
            | CaptureResult::InvalidTimeout
            | CaptureResult::PendingBlocked
            | CaptureResult::TimedOut { .. } => RawServiceObservation::Unavailable,
        }
    }

    /// Whether the unit is exactly `ActiveState=failed` (loaded) right after a stop:
    /// the same strict query and parsing as `query_service`; anything unreadable is
    /// "not failed", so no reset is sent.
    fn query_failed_after_stop(&mut self) -> bool {
        let arguments = [
            "show".to_string(),
            "--no-pager".to_string(),
            "--no-legend".to_string(),
            "--property=ActiveState,SubState,LoadState".to_string(),
            self.unit.clone(),
        ];
        let timeout = self.query_timeout();
        match run_capture(
            &mut self.children,
            &self.systemctl.path,
            &arguments,
            timeout,
        ) {
            CaptureResult::Exited(status, output) if status.success() && output.is_complete() => {
                matches!(
                    parse_properties(&output.bytes),
                    Some(("failed", _, "loaded"))
                )
            }
            _ => false,
        }
    }

    fn query_health(&mut self) -> RawHealthObservation {
        // Checked again immediately before every spawn: a swapped or loosened
        // program is Unknown, never Healthy or Unhealthy.
        if verify_health_program(&self.health.path, self.health_trust).is_err() {
            return RawHealthObservation::Unavailable;
        }
        match spawn_and_wait(
            &mut self.children,
            &self.health.path,
            &self.health.arguments,
            self.health_timeout,
            false,
        ) {
            CaptureResult::Exited(status, _) if status.success() => RawHealthObservation::Healthy,
            CaptureResult::Exited(_, _) => RawHealthObservation::Unhealthy,
            CaptureResult::SpawnFailed
            | CaptureResult::InvalidTimeout
            | CaptureResult::PendingBlocked
            | CaptureResult::TimedOut { .. } => RawHealthObservation::Unavailable,
        }
    }
}

impl crate::resource_executor::sealed::ServiceBackend for LinuxSystemdServiceBackend {}

impl crate::resource_executor::ServiceBackend for LinuxSystemdServiceBackend {
    fn request_service_start(&mut self) -> ActionDiagnostic {
        self.run_systemctl_action("start", self.start_timeout)
    }

    fn observe_service(&mut self) -> RawServiceObservation {
        self.query_service()
    }

    fn request_service_stop(&mut self) -> ActionDiagnostic {
        let diagnostic = self.run_systemctl_action("stop", self.stop_timeout);
        // G-30 (Owner ruling (a), 2026-11-19): a unit whose start failed stays
        // `failed` after a successful stop, which C-6 never reads as Stopped, so a
        // cleanup could never finish. Only then, and at most once per stop,
        // `systemctl reset-failed` is sent. The stop decision itself is unchanged:
        // the caller's next observation counts as Stopped only for
        // ("inactive","dead"); a reset that fails, times out or leaves any other
        // state stays Unknown (the node stays Blocked).
        if diagnostic == ActionDiagnostic::Success && self.query_failed_after_stop() {
            let _ = self.run_systemctl_action("reset-failed", self.stop_timeout);
        }
        diagnostic
    }

    fn observe_health(&mut self) -> RawHealthObservation {
        self.query_health()
    }
}

fn validate_unit(unit: &str) -> Result<(), SystemdServiceConfigError> {
    if unit.trim().is_empty()
        || unit
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        || unit.contains('/')
    {
        return Err(SystemdServiceConfigError(
            "systemd unit must be a non-empty unit name without whitespace or '/'".into(),
        ));
    }
    Ok(())
}

fn validate_timeout(timeout: Duration, label: &str) -> Result<(), SystemdServiceConfigError> {
    if timeout.is_zero() {
        return Err(SystemdServiceConfigError(format!(
            "{label} must be greater than zero"
        )));
    }
    if timeout > Duration::from_secs(ACTION_TIMEOUT_CEILING_SEC) {
        return Err(SystemdServiceConfigError(format!(
            "{label} must not exceed {ACTION_TIMEOUT_CEILING_SEC} seconds"
        )));
    }
    Ok(())
}

fn verify_health_program(
    path: &Path,
    trust: super::command_service::TrustPolicy,
) -> Result<(), SystemdServiceConfigError> {
    let text = path.to_string_lossy();
    super::command_service::verify_trusted_executable(&text, trust).map_err(|refusal| {
        SystemdServiceConfigError(format!(
            "health command {text} is not a trusted executable: {refusal}"
        ))
    })
}

fn validate_executable(path: &Path, label: &str) -> Result<(), SystemdServiceConfigError> {
    let metadata = std::fs::metadata(path)
        .map_err(|_| SystemdServiceConfigError(format!("configured {label} is not accessible")))?;
    if !metadata.is_file() {
        return Err(SystemdServiceConfigError(format!(
            "configured {label} is not a regular file"
        )));
    }
    #[cfg(unix)]
    if std::os::unix::fs::PermissionsExt::mode(&metadata.permissions()) & 0o111 == 0 {
        return Err(SystemdServiceConfigError(format!(
            "configured {label} is not executable"
        )));
    }
    Ok(())
}

#[derive(Debug)]
enum CaptureResult {
    Exited(ExitStatus, CapturedOutput),
    /// The deadline passed (or the child could not be queried). The child got
    /// SIGKILL when its pid was known to be ours. `cleanup_succeeded` is true
    /// only if the kill was delivered AND the child was reaped within the
    /// budget; otherwise an unreaped child is parked in `Children::pending`.
    TimedOut {
        cleanup_succeeded: bool,
    },
    SpawnFailed,
    /// `now + timeout` is not representable. Decided before any process is
    /// spawned, so there is nothing to clean up.
    InvalidTimeout,
    /// An earlier child is still owed a reap; nothing was spawned.
    PendingBlocked,
}

#[derive(Debug)]
struct CapturedOutput {
    bytes: Vec<u8>,
    exceeded_limit: bool,
    read_failed: bool,
    /// The pipe had not reached EOF when the wait ended: a process other than
    /// the (exited) child still holds its write end, so more may follow.
    unfinished: bool,
}

impl CapturedOutput {
    /// A command whose stdout is not captured has no output to be incomplete.
    fn not_captured() -> Self {
        Self {
            bytes: Vec::new(),
            exceeded_limit: false,
            read_failed: false,
            unfinished: false,
        }
    }

    /// The bytes are the whole output, read to EOF, within the size limit.
    fn is_complete(&self) -> bool {
        !self.exceeded_limit && !self.read_failed && !self.unfinished
    }
}

fn run_action(
    children: &mut Children,
    path: &Path,
    arguments: &[String],
    timeout: Duration,
) -> ActionDiagnostic {
    match spawn_and_wait(children, path, arguments, timeout, false) {
        CaptureResult::Exited(status, _) if status.success() => ActionDiagnostic::Success,
        CaptureResult::Exited(_, _) => ActionDiagnostic::Error("systemd action failed".into()),
        CaptureResult::TimedOut {
            cleanup_succeeded: true,
        } => ActionDiagnostic::Timeout,
        CaptureResult::TimedOut {
            cleanup_succeeded: false,
        } => ActionDiagnostic::Error("systemd action cleanup is uncertain".into()),
        CaptureResult::SpawnFailed => {
            ActionDiagnostic::Error("systemd action could not start".into())
        }
        CaptureResult::InvalidTimeout => {
            ActionDiagnostic::Error("systemd action timeout is out of range".into())
        }
        CaptureResult::PendingBlocked => ActionDiagnostic::Error(
            "an earlier systemd command could not be reaped; nothing is spawned".into(),
        ),
    }
}

fn run_capture(
    children: &mut Children,
    path: &Path,
    arguments: &[String],
    timeout: Duration,
) -> CaptureResult {
    spawn_and_wait(children, path, arguments, timeout, true)
}

fn spawn_and_wait(
    children: &mut Children,
    path: &Path,
    arguments: &[String],
    timeout: Duration,
    capture_output: bool,
) -> CaptureResult {
    // An owed child is dealt with before anything new exists: while one is
    // still unreaped nothing is spawned.
    if !children.discharge() {
        return CaptureResult::PendingBlocked;
    }
    // The only fallible deadline arithmetic, done before anything exists that
    // would have to be cleaned up. The clock starts here, so the spawn itself
    // counts against the timeout (as in the command backend).
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return CaptureResult::InvalidTimeout;
    };
    let mut command = Command::new(path);
    command.args(arguments);
    if capture_output {
        command.stdout(Stdio::piped());
    } else {
        command.stdout(Stdio::null());
    }
    command.stderr(Stdio::null());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => return CaptureResult::SpawnFailed,
    };

    let stdout = child.stdout.take();
    wait_for_child(children, child, deadline, stdout)
}

/// Wait for `child` until `deadline`, reading its output without blocking (the
/// pipe is made non-blocking here, before any read). The child's exit and the
/// completeness of its output are decided separately.
fn wait_for_child(
    children: &mut Children,
    mut child: Child,
    deadline: Instant,
    mut stdout: Option<ChildStdout>,
) -> CaptureResult {
    // A pipe that cannot be made non-blocking is never read (a silent child
    // would hold a blocking read past the deadline): straight to the deadline
    // cleanup. The pipe is closed on return.
    if let Some(pipe) = &stdout
        && (children.ops.set_nonblocking)(pipe.as_raw_fd()).is_err()
    {
        return time_out(children, child, true);
    }
    let mut capture = Capture::new();
    loop {
        if let Some(pipe) = stdout.as_mut() {
            capture.drain(pipe);
        }
        match (children.ops.try_wait)(&mut child) {
            // Reaped, but first seen at or after the deadline: the exit cannot
            // be shown to have happened in time, so it is a timeout and not a
            // success. The child is gone (nothing is owed); its output is not
            // used.
            Ok(Some(_)) if Instant::now() >= deadline => {
                return CaptureResult::TimedOut {
                    cleanup_succeeded: true,
                };
            }
            Ok(Some(status)) => {
                let output = match stdout.as_mut() {
                    Some(pipe) => {
                        finish_capture(&mut capture, pipe, deadline);
                        capture.into_output()
                    }
                    None => CapturedOutput::not_captured(),
                };
                return CaptureResult::Exited(status, output);
            }
            Ok(None) => {
                let now = Instant::now();
                if now >= deadline {
                    return time_out(children, child, true);
                }
                thread::sleep(POLL_INTERVAL.min(deadline - now));
            }
            // The wait query failed (`ECHILD`: someone else reaped it): the
            // pid is no longer known to be ours, so nothing is signalled.
            Err(_) => return time_out(children, child, false),
        }
    }
}

/// The deadline path: SIGKILL (only when the pid is known to be ours), then a
/// bounded reap. A child that is not reaped is parked, never forgotten.
fn time_out(children: &mut Children, mut child: Child, may_signal: bool) -> CaptureResult {
    let ops = children.ops;
    let delivered = may_signal && (ops.kill)(&mut child).is_ok();
    if reap(&ops, &mut child, ops.kill_reap_budget) {
        CaptureResult::TimedOut {
            cleanup_succeeded: delivered,
        }
    } else {
        debug_assert!(children.pending.is_none(), "one owed child at most");
        children.pending = Some(child);
        CaptureResult::TimedOut {
            cleanup_succeeded: false,
        }
    }
}

/// Poll `try_wait` for at most `budget`. `true` only when the child was
/// reaped; a failed query ends the wait at once.
fn reap(ops: &ChildOps, child: &mut Child, budget: Duration) -> bool {
    let Some(deadline) = Instant::now().checked_add(budget) else {
        return false;
    };
    loop {
        match (ops.try_wait)(child) {
            Ok(Some(_)) => return true,
            Ok(None) => {}
            Err(_) => return false,
        }
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        thread::sleep(POLL_INTERVAL.min(deadline - now));
    }
}

/// After the child exited: keep draining until EOF or the deadline. At least
/// one pass is made even when the deadline has passed, because everything the
/// child wrote is already in the pipe.
fn finish_capture(capture: &mut Capture, source: &mut impl Read, deadline: Instant) {
    loop {
        capture.drain(source);
        if capture.end != End::Open {
            return;
        }
        let now = Instant::now();
        if now >= deadline {
            return;
        }
        thread::sleep(POLL_INTERVAL.min(deadline - now));
    }
}

/// How reading the output pipe stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    Open,
    Eof,
    Failed,
}

struct Capture {
    bytes: Vec<u8>,
    exceeded_limit: bool,
    end: End,
}

impl Capture {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(MAX_CAPTURED_OUTPUT),
            exceeded_limit: false,
            end: End::Open,
        }
    }

    /// Read what is available without blocking. Surplus beyond the limit is
    /// discarded (and remembered) so a chatty child never fills the pipe.
    fn drain(&mut self, source: &mut impl Read) {
        let mut buffer = [0u8; READ_BUFFER_SIZE];
        for _ in 0..DRAIN_READS_PER_PASS {
            if self.end != End::Open {
                return;
            }
            match source.read(&mut buffer) {
                Ok(0) => {
                    self.end = End::Eof;
                    return;
                }
                Ok(read) => {
                    let remaining = MAX_CAPTURED_OUTPUT.saturating_sub(self.bytes.len());
                    let retained = read.min(remaining);
                    self.bytes.extend_from_slice(&buffer[..retained]);
                    if retained < read {
                        self.exceeded_limit = true;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => {
                    self.end = End::Failed;
                    return;
                }
            }
        }
    }

    fn into_output(self) -> CapturedOutput {
        CapturedOutput {
            bytes: self.bytes,
            exceeded_limit: self.exceeded_limit,
            read_failed: self.end == End::Failed,
            unfinished: self.end == End::Open,
        }
    }
}

/// The three properties of `systemctl show`, each exactly once and non-empty, and
/// nothing else; `None` for any other output.
fn parse_properties(output: &[u8]) -> Option<(&str, &str, &str)> {
    let text = std::str::from_utf8(output).ok()?;
    let mut active = None;
    let mut sub = None;
    let mut load = None;
    for line in text.lines() {
        let (key, value) = line.split_once('=')?;
        if value.is_empty() {
            return None;
        }
        match key {
            "ActiveState" if active.is_none() => active = Some(value),
            "SubState" if sub.is_none() => sub = Some(value),
            "LoadState" if load.is_none() => load = Some(value),
            _ => return None,
        }
    }
    Some((active?, sub?, load?))
}

fn classify_properties(output: &[u8]) -> RawServiceObservation {
    let Some((active, sub, load)) = parse_properties(output) else {
        return RawServiceObservation::Unavailable;
    };
    if load != "loaded" {
        return RawServiceObservation::Unavailable;
    }
    match (active, sub) {
        ("active", "running") => RawServiceObservation::Running,
        ("inactive", "dead") => RawServiceObservation::Stopped,
        _ => RawServiceObservation::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource_executor::ServiceBackend;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Stdio;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

    /// Set only on the single warm-up run of a freshly written stub; the stub's
    /// first line exits before its body runs. Never set for a real run.
    const WARMUP_ENV: &str = "MKM_TEST_WARMUP";
    /// Polling deadline for the warm-up run only (it exits at once; the wait is
    /// the OS's first-execution scan of a new file, observed up to ~9 s under
    /// load). It is not a wall-clock bound on the whole warm-up: once it is
    /// reached, `wait_for_child` kills and waits for the child synchronously and
    /// that cleanup has no time limit of its own. A failed cleanup is reported
    /// separately from a plain timeout (see `warm_up_outcome`).
    const WARMUP_LIMIT: Duration = Duration::from_secs(60);

    fn script(body: &str) -> PathBuf {
        assert!(
            std::env::var_os(WARMUP_ENV).is_none(),
            "{WARMUP_ENV} must not be set in the test environment"
        );
        let path = std::env::temp_dir().join(format!(
            "mikagami-systemd-test-{}-{}",
            std::process::id(),
            NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(
            &path,
            format!("#!/bin/sh\n[ -n \"$MKM_TEST_WARMUP\" ] && exit 0\n{body}\n"),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        warm_up(&path);
        path
    }

    /// Run a freshly written stub once, without its body, so the OS's
    /// first-execution scan of a new file (macOS XProtect, serialized and slow
    /// under concurrent new-script executions) is paid here and not inside the
    /// timed waits the tests assert on. A failure is a test error, never ignored.
    fn warm_up(path: &Path) {
        if let Err(message) = warm_up_with_limit(path, WARMUP_LIMIT) {
            panic!("{message}");
        }
    }

    fn warm_up_with_limit(path: &Path, limit: Duration) -> Result<(), String> {
        let mut command = Command::new(path);
        command
            .env(WARMUP_ENV, "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let deadline = Instant::now()
            .checked_add(limit)
            .ok_or_else(|| format!("warm-up limit {limit:?} is not representable"))?;
        let child = command.spawn().map_err(|error| {
            format!(
                "test stub warm-up could not start {}: {error}",
                path.display()
            )
        })?;
        let mut children = Children::new(ChildOps::PRODUCTION);
        warm_up_outcome(
            path,
            limit,
            &wait_for_child(&mut children, child, deadline, None),
        )
    }

    /// Classify one warm-up result. A timeout whose kill/wait cleanup succeeded
    /// and a timeout whose cleanup failed are different failures: the second
    /// leaves a child that may not have been reaped.
    fn warm_up_outcome(path: &Path, limit: Duration, result: &CaptureResult) -> Result<(), String> {
        match result {
            CaptureResult::Exited(status, _) if status.success() => Ok(()),
            CaptureResult::Exited(status, _) => Err(format!(
                "test stub warm-up of {} exited with {status}",
                path.display()
            )),
            CaptureResult::TimedOut {
                cleanup_succeeded: true,
            } => Err(format!(
                "test stub warm-up of {} did not finish within the {limit:?} polling deadline \
                 (or its status could not be read); the child was killed and reaped",
                path.display()
            )),
            CaptureResult::TimedOut {
                cleanup_succeeded: false,
            } => Err(format!(
                "test stub warm-up of {} timed out and CLEANUP FAILED: killing or reaping the \
                 child did not succeed, so it may still be running",
                path.display()
            )),
            CaptureResult::SpawnFailed => Err(format!(
                "test stub warm-up of {} could not start",
                path.display()
            )),
            CaptureResult::InvalidTimeout => Err(format!(
                "test stub warm-up of {} has an unrepresentable deadline",
                path.display()
            )),
            CaptureResult::PendingBlocked => Err(format!(
                "test stub warm-up of {} was blocked by an unreaped child",
                path.display()
            )),
        }
    }

    fn backend(
        systemctl_body: &str,
        health_body: &str,
    ) -> (LinuxSystemdServiceBackend, PathBuf, PathBuf) {
        backend_with_timeout(systemctl_body, health_body, Duration::from_secs(10))
    }

    fn backend_with_timeout(
        systemctl_body: &str,
        health_body: &str,
        timeout: Duration,
    ) -> (LinuxSystemdServiceBackend, PathBuf, PathBuf) {
        backend_with_timeouts(systemctl_body, health_body, timeout, timeout)
    }

    fn backend_with_timeouts(
        systemctl_body: &str,
        health_body: &str,
        action_timeout: Duration,
        health_timeout: Duration,
    ) -> (LinuxSystemdServiceBackend, PathBuf, PathBuf) {
        let systemctl = script(systemctl_body);
        let health = script(health_body);
        let backend = LinuxSystemdServiceBackend::with_systemctl_path(
            "example.service",
            systemctl.clone(),
            action_timeout,
            action_timeout,
            vec![health.to_string_lossy().into_owned()],
            health_timeout,
            super::super::command_service::TrustPolicy::for_test_user(),
        )
        .unwrap();
        (backend, systemctl, health)
    }

    fn fresh() -> Children {
        Children::new(ChildOps::PRODUCTION)
    }

    fn remove(paths: &[PathBuf]) {
        for path in paths {
            let _ = fs::remove_file(path);
        }
    }

    /// C-6: only ("active","running") is Running and only ("inactive","dead") is
    /// Stopped. Every transitional or failed state is Unknown, so a start/stop
    /// that is still in flight (or failed) can never be read as ZeroResource.
    #[test]
    fn ba_c6_only_inactive_dead_is_stopped() {
        let states = [
            ("activating", "start"),
            ("activating", "start-pre"),
            ("activating", "auto-restart"),
            ("deactivating", "stop"),
            ("deactivating", "stop-sigterm"),
            ("reloading", "reload"),
            ("failed", "failed"),
            ("inactive", "failed"),
            ("active", "exited"),
            ("active", "start-post"),
            ("maintenance", "dead"),
        ];
        for (active, sub) in states {
            let text = format!("ActiveState={active}\nSubState={sub}\nLoadState=loaded\n");
            let observed = classify_properties(text.as_bytes());
            assert_ne!(observed, RawServiceObservation::Stopped, "{active}/{sub}");
            assert_ne!(observed, RawServiceObservation::Running, "{active}/{sub}");
        }
        assert_eq!(
            classify_properties(b"ActiveState=inactive\nSubState=dead\nLoadState=loaded\n"),
            RawServiceObservation::Stopped
        );
        assert_eq!(
            classify_properties(b"ActiveState=inactive\nSubState=dead\nLoadState=not-found\n"),
            RawServiceObservation::Unavailable
        );
    }

    /// C-6: `systemctl start` times out, the client is killed, but the start JOB
    /// completes later inside systemd (modelled by a state file flipped by a
    /// background process the stub leaves behind). Throughout the window the
    /// observation is never Stopped: Unknown while activating, Running once the
    /// late start lands. A responder that requires Stopped therefore never says
    /// ACK for a node whose Mikagami-initiated start is still in flight.
    #[test]
    fn ba_c6_start_job_outliving_its_client_is_never_observed_as_stopped() {
        let state = std::env::temp_dir().join(format!(
            "mikagami-ba-audit-c6-state-{}-{}",
            std::process::id(),
            NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&state, "inactive\n").unwrap();
        let s = state.display();
        let body = format!(
            "S='{s}'\n\
         case \"$1\" in\n\
           show) case \"$(cat \"$S\")\" in\n\
                   activating) printf 'ActiveState=activating\\nSubState=start\\nLoadState=loaded\\n';;\n\
                   active) printf 'ActiveState=active\\nSubState=running\\nLoadState=loaded\\n';;\n\
                   *) printf 'ActiveState=inactive\\nSubState=dead\\nLoadState=loaded\\n';;\n\
                 esac;;\n\
           start) echo activating > \"$S\"; (sleep 2; if [ \"$(cat \"$S\")\" = activating ]; then echo active > \"$S\"; fi) >/dev/null 2>&1 & sleep 10;;\n\
           stop) echo inactive > \"$S\";;\n\
         esac"
        );
        let (mut service_backend, systemctl, health) =
            backend_with_timeout(&body, "exit 0", Duration::from_secs(1));
        assert_eq!(
            service_backend.observe_service(),
            RawServiceObservation::Stopped
        );
        assert_eq!(
            service_backend.request_service_start(),
            ActionDiagnostic::Timeout
        );
        // client gone; job still pending
        assert_eq!(
            service_backend.observe_service(),
            RawServiceObservation::Unavailable,
            "pending start must read as Unknown, never Stopped"
        );
        std::thread::sleep(Duration::from_millis(2600));
        assert_eq!(
            service_backend.observe_service(),
            RawServiceObservation::Running,
            "the late job really started the service after the client was killed"
        );
        // Mikagami's own cleanup (stop) brings it back to a provable Stopped.
        assert_eq!(
            service_backend.request_service_stop(),
            ActionDiagnostic::Success
        );
        assert_eq!(
            service_backend.observe_service(),
            RawServiceObservation::Stopped
        );
        remove(&[systemctl, health, state]);
    }

    #[test]
    fn classifies_only_loaded_running_and_loaded_inactive_dead() {
        assert_eq!(
            classify_properties(b"ActiveState=active\nSubState=running\nLoadState=loaded\n"),
            RawServiceObservation::Running
        );
        assert_eq!(
            classify_properties(b"ActiveState=inactive\nSubState=dead\nLoadState=loaded\n"),
            RawServiceObservation::Stopped
        );
        for state in [
            b"ActiveState=failed\nSubState=failed\nLoadState=loaded\n".as_slice(),
            b"ActiveState=activating\nSubState=start\nLoadState=loaded\n",
            b"ActiveState=deactivating\nSubState=stop\nLoadState=loaded\n",
            b"ActiveState=reloading\nSubState=reload\nLoadState=loaded\n",
            b"ActiveState=active\nSubState=exited\nLoadState=loaded\n",
            b"ActiveState=inactive\nSubState=dead\nLoadState=not-found\n",
        ] {
            assert_eq!(
                classify_properties(state),
                RawServiceObservation::Unavailable
            );
        }
    }

    #[test]
    fn malformed_and_duplicate_properties_are_unknown() {
        for output in [
            b"ActiveState=active\nSubState=running\n".as_slice(),
            b"ActiveState=active\nSubState=running\nLoadState=loaded\nLoadState=not-found\n",
            b"ActiveState=active\nSubState=running\nLoadState=loaded\nExtra=value\n",
            b"ActiveState=active\nnot-a-property\nLoadState=loaded\n",
            &[0xff, 0xfe],
        ] {
            assert_eq!(
                classify_properties(output),
                RawServiceObservation::Unavailable
            );
        }
    }

    #[test]
    fn action_diagnostic_is_independent_from_running_observation() {
        for (action, expected) in [
            ("start", ActionDiagnostic::Success),
            (
                "start-fail",
                ActionDiagnostic::Error("systemd action failed".into()),
            ),
        ] {
            let (mut backend, systemctl, health) = backend(
                &format!(
                    "case \"$1\" in show) printf 'ActiveState=active\\nSubState=running\\nLoadState=loaded\\n';; start) exit {};; start-fail) exit 1;; esac",
                    if action == "start" { 0 } else { 1 }
                ),
                "exit 0",
            );
            let result = backend.request_service_start();
            assert_eq!(result, expected);
            assert_eq!(backend.observe_service(), RawServiceObservation::Running);
            remove(&[systemctl, health]);
        }
    }

    #[test]
    fn action_diagnostic_is_independent_from_stopped_observation() {
        for (action, expected) in [
            ("stop", ActionDiagnostic::Success),
            (
                "stop-fail",
                ActionDiagnostic::Error("systemd action failed".into()),
            ),
        ] {
            let (mut backend, systemctl, health) = backend(
                &format!(
                    "case \"$1\" in show) printf 'ActiveState=inactive\\nSubState=dead\\nLoadState=loaded\\n';; stop) exit {};; stop-fail) exit 1;; esac",
                    if action == "stop" { 0 } else { 1 }
                ),
                "exit 0",
            );
            let result = backend.request_service_stop();
            assert_eq!(result, expected);
            assert_eq!(backend.observe_service(), RawServiceObservation::Stopped);
            remove(&[systemctl, health]);
        }
    }

    #[test]
    fn timeout_is_independent_from_running_or_unknown_observation() {
        let (mut service_backend, systemctl, health) = backend_with_timeout(
            "case \"$1\" in show) printf 'ActiveState=active\\nSubState=running\\nLoadState=loaded\\n';; start|stop) sleep 4;; esac",
            "exit 0",
            Duration::from_secs(2),
        );
        assert_eq!(
            service_backend.request_service_start(),
            ActionDiagnostic::Timeout
        );
        assert_eq!(
            service_backend.observe_service(),
            RawServiceObservation::Running
        );
        remove(&[systemctl, health]);

        let (mut service_backend, systemctl, health) = backend_with_timeout(
            "case \"$1\" in show) sleep 4;; start|stop) sleep 4;; esac",
            "exit 0",
            Duration::from_secs(2),
        );
        assert_eq!(
            service_backend.request_service_stop(),
            ActionDiagnostic::Timeout
        );
        assert_eq!(
            service_backend.observe_service(),
            RawServiceObservation::Unavailable
        );
        remove(&[systemctl, health]);
    }

    /// Owner decision A-7: the health program gets the root-owned executable
    /// check at construction and again immediately before every spawn.
    #[test]
    fn health_program_must_be_trusted_at_construction_and_at_every_spawn() {
        use super::super::command_service::TrustPolicy;
        let systemctl = script(
            "case \"$1\" in show) printf 'ActiveState=active\\nSubState=running\\nLoadState=loaded\\n';; esac",
        );
        let health = script("exit 0");
        let build = |trust: TrustPolicy| {
            LinuxSystemdServiceBackend::with_systemctl_path(
                "example.service",
                systemctl.clone(),
                Duration::from_secs(5),
                Duration::from_secs(5),
                vec![health.to_string_lossy().into_owned()],
                Duration::from_secs(5),
                trust,
            )
        };
        let own = TrustPolicy::for_test_user();
        assert!(build(own).is_ok());
        // production policy (root-owned) refuses a user-owned health program
        if own.uid != 0 {
            let error = build(TrustPolicy::PRODUCTION).unwrap_err().to_string();
            assert!(error.contains("not a trusted executable"), "{error}");
        }
        // a loosened program is refused at the next spawn: Unknown, not Healthy
        let mut backend = build(own).unwrap();
        assert_eq!(backend.observe_health(), RawHealthObservation::Healthy);
        fs::set_permissions(&health, fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(backend.observe_health(), RawHealthObservation::Unavailable);
        remove(&[systemctl, health]);
    }

    #[test]
    fn health_is_independent_and_timeout_is_unknown() {
        let (mut service_backend, systemctl, health) = backend(
            "case \"$1\" in show) printf 'ActiveState=active\\nSubState=running\\nLoadState=loaded\\n';; esac",
            "exit 1",
        );
        assert_eq!(
            service_backend.observe_service(),
            RawServiceObservation::Running
        );
        assert_eq!(
            service_backend.observe_health(),
            RawHealthObservation::Unhealthy
        );
        remove(&[systemctl, health]);

        let (mut service_backend, systemctl, health) = backend_with_timeouts(
            "case \"$1\" in show) printf 'ActiveState=inactive\\nSubState=dead\\nLoadState=loaded\\n';; esac",
            "sleep 2",
            Duration::from_secs(2),
            Duration::from_millis(500),
        );
        assert_eq!(
            service_backend.observe_service(),
            RawServiceObservation::Stopped
        );
        assert_eq!(
            service_backend.observe_health(),
            RawHealthObservation::Unavailable
        );
        remove(&[systemctl, health]);
    }

    #[test]
    fn large_health_output_is_ignored_for_exit_status() {
        let (mut service_backend, systemctl, health) = backend(
            "case \"$1\" in show) printf 'ActiveState=active\\nSubState=running\\nLoadState=loaded\\n';; esac",
            "head -c 131072 /dev/zero; exit 0",
        );
        assert_eq!(
            service_backend.observe_health(),
            RawHealthObservation::Healthy
        );
        remove(&[systemctl, health]);

        let (mut service_backend, systemctl, health) = backend(
            "case \"$1\" in show) printf 'ActiveState=active\\nSubState=running\\nLoadState=loaded\\n';; esac",
            "head -c 131072 /dev/zero; exit 1",
        );
        assert_eq!(
            service_backend.observe_health(),
            RawHealthObservation::Unhealthy
        );
        remove(&[systemctl, health]);
    }

    #[test]
    fn systemctl_output_overflow_is_unknown() {
        let (mut backend, systemctl, health) = backend(
            "case \"$1\" in show) head -c 8192 /dev/zero;; esac",
            "exit 0",
        );
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable
        );
        remove(&[systemctl, health]);
    }

    #[test]
    fn rejects_invalid_unit_paths_and_timeouts() {
        assert!(validate_unit("").is_err());
        assert!(validate_unit("bad unit.service").is_err());
        assert!(validate_unit("/bad.service").is_err());
        assert!(validate_timeout(Duration::ZERO, "timeout").is_err());
    }

    #[test]
    fn nonexistent_or_failed_query_is_unknown() {
        let (mut backend, systemctl, health) = backend("exit 1", "exit 0");
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable
        );
        remove(&[systemctl, health]);
    }

    #[test]
    fn health_success_is_not_service_running() {
        let (mut backend, systemctl, health) = backend(
            "case \"$1\" in show) printf 'ActiveState=inactive\\nSubState=dead\\nLoadState=loaded\\n';; esac",
            "exit 0",
        );
        assert_eq!(backend.observe_health(), RawHealthObservation::Healthy);
        assert_eq!(backend.observe_service(), RawServiceObservation::Stopped);
        remove(&[systemctl, health]);
    }

    #[test]
    fn warmup_skips_the_stub_body_and_does_not_reach_real_runs() {
        let marker = std::env::temp_dir().join(format!(
            "mikagami-systemd-test-marker-{}-{}",
            std::process::id(),
            NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let path = script(&format!(
            "printf 'ran:%s' \"${{MKM_TEST_WARMUP-unset}}\" > '{}'",
            marker.display()
        ));
        // script() has already warmed the stub up: the body must not have run.
        assert!(!marker.exists(), "the warm-up must not run the stub body");
        // A real run executes the body and does not see the warm-up variable.
        assert!(Command::new(&path).status().unwrap().success());
        assert_eq!(fs::read_to_string(&marker).unwrap(), "ran:unset");
        // The variable never entered this process's environment either.
        assert!(std::env::var_os(WARMUP_ENV).is_none());
        remove(&[path, marker]);
    }

    fn raw_script(body: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "mikagami-systemd-test-raw-{}-{}",
            std::process::id(),
            NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    // Branches A-D run the real warm-up path (real spawn / exit / kill / wait).
    #[test]
    fn warmup_failure_kinds_are_distinguished_on_real_processes() {
        use std::os::unix::process::ExitStatusExt;

        // A: normal exit.
        let ok = raw_script("exit 0");
        assert_eq!(warm_up_with_limit(&ok, Duration::from_secs(60)), Ok(()));

        // B: the stub cannot be started (no such file).
        let missing = std::env::temp_dir().join(format!(
            "mikagami-systemd-test-missing-{}-{}",
            std::process::id(),
            NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let spawn = warm_up_with_limit(&missing, Duration::from_secs(60)).unwrap_err();
        assert!(spawn.contains("could not start"), "{spawn}");
        assert!(spawn.contains(&missing.display().to_string()), "{spawn}");

        // C: non-zero exit.
        let failing = raw_script("exit 3");
        let exited = warm_up_with_limit(&failing, Duration::from_secs(60)).unwrap_err();
        assert!(exited.contains("exited with"), "{exited}");
        assert!(exited.contains(&failing.display().to_string()), "{exited}");
        assert!(!exited.contains("CLEANUP FAILED"), "{exited}");

        // D: timeout, kill and wait succeed. `exec` makes the killed process the
        // sleeper itself, so no grandchild is left behind.
        let hanging = raw_script("exec sleep 30");
        let timed_out = warm_up_with_limit(&hanging, Duration::from_millis(200)).unwrap_err();
        assert!(timed_out.contains("polling deadline"), "{timed_out}");
        assert!(timed_out.contains("killed and reaped"), "{timed_out}");
        assert!(
            timed_out.contains(&hanging.display().to_string()),
            "{timed_out}"
        );
        assert!(!timed_out.contains("CLEANUP FAILED"), "{timed_out}");

        // Same classifier, other variants, without a process (type level).
        let exit_zero =
            CaptureResult::Exited(ExitStatus::from_raw(0), CapturedOutput::not_captured());
        assert_eq!(
            warm_up_outcome(&ok, Duration::from_secs(1), &exit_zero),
            Ok(())
        );
        let spawn_failed =
            warm_up_outcome(&ok, Duration::from_secs(1), &CaptureResult::SpawnFailed).unwrap_err();
        assert!(spawn_failed.contains("could not start"), "{spawn_failed}");
        assert!(!spawn_failed.contains("CLEANUP FAILED"), "{spawn_failed}");
        remove(&[ok, failing, hanging]);
    }

    // E: kill/wait failure cannot be produced safely on a real OS, so this
    // branch is checked at the type/branch level with a constructed result.
    #[test]
    fn warmup_cleanup_failure_is_not_reported_as_a_plain_timeout() {
        let path = PathBuf::from("/nonexistent/stub-for-cleanup-failure");
        let limit = Duration::from_secs(60);
        let clean = warm_up_outcome(
            &path,
            limit,
            &CaptureResult::TimedOut {
                cleanup_succeeded: true,
            },
        )
        .unwrap_err();
        let dirty = warm_up_outcome(
            &path,
            limit,
            &CaptureResult::TimedOut {
                cleanup_succeeded: false,
            },
        )
        .unwrap_err();
        assert_ne!(clean, dirty);
        assert!(dirty.contains("CLEANUP FAILED"), "{dirty}");
        assert!(dirty.contains(&path.display().to_string()), "{dirty}");
        assert!(!dirty.contains("polling deadline"), "{dirty}");
        assert!(!dirty.contains("killed and reaped"), "{dirty}");
        assert!(clean.contains("killed and reaped"), "{clean}");
        assert!(!clean.contains("CLEANUP FAILED"), "{clean}");
    }

    // ---- NF-1: the deadline is decided before anything is spawned -------------------------

    fn marker_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "mikagami-systemd-test-{tag}-{}-{}",
            std::process::id(),
            NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    /// A stub that leaves a mark when its body really runs (the warm-up
    /// returns before the mark).
    fn marking_script(mark: &Path, tail: &str) -> PathBuf {
        script(&format!("touch '{}'\n{tail}", mark.display()))
    }

    /// Timeouts no `Instant` can hold: refused before the spawn, with no
    /// panic, no child, and an explicit result on every path.
    #[test]
    fn an_unrepresentable_timeout_is_refused_before_anything_is_spawned() {
        let mark = marker_path("overflow-mark");
        let program = marking_script(&mark, "exit 0");
        for timeout in [
            Duration::MAX,
            Duration::from_secs(u64::MAX),
            Duration::new(u64::MAX, 999_999_999),
            Duration::from_secs(u64::MAX / 2),
            Duration::from_secs(i64::MAX as u64),
        ] {
            for capture in [false, true] {
                assert!(
                    matches!(
                        spawn_and_wait(&mut fresh(), &program, &[], timeout, capture),
                        CaptureResult::InvalidTimeout
                    ),
                    "{timeout:?} capture={capture}"
                );
                assert!(!mark.exists(), "{timeout:?}: a child was spawned");
            }
        }
        // Positive control: the same stub, a sane timeout, does run.
        assert!(matches!(
            spawn_and_wait(&mut fresh(), &program, &[], Duration::from_secs(20), false),
            CaptureResult::Exited(status, _) if status.success()
        ));
        assert!(mark.exists());
        remove(&[program, mark]);
    }

    /// The backend refuses an out-of-range timeout at construction (the same
    /// ceiling as the command backend and the configuration), and every action
    /// path still refuses one that got past construction, spawning nothing.
    #[test]
    fn timeouts_are_bounded_at_construction_and_refused_at_every_spawn() {
        let ceiling = Duration::from_secs(ACTION_TIMEOUT_CEILING_SEC);
        assert_eq!(ceiling, Duration::from_secs(86_400));
        assert!(validate_timeout(Duration::from_secs(1), "timeout").is_ok());
        assert!(validate_timeout(ceiling, "timeout").is_ok());
        for refused in [
            ceiling + Duration::from_nanos(1),
            Duration::from_secs(86_401),
            Duration::from_secs(u64::MAX),
            Duration::MAX,
            Duration::ZERO,
        ] {
            assert!(validate_timeout(refused, "timeout").is_err(), "{refused:?}");
        }
        let health = script("exit 0");
        let systemctl = script("exit 0");
        for (label, start, stop, health_timeout) in [
            ("start", Duration::MAX, ceiling, ceiling),
            ("stop", ceiling, Duration::from_secs(86_401), ceiling),
            ("health", ceiling, ceiling, Duration::MAX),
        ] {
            let result = LinuxSystemdServiceBackend::with_systemctl_path(
                "example.service",
                systemctl.clone(),
                start,
                stop,
                vec![health.to_string_lossy().into_owned()],
                health_timeout,
                super::super::command_service::TrustPolicy::for_test_user(),
            );
            let error = result.unwrap_err().to_string();
            assert!(
                error.contains(&format!("{label} timeout must not exceed 86400 seconds")),
                "{label}: {error}"
            );
        }
        // The maximum itself is accepted.
        assert!(
            LinuxSystemdServiceBackend::with_systemctl_path(
                "example.service",
                systemctl.clone(),
                ceiling,
                ceiling,
                vec![health.to_string_lossy().into_owned()],
                ceiling,
                super::super::command_service::TrustPolicy::for_test_user(),
            )
            .is_ok()
        );
        remove(&[systemctl, health]);

        // Past construction (fields set directly): every path refuses and
        // spawns nothing.
        let systemctl_mark = marker_path("systemctl-mark");
        let health_mark = marker_path("health-mark");
        let systemctl = marking_script(&systemctl_mark, "exit 0");
        let health = marking_script(&health_mark, "exit 0");
        let mut backend = LinuxSystemdServiceBackend::with_systemctl_path(
            "example.service",
            systemctl.clone(),
            Duration::from_secs(10),
            Duration::from_secs(10),
            vec![health.to_string_lossy().into_owned()],
            Duration::from_secs(10),
            super::super::command_service::TrustPolicy::for_test_user(),
        )
        .unwrap();
        backend.start_timeout = Duration::MAX;
        backend.stop_timeout = Duration::MAX;
        backend.health_timeout = Duration::MAX;
        assert!(matches!(
            backend.request_service_start(),
            ActionDiagnostic::Error(message) if message.contains("timeout is out of range")
        ));
        assert!(matches!(
            backend.request_service_stop(),
            ActionDiagnostic::Error(message) if message.contains("timeout is out of range")
        ));
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable
        );
        assert_eq!(backend.observe_health(), RawHealthObservation::Unavailable);
        assert!(!systemctl_mark.exists(), "systemctl was spawned");
        assert!(!health_mark.exists(), "the health command was spawned");
        remove(&[systemctl, health, systemctl_mark, health_mark]);
    }

    /// The boundary values at the run level: the ceiling and one second past
    /// it are representable (the ceiling is the constructor's concern), and
    /// both run and finish normally.
    #[test]
    fn the_ceiling_and_the_value_past_it_are_representable_deadlines() {
        for seconds in [ACTION_TIMEOUT_CEILING_SEC, ACTION_TIMEOUT_CEILING_SEC + 1] {
            let program = script("exit 0");
            assert!(
                matches!(
                    spawn_and_wait(
                        &mut fresh(),
                        &program,
                        &[],
                        Duration::from_secs(seconds),
                        false
                    ),
                    CaptureResult::Exited(status, _) if status.success()
                ),
                "{seconds}"
            );
            remove(&[program]);
        }
    }

    /// An ordinary exit, with captured output.
    #[test]
    fn a_normal_exit_returns_its_status_and_output() {
        let program = script("printf 'ActiveState=active'; exit 4");
        match spawn_and_wait(&mut fresh(), &program, &[], Duration::from_secs(20), true) {
            CaptureResult::Exited(status, output) => {
                assert_eq!(status.code(), Some(4));
                assert_eq!(output.bytes, b"ActiveState=active");
                assert!(output.is_complete());
            }
            other => panic!("{other:?}"),
        }
        remove(&[program]);
    }

    /// A timeout kills and reaps the child (nothing is left owed), and a
    /// normal run afterwards works on the same `Children`. That the read end
    /// of the pipe is closed on return is shown by
    /// `the_read_end_is_closed_when_the_call_returns`.
    #[test]
    fn a_timeout_kills_reaps_and_closes_the_reader() {
        fn pid_exists(pid: u32) -> bool {
            // SAFETY: signal 0 delivers nothing.
            unsafe { kill(i32::try_from(pid).unwrap(), 0) == 0 }
        }
        unsafe extern "C" {
            fn kill(pid: i32, signal: i32) -> i32;
        }

        // `exec` makes the killed process the sleeper itself: no grandchild
        // keeps the pipe open.
        let slow = script("exec sleep 30");
        let started = Instant::now();
        let mut children = fresh();
        let mut command = Command::new(&slow);
        command.stdout(Stdio::piped()).stderr(Stdio::null());
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(300))
            .unwrap();
        let mut child = command.spawn().unwrap();
        let pid = child.id();
        let stdout = child.stdout.take();
        let result = wait_for_child(&mut children, child, deadline, stdout);
        assert!(
            matches!(
                result,
                CaptureResult::TimedOut {
                    cleanup_succeeded: true
                }
            ),
            "{result:?}"
        );
        assert!(children.pending.is_none(), "a reaped child is not owed");
        assert!(!pid_exists(pid), "the child was neither killed nor reaped");
        assert!(started.elapsed() < Duration::from_secs(25));

        let quick = script("printf done");
        match spawn_and_wait(&mut children, &quick, &[], Duration::from_secs(20), true) {
            CaptureResult::Exited(status, output) => {
                assert!(status.success());
                assert_eq!(output.bytes, b"done");
                assert!(output.is_complete());
            }
            other => panic!("{other:?}"),
        }
        assert!(children.pending.is_none());
        remove(&[slow, quick]);
    }

    /// Through the backend: a timeout is a `Timeout` diagnostic and the child
    /// is gone (killed and reaped by `wait_for_child`).
    #[test]
    fn a_backend_timeout_still_reports_timeout_and_leaves_no_child() {
        let pidfile = marker_path("timeout-pid");
        let (mut backend, systemctl, health) = backend_with_timeout(
            &format!("echo $$ > '{}'\nexec sleep 30", pidfile.display()),
            "exit 0",
            Duration::from_millis(500),
        );
        assert_eq!(backend.request_service_start(), ActionDiagnostic::Timeout);
        let pid: i32 = fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        unsafe extern "C" {
            fn kill(pid: i32, signal: i32) -> i32;
        }
        // SAFETY: signal 0 delivers nothing.
        assert_ne!(unsafe { kill(pid, 0) }, 0, "the timed-out child is gone");
        remove(&[systemctl, health, pidfile]);
    }

    // ---- FH-1: the wait is bounded and the output is never trusted when cut off ----------

    /// One scripted answer of a fake output pipe.
    enum Step {
        Data(Vec<u8>),
        Eof,
        Block,
        Fail(std::io::ErrorKind),
    }

    /// A fake non-blocking pipe: the steps in order, then "no data yet" for
    /// ever (a writer that is still held open and silent).
    struct Scripted(std::collections::VecDeque<Step>);

    impl Scripted {
        fn new(steps: Vec<Step>) -> Self {
            Self(steps.into())
        }
    }

    impl Read for Scripted {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            match self.0.pop_front() {
                None | Some(Step::Block) => Err(std::io::ErrorKind::WouldBlock.into()),
                Some(Step::Eof) => Ok(0),
                Some(Step::Fail(kind)) => Err(kind.into()),
                Some(Step::Data(mut bytes)) => {
                    let taken = bytes.len().min(buffer.len());
                    buffer[..taken].copy_from_slice(&bytes[..taken]);
                    if taken < bytes.len() {
                        self.0.push_front(Step::Data(bytes.split_off(taken)));
                    }
                    Ok(taken)
                }
            }
        }
    }

    fn finished(steps: Vec<Step>, deadline: Instant) -> CapturedOutput {
        let mut capture = Capture::new();
        finish_capture(&mut capture, &mut Scripted::new(steps), deadline);
        capture.into_output()
    }

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    fn passed() -> Instant {
        Instant::now()
            .checked_sub(Duration::from_millis(5))
            .unwrap()
    }

    /// EOF that arrives while the deadline is still ahead completes the output;
    /// a pause ("no data yet") in between is not an end.
    #[test]
    fn eof_before_the_deadline_completes_the_output() {
        let output = finished(
            vec![
                Step::Data(b"abc".to_vec()),
                Step::Block,
                Step::Data(b"def".to_vec()),
                Step::Eof,
            ],
            far(),
        );
        assert_eq!(output.bytes, b"abcdef");
        assert!(output.is_complete());
    }

    /// The deadline has already passed when the child's exit is seen. The
    /// single pass that is always made still reads what is already in the pipe
    /// (data and its EOF: complete), but an EOF that only comes after that
    /// pass is not waited for (unfinished).
    #[test]
    fn the_deadline_boundary_is_one_pass_for_the_output() {
        let at_the_deadline = finished(vec![Step::Data(b"ok".to_vec()), Step::Eof], passed());
        assert_eq!(at_the_deadline.bytes, b"ok");
        assert!(at_the_deadline.is_complete(), "already in the pipe");

        let after_the_deadline = finished(vec![Step::Block, Step::Eof], passed());
        assert!(after_the_deadline.unfinished);
        assert!(!after_the_deadline.is_complete());

        // Data without its EOF at the deadline: the bytes are kept, but the
        // output is not claimed complete.
        let partial = finished(vec![Step::Data(b"part".to_vec())], passed());
        assert_eq!(partial.bytes, b"part");
        assert!(partial.unfinished && !partial.is_complete());
    }

    /// A writer that never closes and never writes: the wait ends at the
    /// deadline, not before it and not after it.
    #[test]
    fn a_silent_open_writer_ends_the_wait_at_the_deadline() {
        let started = Instant::now();
        let output = within(Duration::from_secs(30), move || {
            finished(vec![], started + Duration::from_millis(120))
        });
        let waited = started.elapsed();
        assert!(output.unfinished && !output.is_complete());
        assert!(waited >= Duration::from_millis(120), "{waited:?}");
        assert!(waited < Duration::from_secs(10), "{waited:?}");
    }

    /// An I/O error ends the read, keeps what was read, and is never EOF; an
    /// interrupted read is retried.
    #[test]
    fn a_reader_error_is_a_failure_and_an_interruption_is_retried() {
        let failed = finished(
            vec![
                Step::Data(b"ab".to_vec()),
                Step::Fail(std::io::ErrorKind::Other),
                Step::Data(b"never read".to_vec()),
                Step::Eof,
            ],
            far(),
        );
        assert_eq!(failed.bytes, b"ab");
        assert!(failed.read_failed && !failed.unfinished && !failed.is_complete());

        let retried = finished(
            vec![
                Step::Fail(std::io::ErrorKind::Interrupted),
                Step::Data(b"z".to_vec()),
                Step::Eof,
            ],
            far(),
        );
        assert_eq!(retried.bytes, b"z");
        assert!(retried.is_complete());
    }

    /// Output beyond the limit is dropped and flagged, even when EOF follows.
    #[test]
    fn output_beyond_the_limit_is_flagged_and_never_complete() {
        let output = finished(
            vec![
                Step::Data(vec![b'a'; 3000]),
                Step::Data(vec![b'b'; 3000]),
                Step::Eof,
            ],
            far(),
        );
        assert_eq!(output.bytes.len(), MAX_CAPTURED_OUTPUT);
        assert!(output.exceeded_limit && !output.is_complete());
        // exactly the limit is not an overflow
        let exact = finished(
            vec![Step::Data(vec![b'a'; MAX_CAPTURED_OUTPUT]), Step::Eof],
            far(),
        );
        assert!(!exact.exceeded_limit && exact.is_complete());
    }

    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }

    fn pid_alive(pid: i32) -> bool {
        // SAFETY: signal 0 delivers nothing.
        unsafe { kill(pid, 0) == 0 }
    }

    fn kill_pid(pid: i32) {
        // SAFETY: a test's own helper process.
        unsafe { kill(pid, 9) };
    }

    fn read_pid(path: &Path) -> i32 {
        fs::read_to_string(path).unwrap().trim().parse().unwrap()
    }

    /// Run `work` on a helper thread and fail (instead of hanging the suite)
    /// when it does not return in time. Only a regression to an unbounded
    /// wait leaves the helper thread behind.
    fn within<T: Send + 'static>(limit: Duration, work: impl FnOnce() -> T + Send + 'static) -> T {
        let (sender, receiver) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let _ = sender.send(work());
        });
        receiver
            .recv_timeout(limit)
            .unwrap_or_else(|_| panic!("the call did not return within {limit:?}"))
    }

    const RUNNING: &str = "printf 'ActiveState=active\\nSubState=running\\nLoadState=loaded\\n'";

    /// FH-1 counterexample 1/2: the child exits (status 0, a complete-looking
    /// answer) but another process keeps the stdout pipe open and silent. The
    /// call returns at its deadline instead of waiting for that process, and
    /// the answer is not believed (the pipe never reached EOF).
    #[test]
    fn a_writer_outside_the_child_does_not_hold_the_call_past_its_deadline() {
        let pidfile = marker_path("holder-pid");
        let body = format!(
            "case \"$1\" in show) sleep 60 &\necho $! > '{}'\n{RUNNING};; esac",
            pidfile.display()
        );
        let (mut backend, systemctl, health) =
            backend_with_timeout(&body, "exit 0", Duration::from_millis(500));
        let started = Instant::now();
        let (backend, observed) = within(Duration::from_secs(30), move || {
            let observed = backend.observe_service();
            (backend, observed)
        });
        let waited = started.elapsed();
        let holder = read_pid(&pidfile);
        assert!(pid_alive(holder), "the holder must still be running");
        kill_pid(holder);
        assert_eq!(
            observed,
            RawServiceObservation::Unavailable,
            "an answer whose pipe never closed is not a service state"
        );
        assert!(waited < Duration::from_secs(25), "{waited:?}");
        assert!(
            backend.children.pending.is_none(),
            "the child itself was reaped"
        );
        remove(&[systemctl, health, pidfile]);
    }

    /// FH-1 counterexample 3: the writer outside the child closes before the
    /// deadline. The output is complete and used.
    #[test]
    fn a_writer_that_closes_before_the_deadline_gives_a_complete_answer() {
        let body = format!("case \"$1\" in show) sleep 0.3 &\n{RUNNING};; esac");
        let (mut backend, systemctl, health) =
            backend_with_timeout(&body, "exit 0", Duration::from_secs(30));
        assert_eq!(backend.observe_service(), RawServiceObservation::Running);
        remove(&[systemctl, health]);
    }

    /// FH-1 counterexample 10: a late writer of an earlier, abandoned call can
    /// reach neither the next call's output nor its result, because every call
    /// has its own pipe and the read end of the old one is closed.
    #[test]
    fn a_late_writer_of_an_abandoned_call_cannot_reach_the_next_call() {
        let flag = marker_path("late-flag");
        let pidfile = marker_path("late-pid");
        // First `show`: leaves a background process that, after the call has
        // given up, writes a *different* (Stopped) answer to the old pipe and
        // records whether that write was possible. Later `show`s answer
        // Running.
        let body = format!(
            "case \"$1\" in show)\n\
             if [ ! -e '{flag}' ]; then : > '{flag}'\n\
               ( sleep 2; printf 'ActiveState=inactive\\nSubState=dead\\nLoadState=loaded\\n' ) &\n\
               echo $! > '{pid}'\n\
             fi\n\
             {RUNNING};; esac",
            flag = flag.display(),
            pid = pidfile.display()
        );
        let (mut backend, systemctl, health) =
            backend_with_timeout(&body, "exit 0", Duration::from_millis(400));
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable,
            "the first call never saw EOF"
        );
        let late = read_pid(&pidfile);
        // Wait until the late writer has really run (and failed to write).
        let waited = Instant::now();
        while pid_alive(late) && waited.elapsed() < Duration::from_secs(30) {
            thread::sleep(Duration::from_millis(20));
        }
        assert!(!pid_alive(late), "the late writer did not finish");
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Running,
            "an old writer must not change a later answer"
        );
        remove(&[systemctl, health, flag, pidfile]);
    }

    /// FH-1: the read end is closed when the call returns. A background writer
    /// that keeps writing ends with SIGPIPE only if nothing leaked the read end.
    #[test]
    fn the_read_end_is_closed_when_the_call_returns() {
        let pidfile = marker_path("writer-pid");
        let body = format!(
            "case \"$1\" in show)\n\
             ( while printf x; do sleep 0.05; done ) &\n\
             echo $! > '{}'\n\
             {RUNNING};; esac",
            pidfile.display()
        );
        let (mut backend, systemctl, health) =
            backend_with_timeout(&body, "exit 0", Duration::from_millis(400));
        let observed = within(Duration::from_secs(30), move || backend.observe_service());
        assert_eq!(observed, RawServiceObservation::Unavailable);
        let writer = read_pid(&pidfile);
        let waited = Instant::now();
        while pid_alive(writer) && waited.elapsed() < Duration::from_secs(30) {
            thread::sleep(Duration::from_millis(20));
        }
        let leaked = pid_alive(writer);
        if leaked {
            kill_pid(writer);
        }
        assert!(!leaked, "the writer still has a reader: the pipe leaked");
        remove(&[systemctl, health, pidfile]);
    }

    const FD_CASE_ENV: &str = "MKM_TEST_SYSTEMD_FD_CASE";
    const FD_CASE_TEST: &str = "resource_executor::systemd_service::tests::fd_isolated_child";

    fn open_descriptors() -> usize {
        fs::read_dir("/dev/fd").unwrap().count()
    }

    /// Does nothing unless the parent test below started this binary for it:
    /// the descriptor count is only meaningful with no other test running.
    #[test]
    fn fd_isolated_child() {
        if std::env::var_os(FD_CASE_ENV).is_none() {
            return;
        }
        let pids = marker_path("fd-pids");
        let body = format!(
            "case \"$1\" in show) sleep 2 &\necho $! >> '{}'\n{RUNNING};; esac",
            pids.display()
        );
        let (mut backend, systemctl, health) =
            backend_with_timeout(&body, "exit 0", Duration::from_millis(150));
        // One call first: lazily opened process-wide descriptors do not count.
        assert_eq!(
            backend.observe_service(),
            RawServiceObservation::Unavailable
        );
        let before = open_descriptors();
        for _ in 0..25 {
            assert_eq!(
                backend.observe_service(),
                RawServiceObservation::Unavailable
            );
            assert!(backend.children.pending.is_none());
        }
        let after = open_descriptors();
        assert_eq!(before, after, "descriptors accumulated over timeouts");
        for line in fs::read_to_string(&pids).unwrap().lines() {
            let pid: i32 = line.trim().parse().unwrap();
            let waited = Instant::now();
            while pid_alive(pid) && waited.elapsed() < Duration::from_secs(30) {
                thread::sleep(Duration::from_millis(20));
            }
            assert!(!pid_alive(pid), "a helper process was left behind");
        }
        remove(&[systemctl, health, pids]);
        println!("SYSTEMD-FD-CASE-OK");
    }

    /// FH-1 counterexample 9: repeated give-ups leave no descriptors behind
    /// (run alone in a child process so that nothing else opens files).
    #[test]
    fn descriptors_do_not_accumulate_over_repeated_unfinished_outputs() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", FD_CASE_TEST, "--nocapture", "--test-threads=1"])
            .env(FD_CASE_ENV, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{}\n{stdout}\n{stderr}",
            output.status
        );
        assert!(
            stdout.contains("SYSTEMD-FD-CASE-OK"),
            "did not run\n{stdout}\n{stderr}"
        );
    }

    fn failing_kill(_: &mut Child) -> std::io::Result<()> {
        Err(std::io::Error::from_raw_os_error(1))
    }

    /// A wait query that fails with `EIO`: not `ECHILD`, so the child stays owed.
    fn failing_try_wait(_: &mut Child) -> std::io::Result<Option<ExitStatus>> {
        Err(std::io::Error::from_raw_os_error(5))
    }

    /// The pid is no longer our child (as under an ignored `SIGCHLD`: a child
    /// that ended was already reaped by the kernel). A child that has ended is
    /// reaped here first, so a test leaves no zombie; the answer is `ECHILD`
    /// either way.
    fn echild_try_wait(child: &mut Child) -> std::io::Result<Option<ExitStatus>> {
        let _ = child.try_wait();
        // the literal on purpose: independent of the constant under test
        Err(std::io::Error::from_raw_os_error(10))
    }

    /// Kills made through `counting_kill` (only one test uses it; the calls
    /// run on the watchdog's helper thread, so a thread-local would not do).
    static KILLS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    fn counting_kill(child: &mut Child) -> std::io::Result<()> {
        KILLS.fetch_add(1, Ordering::SeqCst);
        child.kill()
    }

    fn kills() -> u32 {
        KILLS.load(Ordering::SeqCst)
    }

    fn no_nonblocking(_: i32) -> Result<(), i32> {
        Err(5)
    }

    /// Scripts that leave a mark when their body really runs; the `exec sleep`
    /// start is the child that has to be killed.
    struct Marked {
        backend: Option<LinuxSystemdServiceBackend>,
        systemctl: PathBuf,
        health: PathBuf,
        marks: [PathBuf; 2],
    }

    fn marked_backend(start_body: &str, timeout: Duration) -> Marked {
        let systemctl_mark = marker_path("pending-systemctl");
        let health_mark = marker_path("pending-health");
        let body = format!(
            "touch '{}'\ncase \"$1\" in show) {RUNNING};; start) {start_body};; stop) exit 0;; esac",
            systemctl_mark.display()
        );
        let (backend, systemctl, health) = backend_with_timeouts(
            &body,
            &format!("touch '{}'\nexit 0", health_mark.display()),
            timeout,
            timeout,
        );
        // `script` has warmed both up without running their bodies.
        assert!(!systemctl_mark.exists() && !health_mark.exists());
        Marked {
            backend: Some(backend),
            systemctl,
            health,
            marks: [systemctl_mark, health_mark],
        }
    }

    impl Marked {
        fn b(&mut self) -> &mut LinuxSystemdServiceBackend {
            self.backend.as_mut().unwrap()
        }

        /// Run one backend call under the watchdog: a regression to an
        /// unbounded wait fails the test instead of hanging the suite.
        fn guarded<T: Send + 'static>(
            &mut self,
            call: impl FnOnce(&mut LinuxSystemdServiceBackend) -> T + Send + 'static,
        ) -> T {
            let mut backend = self.backend.take().unwrap();
            let (backend, answer) = within(Duration::from_secs(30), move || {
                let answer = call(&mut backend);
                (backend, answer)
            });
            self.backend = Some(backend);
            answer
        }

        fn finish(self) {
            let [a, b] = self.marks;
            remove(&[self.systemctl, self.health, a, b]);
        }
    }

    /// FH-1 counterexample 4: the kill fails and the child lives on. The
    /// result is not a clean timeout, the child stays owed, every later
    /// command (action, `show`, health) is refused without being spawned and
    /// without waiting, and a later call that can kill it discharges the debt
    /// before it spawns anything.
    #[test]
    fn a_timeout_whose_kill_fails_keeps_the_child_owed_and_blocks_every_command() {
        let mut marked = marked_backend("exec sleep 60", Duration::from_millis(300));
        marked.b().children.ops.kill = failing_kill;
        marked.b().children.ops.kill_reap_budget = Duration::from_millis(150);
        marked.b().children.ops.retry_reap_budget = Duration::from_millis(100);
        assert!(matches!(
            marked.guarded(|b| b.request_service_start()),
            ActionDiagnostic::Error(message) if message.contains("cleanup is uncertain")
        ));
        let owed = marked.b().children.pending.as_ref().map(Child::id);
        assert!(owed.is_some(), "an unreaped child must be kept");
        let owed = i32::try_from(owed.unwrap()).unwrap();
        assert!(pid_alive(owed));

        let [systemctl_mark, health_mark] = marked.marks.clone();
        let _ = fs::remove_file(&systemctl_mark);
        let started = Instant::now();
        assert!(matches!(
            marked.guarded(|b| b.request_service_stop()),
            ActionDiagnostic::Error(message) if message.contains("earlier systemd command")
        ));
        assert_eq!(
            marked.guarded(|b| b.observe_service()),
            RawServiceObservation::Unavailable
        );
        assert_eq!(
            marked.guarded(|b| b.observe_health()),
            RawHealthObservation::Unavailable
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "refusals must not wait long"
        );
        assert!(
            !systemctl_mark.exists(),
            "systemctl was spawned while a child was owed"
        );
        assert!(
            !health_mark.exists(),
            "health was spawned while a child was owed"
        );
        assert!(
            marked.b().children.pending.is_some(),
            "refusals do not discharge"
        );

        // The kill works again: the debt is discharged first, then work resumes.
        marked.b().children.ops.kill = Child::kill;
        marked.b().children.ops.retry_reap_budget = RETRY_REAP_BUDGET;
        assert_eq!(
            marked.guarded(|b| b.request_service_stop()),
            ActionDiagnostic::Success
        );
        assert!(marked.b().children.pending.is_none());
        assert!(!pid_alive(owed), "the owed child was killed and reaped");
        assert!(systemctl_mark.exists(), "positive control: the stop ran");
        marked.finish();
    }

    /// F1-4: a child that has long exited, but is first looked at after the
    /// deadline, is a timeout and not a success; one looked at before the
    /// deadline is a success. (The deadline is given directly, so the outcome
    /// does not depend on timing.)
    #[test]
    fn an_exit_first_seen_after_the_deadline_is_a_timeout_not_a_success() {
        let program = script("printf 'ActiveState=active'; exit 0");
        for (deadline, expect_exit) in [(far(), true), (passed(), false)] {
            let mut command = Command::new(&program);
            command.stdout(Stdio::piped()).stderr(Stdio::null());
            let mut child = command.spawn().unwrap();
            let stdout = child.stdout.take();
            // Let it exit (its status stays unread until wait_for_child).
            thread::sleep(Duration::from_millis(300));
            let mut children = fresh();
            let result = wait_for_child(&mut children, child, deadline, stdout);
            match (&result, expect_exit) {
                (CaptureResult::Exited(status, output), true) => {
                    assert!(status.success() && output.is_complete());
                }
                (
                    CaptureResult::TimedOut {
                        cleanup_succeeded: true,
                    },
                    false,
                ) => {}
                _ => panic!("expect_exit={expect_exit}: {result:?}"),
            }
            assert!(children.pending.is_none());
        }
        remove(&[program]);
    }

    /// A kill that fails is not a clean timeout even when the child then ends
    /// on its own and is reaped: nothing is left owed, but the result says the
    /// cleanup was not as intended.
    #[test]
    fn a_failed_kill_is_not_a_clean_timeout_even_when_the_child_ends_on_its_own() {
        let mut marked = marked_backend("exec sleep 1", Duration::from_millis(200));
        marked.b().children.ops.kill = failing_kill;
        assert!(matches!(
            marked.guarded(|b| b.request_service_start()),
            ActionDiagnostic::Error(message) if message.contains("cleanup is uncertain")
        ));
        assert!(
            marked.b().children.pending.is_none(),
            "the child was reaped, so nothing is owed"
        );
        marked.finish();
    }

    /// FH-1 counterexample 5: the wait query itself fails (the pid may no
    /// longer be ours). No signal is sent for it, the child stays owed, every
    /// later command is refused, and once the query works again the child is
    /// killed (it is still ours) and reaped.
    #[test]
    fn a_failed_wait_query_sends_no_signal_and_keeps_the_child_owed() {
        let mut marked = marked_backend("exec sleep 60", Duration::from_secs(20));
        marked.b().children.ops.try_wait = failing_try_wait;
        marked.b().children.ops.kill = counting_kill;
        marked.b().children.ops.kill_reap_budget = Duration::from_millis(100);
        marked.b().children.ops.retry_reap_budget = Duration::from_millis(100);
        KILLS.store(0, Ordering::SeqCst);
        assert!(matches!(
            marked.guarded(|b| b.request_service_start()),
            ActionDiagnostic::Error(message) if message.contains("cleanup is uncertain")
        ));
        assert_eq!(kills(), 0, "no signal after a failed wait query");
        let owed = i32::try_from(marked.b().children.pending.as_ref().unwrap().id()).unwrap();
        assert!(pid_alive(owed));
        let [systemctl_mark, _] = marked.marks.clone();
        let _ = fs::remove_file(&systemctl_mark);
        assert!(matches!(
            marked.guarded(|b| b.request_service_stop()),
            ActionDiagnostic::Error(message) if message.contains("earlier systemd command")
        ));
        assert_eq!(kills(), 0, "the retry must not signal either");
        assert!(!systemctl_mark.exists());
        assert!(marked.b().children.pending.is_some());

        marked.b().children.ops.try_wait = Child::try_wait;
        assert_eq!(
            marked.guarded(|b| b.request_service_stop()),
            ActionDiagnostic::Success
        );
        assert!(kills() >= 1, "the still-owned child is killed on discharge");
        assert!(marked.b().children.pending.is_none());
        assert!(!pid_alive(owed));
        marked.finish();
    }

    /// A pipe that cannot be made non-blocking is never read: the call goes
    /// straight to the deadline cleanup (kill + reap) instead of waiting for a
    /// silent child, and nothing stays owed.
    #[test]
    fn a_pipe_that_cannot_be_made_non_blocking_is_cleaned_up_at_once() {
        let (mut backend, systemctl, health) = backend_with_timeout(
            "case \"$1\" in show) exec sleep 60;; esac",
            "exit 0",
            Duration::from_secs(20),
        );
        backend.children.ops.set_nonblocking = no_nonblocking;
        let started = Instant::now();
        let observed = within(Duration::from_secs(30), move || {
            let observed = backend.observe_service();
            assert!(backend.children.pending.is_none());
            observed
        });
        assert_eq!(observed, RawServiceObservation::Unavailable);
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "it must not wait for the child"
        );
        remove(&[systemctl, health]);
    }

    /// Output that is too large is Unknown, and the child that wrote far more
    /// than the pipe holds is not stalled (the surplus is drained and dropped).
    #[test]
    fn a_flood_of_output_neither_stalls_the_child_nor_becomes_a_state() {
        let (mut backend, systemctl, health) = backend(
            "case \"$1\" in show) head -c 1048576 /dev/zero;; esac",
            "exit 0",
        );
        let observed = within(Duration::from_secs(60), move || backend.observe_service());
        assert_eq!(observed, RawServiceObservation::Unavailable);
        remove(&[systemctl, health]);
    }

    /// Source shape of FH-1: no thread and no blocking join / wait / read-to-end
    /// in the production part of this file.
    #[test]
    fn production_code_has_no_thread_and_no_unbounded_wait() {
        let source = include_str!("systemd_service.rs");
        let production = &source[..source.find("#[cfg(test)]").unwrap()];
        for forbidden in [
            "thread::spawn",
            "thread::Builder",
            "thread::scope",
            "JoinHandle",
            ".join(",
            ".wait()",
            "wait_with_output",
            "read_to_end",
            "read_to_string",
            ".output()",
        ] {
            assert!(!production.contains(forbidden), "{forbidden}");
        }
    }

    // ---- BL-3 (option A): `ECHILD` settles the debt, nothing else does ------------------

    static ECHILD_KILLS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    static OTHER_KILLS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    static NONE_KILLS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    static WAIT_ERRNO: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(5);

    fn echild_counting_kill(child: &mut Child) -> std::io::Result<()> {
        ECHILD_KILLS.fetch_add(1, Ordering::SeqCst);
        child.kill()
    }

    fn other_counting_kill(child: &mut Child) -> std::io::Result<()> {
        OTHER_KILLS.fetch_add(1, Ordering::SeqCst);
        child.kill()
    }

    fn none_counting_kill(child: &mut Child) -> std::io::Result<()> {
        NONE_KILLS.fetch_add(1, Ordering::SeqCst);
        child.kill()
    }

    fn errno_try_wait(_: &mut Child) -> std::io::Result<Option<ExitStatus>> {
        Err(std::io::Error::from_raw_os_error(
            WAIT_ERRNO.load(Ordering::SeqCst),
        ))
    }

    /// A live child of this test standing for "a child that is no longer ours".
    fn stand_in() -> (Child, i32) {
        let child = Command::new("/bin/sleep").arg("60").spawn().unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        (child, pid)
    }

    fn finish_stand_in(pid: i32) {
        unsafe extern "C" {
            fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        }
        kill_pid(pid);
        let mut status = 0;
        // SAFETY: the pid is a child of this test process.
        unsafe { waitpid(pid, &mut status, 0) };
    }

    /// T1: `ECHILD` settles the debt: no signal to the old pid, and the next
    /// command can be spawned.
    #[test]
    fn echild_settles_the_debt_without_a_signal_and_lets_the_next_command_run() {
        let (child, pid) = stand_in();
        let mut children = fresh();
        children.ops.try_wait = echild_try_wait;
        children.ops.kill = echild_counting_kill;
        ECHILD_KILLS.store(0, Ordering::SeqCst);
        children.pending = Some(child);
        assert!(children.discharge());
        assert!(children.pending.is_none());
        assert_eq!(
            ECHILD_KILLS.load(Ordering::SeqCst),
            0,
            "no signal after ECHILD"
        );
        assert!(pid_alive(pid), "the old pid was not touched");
        finish_stand_in(pid);

        // through the backend: the next command is spawned and runs
        let mut marked = marked_backend("exit 0", Duration::from_secs(20));
        let (child, pid) = stand_in();
        marked.b().children.ops.try_wait = echild_try_wait;
        marked.b().children.ops.kill = echild_counting_kill;
        marked.b().children.pending = Some(child);
        let [systemctl_mark, _] = marked.marks.clone();
        assert!(!systemctl_mark.exists());
        // The next command is spawned. Its own child also answers ECHILD under
        // this stand-in, so its result is the uncertain error, never a success.
        assert!(matches!(
            marked.guarded(|b| b.request_service_stop()),
            ActionDiagnostic::Error(m) if m.contains("cleanup is uncertain")
        ));
        // (it was left running: wait for its first line)
        let waited = Instant::now();
        while !systemctl_mark.exists() && waited.elapsed() < Duration::from_secs(30) {
            thread::sleep(Duration::from_millis(20));
        }
        assert!(systemctl_mark.exists(), "the next command was spawned");
        assert_eq!(ECHILD_KILLS.load(Ordering::SeqCst), 0);
        finish_stand_in(pid);
        marked.finish();
    }

    /// T2: any other wait failure keeps the child, refuses every spawn and
    /// sends no signal; once the query works the still-owned child is killed.
    #[test]
    fn a_wait_failure_other_than_echild_keeps_the_child_owed() {
        for errno in [5, 22, 1, 13] {
            let mut marked = marked_backend("exit 0", Duration::from_secs(20));
            let (child, pid) = stand_in();
            WAIT_ERRNO.store(errno, Ordering::SeqCst);
            marked.b().children.ops.try_wait = errno_try_wait;
            marked.b().children.ops.kill = other_counting_kill;
            marked.b().children.ops.retry_reap_budget = Duration::from_millis(100);
            marked.b().children.pending = Some(child);
            OTHER_KILLS.store(0, Ordering::SeqCst);
            let [systemctl_mark, health_mark] = marked.marks.clone();
            for _ in 0..3 {
                assert!(
                    matches!(
                        marked.guarded(|b| b.request_service_stop()),
                        ActionDiagnostic::Error(m) if m.contains("earlier systemd command")
                    ),
                    "errno {errno}"
                );
                assert_eq!(
                    marked.guarded(|b| b.observe_service()),
                    RawServiceObservation::Unavailable
                );
                assert_eq!(
                    marked.guarded(|b| b.observe_health()),
                    RawHealthObservation::Unavailable
                );
            }
            assert!(
                !systemctl_mark.exists() && !health_mark.exists(),
                "errno {errno}: spawned"
            );
            assert_eq!(
                OTHER_KILLS.load(Ordering::SeqCst),
                0,
                "errno {errno}: signalled"
            );
            assert!(marked.b().children.pending.is_some() && pid_alive(pid));
            // recovery: the query works again, the child is still ours
            marked.b().children.ops.try_wait = Child::try_wait;
            assert_eq!(
                marked.guarded(|b| b.request_service_stop()),
                ActionDiagnostic::Success
            );
            assert_eq!(OTHER_KILLS.load(Ordering::SeqCst), 1, "errno {errno}");
            assert!(marked.b().children.pending.is_none());
            let _ = pid; // killed and reaped by the discharge
            marked.finish();
        }
    }

    /// T3: a child that is still ours and not reaped: the existing bounded
    /// cleanup (one kill, bounded reap) is unchanged and the debt stays.
    #[test]
    fn a_still_running_unreaped_child_stays_owed_through_the_bounded_cleanup() {
        let (child, pid) = stand_in();
        let mut children = fresh();
        children.ops.try_wait = never_reaped_for_bl3;
        children.ops.kill = none_counting_kill;
        children.ops.retry_reap_budget = Duration::from_millis(150);
        NONE_KILLS.store(0, Ordering::SeqCst);
        children.pending = Some(child);
        let started = Instant::now();
        assert!(!children.discharge());
        assert!(started.elapsed() < Duration::from_secs(5), "bounded");
        assert!(children.pending.is_some());
        assert_eq!(NONE_KILLS.load(Ordering::SeqCst), 1);
        // the next command is refused
        let mut marked = marked_backend("exit 0", Duration::from_secs(20));
        let (child2, pid2) = stand_in();
        marked.b().children.ops.try_wait = never_reaped_for_bl3;
        marked.b().children.ops.retry_reap_budget = Duration::from_millis(100);
        marked.b().children.pending = Some(child2);
        assert!(matches!(
            marked.guarded(|b| b.request_service_stop()),
            ActionDiagnostic::Error(m) if m.contains("earlier systemd command")
        ));
        assert!(!marked.marks[0].exists());
        finish_stand_in(pid2);
        finish_stand_in(pid);
        marked.finish();
    }

    fn never_reaped_for_bl3(_: &mut Child) -> std::io::Result<Option<ExitStatus>> {
        Ok(None)
    }

    /// T4: `ECHILD` is never promoted: with every wait answering `ECHILD` (the
    /// effect of an ignored `SIGCHLD`), no call is ever a success, whatever
    /// `show` and the health command would say.
    #[test]
    fn echild_is_never_promoted_to_success_stopped_or_healthy() {
        let mut marked = marked_backend("exit 0", Duration::from_secs(20));
        marked.b().children.ops.try_wait = echild_try_wait;
        for round in 0..5 {
            assert!(
                matches!(
                    marked.guarded(|b| b.request_service_start()),
                    ActionDiagnostic::Error(m) if m.contains("cleanup is uncertain")
                ),
                "round {round}"
            );
            assert_eq!(
                marked.guarded(|b| b.observe_service()),
                RawServiceObservation::Unavailable,
                "round {round}: show says Running, but its exit was never seen"
            );
            assert!(
                matches!(
                    marked.guarded(|b| b.request_service_stop()),
                    ActionDiagnostic::Error(_)
                ),
                "round {round}"
            );
            assert_eq!(
                marked.guarded(|b| b.observe_health()),
                RawHealthObservation::Unavailable,
                "round {round}: the health program exits 0, but its exit was never seen"
            );
        }
        marked.finish();
    }

    const BL3_ENV: &str = "MKM_TEST_BL3_SIGIGN";
    const BL3_TEST: &str = "resource_executor::systemd_service::tests::bl3_sigign_child";

    unsafe extern "C" {
        fn signal(sig: i32, handler: usize) -> usize;
    }

    /// Child process of T5: SIGCHLD ignored in this process only.
    #[test]
    fn bl3_sigign_child() {
        if std::env::var_os(BL3_ENV).is_none() {
            return;
        }
        let mut marked = marked_backend("exit 0", Duration::from_secs(20)); // scripts warmed first
        let sigchld = if cfg!(target_os = "macos") { 20 } else { 17 };
        // SAFETY: an isolated child process; 1 is SIG_IGN.
        unsafe { signal(sigchld, 1) };
        let [systemctl_mark, _] = marked.marks.clone();
        let started = Instant::now();
        let first = marked.guarded(|b| b.request_service_start());
        assert!(
            matches!(&first, ActionDiagnostic::Error(m) if m.contains("cleanup is uncertain")),
            "{first:?}"
        );
        assert!(
            marked.b().children.pending.is_some(),
            "the already reaped child is owed for now"
        );
        let _ = fs::remove_file(&systemctl_mark);
        let show = marked.guarded(|b| b.observe_service());
        assert_eq!(show, RawServiceObservation::Unavailable);
        assert!(
            systemctl_mark.exists(),
            "ECHILD settled the debt: the next command was spawned"
        );
        let stop = marked.guarded(|b| b.request_service_stop());
        assert!(matches!(&stop, ActionDiagnostic::Error(_)), "{stop:?}");
        let health = marked.guarded(|b| b.observe_health());
        assert_eq!(health, RawHealthObservation::Unavailable);
        assert!(started.elapsed() < Duration::from_secs(30));
        println!("BL3-SIGIGN-OK first={first:?} show={show:?} stop={stop:?} health={health:?}");
    }

    /// T5: the real thing in an isolated child process (the SIGCHLD setting is
    /// process-wide, so it never touches this test process): no hang, no
    /// success, nothing stuck.
    #[test]
    fn an_ignored_sigchld_no_longer_locks_the_backend_out_and_never_succeeds() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", BL3_TEST, "--nocapture", "--test-threads=1"])
            .env(BL3_ENV, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{}\n{stdout}\n{stderr}",
            output.status
        );
        assert!(
            stdout.contains("BL3-SIGIGN-OK"),
            "did not run\n{stdout}\n{stderr}"
        );
        println!(
            "{}",
            stdout
                .lines()
                .find(|l| l.contains("BL3-SIGIGN-OK"))
                .unwrap_or("")
        );
    }

    // ---- G-30 (Owner ruling (a)): at most one `reset-failed` after a stop that leaves `failed`

    /// A unit whose start failed: `show` reports failed/failed until a successful
    /// `reset-failed` (as systemd does); every call is appended to a log.
    fn failed_unit(reset_body: &str) -> (PathBuf, PathBuf, String) {
        let base = std::env::temp_dir().join(format!(
            "mikagami-g30-{}-{}",
            std::process::id(),
            NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let state = base.with_extension("reset");
        let log = base.with_extension("log");
        let body = format!(
            "echo \"$1\" >> '{log}'\ncase \"$1\" in show) if [ -f '{state}' ]; then printf 'ActiveState=inactive\\nSubState=dead\\nLoadState=loaded\\n'; else printf 'ActiveState=failed\\nSubState=failed\\nLoadState=loaded\\n'; fi;; stop) exit 0;; reset-failed) {reset_body};; esac",
            log = log.display(),
            state = state.display(),
        );
        (state, log, body)
    }

    fn calls(log: &Path) -> Vec<String> {
        fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn g30_a_failed_unit_after_a_stop_gets_one_reset_and_then_reads_inactive_dead() {
        let (state, log, body) = failed_unit("");
        let body = body.replace(
            "reset-failed) ;;",
            &format!("reset-failed) touch '{}';;", state.display()),
        );
        let (mut backend, systemctl, health) = backend(&body, "exit 0");
        assert_eq!(backend.request_service_stop(), ActionDiagnostic::Success);
        assert_eq!(backend.observe_service(), RawServiceObservation::Stopped);
        let c = calls(&log);
        assert_eq!(
            c.iter().filter(|x| *x == "reset-failed").count(),
            1,
            "{c:?}"
        );
        assert_eq!(c, ["stop", "show", "reset-failed", "show"]);
        remove(&[systemctl, health, state, log]);
    }

    #[test]
    fn g30_a_reset_that_fails_or_times_out_leaves_the_unit_unknown() {
        for reset in ["exit 1", "sleep 5"] {
            let (state, log, body) = failed_unit(reset);
            let (mut backend, systemctl, health) =
                backend_with_timeout(&body, "exit 0", Duration::from_secs(2));
            assert_eq!(backend.request_service_stop(), ActionDiagnostic::Success);
            assert_eq!(
                backend.observe_service(),
                RawServiceObservation::Unavailable,
                "{reset}: still failed is never Stopped (C-6)"
            );
            let c = calls(&log);
            assert_eq!(
                c.iter().filter(|x| *x == "reset-failed").count(),
                1,
                "{reset}: {c:?}"
            );
            remove(&[systemctl, health, state, log]);
        }
    }

    #[test]
    fn g30_no_reset_after_a_failed_stop_or_for_any_other_state() {
        // the stop itself failed: no reset, the unit stays failed and Unknown
        let (state, log, body) = failed_unit("touch /dev/null");
        let body = body.replace("stop) exit 0;;", "stop) exit 1;;");
        let (mut b, systemctl, health) = backend(&body, "exit 0");
        assert_ne!(b.request_service_stop(), ActionDiagnostic::Success);
        assert_eq!(b.observe_service(), RawServiceObservation::Unavailable);
        assert!(!calls(&log).contains(&"reset-failed".to_string()));
        remove(&[systemctl, health, state, log]);
        // any state other than exactly ActiveState=failed (loaded), or unreadable output: no reset
        for show in [
            "printf 'ActiveState=inactive\\nSubState=dead\\nLoadState=loaded\\n'",
            "printf 'ActiveState=deactivating\\nSubState=stop-sigterm\\nLoadState=loaded\\n'",
            "printf 'ActiveState=inactive\\nSubState=failed\\nLoadState=loaded\\n'",
            "printf 'ActiveState=failed\\nSubState=failed\\nLoadState=not-found\\n'",
            "printf 'ActiveState=failed\\nSubState=failed\\nLoadState=loaded\\nExtra=x\\n'",
            "exit 1",
        ] {
            let base = std::env::temp_dir().join(format!(
                "mikagami-g30o-{}-{}",
                std::process::id(),
                NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed)
            ));
            let log = base.with_extension("log");
            let (mut backend, systemctl, health) = backend(
                &format!(
                    "echo \"$1\" >> '{}'\ncase \"$1\" in show) {show};; stop) exit 0;; reset-failed) exit 0;; esac",
                    log.display()
                ),
                "exit 0",
            );
            assert_eq!(backend.request_service_stop(), ActionDiagnostic::Success);
            assert!(!calls(&log).contains(&"reset-failed".to_string()), "{show}");
            remove(&[systemctl, health, log]);
        }
    }

    #[test]
    fn g30_c6_is_unchanged_failed_is_never_stopped() {
        for text in [
            b"ActiveState=failed\nSubState=failed\nLoadState=loaded\n".as_slice(),
            b"ActiveState=inactive\nSubState=failed\nLoadState=loaded\n",
        ] {
            assert_eq!(
                classify_properties(text),
                RawServiceObservation::Unavailable
            );
        }
        assert_eq!(
            parse_properties(b"ActiveState=failed\nSubState=failed\nLoadState=loaded\n"),
            Some(("failed", "failed", "loaded"))
        );
        assert_eq!(
            parse_properties(
                b"ActiveState=failed\nActiveState=failed\nSubState=x\nLoadState=loaded\n"
            ),
            None
        );
    }
}
