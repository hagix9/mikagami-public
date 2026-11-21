//! Stage 13.4 production binary wiring: `mikagami daemon run`.
//!
//! Thin orchestration only — every security and HA decision stays in the
//! existing library layers. This module wires:
//!
//! ```text
//! Config::load -> production validation -> Psk::load(Config.security.psk_file)
//!   -> LinuxPlatformConfig -> LinuxDaemonRuntime
//!   -> production Witness transport + HELLO -> WitnessSession + adapter
//!   -> attach_witness -> Daemon::new -> start() recovery gate
//!   -> foreground non-overlapping observation loop -> clean shutdown
//! ```
//!
//! The only path from here to a promotion attempt is the loop's single
//! consumption point: an operator's SIGUSR1 intent or the automatic trigger's
//! one-shot request (`[failover] auto`, v1.0 Amendment REV-1/REV-2), both run
//! by the same `promote` closure. The loop itself never calls `promote`,
//! acquires a lease or mutates a resource, and never issues a Witness
//! request: every attempt issues its own `GET_TERM` inside the attempt.

use std::fmt;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::daemon::{Daemon, DaemonRuntime, DaemonState, StartResult, TickResult};

/// Terminal classification of the foreground observation loop.
#[allow(dead_code)] // production use is Linux-only; tests exercise it everywhere
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LoopExit {
    /// Shutdown was observed and completed cleanly.
    Clean,
    /// Shutdown was requested but resource cleanup remains pending
    /// (`TickResult::ShutdownRequiresCleanup`); exits non-zero.
    ShutdownRequiresCleanup,
    /// Structural/runtime fatal failure (class D) or an unexpected
    /// non-running state; exits non-zero.
    Fatal(String),
    /// The shared control lock was lost. This is deliberately **not** a
    /// normal shutdown: the loop returns at once so no demotion, VIP release,
    /// service stop, lease operation or fencing cleanup is attempted after
    /// the process can no longer prove that it is the only control process.
    ControlLockLost(String),
}

impl fmt::Display for LoopExit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clean => formatter.write_str("clean shutdown"),
            Self::ShutdownRequiresCleanup => {
                formatter.write_str("shutdown requires unresolved resource cleanup")
            }
            Self::Fatal(error) => write!(formatter, "fatal runtime failure: {error}"),
            Self::ControlLockLost(error) => {
                write!(
                    formatter,
                    "control lock lost; stopping without resource cleanup: {error}"
                )
            }
        }
    }
}

/// Stage 13.5 operator-intent latch (MKM-13.5-04).
///
/// The signal handler may only *set* the pending bit. `consume` atomically
/// takes it so at most one synchronous promotion attempt can start;
/// `discard` clears it without consumption. There is no counter and no
/// queue: N signal deliveries before consumption still yield one pending
/// bit — POSIX coalescing is the intended semantics.
#[allow(dead_code)] // production use is Linux-only; tests exercise it everywhere
pub(crate) trait PromotionIntentLatch {
    /// Atomically take the pending intent. Consumption is destructive: a
    /// consumed intent can start at most one attempt.
    fn consume(&self) -> bool;
    /// Atomically clear any pending intent without consuming it.
    fn discard(&self);
}

impl PromotionIntentLatch for AtomicBool {
    fn consume(&self) -> bool {
        self.swap(false, Ordering::SeqCst)
    }
    fn discard(&self) {
        self.store(false, Ordering::SeqCst);
    }
}

/// The foreground observation loop (MKM-13.4-03/05/12, MKM-13.5-04/05).
///
/// One iteration: observe shutdown intent -> consume at most one pending
/// promotion intent (executing exactly one synchronous attempt only while
/// `Running` and idle) -> sample exactly one authoritative `Instant` ->
/// execute exactly one `tick_at` -> handle the result -> wait the full
/// cadence. Ticks and promotions never overlap and never catch up: a delayed
/// iteration still performs exactly one tick, because `now` is sampled once
/// and each iteration ends with an unconditional wait.
///
/// Failure classes (design §11):
/// - C (recoverable observation failure) is contained inside `tick_at` as
///   `ObservationUnavailable` — evidence was not strengthened; the loop
///   simply continues at the normal cadence (no hot retry).
/// - D (structural/runtime fatal) surfaces as `Err` or a non-running state
///   and stops the loop.
/// - Shutdown truth is `Daemon`-owned: `should_stop` only requests it; the
///   next `tick_at` performs `runtime.shutdown()` and no further tick is
///   issued after shutdown is observed. Every `should_stop` observation that
///   returns true is propagated by `request_shutdown` before the next
///   operation of the iteration, so no tick — hence no foreground fencing
///   step — runs after a stop was observed (Stage 14 §27.4, F14.9-01).
///
/// Stage 13.5 intent rules: the latch is cleared once at entry (intent that
/// arrived before the daemon was `Running` is never carried forward), on
/// every shutdown observation, and after each synchronous attempt (a signal
/// received during an attempt is discarded — never an implicit retry). An
/// intent consumed while not `Running` is dropped without effect.
#[allow(dead_code)] // production use is Linux-only; tests exercise it everywhere
pub(crate) fn run_observation_loop<R, Stop, Wait, Clock>(
    daemon: &mut Daemon<R>,
    interval: Duration,
    should_stop: Stop,
    wait: Wait,
    clock: Clock,
    intent: &dyn PromotionIntentLatch,
    prime: impl FnMut(&mut Daemon<R>, Instant),
    promote: impl FnMut(&mut Daemon<R>),
) -> LoopExit
where
    R: DaemonRuntime,
    Stop: FnMut() -> bool,
    Wait: FnMut(Duration),
    Clock: FnMut() -> Instant,
{
    run_observation_loop_checked(
        daemon,
        interval,
        || None,
        should_stop,
        wait,
        clock,
        intent,
        prime,
        promote,
    )
}

/// The loop with a dedicated lock-loss predicate. The predicate is checked
/// before every ordinary iteration and immediately before a promotion. When it
/// reports an error, the loop returns [`LoopExit::ControlLockLost`] **without**
/// calling `request_shutdown` or `tick_at`: normal shutdown can demote, release
/// the VIP, stop the service and touch the lease, all of which may race a new
/// control owner after the lock was replaced.
#[allow(dead_code)]
fn run_observation_loop_checked<R, Stop, Wait, Clock, LockLost>(
    daemon: &mut Daemon<R>,
    interval: Duration,
    mut lock_lost: LockLost,
    mut should_stop: Stop,
    mut wait: Wait,
    mut clock: Clock,
    intent: &dyn PromotionIntentLatch,
    mut prime: impl FnMut(&mut Daemon<R>, Instant),
    mut promote: impl FnMut(&mut Daemon<R>),
) -> LoopExit
where
    R: DaemonRuntime,
    Stop: FnMut() -> bool,
    Wait: FnMut(Duration),
    Clock: FnMut() -> Instant,
    LockLost: FnMut() -> Option<String>,
{
    intent.discard();
    loop {
        if let Some(error) = lock_lost() {
            intent.discard();
            return LoopExit::ControlLockLost(error);
        }
        if should_stop() {
            intent.discard();
            // Idempotent; errors only when the daemon already left a state
            // that can shut down — the tick below resolves that into a
            // terminal result either way.
            let _ = daemon.request_shutdown();
        }
        // At-most-one consumption point. The pending bit is always taken —
        // an intent that cannot run (not `Running`, promotion in flight, or
        // shutdown already requested) is discarded by this consume and can
        // never cause a later surprise mutation. The shutdown flag is
        // re-checked here so a shutdown signal racing in after the check
        // above still wins over a pending intent.
        //
        // The automatic trigger (`[failover] auto`) enters here and nowhere
        // else: its request is the same one-shot as the operator's, consumed
        // at this single point, and it runs the same single attempt. Both
        // one-shots are always taken together: an operator's intent takes
        // precedence in the same iteration, and the automatic request that
        // lost to it is dropped with it — it was raised from conditions that
        // the manual attempt may have changed, so it must not run on a later
        // iteration (it is re-raised by the next poll if it still holds).
        let operator_intent = intent.consume();
        let auto_request = daemon.take_auto_request();
        let auto_origin = if operator_intent { None } else { auto_request };
        if (operator_intent || auto_origin.is_some())
            && daemon.state() == DaemonState::Running
            && daemon
                .promotion_attempt_lifecycle()
                .in_flight_id()
                .is_none()
        {
            if let Some(error) = lock_lost() {
                // The intent is discarded; no promotion, fencing, lease or
                // VIP/service operation starts after the lock is lost.
                intent.discard();
                return LoopExit::ControlLockLost(error);
            }
            if should_stop() {
                // F14.9-01: the stop wins over the consumed intent and is
                // propagated at once.
                let _ = daemon.request_shutdown();
            } else {
                daemon.set_trigger_origin(auto_origin);
                promote(daemon);
                daemon.set_trigger_origin(None);
                intent.discard();
                // Stage 14 §27.4 (G8-A/B): an attempt can block in its fence
                // action up to the step's return deadline. A shutdown
                // requested meanwhile is observed as soon as the attempt
                // returns, so this iteration's tick performs the shutdown and
                // no fencing step starts after it.
                if should_stop() {
                    let _ = daemon.request_shutdown();
                }
            }
        }
        if let Some(error) = lock_lost() {
            // No primitive tick/cleanup runs after the lock is lost.
            return LoopExit::ControlLockLost(error);
        }
        let now = clock();
        // F14.9-01 (§27.4): the last observation before the tick. A stop seen
        // here is propagated to the Daemon before `tick_at`, so this
        // iteration's tick performs the shutdown and cannot start a
        // foreground fencing step. Otherwise, caller-driven Witness
        // observation issuance: begin one GET_TERM request generation while
        // the shared session's outstanding slot is free. The attempt path's
        // single `evaluate_authority_attempt` poll can only complete a
        // generation whose response has already arrived, so the request must
        // exist before the signal — it is never a poll, never evaluation,
        // and suppressed under shutdown.
        if should_stop() {
            intent.discard();
            let _ = daemon.request_shutdown();
        } else {
            prime(daemon, now);
        }
        match daemon.tick_at(now) {
            Ok(TickResult::Observed | TickResult::ObservationUnavailable) => {}
            Ok(TickResult::ShutdownComplete) => return LoopExit::Clean,
            Ok(TickResult::ShutdownRequiresCleanup) => {
                return LoopExit::ShutdownRequiresCleanup;
            }
            Ok(TickResult::NotRunning) => {
                return LoopExit::Fatal(format!(
                    "daemon left the running state: {:?}",
                    daemon.state()
                ));
            }
            Err(crate::daemon::DaemonError::ControlLockLost(error)) => {
                return LoopExit::ControlLockLost(error);
            }
            Err(error) => return LoopExit::Fatal(error.to_string()),
        }
        let delay = match daemon.next_wait_delay(interval) {
            Ok(delay) => delay,
            Err(error) => return LoopExit::Fatal(error.to_string()),
        };
        wait(delay);
    }
}

/// Recovery gate (MKM-13.4-02, failure class B): the normal loop may begin
/// only when `Daemon::start` reports `Running`. `RecoveryBlocked` and startup
/// errors never enter the loop.
#[allow(dead_code)] // production use is Linux-only
fn recovery_gate(
    result: Result<StartResult, crate::daemon::DaemonError>,
    cause: Option<String>,
) -> Result<(), String> {
    match result {
        Ok(StartResult::Running) => Ok(()),
        Ok(StartResult::RecoveryBlocked) => {
            let cause = cause.unwrap_or_else(|| "the reason is not known".to_string());
            crate::operator_log::error_recovery_blocked(&cause);
            Err(format!(
                "recovery gate blocked daemon startup ({cause}); refusing to run"
            ))
        }
        Err(error) => Err(format!("daemon startup failed: {error}")),
    }
}

/// Build the production Witness session and observation adapter.
///
/// This is the only production session-establishment path: it opens the
/// configured TCP transport, runs the Protocol v1 HELLO/HELLO_ACK exchange to
/// learn the Witness process `session_id`, then constructs the neutral
/// `WitnessSession` (one connection, one `ProcessSession`, one
/// `MessageAuthenticator`, one outstanding slot) and the observation-only
/// `WitnessEvidenceAdapter`.
///
/// Every failure here is a class-A startup error: no partial session is
/// attached. The PSK arrives only as the already-loaded `Psk` value; it is
/// never read from argv, logged, or formatted.
#[allow(dead_code)] // production use is Linux-only; tests exercise it everywhere
fn connect_witness_session(
    config: &crate::config::Config,
    psk: crate::security::Psk,
) -> Result<
    (
        crate::witness_runtime::WitnessSession,
        crate::evidence_fusion::adapter::WitnessEvidenceAdapter,
    ),
    String,
> {
    use crate::protocol::{CborSerializer, ClusterId, NodeId, Term};
    use crate::session::OutboundHandshake;
    use crate::tcp::{ReceiveMessageResult, TcpConnection};
    use std::net::SocketAddr;

    let witness = config
        .witness
        .as_ref()
        .filter(|witness| witness.enabled == Some(true))
        .ok_or_else(|| {
            "witness is required for production operation but is not enabled".to_string()
        })?;
    let witness_id = witness
        .id
        .as_deref()
        .filter(|id| !id.trim().is_empty())
        .ok_or_else(|| "witness.id is required for production operation".to_string())?;
    let address = witness
        .address
        .as_deref()
        .ok_or_else(|| "witness.address is required for production operation".to_string())?
        .parse::<SocketAddr>()
        .map_err(|error| format!("witness.address is not a valid socket address: {error}"))?;

    let connect_timeout = Duration::from_secs(config.heartbeat.connect_timeout_sec.max(1));
    let request_timeout = crate::evidence_fusion::WITNESS_EVIDENCE_TIMEOUT;
    let mut connection =
        TcpConnection::connect(address, connect_timeout, request_timeout, request_timeout)
            .map_err(|error| format!("witness connection to {address} failed: {error}"))?;

    let authenticator = crate::security::MessageAuthenticator::new(psk);
    let mut process = crate::session::ProcessSession::generate()
        .map_err(|error| format!("process session generation failed: {error}"))?;

    let local_node_id = NodeId::new(config.node.id.clone());
    let cluster_id = ClusterId::new(config.cluster.id.clone());
    let mut handshake = OutboundHandshake::new(
        cluster_id.clone(),
        local_node_id.clone(),
        NodeId::new(witness_id.to_string()),
        config.node.priority,
    );
    let hello = handshake
        .build_hello(&mut process, Term(0))
        .map_err(|error| format!("witness HELLO construction failed: {error}"))?;
    connection
        .send_message(hello, &CborSerializer, &authenticator)
        .map_err(|error| format!("witness HELLO send failed: {error}"))?;
    let message = match connection
        .receive_message(&CborSerializer, &authenticator)
        .map_err(|error| format!("witness HELLO_ACK receive failed: {error}"))?
    {
        ReceiveMessageResult::Message(message) => message,
        ReceiveMessageResult::Eof => {
            return Err("witness closed the connection before HELLO_ACK".to_string());
        }
    };
    handshake
        .accept_hello_ack(&message)
        .map_err(|error| format!("witness HELLO_ACK rejected: {error}"))?;
    let witness_session_id = handshake
        .peer_session_id()
        .cloned()
        .ok_or_else(|| "witness handshake established no session id".to_string())?;

    let connection = crate::witness_runtime::WitnessConnection::new(
        local_node_id,
        NodeId::new(witness_id.to_string()),
        cluster_id,
        witness_session_id,
        connection,
    );
    let session = crate::witness_runtime::WitnessSession::new(connection, process, authenticator);
    let observer = crate::evidence_fusion::adapter::WitnessEvidenceAdapter::new(request_timeout)
        .map_err(|error| error.to_string())?;
    Ok((session, observer))
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::config::Config;
    use crate::control_lock::ControlLock;
    use crate::daemon::Daemon;
    use crate::linux_node_runtime::LinuxPlatformConfig;
    use crate::security::Psk;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    /// SIGINT/SIGTERM intent latch. Signal handling only sets the flag; the
    /// observation loop observes it between iterations and lets `Daemon` own
    /// the shutdown transition (MKM-13.4-05).
    static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

    /// SIGUSR1 at-most-one promotion-intent latch (MKM-13.5-04). The handler
    /// only sets the pending bit; the daemon loop decides whether the intent
    /// is eligible. A signal carries intent only — never authorization,
    /// lease, or permission to skip any check.
    pub(super) static PROMOTION_INTENT: AtomicBool = AtomicBool::new(false);

    extern "C" fn on_shutdown_signal(_signal: libc::c_int) {
        SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
    }

    /// Signal-safe handler: set the pending bit and return. No allocation,
    /// logging, I/O, witness operation, evaluation, lease, promotion, or
    /// ordinary mutex locking may happen here.
    extern "C" fn on_promotion_intent(_signal: libc::c_int) {
        PROMOTION_INTENT.store(true, Ordering::SeqCst);
    }

    pub(super) fn install_shutdown_signals() {
        // SAFETY: `signal` with a plain flag-setting handler is async-signal
        // safe; the handler performs no allocation or locking.
        unsafe {
            libc::signal(libc::SIGINT, on_shutdown_signal as libc::sighandler_t);
            libc::signal(libc::SIGTERM, on_shutdown_signal as libc::sighandler_t);
            libc::signal(libc::SIGUSR1, on_promotion_intent as libc::sighandler_t);
        }
    }

    pub(super) fn shutdown_requested() -> bool {
        SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
    }

    /// Production `daemon run` (foreground). Returns the process exit code.
    ///
    /// Failure classes A/B never enter the loop and exit non-zero. The
    /// loop's terminal classification maps `Clean` to success and everything
    /// else to non-zero.
    pub(crate) fn run_daemon(config_path: &Path, arping_path: &Path) -> ExitCode {
        match run_daemon_inner(config_path, arping_path) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("mikagami: {error}");
                ExitCode::FAILURE
            }
        }
    }

    pub(super) fn run_daemon_inner(
        config_path: &Path,
        arping_path: &Path,
    ) -> Result<ExitCode, String> {
        // Install handlers first: a signal during construction/recovery then
        // resolves as a graceful first-iteration shutdown instead of
        // terminating mid-setup (MKM-13.4-12, shutdown during startup).
        install_shutdown_signals();
        let (mut daemon, interval, control_lock) = prepare_daemon(config_path, arping_path)?;
        // Hold the shared control lock for the whole process lifetime. The
        // `Arc` is shared by the foreground loop's stop predicate, by the
        // live shutdown query the Daemon uses before every fencing step and
        // by the control-lock guard attached before `start` (cf31 M-1), so
        // all of them re-check the path identity. A replacement is detected
        // at the next iteration/boundary, not only at startup. The shadowed
        // `LiveControlLock` binding is not dropped before the function ends.
        let lock_error = Arc::clone(&control_lock.error);
        let control_lock = Arc::clone(&control_lock.lock);
        control_lock
            .verify()
            .map_err(|error| format!("the control lock became unsafe: {error}"))?;
        let lock_for_signal = Arc::clone(&control_lock);
        let error_for_signal = Arc::clone(&lock_error);
        daemon.attach_shutdown_signal(move || {
            // A lost lock is a live stop condition for every fencing/lease
            // boundary. This is not a normal shutdown request: the loop has
            // its own ControlLockLost path that performs no cleanup.
            !verify_lock(&lock_for_signal, &error_for_signal) || shutdown_requested()
        });
        // R-16/R-17: the control-lock guard was attached in `prepare_daemon`
        // before `start` (cf31 M-1) and stays attached for the loop.
        let lock_for_loop = Arc::clone(&control_lock);
        let error_for_loop = Arc::clone(&lock_error);
        let lock_lost = move || {
            if verify_lock(&lock_for_loop, &error_for_loop) {
                None
            } else {
                error_for_loop
                    .lock()
                    .ok()
                    .and_then(|slot| slot.clone())
                    .or_else(|| Some("the control lock path is no longer trusted".to_string()))
            }
        };
        let should_stop = shutdown_requested;
        // No intent may survive from before the daemon was Running: any
        // SIGUSR1 that arrived during construction or recovery is discarded
        // (MKM-13.5-04 — no surprise mutation later). The loop also clears
        // the latch on entry.
        PROMOTION_INTENT.store(false, Ordering::SeqCst);
        let mut manual_attempts: u64 = 0;
        let result = match run_observation_loop_checked(
            &mut daemon,
            interval,
            lock_lost,
            should_stop,
            std::thread::sleep,
            Instant::now,
            &PROMOTION_INTENT,
            |_daemon: &mut Daemon<crate::daemon::LinuxDaemonRuntime>, _now: Instant| {
                // Phase 14.12 E3b: the background priming is retired. A
                // manual promotion attempt issues its own GET_TERM (and
                // waits at most its deadline for it); the loop never sends
                // a Witness request, so an idle Standby leaves none behind.
            },
            move |daemon| {
                // Exactly one synchronous attempt through the single
                // authority owner. The request id is identity-only, unique
                // per consumed intent, and carries no authorization.
                manual_attempts += 1;
                let request_id = crate::promotion_attempt::PromotionRequestId::new(format!(
                    "{}-{manual_attempts}",
                    daemon.trigger_label()
                ));
                let kind = daemon.trigger_kind();
                let result = daemon.execute_promotion_attempt(
                    crate::promotion_attempt::PromotionExecutionRequest::new(request_id.clone()),
                );
                eprintln!(
                    "mikagami: {kind} promotion attempt {} -> {result:?}",
                    request_id.as_str()
                );
            },
        ) {
            LoopExit::Clean => Ok(ExitCode::SUCCESS),
            LoopExit::ControlLockLost(error) => {
                return Err(format!("the control lock became unsafe: {error}"));
            }
            other => Err(other.to_string()),
        };
        // (the match is bound below so a lock error can win over every exit word)
        // not report a clean shutdown while it can no longer prove that it is
        // the only control process on this host.
        if let Some(error) = lock_error
            .lock()
            .map_err(|_| "the control lock error latch is poisoned".to_string())?
            .clone()
        {
            return Err(format!("the control lock became unsafe: {error}"));
        }
        // A clean loop exit can still be followed by a lock-path change; never
        // report success without one final identity check.
        if result.is_ok()
            && let Err(error) = control_lock.verify()
        {
            return Err(format!("the control lock became unsafe: {error}"));
        }
        result
    }

    /// Re-check the lock path identity. `false` means the host can no longer
    /// prove that this process is the only control process; the first error is
    /// retained for the non-zero exit after the loop.
    pub(super) fn verify_lock(lock: &ControlLock, error: &Mutex<Option<String>>) -> bool {
        match lock.verify() {
            Ok(()) => true,
            Err(problem) => {
                if let Ok(mut slot) = error.lock()
                    && slot.is_none()
                {
                    *slot = Some(problem.to_string());
                }
                false
            }
        }
    }

    /// The process-lifetime control lock and the first lock-path error seen
    /// by any of its readers (cf31 M-1). Created right after the startup
    /// control gate, so the guard used by `Daemon::start` and the readers of
    /// the observation loop share one lock and one error latch.
    pub(super) struct LiveControlLock {
        pub(super) lock: Arc<ControlLock>,
        pub(super) error: Arc<Mutex<Option<String>>>,
    }

    impl LiveControlLock {
        pub(super) fn new(lock: ControlLock) -> Self {
            Self {
                lock: Arc::new(lock),
                error: Arc::new(Mutex::new(None)),
            }
        }

        /// The first recorded lock-path error. A poisoned latch is never
        /// read as "no error".
        fn first_error(&self) -> Option<String> {
            match self.error.lock() {
                Ok(slot) => slot.clone(),
                Err(_) => Some("the control lock error latch is poisoned".to_string()),
            }
        }
    }

    /// cf31 M-1: attach the live control-lock guard, and only then run
    /// `Daemon::start`. The startup reconciliation (the trusted ZeroResource,
    /// the fresh ZeroResource before an exceptional settle) samples this
    /// guard through `startup_guarded`; before cf31 it read the default
    /// "no reader" guard, so a replaced lock could not stop a settle. A lock
    /// error recorded during startup wins over the start result.
    ///
    /// R-16/R-17: the Daemon also samples this reader before shutdown
    /// cleanup, before the foreground renewal step, and around the cleanup
    /// workflow. It reports the lock loss as its own error, never as SIGTERM.
    pub(super) fn start_with_live_control_lock<R: DaemonRuntime>(
        daemon: &mut Daemon<R>,
        live: &LiveControlLock,
    ) -> Result<(), String> {
        let lock_for_guard = Arc::clone(&live.lock);
        let error_for_guard = Arc::clone(&live.error);
        daemon.attach_control_lock_guard(move || {
            if verify_lock(&lock_for_guard, &error_for_guard) {
                None
            } else {
                error_for_guard
                    .lock()
                    .ok()
                    .and_then(|slot| slot.clone())
                    .or_else(|| Some("the control lock path is no longer trusted".to_string()))
            }
        });
        let started = daemon.start();
        if let Some(error) = live.first_error() {
            return Err(format!("the control lock became unsafe: {error}"));
        }
        recovery_gate(started, daemon.recovery_block_cause())
    }

    /// The safety boundary that precedes every Witness/peer/resource effect:
    /// take the host control lock and prove that no durable manual operation
    /// is unresolved. The returned lock is held by the caller for the process
    /// lifetime. `Config::load` and the signal handlers are the only things
    /// that run before this gate, and both are read-only.
    pub(super) fn startup_control_gate(config: &Config) -> Result<ControlLock, String> {
        let lock = ControlLock::acquire(
            Path::new(&config.control.lock_path),
            crate::attestation::ROOT_UID,
        )
        .map_err(|error| format!("refusing to start the HA daemon: {error}"))?;
        lock.verify()
            .map_err(|error| format!("refusing to start the HA daemon: {error}"))?;
        match crate::manual_barrier::check(
            Path::new(&config.control.manual_barrier_path),
            crate::attestation::ROOT_UID,
            &config.cluster.id,
            &config.node.id,
        ) {
            Ok(crate::manual_barrier::BarrierState::Clear) => Ok(lock),
            Ok(crate::manual_barrier::BarrierState::Open(record)) => Err(format!(
                "refusing to start the HA daemon: a manual operation ({}) from {} to {} \
                 may still be in flight on this node; complete or verify it with \
                 `resource reconcile vip` on the control host, then start HA again \
                 (the barrier is never expired by time)",
                record.op_id, record.source, record.target
            )),
            Err(error) => Err(format!(
                "refusing to start the HA daemon: the manual-operation barrier is not \
                 provably clear: {error}"
            )),
        }
    }

    /// Production construction + recovery gate, before the observation loop.
    ///
    /// Class A — startup/configuration. Any failure here is fatal before the
    /// loop and never reaches observation:
    /// `Config::load` -> `Psk::load(Config.security.psk_file)` ->
    /// `LinuxPlatformConfig` -> `LinuxDaemonRuntime` -> production Witness
    /// transport + HELLO -> `attach_witness` -> `Daemon::new` -> live
    /// control-lock guard -> recovery gate (cf31 M-1).
    ///
    /// MKM-13.4-01: the production WitnessSession + observer are attached
    /// before the daemon exists; normal operation never runs with
    /// `witness_session = None`.
    pub(super) fn prepare_daemon(
        config_path: &Path,
        arping_path: &Path,
    ) -> Result<
        (
            Daemon<crate::daemon::LinuxDaemonRuntime>,
            Duration,
            LiveControlLock,
        ),
        String,
    > {
        let config = Config::load(config_path).map_err(|error| error.to_string())?;
        // Safety boundary first: take the host-wide control lock and check the
        // durable manual-operation barrier before the PSK, the Witness, the
        // peer or any resource is touched. A refusal here has no side effect
        // beyond creating the private lock directory/file.
        let control_lock = startup_control_gate(&config)?;
        let live_lock = LiveControlLock::new(control_lock);
        // The PSK is loaded from the configured file only; the error may name
        // the file path but never its contents.
        let psk = Psk::load(Path::new(&config.security.psk_file)).map_err(|error| {
            format!(
                "could not load PSK file {}: {error}",
                config.security.psk_file
            )
        })?;
        let platform = LinuxPlatformConfig::new(arping_path).map_err(|error| error.to_string())?;
        let mut runtime = crate::daemon::LinuxDaemonRuntime::new(&config, platform)
            .map_err(|error| error.to_string())?;
        let (session, observer) = connect_witness_session(&config, psk)?;
        runtime.attach_witness(session, observer);
        let mut daemon = Daemon::new(runtime);
        for warning in config.startup_warnings() {
            crate::operator_log::warn_startup(&warning);
        }
        daemon.enable_auto(crate::auto_failover::AutoConfig {
            enabled: config.failover.auto,
            preferred: config.node.preferred,
            dwell_ms: config.failover.dwell_sec.saturating_mul(1_000),
            bootstrap_dwell_ms: config.failover.bootstrap_dwell_sec.saturating_mul(1_000),
            bootstrap_defer_ms: config.failover.bootstrap_defer_sec.saturating_mul(1_000),
            max_fence_actions: u32::try_from(config.failover.max_fence_actions).unwrap_or(1),
            cycle_timeout_ms: config.failover.cycle_timeout_sec.saturating_mul(1_000),
        });
        // Class B — recovery gate. The loop must not begin on failure. The
        // startup reconciliation runs behind the live control-lock guard.
        start_with_live_control_lock(&mut daemon, &live_lock)?;
        let interval = Duration::from_secs(config.heartbeat.interval_sec.max(1));
        Ok((daemon, interval, live_lock))
    }
}

#[cfg(target_os = "linux")]
pub(crate) use linux::run_daemon;

/// Non-Linux platforms have no production daemon runtime.
#[cfg(not(target_os = "linux"))]
pub(crate) fn run_daemon(
    _config_path: &std::path::Path,
    _arping_path: &std::path::Path,
) -> ExitCode {
    eprintln!("mikagami: 'daemon run' is supported on Linux only");
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::{
        DaemonHealth, DaemonService, DaemonSnapshot, DaemonState, DaemonVip, ShutdownResult,
    };
    use crate::peer_observer::PeerObservationState;
    use crate::state_machine::NodeState;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    fn standby_snapshot() -> DaemonSnapshot {
        DaemonSnapshot {
            node_state: NodeState::Standby,
            health: DaemonHealth::Healthy,
            vip: DaemonVip::Absent,
            service: DaemonService::Stopped,
            resource_owning: false,
            recovery_reconciled: true,
            unresolved_mutation: false,
        }
    }

    /// Observation of the runtime shared with the test — `Daemon` owns the
    /// runtime, so the test keeps this handle for scripted input and counters.
    #[derive(Clone, Default)]
    struct Probe {
        observe_results: Arc<Mutex<VecDeque<Result<DaemonSnapshot, String>>>>,
        peer_ticks: Arc<Mutex<Vec<Instant>>>,
        shutdown_calls: Arc<Mutex<u32>>,
    }

    /// Deterministic runtime: scripted observe results, recorded peer
    /// advances, configurable shutdown outcome.
    struct FakeRuntime {
        probe: Probe,
        shutdown_result: ShutdownResult,
    }

    impl FakeRuntime {
        fn running(probe: Probe) -> Self {
            Self {
                probe,
                shutdown_result: ShutdownResult::Clean,
            }
        }
    }

    impl DaemonRuntime for FakeRuntime {
        fn startup(&mut self) -> Result<DaemonSnapshot, String> {
            Ok(standby_snapshot())
        }

        fn observe(&mut self) -> Result<DaemonSnapshot, String> {
            self.probe
                .observe_results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Ok(standby_snapshot()))
        }

        fn shutdown(
            &mut self,
            _control_lock_safe: &dyn Fn() -> bool,
        ) -> Result<ShutdownResult, String> {
            *self.probe.shutdown_calls.lock().unwrap() += 1;
            Ok(self.shutdown_result)
        }

        fn peer_tick_at(
            &mut self,
            now: Instant,
            _peer_status: Option<crate::daemon::PeerStatusSnapshot>,
        ) -> Result<Option<PeerObservationState>, String> {
            self.probe.peer_ticks.lock().unwrap().push(now);
            Ok(Some(PeerObservationState::Unavailable))
        }
    }

    /// Scriptable shutdown flag + recorded waits + scripted clock samples.
    /// `stop` is a *level* flag, like the real signal atomic: the loop may
    /// read it any number of times per iteration and it never un-sets.
    /// Tests set it from their orchestration closures at a chosen moment.
    struct Harness {
        stop: std::cell::Cell<bool>,
        waits: Vec<Duration>,
        times: VecDeque<Instant>,
        fallback: Instant,
    }

    impl Harness {
        fn new(times: &[Instant]) -> Self {
            Self {
                stop: std::cell::Cell::new(false),
                waits: Vec::new(),
                times: times.iter().copied().collect(),
                fallback: *times.last().unwrap(),
            }
        }
    }

    /// Scripted intent latch for tests — mirrors the `AtomicBool` contract:
    /// `set` models a signal delivery (idempotent, coalescing), `consume`
    /// takes the pending bit exactly once, `discard` clears it.
    #[derive(Default)]
    struct FlagLatch(std::cell::Cell<bool>);

    impl FlagLatch {
        fn set(&self) {
            self.0.set(true);
        }
    }

    impl PromotionIntentLatch for FlagLatch {
        fn consume(&self) -> bool {
            self.0.replace(false)
        }
        fn discard(&self) {
            self.0.set(false);
        }
    }

    /// Drive the loop with the shared harness: `stop` is set after
    /// `stop_after_waits` recorded waits (i.e., shutdown is observed on the
    /// following iteration). `0` means the flag is already set at entry.
    fn run_loop<R: DaemonRuntime>(
        daemon: &mut Daemon<R>,
        harness: &mut Harness,
        interval: Duration,
        stop_after_waits: usize,
    ) -> LoopExit {
        let idle = FlagLatch::default();
        if stop_after_waits == 0 {
            harness.stop.set(true);
        }
        run_observation_loop(
            daemon,
            interval,
            || harness.stop.get(),
            |interval| {
                harness.waits.push(interval);
                if harness.waits.len() == stop_after_waits {
                    harness.stop.set(true);
                }
            },
            || harness.times.pop_front().unwrap_or(harness.fallback),
            &idle,
            |_, _| {},
            |_| {},
        )
    }

    // -----------------------------------------------------------------
    // Stage 14 Phase 14.6 (DC-14.6-01 Option 1): pending-reap runtime
    // ownership composed with the real `Daemon` and loop. The runtime below
    // composes the production `CommandBackend` helpers exactly as the Linux
    // owner does (`poll_pending_reap_foreground` first in the foreground
    // tick; Revision 10 clean AND an empty slot after one poll at shutdown).
    // Its driver panics on any spawn, signal, sleep or pipe operation.
    // -----------------------------------------------------------------

    type SharedBackend = std::rc::Rc<
        std::cell::RefCell<
            crate::fencing_backend::CommandBackend<
                crate::fencing_backend::test_support::ScriptedReapDriver,
            >,
        >,
    >;

    struct PendingReapRuntime {
        backend: SharedBackend,
        /// Models a future step caller that hits the §16.7.3 invariant.
        inject_violation: bool,
    }

    impl PendingReapRuntime {
        fn new() -> (Self, SharedBackend) {
            let backend = std::rc::Rc::new(std::cell::RefCell::new(
                crate::fencing_backend::CommandBackend::new(
                    crate::fencing_backend::test_support::ScriptedReapDriver::default(),
                ),
            ));
            (
                Self {
                    backend: backend.clone(),
                    inject_violation: false,
                },
                backend,
            )
        }
    }

    impl DaemonRuntime for PendingReapRuntime {
        fn startup(&mut self) -> Result<DaemonSnapshot, String> {
            Ok(standby_snapshot())
        }

        fn observe(&mut self) -> Result<DaemonSnapshot, String> {
            Ok(standby_snapshot())
        }

        fn foreground_lifecycle_tick(
            &mut self,
            _shutdown_requested: &dyn Fn() -> bool,
            _live_shutdown: &dyn Fn() -> bool,
            _control_lock_safe: &dyn Fn() -> bool,
        ) -> Result<(), String> {
            let mut backend = self.backend.borrow_mut();
            let _ = backend.foreground_pending_reap();
            if self.inject_violation {
                let rejected = crate::fencing_backend::test_support::TestLeader(9999);
                if let Err(violation) =
                    crate::fencing_backend::test_support::retain(&mut backend, rejected, 9999)
                {
                    return Err(violation.into_observation_invariant());
                }
            }
            // The unchanged Standby early return follows the poll.
            Ok(())
        }

        fn shutdown(
            &mut self,
            _control_lock_safe: &dyn Fn() -> bool,
        ) -> Result<ShutdownResult, String> {
            let pending = self.backend.borrow_mut().shutdown_pending_reap();
            // Revision 10 conditions are clean in this fixture.
            Ok(if pending.slot_empty {
                ShutdownResult::Clean
            } else {
                ShutdownResult::RequiresCleanup
            })
        }
    }

    fn reap_calls(backend: &SharedBackend) -> u32 {
        crate::fencing_backend::test_support::driver(&mut backend.borrow_mut()).reap_calls
    }

    fn occupy(backend: &SharedBackend, pid: u32) {
        let leader = crate::fencing_backend::test_support::TestLeader(pid);
        crate::fencing_backend::test_support::retain(&mut backend.borrow_mut(), leader, pid)
            .expect("empty slot");
    }

    /// G8-C / PR-07: shutdown with an occupied slot makes one non-blocking
    /// poll (no wait, no signal) and exits `ShutdownRequiresCleanup` within one
    /// iteration of the request — never `Clean`; the retained leader stays
    /// owned. Ordinary iterations before it poll exactly once each (PR-04).
    #[test]
    fn stage14_6_g8c_occupied_slot_shutdown_requires_cleanup() {
        for stop_after_waits in [0, 3] {
            let (runtime, backend) = PendingReapRuntime::new();
            occupy(&backend, 4242);
            let mut daemon = Daemon::new(runtime);
            assert_eq!(daemon.start().unwrap(), StartResult::Running);
            let t0 = Instant::now();
            let mut harness = Harness::new(&[t0]);
            let exit = run_loop(
                &mut daemon,
                &mut harness,
                Duration::from_secs(1),
                stop_after_waits,
            );
            assert_eq!(
                exit,
                LoopExit::ShutdownRequiresCleanup,
                "{stop_after_waits}"
            );
            assert_eq!(daemon.state(), DaemonState::ShutdownBlocked);
            assert_eq!(harness.waits.len(), stop_after_waits);
            // One poll per ordinary iteration plus exactly one at shutdown.
            assert_eq!(reap_calls(&backend), stop_after_waits as u32 + 1);
            let view = backend.borrow().pending_reap_diagnostics().unwrap();
            assert_eq!(view.pid, 4242);
            assert_eq!(view.polls, stop_after_waits as u64 + 1);
        }
    }

    /// PR-07 variant: the leader becomes reapable just before the shutdown
    /// poll; the slot clears and the classification is the unchanged clean
    /// result. With an empty slot throughout, the loop is unchanged and makes
    /// no reap call at all.
    #[test]
    fn stage14_6_pr07_cleared_or_empty_slot_shuts_down_clean() {
        let (runtime, backend) = PendingReapRuntime::new();
        occupy(&backend, 4243);
        crate::fencing_backend::test_support::driver(&mut backend.borrow_mut())
            .reaps
            .push_back(crate::fencing_backend::ReapResult::Exited(
                crate::fencing_backend::LeaderStatus::Signal(9),
            ));
        let mut daemon = Daemon::new(runtime);
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        let t0 = Instant::now();
        let mut harness = Harness::new(&[t0]);
        assert_eq!(
            run_loop(&mut daemon, &mut harness, Duration::from_secs(1), 0),
            LoopExit::Clean
        );
        assert!(backend.borrow().pending_reap_diagnostics().is_none());
        assert_eq!(reap_calls(&backend), 1);

        let (runtime, backend) = PendingReapRuntime::new();
        let mut daemon = Daemon::new(runtime);
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        let mut harness = Harness::new(&[t0, t0, t0]);
        assert_eq!(
            run_loop(&mut daemon, &mut harness, Duration::from_secs(1), 2),
            LoopExit::Clean
        );
        assert_eq!(harness.waits, vec![Duration::from_secs(1); 2]);
        assert_eq!(reap_calls(&backend), 0, "an empty slot is never polled");
    }

    /// §16.7.3: a transfer into the occupied slot maps to
    /// `DaemonError::ObservationInvariant` and the loop exits `Fatal`. The
    /// occupied slot is neither overwritten nor cleared.
    #[test]
    fn stage14_6_invariant_violation_exits_fatal_and_keeps_the_slot() {
        let (mut runtime, backend) = PendingReapRuntime::new();
        occupy(&backend, 4244);
        runtime.inject_violation = true;
        let mut daemon = Daemon::new(runtime);
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        match daemon.tick_at(Instant::now()) {
            Err(crate::daemon::DaemonError::ObservationInvariant(message)) => {
                assert!(
                    message.starts_with("pending_reap invariant violation"),
                    "{message}"
                );
                assert!(message.contains("existing pid 4244"));
            }
            other => panic!("expected ObservationInvariant, got {other:?}"),
        }
        let t0 = Instant::now();
        let mut harness = Harness::new(&[t0]);
        match run_loop(&mut daemon, &mut harness, Duration::from_secs(1), 5) {
            LoopExit::Fatal(message) => {
                assert!(
                    message.contains("daemon observation invariant failed"),
                    "{message}"
                );
                assert!(message.contains("pending_reap invariant violation"));
            }
            other => panic!("expected Fatal, got {other:?}"),
        }
        assert!(harness.waits.is_empty(), "fatal on the first iteration");
        assert_eq!(
            backend.borrow().pending_reap_diagnostics().unwrap().pid,
            4244
        );
    }

    #[test]
    fn loop_ticks_once_per_iteration_then_exits_clean_on_shutdown() {
        let probe = Probe::default();
        let mut daemon = Daemon::new(FakeRuntime::running(probe.clone()));
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        let t0 = Instant::now();
        let mut harness = Harness::new(&[t0, t0, t0]);

        let exit = run_loop(&mut daemon, &mut harness, Duration::from_secs(1), 2);

        assert_eq!(exit, LoopExit::Clean);
        // One peer advance per observation iteration; the shutdown tick does
        // not advance the peer; waits follow only non-terminal iterations.
        assert_eq!(probe.peer_ticks.lock().unwrap().len(), 2);
        assert_eq!(harness.waits, vec![Duration::from_secs(1); 2]);
        assert_eq!(daemon.state(), DaemonState::Stopped);
    }

    #[test]
    fn delayed_iteration_does_not_cause_catch_up_burst() {
        let probe = Probe::default();
        let mut daemon = Daemon::new(FakeRuntime::running(probe.clone()));
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        let t0 = Instant::now();
        // The second sample is far in the future: still exactly one tick and
        // one wait per iteration, no burst.
        let mut harness = Harness::new(&[
            t0,
            t0 + Duration::from_secs(3600),
            t0 + Duration::from_secs(3601),
            t0 + Duration::from_secs(3602),
        ]);

        let exit = run_loop(&mut daemon, &mut harness, Duration::from_secs(1), 3);

        assert_eq!(exit, LoopExit::Clean);
        assert_eq!(probe.peer_ticks.lock().unwrap().len(), 3);
        assert_eq!(harness.waits.len(), 3);
    }

    #[test]
    fn recoverable_observation_failure_keeps_normal_cadence() {
        let probe = Probe::default();
        probe.observe_results.lock().unwrap().extend([
            Err("peer observation I/O failed".to_string()),
            Ok(standby_snapshot()),
        ]);
        let mut daemon = Daemon::new(FakeRuntime::running(probe.clone()));
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        let t0 = Instant::now();
        let mut harness = Harness::new(&[t0, t0, t0]);

        let exit = run_loop(&mut daemon, &mut harness, Duration::from_secs(1), 1);

        assert_eq!(exit, LoopExit::Clean);
        // The failed observation still drove one peer advance, still ended
        // with the full cadence wait (no hot retry, no spin), then the next
        // iteration observed shutdown intent and stopped without a new
        // observation tick.
        assert_eq!(probe.peer_ticks.lock().unwrap().len(), 1);
        assert_eq!(harness.waits, vec![Duration::from_secs(1)]);
        assert_eq!(
            daemon.last_observation_error(),
            Some("peer observation I/O failed")
        );
    }

    #[test]
    fn structural_failure_stops_the_loop_as_fatal() {
        let probe = Probe::default();
        // Active without resource ownership is a fatal observation invariant.
        probe
            .observe_results
            .lock()
            .unwrap()
            .push_back(Ok(DaemonSnapshot {
                node_state: NodeState::Active,
                health: DaemonHealth::Healthy,
                vip: DaemonVip::Present,
                service: DaemonService::Running,
                resource_owning: false,
                recovery_reconciled: true,
                unresolved_mutation: false,
            }));
        let mut daemon = Daemon::new(FakeRuntime::running(probe));
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        let t0 = Instant::now();
        let mut harness = Harness::new(&[t0, t0]);

        let exit = run_loop(
            &mut daemon,
            &mut harness,
            Duration::from_secs(1),
            usize::MAX,
        );

        assert!(matches!(exit, LoopExit::Fatal(_)));
        assert_eq!(daemon.state(), DaemonState::Failed);
        assert!(harness.waits.is_empty(), "fatal exit must not wait");
    }

    #[test]
    fn shutdown_cleanup_block_exits_nonzero_without_further_ticks() {
        let probe = Probe::default();
        let mut runtime = FakeRuntime::running(probe.clone());
        runtime.shutdown_result = ShutdownResult::RequiresCleanup;
        let mut daemon = Daemon::new(runtime);
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        let t0 = Instant::now();
        let mut harness = Harness::new(&[t0]);

        let exit = run_loop(&mut daemon, &mut harness, Duration::from_secs(1), 0);

        assert_eq!(exit, LoopExit::ShutdownRequiresCleanup);
        assert_eq!(daemon.state(), DaemonState::ShutdownBlocked);
        // No peer advance ran: the shutdown tick replaced observation.
        assert!(probe.peer_ticks.lock().unwrap().is_empty());
    }

    #[test]
    fn no_new_tick_after_shutdown_observed() {
        let probe = Probe::default();
        let mut daemon = Daemon::new(FakeRuntime::running(probe.clone()));
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        // Shutdown intent already set: the first iteration's tick performs
        // shutdown only — no observation, no peer advance.
        let t0 = Instant::now();
        let mut harness = Harness::new(&[t0, t0, t0]);

        let exit = run_loop(&mut daemon, &mut harness, Duration::from_secs(1), 0);

        assert_eq!(exit, LoopExit::Clean);
        assert!(probe.peer_ticks.lock().unwrap().is_empty());
    }

    #[test]
    fn one_authoritative_instant_per_iteration_reaches_peer_tick() {
        let probe = Probe::default();
        let mut daemon = Daemon::new(FakeRuntime::running(probe.clone()));
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_millis(5);
        let mut harness = Harness::new(&[t0, t1]);

        let exit = run_loop(&mut daemon, &mut harness, Duration::from_secs(1), 1);

        assert_eq!(exit, LoopExit::Clean);
        // The peer advance used exactly the sampled instant for that
        // iteration; the shutdown tick did not advance the peer.
        assert_eq!(probe.peer_ticks.lock().unwrap().as_slice(), &[t0]);
    }

    #[test]
    fn recovery_gate_blocks_loop_entry() {
        assert!(recovery_gate(Ok(StartResult::RecoveryBlocked), None).is_err());
        assert!(recovery_gate(Ok(StartResult::Running), None).is_ok());
        let named = recovery_gate(
            Ok(StartResult::RecoveryBlocked),
            Some("a lease release obligation (term 7) is armed".into()),
        )
        .unwrap_err();
        assert!(named.contains("release obligation (term 7)"), "{named}");
        assert!(
            recovery_gate(
                Err(crate::daemon::DaemonError::Startup("boom".into())),
                None
            )
            .is_err()
        );
    }

    // ---- MKM-13.5 promotion-intent latch ---------------------------------
    //
    // Intent is modeled by `FlagLatch::set` from harness callbacks — the same
    // one-bit contract the signal handler exercises. These tests prove the
    // semantics deterministically rather than racing a real OS signal.

    /// One intent while Running+idle → exactly one synchronous attempt, and
    /// the attempt runs before that iteration's tick (single owner).
    #[test]
    fn intent_while_running_starts_exactly_one_attempt() {
        let probe = Probe::default();
        let mut daemon = Daemon::new(FakeRuntime::running(probe.clone()));
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        let t0 = Instant::now();
        let mut harness = Harness::new(&[t0, t0, t0]);
        let intent = FlagLatch::default();
        let mut attempts = 0u32;
        let mut waited = 0u32;

        let exit = run_observation_loop(
            &mut daemon,
            Duration::from_secs(1),
            || harness.stop.get(),
            |interval| {
                harness.waits.push(interval);
                waited += 1;
                // A signal arrives during the wait after iteration 1.
                if waited == 1 {
                    intent.set();
                }
                if waited == 2 {
                    harness.stop.set(true);
                }
            },
            || harness.times.pop_front().unwrap_or(harness.fallback),
            &intent,
            |_, _| {},
            |_| attempts += 1,
        );

        assert_eq!(exit, LoopExit::Clean);
        assert_eq!(attempts, 1, "one intent → exactly one attempt");
        assert!(daemon.state() == DaemonState::Stopped);
    }

    /// Stage 14 Phase 14.9 §27.4 (G8-A/B loop half): a shutdown requested
    /// while the synchronous attempt runs (for example during its bounded
    /// fence action) is observed as soon as the attempt returns. The same
    /// iteration's tick performs the shutdown: no ordinary tick — hence no
    /// foreground fencing step — and no wait follow the attempt.
    #[test]
    fn stage14_9_shutdown_during_attempt_is_observed_when_it_returns() {
        let probe = Probe::default();
        let mut daemon = Daemon::new(FakeRuntime::running(probe.clone()));
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        let t0 = Instant::now();
        let mut harness = Harness::new(&[t0, t0, t0]);
        let intent = FlagLatch::default();
        let mut attempts = 0u32;

        let exit = run_observation_loop(
            &mut daemon,
            Duration::from_secs(1),
            || harness.stop.get(),
            |interval| {
                harness.waits.push(interval);
                if harness.waits.len() == 1 {
                    intent.set();
                }
            },
            || harness.times.pop_front().unwrap_or(harness.fallback),
            &intent,
            |_, _| {},
            |_| {
                attempts += 1;
                // Shutdown arrives while the attempt blocks.
                harness.stop.set(true);
            },
        );

        assert_eq!(exit, LoopExit::Clean);
        assert_eq!(attempts, 1);
        assert_eq!(harness.waits.len(), 1, "no wait after the attempt");
        assert_eq!(
            probe.peer_ticks.lock().unwrap().len(),
            1,
            "no ordinary tick after the attempt"
        );
        assert_eq!(daemon.state(), DaemonState::Stopped);
    }

    /// F14.9-01 (§27.4): a stop observed after the loop-top check but before
    /// the tick (the original audit probe: at the prime point) is propagated
    /// by `request_shutdown` before `tick_at`, so that tick is the shutdown
    /// tick — no ordinary tick (hence no foreground fencing step), no prime,
    /// and no wait.
    #[test]
    fn stage14_9_f01_stop_observed_before_tick_is_requested_before_the_tick() {
        let probe = Probe::default();
        let mut daemon = Daemon::new(FakeRuntime::running(probe.clone()));
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        let t0 = Instant::now();
        let mut harness = Harness::new(&[t0]);
        let observations = std::cell::Cell::new(0u32);
        let primes = std::cell::Cell::new(0u32);
        let idle = FlagLatch::default();

        let exit = run_observation_loop(
            &mut daemon,
            Duration::from_secs(1),
            || {
                let n = observations.get() + 1;
                observations.set(n);
                n >= 2
            },
            |interval| harness.waits.push(interval),
            || harness.times.pop_front().unwrap_or(harness.fallback),
            &idle,
            |_, _| primes.set(primes.get() + 1),
            |_| panic!("no intent was delivered"),
        );

        assert_eq!(exit, LoopExit::Clean);
        assert_eq!(observations.get(), 2, "loop top, then the pre-tick check");
        assert_eq!(primes.get(), 0);
        assert!(harness.waits.is_empty(), "no wait after the stop");
        assert!(
            probe.peer_ticks.lock().unwrap().is_empty(),
            "no ordinary tick after the stop was observed"
        );
        assert_eq!(daemon.state(), DaemonState::Stopped);
    }

    /// F14.9-01: a stop observed at the intent consumption point wins over
    /// the intent and is requested at once — even if a later read would not
    /// repeat it (the real latch never clears; this pins that the first
    /// observation, not a later one, is what propagates).
    #[test]
    fn stage14_9_f01_stop_seen_at_the_intent_point_is_requested_at_once() {
        let probe = Probe::default();
        let mut daemon = Daemon::new(FakeRuntime::running(probe.clone()));
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        let t0 = Instant::now();
        let mut harness = Harness::new(&[t0]);
        let observations = std::cell::Cell::new(0u32);
        let intent = FlagLatch::default();

        let exit = run_observation_loop(
            &mut daemon,
            Duration::from_secs(1),
            || {
                let n = observations.get() + 1;
                observations.set(n);
                if n == 1 {
                    // SIGUSR1 arrives after the loop-entry discard.
                    intent.set();
                }
                // Observed at the intent point only (and, so that a
                // regression still terminates, again from the fifth read).
                n == 2 || n >= 5
            },
            |interval| harness.waits.push(interval),
            || harness.times.pop_front().unwrap_or(harness.fallback),
            &intent,
            |_, _| {},
            |_| panic!("the stop wins over the intent"),
        );

        assert_eq!(exit, LoopExit::Clean);
        assert!(harness.waits.is_empty());
        assert!(
            probe.peer_ticks.lock().unwrap().is_empty(),
            "no ordinary tick"
        );
        assert_eq!(daemon.state(), DaemonState::Stopped);
    }

    /// N deliveries before consumption still yield one pending bit; a
    /// delivery during the synchronous attempt is discarded, not queued.
    #[test]
    fn coalesced_and_during_attempt_intents_do_not_multiply() {
        let probe = Probe::default();
        let mut daemon = Daemon::new(FakeRuntime::running(probe.clone()));
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        let t0 = Instant::now();
        let mut harness = Harness::new(&[t0, t0, t0]);
        let intent = FlagLatch::default();
        let mut attempts = 0u32;
        let mut waited = 0u32;

        let exit = run_observation_loop(
            &mut daemon,
            Duration::from_secs(1),
            || harness.stop.get(),
            |interval| {
                harness.waits.push(interval);
                waited += 1;
                // Two coalesced deliveries before the next consumption.
                if waited == 1 {
                    intent.set();
                    intent.set();
                }
                if waited == 2 {
                    harness.stop.set(true);
                }
            },
            || harness.times.pop_front().unwrap_or(harness.fallback),
            &intent,
            |_, _| {},
            |_| {
                attempts += 1;
                // A signal arrives mid-attempt: must be discarded — the
                // loop never queues an implicit retry.
                intent.set();
            },
        );

        assert_eq!(exit, LoopExit::Clean);
        assert_eq!(
            attempts, 1,
            "coalescing + in-flight discard → still one attempt"
        );
    }

    /// An intent that exists before the loop entry is discarded once —
    /// signals from construction/recovery never carry forward.
    #[test]
    fn pre_loop_intent_is_discarded_at_entry() {
        let probe = Probe::default();
        let mut daemon = Daemon::new(FakeRuntime::running(probe.clone()));
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        let t0 = Instant::now();
        let mut harness = Harness::new(&[t0, t0]);
        let intent = FlagLatch::default();
        intent.set();
        let mut attempts = 0u32;

        let exit = run_observation_loop(
            &mut daemon,
            Duration::from_secs(1),
            || harness.stop.get(),
            |interval| {
                harness.waits.push(interval);
                harness.stop.set(true);
            },
            || harness.times.pop_front().unwrap_or(harness.fallback),
            &intent,
            |_, _| {},
            |_| attempts += 1,
        );

        assert_eq!(exit, LoopExit::Clean);
        assert_eq!(attempts, 0, "pre-Running intent must not survive");
    }

    /// An intent arriving while shutdown is already requested is discarded
    /// — shutdown wins over promotion.
    #[test]
    fn intent_while_shutdown_requested_is_discarded() {
        let probe = Probe::default();
        let mut daemon = Daemon::new(FakeRuntime::running(probe.clone()));
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        let t0 = Instant::now();
        let mut harness = Harness::new(&[t0, t0]);
        let intent = FlagLatch::default();
        let mut attempts = 0u32;

        let exit = run_observation_loop(
            &mut daemon,
            Duration::from_secs(1),
            || harness.stop.get(),
            |interval| {
                harness.waits.push(interval);
                // Signal lands after iteration 1; shutdown is observed at
                // the start of iteration 2 → intent discarded before use.
                intent.set();
                harness.stop.set(true);
            },
            || harness.times.pop_front().unwrap_or(harness.fallback),
            &intent,
            |_, _| {},
            |_| attempts += 1,
        );

        assert_eq!(exit, LoopExit::Clean);
        assert_eq!(attempts, 0, "shutdown has priority over intent");
    }

    /// An intent consumed while the daemon is not Running (never started)
    /// is dropped — no promotion, and the daemon exits Fatal as before.
    #[test]
    fn intent_while_not_running_is_dropped() {
        let probe = Probe::default();
        let mut daemon = Daemon::new(FakeRuntime::running(probe.clone()));
        // Deliberately not started: daemon.state() != Running.
        let t0 = Instant::now();
        let mut harness = Harness::new(&[t0]);
        let intent = FlagLatch::default();
        intent.set();
        let mut attempts = 0u32;

        let exit = run_observation_loop(
            &mut daemon,
            Duration::from_secs(1),
            || harness.stop.get(),
            |interval| harness.waits.push(interval),
            || harness.times.pop_front().unwrap_or(harness.fallback),
            &intent,
            |_, _| {},
            |_| attempts += 1,
        );

        assert!(matches!(exit, LoopExit::Fatal(_)));
        assert_eq!(attempts, 0);
    }

    /// After one attempt completes, a *fresh* signal may start a new
    /// attempt — each consumed intent maps to at most one attempt, and a
    /// new explicit delivery is the only way to get another.
    #[test]
    fn fresh_signal_after_completed_attempt_starts_new_attempt() {
        let probe = Probe::default();
        let mut daemon = Daemon::new(FakeRuntime::running(probe.clone()));
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        let t0 = Instant::now();
        let mut harness = Harness::new(&[t0, t0, t0, t0]);
        let intent = FlagLatch::default();
        let mut attempts = 0u32;
        let mut waited = 0u32;

        let exit = run_observation_loop(
            &mut daemon,
            Duration::from_secs(1),
            || harness.stop.get(),
            |interval| {
                harness.waits.push(interval);
                waited += 1;
                // Two separate deliveries, each after a completed attempt.
                if waited == 1 || waited == 2 {
                    intent.set();
                }
                if waited == 3 {
                    harness.stop.set(true);
                }
            },
            || harness.times.pop_front().unwrap_or(harness.fallback),
            &intent,
            |_, _| {},
            |_| attempts += 1,
        );

        assert_eq!(exit, LoopExit::Clean);
        assert_eq!(attempts, 2, "each fresh signal → its own attempt");
    }

    /// The attempt executes before the same iteration's observation tick —
    /// the single owner runs promotion and tick in one synchronous thread.
    #[test]
    fn attempt_runs_before_that_iterations_tick() {
        let probe = Probe::default();
        let mut daemon = Daemon::new(FakeRuntime::running(probe.clone()));
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        let t0 = Instant::now();
        let mut harness = Harness::new(&[t0, t0, t0]);
        let intent = FlagLatch::default();
        let order = Arc::new(Mutex::new(Vec::new()));
        let order_in_wait = order.clone();
        let order_in_promote = order.clone();
        let mut waited = 0u32;

        let exit = run_observation_loop(
            &mut daemon,
            Duration::from_secs(1),
            || harness.stop.get(),
            |interval| {
                harness.waits.push(interval);
                waited += 1;
                if waited == 1 {
                    intent.set();
                    order_in_wait.lock().unwrap().push("signal");
                }
                if waited == 2 {
                    harness.stop.set(true);
                }
            },
            || harness.times.pop_front().unwrap_or(harness.fallback),
            &intent,
            |_, _| {},
            |_| order_in_promote.lock().unwrap().push("promote"),
        );

        assert_eq!(exit, LoopExit::Clean);
        let events = order.lock().unwrap();
        let promote_index = events.iter().position(|e| *e == "promote").unwrap();
        // The single promote lands between iteration 1's wait and the
        // shutdown iteration — i.e., consumed at the top of iteration 2,
        // strictly inside the same synchronous loop pass.
        assert_eq!(promote_index, 1);
        assert_eq!(probe.peer_ticks.lock().unwrap().len(), 2);
    }

    /// The caller-driven observation issuance runs once per non-shutdown
    /// iteration and never after shutdown is observed — request priming
    /// exists so a later consumed intent can complete a real observation.
    #[test]
    fn prime_runs_each_iteration_but_never_after_shutdown() {
        let probe = Probe::default();
        let mut daemon = Daemon::new(FakeRuntime::running(probe.clone()));
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        let t0 = Instant::now();
        let mut harness = Harness::new(&[t0, t0, t0, t0]);
        let intent = FlagLatch::default();
        let primes = Arc::new(Mutex::new(0u32));
        let primes_in = primes.clone();
        let mut waited = 0u32;

        let exit = run_observation_loop(
            &mut daemon,
            Duration::from_secs(1),
            || harness.stop.get(),
            |interval| {
                harness.waits.push(interval);
                waited += 1;
                if waited == 2 {
                    harness.stop.set(true);
                }
            },
            || harness.times.pop_front().unwrap_or(harness.fallback),
            &intent,
            |_, _| *primes_in.lock().unwrap() += 1,
            |_| {},
        );

        assert_eq!(exit, LoopExit::Clean);
        // Iterations 1-2 tick normally (primed); iteration 3 observes
        // shutdown and exits — prime is suppressed there.
        assert_eq!(*primes.lock().unwrap(), 2);
    }

    /// Operational result logging carries no secrets: the typed result's
    /// Debug output can never contain the PSK or witness material — the
    /// promotion closure logs only `{result:?}` plus the process-local id.
    #[test]
    fn promotion_result_logging_carries_no_secret_material() {
        for result in [
            crate::promotion_attempt::PromotionAttemptResult::Succeeded,
            crate::promotion_attempt::PromotionAttemptResult::Cancelled,
            crate::promotion_attempt::PromotionAttemptResult::BlockedBeforeMutation,
            crate::promotion_attempt::PromotionAttemptResult::MutationFailed,
            crate::promotion_attempt::PromotionAttemptResult::Rejected(
                crate::promotion_attempt::PromotionAttemptRejection::RejectedShutdown,
            ),
        ] {
            let line = format!("mikagami: manual promotion attempt op-1 -> {result:?}");
            assert!(!line.contains("psk"));
            assert!(!line.contains("secret"));
            // No hex payload longer than a short word may appear.
            assert!(
                !line
                    .split_whitespace()
                    .any(|w| w.len() > 16 && w.chars().all(|c| c.is_ascii_hexdigit()))
            );
        }
    }

    // ---- production witness session wiring -------------------------------

    use crate::config::Config;
    use crate::protocol::{CborSerializer, NodeId};
    use crate::security::{MessageAuthenticator, Psk};
    use crate::session::{ProcessSession, build_hello_ack};
    use crate::tcp::{ReceiveMessageResult, TcpConnection};
    use std::net::{SocketAddr, TcpListener};
    use std::thread::JoinHandle;

    /// A scripted loopback Witness for the production session-establishment
    /// path: accepts one TCP connection, authenticates the HELLO, and replies
    /// with an authenticated HELLO_ACK carrying the fixture's own process
    /// session id — the real Protocol v1 session bootstrap.
    struct FixtureWitness {
        address: SocketAddr,
        handle: Option<JoinHandle<Result<(), String>>>,
    }

    impl FixtureWitness {
        fn spawn(psk: Psk) -> Self {
            Self::spawn_with_ack_signer(psk.clone(), psk)
        }

        /// `ack_psk` may differ from `psk` to script an authentication failure
        /// on the HELLO_ACK deterministically.
        fn spawn_with_ack_signer(psk: Psk, ack_psk: Psk) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let handle = std::thread::spawn(move || {
                let (stream, _) = listener.accept().map_err(|e| e.to_string())?;
                let timeout = Duration::from_secs(5);
                let mut connection = TcpConnection::from_stream(stream, timeout, timeout)
                    .map_err(|e| e.to_string())?;
                let auth = MessageAuthenticator::new(psk);
                let message = match connection
                    .receive_message(&CborSerializer, &auth)
                    .map_err(|e| e.to_string())?
                {
                    ReceiveMessageResult::Message(message) => message,
                    ReceiveMessageResult::Eof => return Err("eof before HELLO".to_string()),
                };
                let mut process = ProcessSession::generate().map_err(|e| e.to_string())?;
                let common = &message.unsigned().common;
                let ack = build_hello_ack(
                    &mut process,
                    common.cluster_id.clone(),
                    NodeId::new("witness-1"),
                    common.sender_node_id.clone(),
                    common.term,
                )
                .map_err(|e| e.to_string())?;
                let ack_auth = MessageAuthenticator::new(ack_psk);
                connection
                    .send_message(ack, &CborSerializer, &ack_auth)
                    .map_err(|e| e.to_string())?;
                // Keep the connection open briefly so the session is usable.
                std::thread::sleep(Duration::from_millis(50));
                Ok(())
            });
            Self {
                address,
                handle: Some(handle),
            }
        }
    }

    impl Drop for FixtureWitness {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn witness_config_toml(address: &str) -> String {
        format!(
            r#"
[cluster]
id = "example-ha"
[node]
id = "node-a"
preferred = true
[peer]
id = "node-b"
address = "127.0.0.1:7946"
[witness]
id = "witness-1"
address = "{address}"
[vip]
address = "192.0.2.50/24"
interface = "eth0"
arp_count = 3
[service]
manager = "systemd"
unit = "nginx.service"
[health]
command = ["/usr/bin/true"]
[security]
psk_file = "/tmp/mikagami-test.psk"
"#
        )
    }

    fn test_psk() -> Psk {
        Psk::from_test_bytes([0x55; 32])
    }

    // ---- Stage 13.5 closeout fixtures ------------------------------------
    //
    // A *serving* Witness and a *silent* peer. Both run the real Protocol v1
    // bootstrap (authenticated HELLO -> HELLO_ACK) and then drive the real
    // message paths the daemon uses — no test-only session constructors.

    /// Serving Witness: after HELLO_ACK it answers GET_TERM with a
    /// compatible no-holder TermStatus, LEASE_REQUEST with a grant to the
    /// local node at the observed term, and LEASE_RELEASE with released —
    /// the complete authority sequence a manual promotion needs.
    #[cfg(target_os = "linux")]
    struct CloseoutWitness {
        address: SocketAddr,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        temporary_renew: std::sync::Arc<AtomicBool>,
        reject_next_request: std::sync::Arc<AtomicBool>,
        handle: Option<JoinHandle<Result<(), String>>>,
    }

    #[cfg(target_os = "linux")]
    impl CloseoutWitness {
        /// The Stage 13.5/13.6 fixture exactly as it was: a fixed term for
        /// GET_TERM and for every grant.
        fn spawn(psk: Psk) -> Self {
            Self::spawn_with(psk, false)
        }

        /// Phase 14.12: the same scripted fixture, except that every
        /// LEASE_REQUEST grant moves the term forward by one
        /// (`grant.term == previous term + 1`). The Stage 14 fencing path
        /// requires `grant.term == anchor_term + 1` (Rev5 §24 I/K, §25), which
        /// a fixed term can never satisfy. Nothing else changes: responses,
        /// fault injection (temporary renew outage, reject-next-request) and
        /// the single-connection shape are the Stage 13.6 fixture's.
        fn spawn_advancing(psk: Psk) -> Self {
            Self::spawn_with(psk, true)
        }

        fn spawn_with(psk: Psk, advancing_terms: bool) -> Self {
            use crate::protocol::LeaseId;
            use crate::protocol::{
                DurationMs, LeaseGrantPayload, LeaseRejectPayload, LeaseReleasedPayload,
                ProtocolMessage, Term, TermStatusPayload, WitnessMutationOutcomeCode,
            };
            use crate::witness_runtime::{
                WitnessConnection, WitnessResponseContext, send_witness_response_with_context,
            };
            use std::sync::atomic::{AtomicBool, Ordering};

            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let stop = std::sync::Arc::new(AtomicBool::new(false));
            let temporary_renew = std::sync::Arc::new(AtomicBool::new(false));
            let reject_next_request = std::sync::Arc::new(AtomicBool::new(false));
            let stop_in = stop.clone();
            let temporary_renew_in = temporary_renew.clone();
            let reject_next_request_in = reject_next_request.clone();
            let handle = std::thread::spawn(move || -> Result<(), String> {
                let (stream, _) = listener.accept().map_err(|e| e.to_string())?;
                let mut connection = TcpConnection::from_stream(
                    stream,
                    Duration::from_millis(400),
                    Duration::from_secs(5),
                )
                .map_err(|e| e.to_string())?;
                let auth = MessageAuthenticator::new(psk);
                let message = match connection
                    .receive_message(&CborSerializer, &auth)
                    .map_err(|e| e.to_string())?
                {
                    ReceiveMessageResult::Message(message) => message,
                    ReceiveMessageResult::Eof => return Err("eof before HELLO".to_string()),
                };
                let mut process = ProcessSession::generate().map_err(|e| e.to_string())?;
                let common = &message.unsigned().common;
                let ack = build_hello_ack(
                    &mut process,
                    common.cluster_id.clone(),
                    NodeId::new("witness-1"),
                    common.sender_node_id.clone(),
                    common.term,
                )
                .map_err(|e| e.to_string())?;
                connection
                    .send_message(ack, &CborSerializer, &auth)
                    .map_err(|e| e.to_string())?;
                // Server side of the session: peer session id is the
                // client's; responses reuse the same ProcessSession.
                let mut witness = WitnessConnection::new(
                    NodeId::new("witness-1"),
                    common.sender_node_id.clone(),
                    common.cluster_id.clone(),
                    common.session_id.clone(),
                    connection,
                );
                let mut term: u64 = 7;
                loop {
                    if stop_in.load(Ordering::SeqCst) {
                        return Ok(());
                    }
                    let pending = match witness.receive_pending(&CborSerializer, &auth) {
                        Ok(pending) => pending,
                        Err(_) => continue, // read timeout polls the stop flag
                    };
                    let Some(request_id) = pending.message().unsigned().common.request_id.clone()
                    else {
                        continue;
                    };
                    let (response, context) = match pending.message().unsigned().message.clone() {
                        ProtocolMessage::GetTerm => (
                            ProtocolMessage::TermStatus(TermStatusPayload {
                                current_term: Term(term),
                                current_holder: None,
                                current_lease_id: None,
                                lease_remaining_ms: None,
                            }),
                            WitnessResponseContext {
                                term: Term(term),
                                lease_id: None,
                            },
                        ),
                        ProtocolMessage::LeaseRequest(_) => {
                            eprintln!("closeout witness: LeaseRequest received");
                            if reject_next_request_in.swap(false, Ordering::SeqCst) {
                                (
                                    ProtocolMessage::LeaseReject(LeaseRejectPayload {
                                        code: WitnessMutationOutcomeCode::PolicyReject,
                                        reason: "active unused lease cannot be preempted".into(),
                                    }),
                                    WitnessResponseContext {
                                        term: Term(term),
                                        lease_id: Some(LeaseId::new("lease-closeout-1")),
                                    },
                                )
                            } else {
                                if advancing_terms {
                                    term += 1;
                                }
                                (
                                    ProtocolMessage::LeaseGrant(LeaseGrantPayload {
                                        term: Term(term),
                                        lease_id: LeaseId::new("lease-closeout-1"),
                                        holder_node_id: common.sender_node_id.clone(),
                                        lease_ttl_ms: DurationMs(10_000),
                                        renew_after_ms: DurationMs(3_000),
                                        lease_remaining_ms: DurationMs(10_000),
                                    }),
                                    WitnessResponseContext {
                                        term: Term(term),
                                        lease_id: Some(LeaseId::new("lease-closeout-1")),
                                    },
                                )
                            }
                        }
                        ProtocolMessage::LeaseRenew(payload) => {
                            eprintln!(
                                "closeout witness: LeaseRenew received temporary={}",
                                temporary_renew_in.load(Ordering::SeqCst)
                            );
                            if temporary_renew_in.load(Ordering::SeqCst) {
                                (
                                    ProtocolMessage::LeaseReject(LeaseRejectPayload {
                                        code: WitnessMutationOutcomeCode::TemporarilyUnavailable,
                                        reason: "controlled closeout temporary outage".into(),
                                    }),
                                    WitnessResponseContext {
                                        term: payload.term,
                                        lease_id: Some(payload.lease_id.clone()),
                                    },
                                )
                            } else {
                                (
                                    ProtocolMessage::LeaseRenewed(LeaseGrantPayload {
                                        term: payload.term,
                                        lease_id: payload.lease_id.clone(),
                                        holder_node_id: common.sender_node_id.clone(),
                                        lease_ttl_ms: DurationMs(10_000),
                                        renew_after_ms: DurationMs(3_000),
                                        lease_remaining_ms: DurationMs(10_000),
                                    }),
                                    WitnessResponseContext {
                                        term: payload.term,
                                        lease_id: Some(payload.lease_id.clone()),
                                    },
                                )
                            }
                        }
                        ProtocolMessage::LeaseRelease(payload) => {
                            eprintln!("closeout witness: LeaseRelease received");
                            (
                                ProtocolMessage::LeaseReleased(LeaseReleasedPayload {
                                    term: payload.term,
                                    lease_id: payload.lease_id.clone(),
                                    result: "released".to_string(),
                                }),
                                WitnessResponseContext {
                                    term: payload.term,
                                    lease_id: Some(payload.lease_id.clone()),
                                },
                            )
                        }
                        _ => continue,
                    };
                    send_witness_response_with_context(
                        &mut witness,
                        &mut process,
                        request_id,
                        response,
                        context,
                        &CborSerializer,
                        &auth,
                    )
                    .map_err(|e| e.to_string())?;
                }
            });
            Self {
                address,
                stop,
                temporary_renew,
                reject_next_request,
                handle: Some(handle),
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for CloseoutWitness {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    /// Cooperative-then-silent peer: completes the authenticated HELLO
    /// handshake, sends real authenticated Heartbeat messages for
    /// `heartbeat_for` (so the peer observer reaches `Fresh`), then goes
    /// silent — the detector mints fresh `LocalLossEvidence` once the last
    /// heartbeat ages past `suspect_after_sec` + `unreachable_after_sec`.
    /// A never-heard peer stays `NeverSeen` and yields no loss evidence, so
    /// genuine heartbeats are required.
    #[cfg(target_os = "linux")]
    struct CloseoutPeer {
        address: SocketAddr,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        handle: Option<JoinHandle<Result<(), String>>>,
    }

    #[cfg(target_os = "linux")]
    impl CloseoutPeer {
        fn spawn(psk: Psk, heartbeat_for: Duration) -> Self {
            use crate::heartbeat::build_heartbeat;
            use crate::protocol::{NodeStatusPayload, Role, Term};
            use crate::state_machine::NodeState;
            use std::sync::atomic::{AtomicBool, Ordering};

            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let stop = std::sync::Arc::new(AtomicBool::new(false));
            let stop_in = stop.clone();
            let handle = std::thread::spawn(move || -> Result<(), String> {
                let (stream, _) = listener.accept().map_err(|e| e.to_string())?;
                let mut connection = TcpConnection::from_stream(
                    stream,
                    Duration::from_millis(50),
                    Duration::from_secs(5),
                )
                .map_err(|e| e.to_string())?;
                let auth = MessageAuthenticator::new(psk);
                let message = match connection
                    .receive_message(&CborSerializer, &auth)
                    .map_err(|e| e.to_string())?
                {
                    ReceiveMessageResult::Message(message) => message,
                    ReceiveMessageResult::Eof => return Err("eof before HELLO".to_string()),
                };
                let mut process = ProcessSession::generate().map_err(|e| e.to_string())?;
                let common = &message.unsigned().common;
                let cluster_id = common.cluster_id.clone();
                let local_node = common.sender_node_id.clone();
                let ack = build_hello_ack(
                    &mut process,
                    cluster_id.clone(),
                    NodeId::new("node-b"),
                    local_node.clone(),
                    common.term,
                )
                .map_err(|e| e.to_string())?;
                connection
                    .send_message(ack, &CborSerializer, &auth)
                    .map_err(|e| e.to_string())?;
                // Phase 1 — live peer: real heartbeats on the established
                // session so the observer sees `Fresh`.
                let status = NodeStatusPayload {
                    node_state: NodeState::Active,
                    operation_phase: None,
                    role: Role::Active,
                    service_state: "running".to_string(),
                    health_state: "healthy".to_string(),
                    vip_state: "present".to_string(),
                };
                let silent_at = Instant::now() + heartbeat_for;
                let mut next_heartbeat = Instant::now();
                loop {
                    if stop_in.load(Ordering::SeqCst) {
                        return Ok(());
                    }
                    if Instant::now() < silent_at && Instant::now() >= next_heartbeat {
                        let heartbeat = build_heartbeat(
                            &mut process,
                            cluster_id.clone(),
                            NodeId::new("node-b"),
                            local_node.clone(),
                            Term(1),
                            None,
                            status.clone(),
                        )
                        .map_err(|e| e.to_string())?;
                        connection
                            .send_message(heartbeat, &CborSerializer, &auth)
                            .map_err(|e| e.to_string())?;
                        next_heartbeat = Instant::now() + Duration::from_millis(400);
                    }
                    // Drain inbound (acks, node heartbeats); the read timeout
                    // doubles as the loop cadence.
                    match connection.receive_message(&CborSerializer, &auth) {
                        Ok(ReceiveMessageResult::Eof) => return Ok(()),
                        _ => continue,
                    }
                }
            });
            Self {
                address,
                stop,
                handle: Some(handle),
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for CloseoutPeer {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    /// MKM-13.5 closeout: external SIGUSR1 → daemon-local intent latch →
    /// fresh `evaluate_authority_attempt` → Authorized → fresh lease grant →
    /// final checkpoint → Stage 11 → real VIP/service mutation on Linux.
    ///
    /// This runs the literal production `daemon run` wiring
    /// (`run_daemon_inner`) — real signal handlers, real latch, real loop —
    /// in-process; only the peer/witness are scripted fixtures. The
    /// orchestrator thread delivers real signals to this process.
    ///
    /// Requires root (production `Psk::load` + real netlink/systemd mutation)
    /// and the closeout lab: `mkm0` dummy interface +
    /// `mikagami-closeout.service` — a `Type=simple` unit
    /// (`ExecStart=/bin/sleep infinity`) so systemd reports
    /// `active/running` ↔ `inactive/dead`, exactly what the service
    /// classifier requires. Run:
    /// `sudo <test-binary> stage_13_5_linux_real_mutation_closeout --include-ignored`.
    ///
    /// Phase 14.12 (Rev5 §34.11): the two Stage 13.6 closeouts are updated ONLY
    /// to satisfy fencing before the promotion SIGUSR1. With `[fencing]
    /// backend = "command"` the production command backend runs the virtual
    /// fence / verify scripts against the virtual target device `vh-node-b`
    /// (a veth pair created by `tests/lab/vf/closeout-lab.sh`; nothing else is
    /// affected). The first SIGUSR1 opens the incident and fences, the daemon's
    /// own foreground verify reaches `CONFIRMED`, and the next SIGUSR1 is the
    /// promotion. The scripted `CloseoutWitness` (with term-advancing grants,
    /// see `spawn_advancing`) and the in-process `CloseoutPeer` are kept; the
    /// Stage 13.5 closeout (`fenced == false`) is untouched.
    #[cfg(target_os = "linux")]
    fn run_linux_real_mutation_closeout(stage13_6: bool, unused_lease: bool) {
        use std::os::unix::fs::PermissionsExt;
        let fenced = stage13_6 || unused_lease;

        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "Linux closeout requires root. Run the test binary via sudo."
        );

        let psk_hex = "55".repeat(32);
        let dir = std::env::temp_dir().join(format!(
            "mikagami-13.5-closeout-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let psk_path = dir.join("cluster.psk");
        std::fs::write(&psk_path, format!("{psk_hex}\n")).unwrap();
        std::fs::set_permissions(&psk_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        // Fixtures bind before the daemon connects.
        let witness = if fenced {
            // Virtual fencing target device: owned by the closeout lab driver.
            let up = std::process::Command::new("/usr/sbin/ip")
                .args(["link", "set", "dev", "vh-node-b", "up"])
                .status()
                .expect("run ip");
            assert!(
                up.success(),
                "fenced closeout needs the closeout lab (tests/lab/vf/closeout-lab.sh up)"
            );
            assert!(
                std::path::Path::new("/usr/local/libexec/mikagami-vf/fence.sh").is_file(),
                "fenced closeout needs the trusted virtual fence scripts"
            );
            CloseoutWitness::spawn_advancing(test_psk())
        } else {
            CloseoutWitness::spawn(test_psk())
        };
        let peer = CloseoutPeer::spawn(test_psk(), Duration::from_secs(4));
        let state_path = dir.join("state.toml");
        let toml = witness_config_toml(&witness.address.to_string())
            .replace(
                "psk_file = \"/tmp/mikagami-test.psk\"",
                &format!("psk_file = \"{}\"", psk_path.display()),
            )
            .replace(
                "address = \"127.0.0.1:7946\"",
                &format!("address = \"{}\"", peer.address),
            )
            // v1.0 has fixed heartbeat timing (suspect 3 s, unreachable
            // 10 s): the fixture peer's silence turns into a fresh loss
            // episode after ~14 s, still inside the 30 s freshness window.
            .replace(
                "unit = \"nginx.service\"",
                "unit = \"mikagami-closeout.service\"",
            )
            .replace("interface = \"eth0\"", "interface = \"mkm0\"")
            .replace("arp_count = 3", "arp_count = 1")
            + &format!("\n[state]\npath = \"{}\"\n", state_path.display())
            + &if fenced {
                "\n[fencing]\nbackend = \"command\"\n\
                 fence = [\"/usr/bin/bash\", \"/usr/local/libexec/mikagami-vf/fence.sh\", \"vh-node-b\"]\n\
                 verify = [\"/usr/bin/bash\", \"/usr/local/libexec/mikagami-vf/verify.sh\", \"vh-node-b\"]\n\
                 fence_timeout_sec = 5\nverify_timeout_sec = 5\nverify_polls = 6\n"
                    .to_string()
            } else {
                String::new()
            };
        let config_path = dir.join("mikagami.toml");
        std::fs::write(&config_path, toml).unwrap();

        // The full production construction path: config -> PSK -> platform
        // -> LinuxDaemonRuntime (peer runtime inside) -> authenticated
        // witness session -> attach -> Daemon -> recovery gate.
        let prepared =
            super::linux::prepare_daemon(&config_path, std::path::Path::new("/bin/true"));
        eprintln!("closeout startup diagnostic: {:?}", prepared.as_ref().err());
        let (mut daemon, interval, _control_lock) =
            prepared.expect("production daemon construction must succeed");
        assert_eq!(daemon.state(), DaemonState::Running);

        // Phase 1 — build the real evidence precondition through production
        // ticks: the fixture peer heartbeats (observer `Fresh`), goes silent
        // (`Stale` → Suspect), and the confirmation window mints
        // `CommunicationLost` + a fresh `lost_at` epoch.
        let mut saw_fresh = false;
        let mut stale_since: Option<Instant> = None;
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let tick = daemon
                .tick_at(Instant::now())
                .expect("phase-1 observation tick");
            assert!(
                matches!(
                    tick,
                    TickResult::Observed | TickResult::ObservationUnavailable
                ),
                "unexpected terminal tick during evidence build-up: {tick:?}"
            );
            match daemon.peer_state() {
                PeerObservationState::Fresh => saw_fresh = true,
                PeerObservationState::Stale => {
                    stale_since.get_or_insert(Instant::now());
                }
                _ => {}
            }
            // Confirmation window (unreachable_after=10s from the last
            // heartbeat) plus margin.
            if stale_since.is_some_and(|t| t.elapsed() > Duration::from_secs(12)) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "peer never went stale — loss epoch cannot form"
            );
            std::thread::sleep(interval);
        }
        assert!(saw_fresh, "fixture heartbeats must have been accepted");
        assert!(stale_since.is_some(), "peer silence must turn stale");

        // Diagnostic visibility: the confirmed loss epoch and the exact
        // inert evaluation result the attempt path will see.
        let assessment = daemon.peer_failure_assessment_for_test();
        eprintln!("closeout: peer failure assessment = {assessment:?}");
        assert_eq!(
            assessment,
            crate::failure_assessment::PeerFailureAssessment::CommunicationLost,
            "fresh local loss evidence must exist before the intent fires"
        );
        // Diagnostic visibility: drive the exact attempt-bound observation
        // the attempt path performs (Phase 14.12 E3b) — the attempt's own
        // GET_TERM, awaited until its authenticated response is accepted —
        // then run the same fresh evaluate the attempt performs internally.
        daemon
            .complete_attempt_observation_for_test()
            .expect("the attempt-bound observation must complete on loopback");
        let evaluation = daemon
            .evaluate_authority_attempt_for_test(Instant::now())
            .expect("authority evaluation must not error");
        eprintln!("closeout: authority evaluation = {evaluation:?}");
        assert!(
            evaluation.as_ref().is_some_and(|e| e.is_authorized()),
            "evaluation must reach Authorized before the signal is delivered"
        );

        // Phase 2 — the real operator path: real signal handlers, real
        // SIGUSR1 -> real PROMOTION_INTENT latch -> the production
        // observation loop -> exactly one execute_promotion_attempt.
        super::linux::install_shutdown_signals();
        let vip_probe = dir.join("vip-seen");
        let vip_probe_for_thread = vip_probe.clone();
        let temporary_renew = witness.temporary_renew.clone();
        // Observation only: wait until the durable fencing incident reads
        // CONFIRMED (the daemon's own foreground verify wrote it).
        let confirmed_path = state_path.clone();
        let wait_confirmed = move |timeout: Duration, min_seq: u64| -> bool {
            let store = crate::node_mutation::NodeMutationStore::new(
                confirmed_path.clone(),
                crate::protocol::ClusterId::new("example-ha"),
                crate::protocol::NodeId::new("node-a"),
            );
            let deadline = Instant::now() + timeout;
            while Instant::now() < deadline {
                let state = store.load_existing().ok().and_then(|state| {
                    state
                        .fencing_incident
                        .map(|incident| (incident.incident_seq, incident.state.operator_name()))
                });
                if matches!(state, Some((seq, "CONFIRMED")) if seq >= min_seq) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            false
        };
        let orchestrator = std::thread::spawn(move || -> Vec<String> {
            // A failed wait is recorded and the remaining operator signals are
            // skipped, but SIGTERM is still delivered so the loop always ends.
            let mut errors: Vec<String> = Vec::new();
            let sigusr1 = || unsafe {
                libc::kill(libc::getpid(), libc::SIGUSR1);
            };
            // Let the loop start (entry clears any stale intent), then
            // deliver the real signal.
            std::thread::sleep(Duration::from_secs(1));
            sigusr1();
            if fenced {
                // Attempt 1 opened the incident and ran the fence action. The
                // daemon verifies on its ordinary iterations; the next
                // (explicit, fresh) SIGUSR1 follows only after CONFIRMED.
                if wait_confirmed(Duration::from_secs(30), 1) {
                    if !unused_lease {
                        sigusr1();
                    }
                } else {
                    errors.push("the fencing incident never reached CONFIRMED".into());
                }
            }
            if unused_lease && errors.is_empty() {
                if fenced {
                    // Attempt 2: grant, then the forced ARM pre-commit failure
                    // abandons the grant (incident now stale by term).
                    sigusr1();
                }
                // The first grant is abandoned by a forced ARM pre-commit
                // failure. A fresh signal then receives the actual typed
                // PolicyReject while the old lease is still represented as
                // unexpired; only after the expiry window does a third fresh
                // signal request the next generation.
                std::thread::sleep(Duration::from_secs(4));
                if fenced {
                    // Attempt 3: the stale incident is retired and a new one
                    // is fenced; it must be CONFIRMED before attempt 4.
                    sigusr1();
                    if !wait_confirmed(Duration::from_secs(30), 2) {
                        errors.push("the second fencing incident never reached CONFIRMED".into());
                    }
                }
                if errors.is_empty() {
                    sigusr1();
                    std::thread::sleep(Duration::from_secs(2));
                    sigusr1();
                }
            }
            // Poll for the real VIP on mkm0 (up to 60s).
            for _ in 0..120 {
                let output = std::process::Command::new("ip")
                    .args(["-o", "-4", "addr", "show", "dev", "mkm0"])
                    .output();
                if output
                    .map(|o| String::from_utf8_lossy(&o.stdout).contains("192.0.2.50"))
                    .unwrap_or(false)
                {
                    std::fs::write(&vip_probe_for_thread, "seen").ok();
                    break;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
            if stage13_6 {
                // First Renew succeeds and extends the authority window. The
                // next Renew is deliberately unavailable until the old
                // window expires, then the post-demotion exact retry becomes
                // successful so Release can complete.
                std::thread::sleep(Duration::from_secs(5));
                temporary_renew.store(true, std::sync::atomic::Ordering::SeqCst);
                std::thread::sleep(Duration::from_secs(7));
                temporary_renew.store(false, std::sync::atomic::Ordering::SeqCst);
                std::thread::sleep(Duration::from_secs(3));
            } else {
                std::thread::sleep(Duration::from_secs(2));
            }
            unsafe {
                libc::kill(libc::getpid(), libc::SIGTERM);
            }
            errors
        });

        let results = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let diag = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let results_in = results.clone();
        let diag_in = diag.clone();
        let arm_fault_once = std::sync::Arc::new(AtomicBool::new(false));
        let reject_next_request = witness.reject_next_request.clone();
        let state_path_for_log = state_path.clone();
        let exit = run_observation_loop(
            &mut daemon,
            interval,
            super::linux::shutdown_requested,
            std::thread::sleep,
            Instant::now,
            &super::linux::PROMOTION_INTENT,
            // Phase 14.12 E3b: no background priming; the attempt issues its own.
            |_daemon: &mut Daemon<crate::daemon::LinuxDaemonRuntime>, _now: Instant| {},
            move |daemon| {
                // Stage 13.2 test-hook seam: record which internal boundary
                // the attempt reached (post-revalidation / post-lease).
                let diag_eval = diag_in.clone();
                daemon.push_promotion_attempt_test_hook(move |daemon| {
                    diag_eval
                        .lock()
                        .unwrap()
                        .push(format!("post-eval peer={:?}", daemon.peer_state()));
                });
                let diag_lease = diag_in.clone();
                if unused_lease {
                    let arm_fault = arm_fault_once.clone();
                    daemon.push_promotion_attempt_test_hook(move |daemon| {
                        diag_lease.lock().unwrap().push(format!(
                            "post-lease peer={:?} {}",
                            daemon.peer_state(),
                            daemon.execution_diagnostics_for_test()
                        ));
                        if !arm_fault.swap(true, std::sync::atomic::Ordering::SeqCst) {
                            crate::recovery::inject_fault_once(
                                crate::recovery::FaultPoint::CandidateTempFsync,
                            );
                        }
                    });
                } else {
                    daemon.push_promotion_attempt_test_hook(move |daemon| {
                        diag_lease.lock().unwrap().push(format!(
                            "post-lease peer={:?} {}",
                            daemon.peer_state(),
                            daemon.execution_diagnostics_for_test()
                        ));
                    });
                }

                let result = daemon.execute_promotion_attempt(
                    crate::promotion_attempt::PromotionExecutionRequest::new(
                        crate::promotion_attempt::PromotionRequestId::new("closeout-sigusr1-1"),
                    ),
                );
                if unused_lease {
                    let store = crate::node_mutation::NodeMutationStore::new(
                        state_path_for_log.clone(),
                        crate::protocol::ClusterId::new("example-ha"),
                        crate::protocol::NodeId::new("node-a"),
                    );
                    let generation = store
                        .load_existing()
                        .map(|state| state.highest_started_mutation_generation)
                        .unwrap_or_default();
                    eprintln!(
                        "closeout: unused-lease attempt generation={generation} O={}",
                        daemon.release_obligation_for_test().unwrap_or(true)
                    );
                    if generation == 1 {
                        reject_next_request.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                }
                eprintln!("mikagami: closeout manual promotion attempt -> {result:?}");
                results_in.lock().unwrap().push(result);
            },
        );
        let orchestrator_errors = orchestrator.join().unwrap();

        // Restore default dispositions so other tests in this process are
        // unaffected.
        unsafe {
            libc::signal(libc::SIGUSR1, libc::SIG_DFL);
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            libc::signal(libc::SIGTERM, libc::SIG_DFL);
        }

        assert!(
            orchestrator_errors.is_empty(),
            "closeout orchestration failed: {orchestrator_errors:?}"
        );
        if unused_lease {
            assert_eq!(exit, LoopExit::ShutdownRequiresCleanup);
            // Fencing first (attempt 1: incident + fence, blocked), then the
            // Stage 13.6 UA sequence: ARM-fail (2), re-fence of the stale
            // incident (3), PolicyReject (4), fresh success (5).
            assert_eq!(
                results.lock().unwrap().as_slice(),
                &[
                    crate::promotion_attempt::PromotionAttemptResult::BlockedBeforeMutation,
                    crate::promotion_attempt::PromotionAttemptResult::BlockedBeforeMutation,
                    crate::promotion_attempt::PromotionAttemptResult::BlockedBeforeMutation,
                    crate::promotion_attempt::PromotionAttemptResult::BlockedBeforeMutation,
                    crate::promotion_attempt::PromotionAttemptResult::Succeeded,
                ],
                "unused-lease closeout must be fence, ARM-fail, re-fence, PolicyReject, then fresh success"
            );
            assert!(
                vip_probe.exists(),
                "fresh unused-lease grant acquired the real VIP"
            );
        } else if stage13_6 {
            assert_eq!(
                exit,
                LoopExit::Clean,
                "Stage 13.6 normal closeout must reach Standby before shutdown"
            );
            // Attempt 1 only fences (incident + fence action, blocked); attempt 2
            // is the one Stage 13.6 promotion.
            assert_eq!(
                results.lock().unwrap().as_slice(),
                &[
                    crate::promotion_attempt::PromotionAttemptResult::BlockedBeforeMutation,
                    crate::promotion_attempt::PromotionAttemptResult::Succeeded,
                ],
                "one fencing attempt, then exactly one Stage 13.6 promotion attempt"
            );
            assert!(vip_probe.exists(), "real VIP acquisition was observed");
            assert!(!daemon.durable_witness_outstanding_for_test().unwrap());
            assert!(!daemon.release_obligation_for_test().unwrap());
            assert_eq!(
                daemon.snapshot().unwrap().node_state,
                crate::state_machine::NodeState::Standby
            );
        } else {
            assert_eq!(
                exit,
                LoopExit::ShutdownRequiresCleanup,
                "promoted-node shutdown must report pending cleanup, never a clean claim"
            );
            assert_eq!(
                results.lock().unwrap().as_slice(),
                &[crate::promotion_attempt::PromotionAttemptResult::Succeeded],
                "exactly one attempt and it must succeed (diag: {:?})",
                diag.lock().unwrap()
            );
            assert!(
                vip_probe.exists(),
                "real VIP mutation must have been observed on mkm0"
            );
        }

        // Post-demote: VIP released, service stopped — local cleanup ran.
        let output = std::process::Command::new("ip")
            .args(["-o", "-4", "addr", "show", "dev", "mkm0"])
            .output()
            .unwrap();
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains("192.0.2.50"),
            "demote must release the VIP"
        );
        let service = std::process::Command::new("systemctl")
            .args(["is-active", "mikagami-closeout.service"])
            .output()
            .unwrap();
        assert_ne!(
            String::from_utf8_lossy(&service.stdout).trim(),
            "active",
            "demote must stop the service"
        );

        if !stage13_6 {
            // The durable LeaseRelease is the residual: recorded, unresolved,
            // and dispatchable only through the single shared session.
            assert!(
                daemon
                    .durable_witness_outstanding_for_test()
                    .expect("durable outstanding read"),
                "demotion must leave a durable outstanding LeaseRelease"
            );
            if unused_lease {
                let released = daemon
                    .execute_durable_witness_mutation_for_test()
                    .expect("unused-lease durable release dispatch");
                eprintln!("closeout: unused-lease durable release -> {released:?}");
            } else {
                // Phase 14.12 E3b: the loop primes no GET_TERM any more, so
                // nothing occupies the session's single outstanding slot
                // here (it was a loop-primed request that had to be retired
                // before this release dispatch). The slot must already be free.
                assert!(
                    !daemon
                        .execution_diagnostics_for_test()
                        .contains("witness_outstanding=true"),
                    "session outstanding slot must be free before release dispatch"
                );
                let released = daemon
                    .execute_durable_witness_mutation_for_test()
                    .expect("typed durable release dispatch");
                eprintln!("closeout: durable lease release -> {released:?}");
            }
            assert!(
                !daemon
                    .durable_witness_outstanding_for_test()
                    .expect("durable outstanding read after release"),
                "durable outstanding mutation must retire after release"
            );
            assert!(!daemon.release_obligation_for_test().unwrap());
        }

        if fenced {
            // The production backend ran both commands against the virtual
            // target; the consumed incident left no durable incident behind.
            let scripts =
                std::fs::read_to_string("/run/mikagami-vf/script-events.log").unwrap_or_default();
            assert!(
                scripts.contains("fence interface=vh-node-b target=node-b")
                    && scripts.contains("verify interface=vh-node-b result=isolated"),
                "fence + verify scripts did not run as expected: {scripts}"
            );
            let store = crate::node_mutation::NodeMutationStore::new(
                state_path.clone(),
                crate::protocol::ClusterId::new("example-ha"),
                crate::protocol::NodeId::new("node-a"),
            );
            let final_state = store.load_existing().expect("final node state");
            assert!(
                final_state.fencing_incident.is_none(),
                "ARM consumed the incident (none may remain): {:?}",
                final_state.fencing_incident
            );
            // Leave the virtual target as found.
            let _ = std::process::Command::new("/usr/sbin/ip")
                .args(["link", "set", "dev", "vh-node-b", "up"])
                .status();
        }

        drop(witness);
        drop(peer);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root + lab fixtures: real Stage 13.6 resource mutation"]
    fn stage_13_6_linux_normal_closeout() {
        run_linux_real_mutation_closeout(true, false);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root + lab fixtures: real Stage 13.6 unused-lease mutation"]
    fn stage_13_6_linux_unused_lease_closeout() {
        run_linux_real_mutation_closeout(false, true);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root + lab fixtures: real resource mutation"]
    fn stage_13_5_linux_real_mutation_closeout() {
        run_linux_real_mutation_closeout(false, false);
    }

    /// MKM-13.4-01: the production wiring connects TCP, runs the authenticated
    /// HELLO/HELLO_ACK bootstrap, and returns the neutral session + observer —
    /// no test-only session constructor is involved.
    #[test]
    fn connect_witness_session_establishes_authenticated_session() {
        let witness = FixtureWitness::spawn(test_psk());
        let config = Config::parse_str(&witness_config_toml(&witness.address.to_string()))
            .expect("config parses");

        let result = connect_witness_session(&config, test_psk());

        let (_session, _observer) =
            result.expect("production witness session should be established");
    }

    #[test]
    fn a_node_configuration_without_a_witness_is_rejected_at_parse() {
        // v1.0 has no availability mode: the Witness section is mandatory, so
        // a configuration without one never reaches the production wiring.
        let toml = witness_config_toml("127.0.0.1:1").replace(
            "[witness]\nid = \"witness-1\"\naddress = \"127.0.0.1:1\"\n",
            "",
        );
        assert!(matches!(
            Config::parse_str(&toml),
            Err(crate::config::ConfigError::Parse(_))
        ));
    }

    #[test]
    fn invalid_witness_address_is_rejected_by_config_validation() {
        // Class-A at the earliest boundary: `Config::load`/`parse_str`
        // validation refuses a non-socket-address witness address before the
        // runtime wiring ever sees it.
        let error = Config::parse_str(&witness_config_toml("not-an-address"))
            .err()
            .unwrap();

        assert!(
            format!("{error:?}").contains("witness.address"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn connect_witness_session_fails_when_unreachable() {
        // Bound then dropped: the port is refused.
        let address = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let config =
            Config::parse_str(&witness_config_toml(&address.to_string())).expect("config parses");

        let error = connect_witness_session(&config, test_psk()).err().unwrap();

        assert!(
            error.contains("witness connection"),
            "unexpected error: {error}"
        );
    }

    /// MKM-13.4-11: a mismatched PSK cannot authenticate the HELLO_ACK — the
    /// session is never attached, and the error carries no secret material.
    #[test]
    fn connect_witness_session_rejects_unauthenticated_ack() {
        let witness =
            FixtureWitness::spawn_with_ack_signer(test_psk(), Psk::from_test_bytes([0x99; 32]));
        let config = Config::parse_str(&witness_config_toml(&witness.address.to_string()))
            .expect("config parses");

        let error = connect_witness_session(&config, test_psk()).err().unwrap();

        assert!(!error.is_empty());
        assert!(
            !error.contains("0x99") && !error.contains("0x55"),
            "error must not carry secret material: {error}"
        );
    }

    /// Stage 13.4 Linux closeout: the real production construction path —
    /// `Config::load` on a real file, `Psk::load` on a root-owned 0600 file,
    /// `LinuxPlatformConfig`, `LinuxDaemonRuntime` (with its internally
    /// constructed peer runtime), the live TCP + authenticated HELLO/HELLO_ACK
    /// `WitnessSession` bootstrap against a scripted loopback fixture,
    /// `attach_witness`, `Daemon::new`, and the recovery gate — then one
    /// production-wired observation tick and a clean `Daemon`-owned shutdown.
    ///
    /// No test-only constructor is involved: the fixture plays only the
    /// remote side of the authenticated protocol. On Linux `Psk::load`
    /// requires a root-owned file, so this test is `#[ignore]`d in the
    /// default suite and run explicitly with privilege:
    /// `sudo <test-binary> stage_13_4_linux_production_wiring_closeout --include-ignored`.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root: production Psk::load demands a root-owned 0600 file"]
    fn stage_13_4_linux_production_wiring_closeout() {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "Linux closeout requires root: the production Psk::load contract \
             is a root-owned 0600 file. Run the test binary via sudo."
        );

        let psk_hex = "55".repeat(32);
        let dir =
            std::env::temp_dir().join(format!("mikagami-13.4-closeout-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let psk_path = dir.join("cluster.psk");
        std::fs::write(&psk_path, format!("{psk_hex}\n")).unwrap();
        std::fs::set_permissions(&psk_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let witness = FixtureWitness::spawn(test_psk());
        let state_path = dir.join("state.toml");
        let toml = witness_config_toml(&witness.address.to_string())
            .replace(
                "psk_file = \"/tmp/mikagami-test.psk\"",
                &format!("psk_file = \"{}\"", psk_path.display()),
            )
            // A real systemd unit that exists and is stopped: recovery must
            // observe genuine zero-resource state to reconcile, not a
            // fabricated one.
            .replace(
                "unit = \"nginx.service\"",
                "unit = \"mikagami-closeout.service\"",
            )
            + &format!("\n[state]\npath = \"{}\"\n", state_path.display());
        let config_path = dir.join("mikagami.toml");
        std::fs::write(&config_path, toml).unwrap();

        // The full production path: config -> PSK -> platform -> runtime ->
        // witness session -> attach -> Daemon -> recovery gate.
        let (mut daemon, _interval, _control_lock) =
            super::linux::prepare_daemon(&config_path, std::path::Path::new("/bin/true"))
                .expect("production daemon construction must succeed");
        assert_eq!(daemon.state(), DaemonState::Running);

        // One production-wired observation tick. The local observation may
        // report unavailable (no peer/service fixture); the tick still runs
        // the real DaemonRuntime path and must not fail closed.
        let tick = daemon.tick_at(Instant::now()).expect("observation tick");
        assert!(matches!(
            tick,
            TickResult::Observed | TickResult::ObservationUnavailable
        ));

        // Clean Daemon-owned shutdown; no further tick afterwards.
        daemon.request_shutdown().expect("request shutdown");
        assert_eq!(
            daemon.tick_at(Instant::now()).expect("shutdown tick"),
            TickResult::ShutdownComplete
        );
        assert_eq!(daemon.state(), DaemonState::Stopped);
        assert_eq!(
            daemon.tick_at(Instant::now()).expect("post-shutdown tick"),
            TickResult::NotRunning
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- Phase 14.12 U-1: authority-backed test-only Witness host ----------
    //
    // A TCP Witness host assembled ONLY from existing Witness code. Every
    // decision (term, lease validity, holder, deadline, journal identity,
    // generation watermark, expiry) is made by the existing
    // `witness_authority::handle_*_authority`, `expire_lease_if_needed` (driven
    // by the existing `WitnessExpiryScheduler`) and `WitnessStateStore`. The
    // host only does transport: accept, HELLO/HELLO_ACK, receive, dispatch by
    // message kind, send the prepared response. It never judges a lease. Its
    // BootIdProvider is an input seam (the same trait the existing Witness
    // tests substitute); the clock is the real `SystemMonotonicClock`.
    //
    // The client side is the production session path
    // (`connect_witness_session` -> `WitnessSession`). A request/response pair
    // here is therefore the real wire protocol, NOT a direct call of an
    // authority function. Test-only; not a product Witness.
    mod u1_witness_host {
        use super::*;
        use crate::protocol::{
            ClusterId, DurationMs, LeaseId, LeaseReleasePayload, LeaseRenewPayload,
            LeaseRequestPayload, ProtocolMessage, RequestId, Term, WitnessMutationOutcomeCode,
        };
        use crate::witness_authority::{
            LeaseExpiryResult, expire_lease_if_needed, handle_get_term_authority,
            handle_lease_release_authority, handle_lease_renew_authority,
            handle_lease_request_authority, send_prepared_lease_response,
            send_prepared_term_status,
        };
        use crate::witness_runtime::{
            WitnessConnection, WitnessResponseObservation, WitnessSession,
        };
        use crate::witness_scheduler::WitnessExpiryScheduler;
        use crate::witness_state::{
            BootId, BootIdProvider, LeaseState, ProcBootIdProvider, SystemMonotonicClock,
            WitnessNotReadyReason, WitnessPersistentState, WitnessReadiness, WitnessStateError,
            WitnessStateStore,
        };
        use std::net::TcpStream;
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;

        type EventLog = Arc<Mutex<Vec<String>>>;
        type HostStore = WitnessStateStore<HostBoot, SystemMonotonicClock>;

        const CLUSTER: &str = "example-ha";
        const WITNESS_ID: &str = "witness-1";

        /// What the host accepts as a first message. The check itself is the
        /// existing inbound handshake contract (`session::PeerSession`):
        /// message type HELLO, cluster id, sender == expected peer, receiver ==
        /// this node, expected priority, non-zero sequence. The policy only
        /// names the expected values; it does not re-implement the checks.
        #[derive(Clone)]
        struct HelloPolicy {
            cluster: String,
            local: String,
            /// (node id, expected HELLO priority)
            allowed: Vec<(String, i32)>,
        }

        impl HelloPolicy {
            fn standard() -> Self {
                Self {
                    cluster: CLUSTER.to_string(),
                    local: WITNESS_ID.to_string(),
                    allowed: vec![
                        ("node-a".to_string(), 100),
                        ("node-b".to_string(), 100),
                        ("node-c".to_string(), 100),
                        ("node-d".to_string(), 100),
                    ],
                }
            }

            /// `node-a:100,node-b:90` (lab env syntax).
            fn parse_allowed(spec: &str) -> Vec<(String, i32)> {
                spec.split(',')
                    .map(|item| {
                        let (node, priority) = item.split_once(':').expect("node:priority");
                        (node.to_string(), priority.parse().expect("priority"))
                    })
                    .collect()
            }
        }

        /// One-line description of the response the existing authority prepared
        /// (diagnostic text for the event log only; it decides nothing).
        fn describe_response(message: &ProtocolMessage) -> String {
            match message {
                ProtocolMessage::LeaseGrant(g) => format!(
                    "grant term={} lease_id={} holder={}",
                    g.term.0,
                    g.lease_id.as_str(),
                    g.holder_node_id.as_str()
                ),
                ProtocolMessage::LeaseRenewed(g) => format!(
                    "renewed term={} lease_id={} remaining_ms={}",
                    g.term.0,
                    g.lease_id.as_str(),
                    g.lease_remaining_ms.0
                ),
                ProtocolMessage::LeaseReleased(r) => format!(
                    "released term={} lease_id={} result={}",
                    r.term.0,
                    r.lease_id.as_str(),
                    r.result
                ),
                ProtocolMessage::LeaseReject(r) => {
                    format!("reject code={:?} reason={:?}", r.code, r.reason)
                }
                other => format!("{:?}", other.message_type()),
            }
        }

        /// Validate the first message of a connection with the existing
        /// `PeerSession`. Returns the HELLO's envelope fields on success.
        fn check_first_message(
            policy: &HelloPolicy,
            hello: &crate::receive::AuthenticatedMessage,
        ) -> Result<(), String> {
            use crate::session::{PeerSession, SessionAction};
            let common = &hello.unsigned().common;
            let sender = common.sender_node_id.as_str();
            let Some((_, priority)) = policy.allowed.iter().find(|(node, _)| node == sender) else {
                return Err(format!("sender {sender:?} is not an expected peer"));
            };
            let mut session = PeerSession::new(
                ClusterId::new(policy.cluster.clone()),
                NodeId::new(policy.local.clone()),
                common.sender_node_id.clone(),
                *priority,
            );
            match session.accept(hello) {
                Ok(SessionAction::SendHelloAck) => Ok(()),
                Ok(other) => Err(format!("unexpected session action {other:?}")),
                Err(error) => Err(error.to_string()),
            }
        }

        #[derive(Clone)]
        enum HostBoot {
            /// The real /proc boot id (lab runs).
            Proc,
            /// A controllable boot id (restart / reboot simulation on any host).
            Fixed(Arc<Mutex<String>>),
        }

        impl BootIdProvider for HostBoot {
            fn current_boot_id(&self) -> Result<BootId, WitnessStateError> {
                match self {
                    HostBoot::Proc => ProcBootIdProvider.current_boot_id(),
                    HostBoot::Fixed(value) => Ok(BootId::new(value.lock().unwrap().clone())),
                }
            }
        }

        fn host_store(path: &Path, boot: &HostBoot) -> HostStore {
            WitnessStateStore::with_providers(
                path,
                ClusterId::new(CLUSTER),
                boot.clone(),
                SystemMonotonicClock,
            )
        }

        /// The persisted authority state as the existing store reports it.
        fn persisted(store: &HostStore) -> Option<WitnessPersistentState> {
            let recovery = store.load();
            if recovery.readiness == WitnessReadiness::Ready {
                recovery.state
            } else {
                None
            }
        }

        fn summary(store: &HostStore) -> String {
            let recovery = store.load();
            match (&recovery.readiness, &recovery.state) {
                (WitnessReadiness::Ready, Some(state)) => format!(
                    "term={} lease={:?} holder={:?} lease_id={:?} deadline={:?} journal={} watermarks={:?}",
                    state.current_term.0,
                    state.lease_state,
                    state
                        .holder_node_id
                        .as_ref()
                        .map(|n| n.as_str().to_string()),
                    state
                        .active_lease_id
                        .as_ref()
                        .map(|l| l.as_str().to_string()),
                    state.lease_deadline_monotonic_ms,
                    state.journal.len(),
                    state.generation_watermarks,
                ),
                (readiness, _) => format!("not-ready {readiness:?}"),
            }
        }

        struct AuthorityWitnessHost {
            address: SocketAddr,
            path: PathBuf,
            boot: HostBoot,
            stop: Arc<AtomicBool>,
            log: EventLog,
            scheduler_cancel: Option<crate::witness_scheduler::SchedulerCancellation>,
            handles: Vec<JoinHandle<()>>,
        }

        impl AuthorityWitnessHost {
            fn spawn(
                bind: &str,
                psk: Psk,
                path: &Path,
                boot: HostBoot,
                with_scheduler: bool,
            ) -> Self {
                Self::spawn_with_policy(
                    bind,
                    psk,
                    path,
                    boot,
                    with_scheduler,
                    HelloPolicy::standard(),
                )
            }

            fn spawn_with_policy(
                bind: &str,
                psk: Psk,
                path: &Path,
                boot: HostBoot,
                with_scheduler: bool,
                policy: HelloPolicy,
            ) -> Self {
                let store = host_store(path, &boot);
                if store.load().readiness
                    == WitnessReadiness::NotReady(WitnessNotReadyReason::StateMissing)
                {
                    store.initialize_new().expect("initialize witness state");
                }
                let listener = TcpListener::bind(bind).unwrap();
                listener.set_nonblocking(true).unwrap();
                let address = listener.local_addr().unwrap();
                let stop = Arc::new(AtomicBool::new(false));
                let log: EventLog = Arc::new(Mutex::new(Vec::new()));
                let mut handles = Vec::new();

                let mut scheduler_cancel = None;
                if with_scheduler {
                    let scheduler = WitnessExpiryScheduler::new(Duration::from_millis(100));
                    let cancel = scheduler.cancellation();
                    scheduler_cancel = Some(cancel.clone());
                    let scheduler_store = host_store(path, &boot);
                    handles.push(std::thread::spawn(move || {
                        let _ = scheduler.run_until_cancelled(&scheduler_store, &cancel);
                    }));
                }

                let (accept_stop, accept_log, accept_path, accept_boot) =
                    (stop.clone(), log.clone(), path.to_path_buf(), boot.clone());
                let accept_policy = policy;
                handles.push(std::thread::spawn(move || {
                    let mut workers: Vec<JoinHandle<()>> = Vec::new();
                    while !accept_stop.load(Ordering::SeqCst) {
                        match listener.accept() {
                            Ok((stream, _)) => {
                                stream.set_nonblocking(false).unwrap();
                                let (psk, path, boot, stop, log, policy) = (
                                    psk.clone(),
                                    accept_path.clone(),
                                    accept_boot.clone(),
                                    accept_stop.clone(),
                                    accept_log.clone(),
                                    accept_policy.clone(),
                                );
                                workers.push(std::thread::spawn(move || {
                                    if let Err(error) = serve_connection(
                                        stream, psk, &path, boot, stop, &log, &policy,
                                    ) {
                                        log.lock()
                                            .unwrap()
                                            .push(format!("connection ended: {error}"));
                                    }
                                }));
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(20));
                            }
                            Err(_) => break,
                        }
                    }
                    for worker in workers {
                        let _ = worker.join();
                    }
                }));
                Self {
                    address,
                    path: path.to_path_buf(),
                    boot,
                    stop,
                    log,
                    scheduler_cancel,
                    handles,
                }
            }

            fn store(&self) -> HostStore {
                host_store(&self.path, &self.boot)
            }

            fn events(&self) -> Vec<String> {
                self.log.lock().unwrap().clone()
            }

            fn shutdown(&mut self) {
                self.stop.store(true, Ordering::SeqCst);
                if let Some(cancel) = &self.scheduler_cancel {
                    cancel.cancel();
                }
                for handle in self.handles.drain(..) {
                    let _ = handle.join();
                }
            }
        }

        impl Drop for AuthorityWitnessHost {
            fn drop(&mut self) {
                self.shutdown();
            }
        }

        fn serve_connection(
            stream: TcpStream,
            psk: Psk,
            path: &Path,
            boot: HostBoot,
            stop: Arc<AtomicBool>,
            log: &EventLog,
            policy: &HelloPolicy,
        ) -> Result<(), String> {
            let mut connection = TcpConnection::from_stream(
                stream,
                Duration::from_millis(400),
                Duration::from_secs(5),
            )
            .map_err(|e| e.to_string())?;
            let auth = MessageAuthenticator::new(psk);
            let hello = match connection
                .receive_message(&CborSerializer, &auth)
                .map_err(|e| e.to_string())?
            {
                ReceiveMessageResult::Message(message) => message,
                ReceiveMessageResult::Eof => return Err("eof before HELLO".into()),
            };
            // U1-1: the first message must be a valid HELLO under the existing
            // inbound handshake contract. Anything else gets no HELLO_ACK, no
            // WitnessConnection and no authority call: the worker ends here and
            // the stream is closed.
            let first_type = hello.unsigned().message.message_type();
            if let Err(reason) = check_first_message(policy, &hello) {
                log.lock().unwrap().push(format!(
                    "first message {first_type:?} from {:?} rejected: {reason}",
                    hello.unsigned().common.sender_node_id.as_str()
                ));
                return Err(format!("first message rejected: {reason}"));
            }
            let mut process = ProcessSession::generate().map_err(|e| e.to_string())?;
            let common = hello.unsigned().common.clone();
            let ack = build_hello_ack(
                &mut process,
                common.cluster_id.clone(),
                NodeId::new(policy.local.clone()),
                common.sender_node_id.clone(),
                common.term,
            )
            .map_err(|e| e.to_string())?;
            connection
                .send_message(ack, &CborSerializer, &auth)
                .map_err(|e| e.to_string())?;
            let peer = common.sender_node_id.as_str().to_string();
            log.lock().unwrap().push(format!("HELLO/HELLO_ACK {peer}"));
            let mut witness = WitnessConnection::new(
                NodeId::new(policy.local.clone()),
                common.sender_node_id.clone(),
                common.cluster_id.clone(),
                common.session_id.clone(),
                connection,
            );
            let store = host_store(path, &boot);
            let mut idle_errors = 0u32;
            // Lab only (Phase 14.12 F7 probes): while this file exists next to
            // the stop file, every GET_TERM answer is signed with a wrong key.
            let bad_answers = std::env::var("MKM_U1_STOPFILE")
                .ok()
                .map(|stop_file| PathBuf::from(stop_file).with_file_name("witness.badauth"));
            let wrong_auth =
                crate::security::MessageAuthenticator::new(Psk::from_test_bytes([0x66; 32]));
            while !stop.load(Ordering::SeqCst) {
                let pending = match witness.receive_pending(&CborSerializer, &auth) {
                    Ok(pending) => pending,
                    Err(_) => {
                        // Read timeout (poll the stop flag) or a closed peer.
                        idle_errors += 1;
                        if idle_errors > 4_000 {
                            return Err("too many receive errors".into());
                        }
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                };
                let kind = pending.message().unsigned().message.message_type();
                // The host decides nothing: the existing authority function is
                // called, it commits (journal + watermark + authority state in
                // one store commit) and only then returns the prepared
                // response. The state is read back BEFORE the response is sent
                // so the log proves persist-before-respond.
                let sent = match &pending.message().unsigned().message {
                    ProtocolMessage::GetTerm => {
                        match handle_get_term_authority(&mut witness, &pending, &store) {
                            Ok(prepared) => {
                                log.lock().unwrap().push(format!(
                                    "{peer} {kind:?} before-send {}",
                                    summary(&store)
                                ));
                                // Lab only (Phase 14.12 E3b probes): a Witness
                                // whose GET_TERM answer takes this long.
                                if let Some(ms) = std::env::var("MKM_LAB_WITNESS_DELAY_MS")
                                    .ok()
                                    .and_then(|v| v.parse::<u64>().ok())
                                {
                                    std::thread::sleep(Duration::from_millis(ms));
                                }
                                let signing = if bad_answers.as_ref().is_some_and(|f| f.exists()) {
                                    &wrong_auth
                                } else {
                                    &auth
                                };
                                send_prepared_term_status(
                                    &mut witness,
                                    &mut process,
                                    prepared,
                                    &CborSerializer,
                                    signing,
                                )
                                .map_err(|e| e.to_string())
                            }
                            Err(error) => {
                                log.lock()
                                    .unwrap()
                                    .push(format!("{peer} {kind:?} authority-error {error:?}"));
                                Ok(())
                            }
                        }
                    }
                    ProtocolMessage::LeaseRequest(_)
                    | ProtocolMessage::LeaseRenew(_)
                    | ProtocolMessage::LeaseRelease(_) => {
                        let prepared = match &pending.message().unsigned().message {
                            ProtocolMessage::LeaseRequest(_) => {
                                handle_lease_request_authority(&mut witness, &pending, &store)
                            }
                            ProtocolMessage::LeaseRenew(_) => {
                                handle_lease_renew_authority(&mut witness, &pending, &store)
                            }
                            _ => handle_lease_release_authority(&mut witness, &pending, &store),
                        };
                        match prepared {
                            Ok(prepared) => {
                                log.lock().unwrap().push(format!(
                                    "{peer} {kind:?} before-send {} => {}",
                                    summary(&store),
                                    describe_response(&prepared.message)
                                ));
                                send_prepared_lease_response(
                                    &mut witness,
                                    &mut process,
                                    prepared,
                                    &CborSerializer,
                                    &auth,
                                )
                                .map_err(|e| e.to_string())
                            }
                            Err(error) => {
                                log.lock()
                                    .unwrap()
                                    .push(format!("{peer} {kind:?} authority-error {error:?}"));
                                Ok(())
                            }
                        }
                    }
                    other => {
                        log.lock()
                            .unwrap()
                            .push(format!("{peer} unhandled {other:?}"));
                        Ok(())
                    }
                };
                sent?;
            }
            Ok(())
        }

        // ---- client: the production session path ------------------------------

        struct Client {
            session: WitnessSession,
            node: String,
            generation: u64,
            next_id: u64,
        }

        impl Client {
            fn connect(address: SocketAddr, node: &str) -> Self {
                let toml = witness_config_toml(&address.to_string())
                    .replace("id = \"node-a\"", &format!("id = \"{node}\""))
                    .replace("id = \"node-b\"", "id = \"zzz-peer\"");
                let config = Config::parse_str(&toml).expect("client config parses");
                let (session, _observer) =
                    crate::daemon_run::connect_witness_session(&config, test_psk())
                        .expect("production witness session");
                Self {
                    session,
                    node: node.to_string(),
                    generation: 0,
                    next_id: 0,
                }
            }

            fn connect_with_psk(address: SocketAddr, node: &str, psk: Psk) -> Self {
                let toml = witness_config_toml(&address.to_string())
                    .replace("id = \"node-a\"", &format!("id = \"{node}\""))
                    .replace("id = \"node-b\"", "id = \"zzz-peer\"");
                let config = Config::parse_str(&toml).expect("client config parses");
                let (session, _observer) = crate::daemon_run::connect_witness_session(&config, psk)
                    .expect("production witness session");
                Self {
                    session,
                    node: node.to_string(),
                    generation: 0,
                    next_id: 0,
                }
            }

            fn fresh_id(&mut self) -> RequestId {
                self.next_id += 1;
                request_uuid(node_tag(&self.node), self.next_id)
            }

            fn finish(&mut self) -> Result<WitnessResponseObservation, String> {
                let pending = self.session.receive_pending().map_err(|e| e.to_string())?;
                self.session
                    .handle_pending_response(&pending)
                    .map_err(|e| e.to_string())
            }

            fn get_term(&mut self) -> crate::protocol::TermStatusPayload {
                let id = self.fresh_id();
                self.session.send_get_term(id).unwrap();
                match self.finish().expect("GET_TERM response") {
                    WitnessResponseObservation::TermStatus(payload) => payload,
                    other => panic!("GET_TERM answered with {other:?}"),
                }
            }

            fn request_with(
                &mut self,
                id: RequestId,
                generation: u64,
                observed_term: u64,
                ttl_ms: u64,
            ) -> Result<WitnessResponseObservation, String> {
                self.session
                    .send_lease_request(
                        id,
                        LeaseRequestPayload {
                            mutation_generation: generation,
                            observed_term: Term(observed_term),
                            priority: 100,
                            requested_ttl: DurationMs(ttl_ms),
                        },
                    )
                    .map_err(|e| e.to_string())?;
                self.finish()
            }

            fn request(&mut self, observed_term: u64) -> WitnessResponseObservation {
                self.generation += 1;
                let (id, generation) = (self.fresh_id(), self.generation);
                self.request_with(id, generation, observed_term, 10_000)
                    .expect("LeaseRequest response")
            }

            fn renew_with(
                &mut self,
                id: RequestId,
                generation: u64,
                term: u64,
                lease_id: &str,
            ) -> Result<WitnessResponseObservation, String> {
                self.session
                    .send_lease_renew(
                        id,
                        LeaseRenewPayload {
                            mutation_generation: generation,
                            term: Term(term),
                            lease_id: LeaseId::new(lease_id),
                        },
                    )
                    .map_err(|e| e.to_string())?;
                self.finish()
            }

            fn renew(&mut self, term: u64, lease_id: &str) -> WitnessResponseObservation {
                self.generation += 1;
                let (id, generation) = (self.fresh_id(), self.generation);
                self.renew_with(id, generation, term, lease_id)
                    .expect("LeaseRenew response")
            }

            fn release(&mut self, term: u64, lease_id: &str) -> WitnessResponseObservation {
                self.generation += 1;
                let (id, generation) = (self.fresh_id(), self.generation);
                self.session
                    .send_lease_release(
                        id,
                        LeaseReleasePayload {
                            mutation_generation: generation,
                            term: Term(term),
                            lease_id: LeaseId::new(lease_id),
                            reason: "u1 spike release".to_string(),
                        },
                    )
                    .unwrap();
                self.finish().expect("LeaseRelease response")
            }
        }

        /// Mutating Witness requests need a canonical lowercase UUID v4
        /// `request_id` (`protocol::is_valid_mutating_request_id`).
        fn request_uuid(tag: u32, n: u64) -> RequestId {
            RequestId::new(format!("{tag:08x}-0000-4000-8000-{n:012x}"))
        }

        fn node_tag(node: &str) -> u32 {
            u32::from(*node.as_bytes().last().unwrap())
        }

        /// Per-run state directory (U1-2).
        ///
        /// * The name is unique per call: pid + wall-clock nanos + a
        ///   process-wide counter + `RandomState` entropy. It is created with
        ///   `create_dir` (never `create_dir_all`), so an existing directory is
        ///   never reused: on `AlreadyExists` a new name is drawn (bounded
        ///   retries, then panic). Nothing is deleted before creation.
        /// * Drop removes only the directory this value created, and only when
        ///   the thread is not panicking. After an assertion failure / panic the
        ///   directory is kept and its path is printed, so the evidence
        ///   survives and no later run touches it.
        struct TempState {
            dir: PathBuf,
            state: PathBuf,
        }

        impl TempState {
            fn unique_name(name: &str, attempt: u32) -> String {
                use std::hash::{BuildHasher, Hasher};
                use std::sync::atomic::AtomicU64;
                static COUNTER: AtomicU64 = AtomicU64::new(0);
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
                hasher.write_u128(nanos);
                hasher.write_u32(attempt);
                format!(
                    "mikagami-u1-{name}-{}-{:x}-{:x}-{:016x}",
                    std::process::id(),
                    nanos,
                    COUNTER.fetch_add(1, Ordering::SeqCst),
                    hasher.finish()
                )
            }
        }

        impl Drop for TempState {
            fn drop(&mut self) {
                if std::thread::panicking() {
                    eprintln!(
                        "U1 evidence preserved (test panicked): {}",
                        self.dir.display()
                    );
                } else {
                    let _ = std::fs::remove_dir_all(&self.dir);
                }
            }
        }

        /// Create a fresh directory under `base`. `namer(name, attempt)` supplies
        /// the candidate names; `create_dir` fails on an existing path, in which
        /// case the next attempt is drawn. Never removes anything.
        fn allocate_in(
            base: &Path,
            name: &str,
            mut namer: impl FnMut(&str, u32) -> String,
        ) -> TempState {
            for attempt in 0..64 {
                let dir = base.join(namer(name, attempt));
                match std::fs::create_dir(&dir) {
                    Ok(()) => {
                        let state = dir.join("witness-state.toml");
                        return TempState { dir, state };
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("cannot create {}: {error}", dir.display()),
                }
            }
            panic!("could not allocate a unique state directory for {name}");
        }

        fn temp_state(name: &str) -> TempState {
            allocate_in(&std::env::temp_dir(), name, TempState::unique_name)
        }

        fn fixed_boot(value: &str) -> HostBoot {
            HostBoot::Fixed(Arc::new(Mutex::new(value.to_string())))
        }

        fn grant(observation: WitnessResponseObservation) -> crate::protocol::LeaseGrantPayload {
            match observation {
                WitnessResponseObservation::LeaseGrant(payload) => payload,
                other => panic!("expected LeaseGrant, got {other:?}"),
            }
        }

        fn rejected(
            observation: WitnessResponseObservation,
            code: WitnessMutationOutcomeCode,
            reason_contains: &str,
        ) {
            match observation {
                WitnessResponseObservation::LeaseReject(payload) => {
                    assert_eq!(payload.code, code, "{payload:?}");
                    assert!(
                        payload.reason.contains(reason_contains),
                        "reason {:?} must contain {reason_contains:?}",
                        payload.reason
                    );
                }
                other => panic!("expected LeaseReject({reason_contains}), got {other:?}"),
            }
        }

        // T1 ------------------------------------------------------------------
        #[test]
        fn u1_t1_get_term_over_the_real_session() {
            let tmp = temp_state("t1");
            let state = tmp.state.clone();
            let mut host = AuthorityWitnessHost::spawn(
                "127.0.0.1:0",
                test_psk(),
                &state,
                fixed_boot("boot-t1"),
                false,
            );
            let mut client = Client::connect(host.address, "node-c");
            let term = client.get_term();
            assert_eq!(term.current_term, Term(0));
            assert!(term.current_holder.is_none() && term.current_lease_id.is_none());
            assert!(term.lease_remaining_ms.is_none());
            // The answer is the persisted authority state, read by the existing
            // handler (the log carries the before-send state).
            let events = host.events();
            assert!(
                events.iter().any(|e| e.contains("HELLO/HELLO_ACK node-c")),
                "{events:?}"
            );
            assert!(
                events
                    .iter()
                    .any(|e| e.contains("GetTerm before-send term=0 lease=None")),
                "{events:?}"
            );
            host.shutdown();
        }

        // T2 ------------------------------------------------------------------
        #[test]
        fn u1_t2_lease_request_grants_and_persists_before_responding() {
            let tmp = temp_state("t2");
            let state = tmp.state.clone();
            let mut host = AuthorityWitnessHost::spawn(
                "127.0.0.1:0",
                test_psk(),
                &state,
                fixed_boot("boot-t2"),
                false,
            );
            let mut client = Client::connect(host.address, "node-c");
            let before = persisted(&host.store()).expect("ready before");
            assert_eq!(before.current_term, Term(0));
            let granted = grant(client.request(0));
            assert_eq!(granted.term, Term(1));
            assert_eq!(granted.holder_node_id.as_str(), "node-c");
            assert_eq!(granted.lease_ttl_ms, DurationMs(10_000));
            assert_eq!(granted.renew_after_ms, DurationMs(3_000));

            // Persisted authority state, independently re-read.
            let after = persisted(&host.store()).expect("ready after");
            assert_eq!(after.current_term, Term(1));
            assert_eq!(after.lease_state, LeaseState::Active);
            assert_eq!(after.active_lease_id, Some(granted.lease_id.clone()));
            assert_eq!(after.holder_node_id.as_ref().unwrap().as_str(), "node-c");
            assert_eq!(after.lease_ttl_ms, Some(DurationMs(10_000)));
            assert_eq!(after.journal.len(), 1);
            assert_eq!(after.generation_watermarks.get("node-c"), Some(&1));

            // Order: the state was already committed when the response was
            // about to be sent (read back by the host between handler and send).
            let events = host.events();
            let before_send = events
                .iter()
                .find(|e| e.contains("LeaseRequest before-send"))
                .unwrap_or_else(|| panic!("{events:?}"));
            assert!(
                before_send.contains("term=1 lease=Active")
                    && before_send.contains("journal=1")
                    && before_send.contains("\"node-c\": 1"),
                "{before_send}"
            );

            // GET_TERM now reflects the persisted lease.
            let term = client.get_term();
            assert_eq!(term.current_term, Term(1));
            assert_eq!(term.current_lease_id, Some(granted.lease_id));
            assert!(term.lease_remaining_ms.unwrap().0 > 0);
            host.shutdown();
        }

        // T3 ------------------------------------------------------------------
        #[test]
        fn u1_t3_lease_renew_extends_the_persisted_deadline() {
            let tmp = temp_state("t3");
            let state = tmp.state.clone();
            let mut host = AuthorityWitnessHost::spawn(
                "127.0.0.1:0",
                test_psk(),
                &state,
                fixed_boot("boot-t3"),
                false,
            );
            let mut client = Client::connect(host.address, "node-c");
            let granted = grant(client.request(0));
            let first = persisted(&host.store()).unwrap();
            let first_deadline = first.lease_deadline_monotonic_ms.unwrap();
            std::thread::sleep(Duration::from_millis(1_500));

            let renewed = match client.renew(1, granted.lease_id.as_str()) {
                WitnessResponseObservation::LeaseRenewed(payload) => payload,
                other => panic!("expected LeaseRenewed, got {other:?}"),
            };
            assert_eq!(renewed.lease_id, granted.lease_id);
            assert_eq!(renewed.term, Term(1));
            assert_eq!(renewed.lease_remaining_ms, DurationMs(10_000));
            let second = persisted(&host.store()).unwrap();
            let second_deadline = second.lease_deadline_monotonic_ms.unwrap();
            let extension = second_deadline - first_deadline;
            assert!(
                (1_400..=4_000).contains(&extension),
                "deadline moved by the wall time between grant and renew, got {extension} ms"
            );
            assert_eq!(second.lease_state, LeaseState::Active);
            assert_eq!(second.current_term, Term(1));
            assert_eq!(second.journal.len(), 2);
            assert_eq!(second.generation_watermarks.get("node-c"), Some(&2));
            host.shutdown();
        }

        // T4 ------------------------------------------------------------------
        #[test]
        fn u1_t4_lease_release_is_persisted() {
            let tmp = temp_state("t4");
            let state = tmp.state.clone();
            let mut host = AuthorityWitnessHost::spawn(
                "127.0.0.1:0",
                test_psk(),
                &state,
                fixed_boot("boot-t4"),
                false,
            );
            let mut client = Client::connect(host.address, "node-c");
            let granted = grant(client.request(0));
            match client.release(1, granted.lease_id.as_str()) {
                WitnessResponseObservation::LeaseReleased(payload) => {
                    assert_eq!(payload.term, Term(1));
                    assert_eq!(payload.lease_id, granted.lease_id);
                    assert_eq!(payload.result, "released");
                }
                other => panic!("expected LeaseReleased, got {other:?}"),
            }
            let after = persisted(&host.store()).unwrap();
            assert_eq!(after.lease_state, LeaseState::None);
            assert!(after.active_lease_id.is_none() && after.holder_node_id.is_none());
            assert!(after.lease_deadline_monotonic_ms.is_none());
            assert_eq!(
                after.current_term,
                Term(1),
                "the term is never lowered by a release"
            );
            assert_eq!(after.journal.len(), 2);
            assert_eq!(after.generation_watermarks.get("node-c"), Some(&2));
            let term = client.get_term();
            assert_eq!(term.current_term, Term(1));
            assert!(term.current_holder.is_none() && term.lease_remaining_ms.is_none());
            // A released lease cannot be renewed.
            rejected(
                client.renew(1, granted.lease_id.as_str()),
                WitnessMutationOutcomeCode::PolicyReject,
                "there is no active lease to renew",
            );
            host.shutdown();
        }

        // T5 ------------------------------------------------------------------
        /// Real-time expiry: the existing scheduler calls the existing
        /// `expire_lease_if_needed` after the persisted deadline. The harness
        /// only polls the persisted state; it never judges an expiry.
        #[test]
        fn u1_t5_scheduler_expires_a_lease_after_its_real_deadline() {
            let tmp = temp_state("t5");
            let state = tmp.state.clone();
            let mut host = AuthorityWitnessHost::spawn(
                "127.0.0.1:0",
                test_psk(),
                &state,
                fixed_boot("boot-t5"),
                true,
            );
            let mut client = Client::connect(host.address, "node-c");
            let t0 = std::time::Instant::now();
            let granted = grant(client.request(0));
            std::thread::sleep(Duration::from_secs(5));
            assert_eq!(
                persisted(&host.store()).unwrap().lease_state,
                LeaseState::Active,
                "still active half way through the TTL"
            );
            let mut expired_at = None;
            while t0.elapsed() < Duration::from_secs(25) {
                if persisted(&host.store()).unwrap().lease_state == LeaseState::None {
                    expired_at = Some(t0.elapsed());
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let expired_at = expired_at.expect("the scheduler must expire the lease");
            assert!(
                expired_at >= Duration::from_secs(10),
                "expiry cannot precede grant + TTL, observed {expired_at:?}"
            );
            let after = persisted(&host.store()).unwrap();
            assert!(after.active_lease_id.is_none() && after.holder_node_id.is_none());
            assert_eq!(after.current_term, Term(1), "expiry keeps the term");
            // Over the wire: no holder, and the old lease can no longer be renewed.
            let term = client.get_term();
            assert!(term.current_holder.is_none() && term.lease_remaining_ms.is_none());
            rejected(
                client.renew(1, granted.lease_id.as_str()),
                WitnessMutationOutcomeCode::PolicyReject,
                "there is no active lease to renew",
            );
            // A new request after expiry is granted at the next term.
            let mut other = Client::connect(host.address, "node-d");
            let next = grant(other.request(1));
            assert_eq!(next.term, Term(2));
            assert_eq!(next.holder_node_id.as_str(), "node-d");
            host.shutdown();
        }

        // T6 ------------------------------------------------------------------
        /// Rejections decided by the existing authority. Each case names the
        /// existing reject reason / outcome code it exercises.
        #[test]
        fn u1_t6_existing_authority_rejects_invalid_requests() {
            let tmp = temp_state("t6");
            let state = tmp.state.clone();
            let mut host = AuthorityWitnessHost::spawn(
                "127.0.0.1:0",
                test_psk(),
                &state,
                fixed_boot("boot-t6"),
                false,
            );
            let mut holder = Client::connect(host.address, "node-c");
            let mut other = Client::connect(host.address, "node-d");
            let granted = grant(holder.request(0));
            let lease = granted.lease_id.as_str().to_string();

            // Invalid lease id.
            rejected(
                holder.renew(1, "not-the-active-lease"),
                WitnessMutationOutcomeCode::PolicyReject,
                "renewal lease_id does not match the active lease",
            );
            // Old term (renew) and old observed_term (request).
            rejected(
                holder.renew(0, &lease),
                WitnessMutationOutcomeCode::PolicyReject,
                "renewal term does not match current Witness term",
            );
            // Not the holder: renew, release, and preemption by another node.
            rejected(
                other.renew(1, &lease),
                WitnessMutationOutcomeCode::PolicyReject,
                "only the current lease holder may renew",
            );
            rejected(
                other.release(1, &lease),
                WitnessMutationOutcomeCode::PolicyReject,
                "only the current lease holder may release",
            );
            rejected(
                other.request(1),
                WitnessMutationOutcomeCode::PolicyReject,
                "an active lease cannot be preempted by LEASE_REQUEST",
            );
            // Stale observed term and wrong TTL on a request.
            rejected(
                other.request(0),
                WitnessMutationOutcomeCode::PolicyReject,
                "observed_term does not match current Witness term",
            );
            other.generation += 1;
            let (id, generation) = (other.fresh_id(), other.generation);
            rejected(
                other.request_with(id, generation, 1, 9_000).unwrap(),
                WitnessMutationOutcomeCode::PolicyReject,
                "requested_ttl must be 10000 milliseconds",
            );

            // Journal identity: a generation behind the watermark, a gap, and a
            // reused request id with a different payload.
            let stale_id = request_uuid(0x5a, 1);
            rejected(
                holder.renew_with(stale_id, 1, 1, &lease).unwrap(),
                WitnessMutationOutcomeCode::RetiredStale,
                "retired or stale",
            );
            let gap_id = request_uuid(0x5a, 2);
            let gap_generation = holder.generation + 5;
            rejected(
                holder
                    .renew_with(gap_id, gap_generation, 1, &lease)
                    .unwrap(),
                WitnessMutationOutcomeCode::GenerationGap,
                "generation gap",
            );
            // The first renewal committed with request id u1-node-c-2 at
            // generation 2; replaying that id with another lease id conflicts.
            let committed_id = request_uuid(node_tag("node-c"), 2);
            rejected(
                holder
                    .renew_with(committed_id, 2, 1, "another-lease")
                    .unwrap(),
                WitnessMutationOutcomeCode::Conflict,
                "journal identity conflict",
            );

            // The rejections did not disturb the authority: still granted to node-c.
            let after = persisted(&host.store()).unwrap();
            assert_eq!(after.lease_state, LeaseState::Active);
            assert_eq!(after.active_lease_id, Some(granted.lease_id));
            assert_eq!(after.holder_node_id.as_ref().unwrap().as_str(), "node-c");
            assert_eq!(after.current_term, Term(1));
            host.shutdown();
        }

        /// A renewal after the persisted deadline, before any expiry processing,
        /// is rejected by the existing authority ("current lease deadline has
        /// expired"); the existing `expire_lease_if_needed` then expires it.
        #[test]
        fn u1_t6_renewal_after_the_deadline_is_rejected_by_the_authority() {
            let tmp = temp_state("t6x");
            let state = tmp.state.clone();
            let mut host = AuthorityWitnessHost::spawn(
                "127.0.0.1:0",
                test_psk(),
                &state,
                fixed_boot("boot-t6x"),
                false,
            );
            let mut client = Client::connect(host.address, "node-c");
            let granted = grant(client.request(0));
            let deadline = persisted(&host.store())
                .unwrap()
                .lease_deadline_monotonic_ms
                .unwrap();
            let store = host.store();
            while store.current_monotonic_ms().unwrap() < deadline + 200 {
                std::thread::sleep(Duration::from_millis(100));
            }
            rejected(
                client.renew(1, granted.lease_id.as_str()),
                WitnessMutationOutcomeCode::PolicyReject,
                "current lease deadline has expired",
            );
            assert_eq!(
                persisted(&store).unwrap().lease_state,
                LeaseState::Active,
                "no scheduler is running: the stale lease is only expired by the expiry path"
            );
            assert_eq!(
                expire_lease_if_needed(&store).unwrap(),
                LeaseExpiryResult::Expired
            );
            assert_eq!(persisted(&store).unwrap().lease_state, LeaseState::None);
            host.shutdown();
        }

        // T7 ------------------------------------------------------------------
        #[test]
        fn u1_t7_restart_keeps_state_journal_and_watermark() {
            let tmp = temp_state("t7");
            let state = tmp.state.clone();
            let boot = fixed_boot("boot-t7a");
            let mut host =
                AuthorityWitnessHost::spawn("127.0.0.1:0", test_psk(), &state, boot.clone(), false);
            let mut client = Client::connect(host.address, "node-c");
            let request_id = request_uuid(0x5b, 1);
            let granted = match client
                .request_with(request_id.clone(), 1, 0, 10_000)
                .unwrap()
            {
                WitnessResponseObservation::LeaseGrant(payload) => payload,
                other => panic!("{other:?}"),
            };
            let before = persisted(&host.store()).unwrap();
            drop(client);
            host.shutdown();
            drop(host);

            // Re-initialise everything from the files.
            let mut host =
                AuthorityWitnessHost::spawn("127.0.0.1:0", test_psk(), &state, boot.clone(), false);
            let reopened = persisted(&host.store()).expect("same boot id: ready");
            assert_eq!(reopened.current_term, before.current_term);
            assert_eq!(reopened.active_lease_id, before.active_lease_id);
            assert_eq!(reopened.holder_node_id, before.holder_node_id);
            assert_eq!(
                reopened.lease_deadline_monotonic_ms,
                before.lease_deadline_monotonic_ms
            );
            assert_eq!(reopened.journal, before.journal);
            assert_eq!(reopened.generation_watermarks, before.generation_watermarks);

            // The persisted journal makes the identical request idempotent.
            let mut client = Client::connect(host.address, "node-c");
            let replay = match client.request_with(request_id, 1, 0, 10_000).unwrap() {
                WitnessResponseObservation::LeaseGrant(payload) => payload,
                other => panic!("{other:?}"),
            };
            assert_eq!(replay.lease_id, granted.lease_id);
            assert_eq!(replay.term, granted.term);
            assert!(replay.lease_remaining_ms.0 <= granted.lease_remaining_ms.0);
            assert_eq!(
                persisted(&host.store()).unwrap().journal.len(),
                1,
                "a duplicate commits nothing"
            );
            // The persisted lease is still renewable by the holder after the restart.
            client.generation = 1;
            assert!(matches!(
                client.renew(1, granted.lease_id.as_str()),
                WitnessResponseObservation::LeaseRenewed(_)
            ));
            drop(client);
            host.shutdown();
            drop(host);

            // A different boot id: the existing store refuses to serve authority
            // (monotonic deadlines are not comparable across boots).
            let HostBoot::Fixed(value) = &boot else {
                unreachable!()
            };
            *value.lock().unwrap() = "boot-t7b".to_string();
            let mut host =
                AuthorityWitnessHost::spawn("127.0.0.1:0", test_psk(), &state, boot.clone(), false);
            assert_eq!(
                host.store().load().readiness,
                WitnessReadiness::NotReady(WitnessNotReadyReason::BootIdChanged)
            );
            let mut client = Client::connect(host.address, "node-c");
            let id = client.fresh_id();
            client.session.send_get_term(id).unwrap();
            assert!(
                client.finish().is_err(),
                "a not-ready Witness must not answer GET_TERM"
            );
            assert!(
                host.events()
                    .iter()
                    .any(|e| e.contains("authority-error NotReady(BootIdChanged)")),
                "{:?}",
                host.events()
            );
            drop(client);
            host.shutdown();
        }

        // U1-1 ----------------------------------------------------------------
        //
        // The first message of a connection must be a valid HELLO under the
        // existing inbound handshake contract (`PeerSession`) and must carry a
        // valid signature. Each negative sends a first message that fails
        // exactly one of those checks and asserts: no HELLO_ACK (nothing but
        // EOF / an error comes back), the host logged the rejection, and the
        // persisted authority state is byte-for-byte what it was before.

        enum FirstReply {
            Closed,
            Message(Box<crate::receive::AuthenticatedMessage>),
        }

        struct FirstMessage {
            message_type: &'static str,
            cluster: &'static str,
            sender: &'static str,
            receiver: &'static str,
            priority: i32,
            sequence: u64,
            /// PSK used to sign (the host holds `test_psk()`).
            psk: Psk,
            kind: FirstKind,
        }

        #[derive(Clone, Copy)]
        enum FirstKind {
            Hello,
            GetTerm,
            LeaseRequest,
        }

        impl FirstMessage {
            fn valid_hello() -> Self {
                Self {
                    message_type: "HELLO",
                    cluster: CLUSTER,
                    sender: "node-c",
                    receiver: WITNESS_ID,
                    priority: 100,
                    sequence: 1,
                    psk: test_psk(),
                    kind: FirstKind::Hello,
                }
            }
        }

        fn send_first_message(address: SocketAddr, first: &FirstMessage) -> FirstReply {
            use crate::protocol::{CommonFields, HelloPayload, PROTOCOL_VERSION, Sequence};
            use crate::protocol::{SessionId, UnsignedEnvelope};
            let mut connection = TcpConnection::connect(
                address,
                Duration::from_secs(2),
                Duration::from_millis(1_500),
                Duration::from_secs(2),
            )
            .expect("raw client connects");
            let auth = MessageAuthenticator::new(first.psk.clone());
            let message = match first.kind {
                FirstKind::Hello => ProtocolMessage::Hello(HelloPayload {
                    priority: first.priority,
                }),
                FirstKind::GetTerm => ProtocolMessage::GetTerm,
                FirstKind::LeaseRequest => ProtocolMessage::LeaseRequest(LeaseRequestPayload {
                    mutation_generation: 1,
                    observed_term: Term(0),
                    priority: 100,
                    requested_ttl: DurationMs(10_000),
                }),
            };
            let request_id = match first.kind {
                FirstKind::Hello => None,
                _ => Some(request_uuid(0x7e, 1)),
            };
            let envelope = UnsignedEnvelope {
                common: CommonFields {
                    protocol_version: PROTOCOL_VERSION,
                    cluster_id: ClusterId::new(first.cluster),
                    sender_node_id: NodeId::new(first.sender),
                    receiver_node_id: NodeId::new(first.receiver),
                    session_id: SessionId::new("u1-negative-session"),
                    sequence: Sequence(first.sequence),
                    term: Term(0),
                    lease_id: None,
                    request_id,
                    operation_id: None,
                },
                message,
            };
            connection
                .send_message(envelope, &CborSerializer, &auth)
                .unwrap_or_else(|e| panic!("{} cannot be sent: {e}", first.message_type));
            match connection.receive_message(&CborSerializer, &auth) {
                Ok(ReceiveMessageResult::Message(message)) => FirstReply::Message(message),
                Ok(ReceiveMessageResult::Eof) | Err(_) => FirstReply::Closed,
            }
        }

        /// The host rejects `first`: no reply, a logged rejection, and the
        /// authority state (term, lease, journal, watermarks) is unchanged.
        fn assert_first_message_rejected(label: &str, first: FirstMessage, reason: &str) {
            let tmp = temp_state(&format!("h-{label}"));
            let host = AuthorityWitnessHost::spawn(
                "127.0.0.1:0",
                test_psk(),
                &tmp.state,
                fixed_boot("boot-h"),
                false,
            );
            let before = summary(&host.store());
            match send_first_message(host.address, &first) {
                FirstReply::Closed => {}
                FirstReply::Message(message) => panic!(
                    "{label}: the host answered a bad first message with {:?}",
                    message.unsigned().message.message_type()
                ),
            }
            // The worker logs on its own thread: wait (bounded) for the entry.
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut events = host.events();
            while !events.iter().any(|e| e.contains("rejected")) {
                assert!(
                    std::time::Instant::now() < deadline,
                    "{label}: no rejection logged: {events:?}"
                );
                std::thread::sleep(Duration::from_millis(20));
                events = host.events();
            }
            assert!(
                events.iter().any(|e| e.contains(reason)),
                "{label}: expected reason {reason:?} in {events:?}"
            );
            assert!(
                !events.iter().any(|e| e.contains("HELLO/HELLO_ACK")),
                "{label}: {events:?}"
            );
            assert_eq!(
                summary(&host.store()),
                before,
                "{label}: authority state changed"
            );
            // The host is still serving valid clients afterwards.
            let mut client = Client::connect(host.address, "node-c");
            assert_eq!(client.get_term().current_term, Term(0));
        }

        #[test]
        fn u1_h1_lease_request_as_first_message_gets_no_hello_ack() {
            let mut first = FirstMessage::valid_hello();
            first.kind = FirstKind::LeaseRequest;
            first.message_type = "LEASE_REQUEST";
            assert_first_message_rejected("lease-request", first, "HELLO is required");
        }

        #[test]
        fn u1_h2_get_term_as_first_message_gets_no_hello_ack() {
            let mut first = FirstMessage::valid_hello();
            first.kind = FirstKind::GetTerm;
            first.message_type = "GET_TERM";
            assert_first_message_rejected("get-term", first, "HELLO is required");
        }

        #[test]
        fn u1_h3_wrong_cluster_hello_is_rejected() {
            let mut first = FirstMessage::valid_hello();
            first.cluster = "other-cluster";
            assert_first_message_rejected("cluster", first, "cluster identity mismatch");
        }

        #[test]
        fn u1_h4_wrong_receiver_hello_is_rejected() {
            let mut first = FirstMessage::valid_hello();
            first.receiver = "witness-2";
            assert_first_message_rejected("receiver", first, "receiver identity mismatch");
        }

        #[test]
        fn u1_h5_unknown_sender_hello_is_rejected() {
            let mut first = FirstMessage::valid_hello();
            first.sender = "intruder";
            assert_first_message_rejected("sender", first, "is not an expected peer");
        }

        #[test]
        fn u1_h6_wrong_priority_hello_is_rejected() {
            let mut first = FirstMessage::valid_hello();
            first.priority = 7;
            assert_first_message_rejected("priority", first, "peer priority mismatch");
        }

        #[test]
        fn u1_h7_hello_signed_with_the_wrong_psk_is_rejected() {
            let mut first = FirstMessage::valid_hello();
            first.psk = Psk::from_test_bytes([0x66; 32]);
            // Fails in the existing authenticated receive path, before any
            // handshake check runs (no `PeerSession` verdict is logged).
            let tmp = temp_state("h-psk");
            let host = AuthorityWitnessHost::spawn(
                "127.0.0.1:0",
                test_psk(),
                &tmp.state,
                fixed_boot("boot-h"),
                false,
            );
            let before = summary(&host.store());
            assert!(matches!(
                send_first_message(host.address, &first),
                FirstReply::Closed
            ));
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while !host.events().iter().any(|e| e.contains("connection ended")) {
                assert!(std::time::Instant::now() < deadline, "{:?}", host.events());
                std::thread::sleep(Duration::from_millis(20));
            }
            assert!(
                !host.events().iter().any(|e| e.contains("HELLO/HELLO_ACK")),
                "{:?}",
                host.events()
            );
            assert_eq!(summary(&host.store()), before);
        }

        #[test]
        fn u1_h8_a_valid_hello_is_still_acknowledged() {
            // The regular clients (T1..T7) keep working through the check; this
            // pins the positive path of the new check on its own.
            let tmp = temp_state("h-ok");
            let host = AuthorityWitnessHost::spawn(
                "127.0.0.1:0",
                test_psk(),
                &tmp.state,
                fixed_boot("boot-h"),
                false,
            );
            let reply = send_first_message(host.address, &FirstMessage::valid_hello());
            match reply {
                FirstReply::Message(message) => assert_eq!(
                    message.unsigned().message.message_type(),
                    crate::protocol::MessageType::HelloAck
                ),
                FirstReply::Closed => panic!("a valid HELLO must be acknowledged"),
            }
        }

        // U1-2 ----------------------------------------------------------------

        #[test]
        fn u1_s1_state_directories_are_unique_across_threads_and_repeats() {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    std::thread::spawn(|| {
                        (0..16)
                            .map(|_| temp_state("s1").dir.clone())
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            let mut all: Vec<PathBuf> = handles
                .into_iter()
                .flat_map(|h| h.join().unwrap())
                .collect();
            let total = all.len();
            all.sort();
            all.dedup();
            assert_eq!(all.len(), total, "state directories collided");
        }

        #[test]
        fn u1_s2_an_existing_directory_is_never_deleted_or_reused() {
            let base = temp_state("s2-base");
            // A leftover from an earlier failed run, named exactly as the old
            // scheme (`<name>-<pid>`) would have named it.
            let legacy = base
                .dir
                .join(format!("mikagami-u1-t1-{}", std::process::id()));
            std::fs::create_dir(&legacy).unwrap();
            std::fs::write(legacy.join("evidence.txt"), b"keep me").unwrap();
            for _ in 0..32 {
                let fresh = allocate_in(&base.dir, "t1", TempState::unique_name);
                assert_ne!(fresh.dir, legacy);
            }
            assert_eq!(
                std::fs::read(legacy.join("evidence.txt")).unwrap(),
                b"keep me"
            );
        }

        #[test]
        fn u1_s3_a_name_collision_draws_a_new_name_without_deleting() {
            let base = temp_state("s3-base");
            let taken = base.dir.join("forced");
            std::fs::create_dir(&taken).unwrap();
            std::fs::write(taken.join("evidence.txt"), b"keep me").unwrap();
            let fresh = allocate_in(&base.dir, "x", |name, attempt| {
                if attempt < 3 {
                    "forced".to_string()
                } else {
                    TempState::unique_name(name, attempt)
                }
            });
            assert_ne!(fresh.dir, taken);
            assert!(fresh.dir.is_dir());
            drop(fresh);
            assert_eq!(
                std::fs::read(taken.join("evidence.txt")).unwrap(),
                b"keep me",
                "the colliding directory must be left alone"
            );
        }

        #[test]
        fn u1_s4_success_removes_only_its_own_directory() {
            let base = temp_state("s4-base");
            let neighbour = base.dir.join("neighbour");
            std::fs::create_dir(&neighbour).unwrap();
            let own = allocate_in(&base.dir, "own", TempState::unique_name);
            std::fs::write(own.state.clone(), b"x").unwrap();
            let own_dir = own.dir.clone();
            drop(own);
            assert!(!own_dir.exists(), "own directory removed after success");
            assert!(neighbour.is_dir(), "a neighbouring directory is untouched");
        }

        #[test]
        fn u1_s5_a_panic_preserves_the_evidence() {
            let base = temp_state("s5-base");
            let base_dir = base.dir.clone();
            let kept = std::thread::spawn(move || {
                let tmp = allocate_in(&base_dir, "boom", TempState::unique_name);
                std::fs::write(&tmp.state, b"evidence").unwrap();
                let path = tmp.dir.clone();
                // Hand the path out through the panic payload.
                std::panic::panic_any(path);
            })
            .join()
            .expect_err("the thread panics");
            let path = kept.downcast::<PathBuf>().expect("path payload");
            assert!(path.is_dir(), "evidence directory survives a panic");
            assert_eq!(
                std::fs::read(path.join("witness-state.toml")).unwrap(),
                b"evidence"
            );
            // A later allocation does not remove it.
            let _later = allocate_in(&base.dir, "boom", TempState::unique_name);
            assert!(path.is_dir());
        }

        // F1 characterization -------------------------------------------------
        //
        // Phase 14.12 Finding P14.12-F1 (see the investigation report). This
        // drives the PRODUCTION observation lifecycle (`connect_witness_session`
        // -> `WitnessSession` + `WitnessEvidenceAdapter`) against the
        // authority-backed Witness host with explicit monotonic instants, in
        // the order the production loop and SIGUSR1 attempts use it:
        //
        //   prime (begin_observation_at)  -> one GET_TERM, deadline = now + 5 s
        //   attempt (poll_observation_at) -> the only call that completes it
        //
        // It prints and asserts what the lifecycle CURRENTLY does. It is a
        // characterization of the finding, not an acceptance test: when F1 is
        // dispositioned its expectations change.
        fn f1_run(spacings_s: &[u64], label: &str) -> Vec<String> {
            use crate::evidence_fusion::adapter::AuthorityViewExpectation;
            let tmp = temp_state(label);
            let host = AuthorityWitnessHost::spawn(
                "127.0.0.1:0",
                test_psk(),
                &tmp.state,
                fixed_boot("boot-f1"),
                false,
            );
            let toml = witness_config_toml(&host.address.to_string())
                .replace("id = \"node-a\"", "id = \"node-c\"")
                .replace("id = \"node-b\"", "id = \"zzz-peer\"");
            let config = Config::parse_str(&toml).unwrap();
            let (mut session, mut observer) =
                crate::daemon_run::connect_witness_session(&config, test_psk()).unwrap();
            let expectation = || AuthorityViewExpectation::new(NodeId::new("node-c"), None, None);
            let t0 = Instant::now();
            let mut out = Vec::new();
            // Iteration 1 prime (what the daemon does at its first loop pass).
            let first = observer.begin_observation_at(&mut session, expectation(), t0);
            out.push(format!(
                "t+0s prime#1 -> {:?}",
                first.map(|id| id.as_str().to_string())
            ));
            std::thread::sleep(Duration::from_millis(250)); // the response arrives
            let mut now = t0;
            for (i, gap) in spacings_s.iter().enumerate() {
                now = now + Duration::from_secs(*gap);
                let at = now.duration_since(t0).as_secs();
                let polled = observer.poll_observation_at(&mut session, now);
                let shown = match &polled {
                    Ok(progress) => format!("{progress:?}"),
                    Err(error) => format!("Err({error:?})"),
                };
                out.push(format!("t+{at}s attempt#{} poll -> {shown}", i + 1));
                // The loop's prime after the attempt (a no-op while Busy).
                let primed = observer.begin_observation_at(&mut session, expectation(), now);
                out.push(format!(
                    "t+{at}s prime after attempt#{} -> {}",
                    i + 1,
                    match primed {
                        Ok(id) => format!("began {}", id.as_str().rsplit('-').next().unwrap()),
                        Err(error) => format!("{error:?}"),
                    }
                ));
                std::thread::sleep(Duration::from_millis(250));
            }
            out.push(format!("witness events: {:?}", host.events()));
            out
        }

        /// T-F1-5 (after Option A): the stale-frame failure is gone. After an
        /// idle period the first attempt still ends `Unavailable(Timeout)` (the
        /// production loop cannot begin a new request while the expired one
        /// holds the session slot, see the F1 report), but the SECOND attempt
        /// is Ready: there is no `RequestIdMismatch` any more.
        #[test]
        fn f1_option_a_second_attempt_after_idle_is_ready_without_stale_frame_error() {
            let lines = f1_run(&[6, 1, 1], "f1-burst");
            for line in &lines {
                eprintln!("F1 {line}");
            }
            let text = lines.join("\n");
            assert!(
                text.contains("attempt#1 poll -> Unavailable(Timeout)"),
                "{text}"
            );
            assert!(text.contains("attempt#2 poll -> Ready("), "{text}");
            assert!(!text.contains("RequestIdMismatch"), "{text}");
        }

        /// T-F1-5: single attempts spaced inside the deadline all succeed after
        /// the first idle attempt; none fails with a stale-frame error.
        #[test]
        fn f1_option_a_spaced_attempts_do_not_alternate_or_fail() {
            let lines = f1_run(&[6, 4, 4, 4, 4], "f1-spaced");
            for line in &lines {
                eprintln!("F1 {line}");
            }
            let text = lines.join("\n");
            assert!(
                text.contains("attempt#1 poll -> Unavailable(Timeout)"),
                "{text}"
            );
            for n in 2..=5 {
                assert!(
                    text.contains(&format!("attempt#{n} poll -> Ready(")),
                    "{text}"
                );
            }
            assert!(!text.contains("Err("), "{text}");
        }

        // T8 (lab, root) ------------------------------------------------------
        /// Long-running host for the netns lab: run only by the spike script
        /// inside the `witness` namespace. Uses the real boot id, the real PSK
        /// file and the existing expiry scheduler.
        #[test]
        #[ignore = "U-1 lab: authority-backed Witness host, run by the spike script inside the witness netns"]
        fn u1_lab_witness_host_serve() {
            use std::io::Write as _;
            let bind = std::env::var("MKM_U1_BIND").unwrap();
            let secs: u64 = std::env::var("MKM_U1_SECS").unwrap().parse().unwrap();
            let psk =
                Psk::load(std::path::Path::new(&std::env::var("MKM_U1_PSK").unwrap())).unwrap();
            let state = PathBuf::from(std::env::var("MKM_U1_STATE").unwrap());
            let mut policy = HelloPolicy::standard();
            if let Ok(spec) = std::env::var("MKM_U1_ALLOWED") {
                policy.allowed = HelloPolicy::parse_allowed(&spec);
            }
            // Optional lab outputs: a streamed event log (one line per event,
            // wall-clock epoch ms + seconds since start) and a stop file whose
            // appearance ends the run early. Both are observation / process
            // control only.
            let mut sink = std::env::var("MKM_U1_EVENT_LOG").ok().map(|path| {
                std::fs::OpenOptions::new()
                    .create_new(true)
                    .append(true)
                    .open(path)
                    .expect("create the event log (never overwritten)")
            });
            let stop_file = std::env::var("MKM_U1_STOPFILE").ok().map(PathBuf::from);
            let mut host = AuthorityWitnessHost::spawn_with_policy(
                &bind,
                psk,
                &state,
                HostBoot::Proc,
                true,
                policy,
            );
            let started = std::time::Instant::now();
            let emit = |sink: &mut Option<std::fs::File>, line: String| {
                let epoch_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis())
                    .unwrap_or(0);
                if let Some(file) = sink.as_mut() {
                    let _ = writeln!(
                        file,
                        "{epoch_ms} {:9.3} {line}",
                        started.elapsed().as_secs_f64()
                    );
                    let _ = file.flush();
                }
                eprintln!("U1-HOST {line}");
            };
            emit(&mut sink, format!("READY listening on {}", host.address));
            let mut written = 0usize;
            loop {
                let events = host.events();
                for event in &events[written..] {
                    emit(&mut sink, format!("event: {event}"));
                }
                written = events.len();
                if started.elapsed() >= Duration::from_secs(secs)
                    || stop_file.as_ref().is_some_and(|f| f.exists())
                {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let events = host.events();
            for event in &events[written..] {
                emit(&mut sink, format!("event: {event}"));
            }
            emit(
                &mut sink,
                format!("final state: {}", summary(&host.store())),
            );
            host.shutdown();
            emit(&mut sink, "STOPPED".to_string());
        }

        /// Seed client for the netns lab: a real network client in the `client`
        /// namespace drives request -> renew -> release against the host and
        /// reports each response. It uses the production session path and a
        /// node id that is not one of the two daemons.
        #[test]
        #[ignore = "U-1 lab: seed client, run by the spike script inside the client netns"]
        fn u1_lab_witness_seed_client() {
            let address: SocketAddr = std::env::var("MKM_U1_ADDR").unwrap().parse().unwrap();
            let psk =
                Psk::load(std::path::Path::new(&std::env::var("MKM_U1_PSK").unwrap())).unwrap();
            let mut client = Client::connect_with_psk(address, "node-c", psk);
            eprintln!("U1-CLIENT get_term: {:?}", client.get_term());
            let granted = grant(client.request(0));
            eprintln!("U1-CLIENT grant: {granted:?}");
            eprintln!(
                "U1-CLIENT renew: {:?}",
                client.renew(granted.term.0, granted.lease_id.as_str())
            );
            eprintln!(
                "U1-CLIENT release: {:?}",
                client.release(granted.term.0, granted.lease_id.as_str())
            );
            eprintln!("U1-CLIENT get_term after: {:?}", client.get_term());
            if std::env::var("MKM_U1_HOLD").as_deref() == Ok("1") {
                // Leave a freshly granted lease active (no release) so the
                // production daemons observe a held lease in TermStatus.
                let held = grant(client.request(granted.term.0));
                eprintln!("U1-CLIENT hold (left active): {held:?}");
            }
        }
    }

    // ---- Phase 14.12 MC-1: management-network snapshot comparison (test-only) ----
    //
    // The VF lab compares the management network before setup, during the run
    // and after teardown. WHETHER IT CHANGED is not decided here: the audited
    // `tests/lab/vf/mgmt-net-compare.sh` decides it. The script is embedded with
    // `include_str!` (the bytes can never drift from the audited file) and is run
    // for every `ip` part of a snapshot, so the Rust lab and the shell lab driver
    // (`closeout-lab.sh`) cannot disagree again. Only DHCP lease / route-expiry
    // seconds are volatile; `0sec` and `forever` are real changes.
    //
    // Why this way (see the MC-1 Rust VF lab report): re-implementing the rules
    // in Rust is what produced the earlier disagreement (it hid `valid_lft 0sec`,
    // flagged route `expires` seconds, and compared only interface NAMES for
    // `link`); executing the audited file in place would tie the lab to the
    // build tree's path; embedding + a private scratch directory keeps the lab
    // self-contained like the other vf_lab scripts.
    //
    // Fail-closed: a part that could not be captured, a part missing from,
    // duplicated in or unknown to either side, a comparison that cannot be
    // run, exits other than 0 / 1, and an exit 0 whose stdout is not EXACTLY
    // one of the script's two "stable" verdict lines (or that wrote anything to
    // stderr) are all FAIL. The shell driver (`closeout-lab.sh`) enforces the
    // same contract. Nothing here changes the network (the capture only runs
    // `ip ... show`, `ss -Hltn` and reads /proc).
    mod mgmt_net {
        use std::collections::BTreeMap;
        use std::fmt;
        use std::path::PathBuf;
        use std::process::{Command, Stdio};
        use std::sync::atomic::{AtomicU64, Ordering};

        /// The audited comparison script, byte for byte.
        pub(super) const COMPARE_SH: &str = include_str!("../tests/lab/vf/mgmt-net-compare.sh");
        const INTERPRETER: &str = "/bin/sh";
        /// The child's whole environment besides `TMPDIR` / `LC_ALL`.
        const CHILD_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
        /// Every snapshot must carry exactly these parts.
        pub(super) const REQUIRED: [&str; 7] = [
            "addr",
            "route4",
            "route6",
            "rule",
            "link",
            "ip_forward",
            "listen",
        ];

        /// The two stdout lines the script prints on exit 0 — and the only
        /// ones that make a part PASS. `closeout-lab.sh` carries the same two
        /// strings (`mgmt_net_verdict_lines_are_the_scripts_and_the_drivers`).
        pub(super) const VERDICT_IDENTICAL: &str = "mgmt-net-compare: IDENTICAL";
        pub(super) const VERDICT_STABLE: &str =
            "mgmt-net-compare: STABLE-IDENTICAL (only finite lease seconds differ)";

        /// Who judges a part.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(super) enum Judge {
            /// `ip` text: judged by the audited script.
            Script,
            /// Not `ip` text (`ip_forward`, listening sockets): exact equality.
            Exact,
        }

        #[derive(Clone, Debug)]
        pub(super) struct Part {
            pub(super) label: &'static str,
            pub(super) judge: Judge,
            /// The captured text, or why it could not be captured.
            pub(super) content: Result<String, String>,
        }

        #[derive(Clone, Debug, Default)]
        pub(super) struct Snapshot {
            pub(super) parts: Vec<Part>,
        }

        /// Who must judge a required part (`None`: not a part at all).
        pub(super) fn judge_of(label: &str) -> Option<Judge> {
            match label {
                "addr" | "route4" | "route6" | "rule" | "link" => Some(Judge::Script),
                "ip_forward" | "listen" => Some(Judge::Exact),
                _ => None,
            }
        }

        impl Snapshot {
            fn part(&self, label: &str) -> Option<&Part> {
                self.parts.iter().find(|part| part.label == label)
            }

            /// Everything wrong with the SHAPE of this snapshot (empty = valid):
            /// each required part exactly once, nothing else, each carrying its
            /// own judge. The order of the parts is not a contract (the
            /// comparison looks parts up by label), so it is not checked. A
            /// capture always builds a valid shape; this guards the comparison
            /// against any other snapshot, whatever produced it.
            pub(super) fn problems(&self) -> Vec<String> {
                let mut problems = Vec::new();
                for label in REQUIRED {
                    match self.parts.iter().filter(|part| part.label == label).count() {
                        1 => {}
                        0 => problems.push(format!("{label}: part missing")),
                        copies => {
                            problems.push(format!("{label}: duplicate part ({copies} copies)"))
                        }
                    }
                }
                for part in &self.parts {
                    match judge_of(part.label) {
                        None => problems.push(format!("{}: unexpected part", part.label)),
                        Some(judge) if judge != part.judge => {
                            problems.push(format!("{}: part carries the wrong judge", part.label));
                        }
                        Some(_) => {}
                    }
                }
                problems
            }
        }

        impl fmt::Display for Snapshot {
            fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
                for part in &self.parts {
                    match &part.content {
                        Ok(text) => writeln!(out, "[{}]\n{}", part.label, text.trim_end())?,
                        Err(why) => writeln!(out, "[{}]\n<<SNAPSHOT FAILED: {why}>>", part.label)?,
                    }
                }
                Ok(())
            }
        }

        #[derive(Debug)]
        pub(super) struct Verdict {
            pub(super) pass: bool,
            /// One line per part (PASS / FAIL and why), with the script's own
            /// diff for a changed part.
            pub(super) report: String,
        }

        /// A private directory for one comparison: created with `create_dir`
        /// (never shared, never reused), mode 0700, named by process id, a
        /// process-wide counter and the time, and removed when dropped — also on
        /// panic (unwinding runs `Drop`).
        pub(super) struct Scratch {
            path: PathBuf,
        }

        static NEXT_SCRATCH: AtomicU64 = AtomicU64::new(0);

        impl Scratch {
            pub(super) fn new() -> std::io::Result<Self> {
                Self::new_in(&std::env::temp_dir())
            }

            pub(super) fn new_in(parent: &std::path::Path) -> std::io::Result<Self> {
                use std::os::unix::fs::DirBuilderExt;
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                for _ in 0..64 {
                    let path = parent.join(format!(
                        "mkm-mgmt-compare-{}-{}-{nanos}",
                        std::process::id(),
                        NEXT_SCRATCH.fetch_add(1, Ordering::SeqCst)
                    ));
                    match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                        Ok(()) => return Ok(Self { path }),
                        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(error) => return Err(error),
                    }
                }
                Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "no unused scratch directory name",
                ))
            }

            pub(super) fn path(&self) -> &std::path::Path {
                &self.path
            }
        }

        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }

        /// The audited comparison of two snapshots.
        pub(super) fn compare(before: &Snapshot, after: &Snapshot) -> Verdict {
            compare_with(before, after, INTERPRETER, COMPARE_SH)
        }

        /// `compare_with` using `parent` for the scratch directory (the tests
        /// use an unusable one to prove that this is a FAIL).
        pub(super) fn compare_in(
            parent: &std::path::Path,
            before: &Snapshot,
            after: &Snapshot,
            interpreter: &str,
            script: &str,
        ) -> Verdict {
            compare_scratch(Scratch::new_in(parent), before, after, interpreter, script)
        }

        /// `compare` with the interpreter and the script text injectable (the
        /// tests use it to prove that a failing comparison is a FAIL).
        pub(super) fn compare_with(
            before: &Snapshot,
            after: &Snapshot,
            interpreter: &str,
            script: &str,
        ) -> Verdict {
            compare_scratch(Scratch::new(), before, after, interpreter, script)
        }

        fn compare_scratch(
            scratch: std::io::Result<Scratch>,
            before: &Snapshot,
            after: &Snapshot,
            interpreter: &str,
            script: &str,
        ) -> Verdict {
            let mut pass = true;
            let mut report = String::new();
            let mut fail = |report: &mut String, line: String| {
                pass = false;
                report.push_str(&line);
                report.push('\n');
            };
            // The shape of both sides is judged BEFORE anything is compared:
            // every required part exactly once, nothing else, the right judge.
            // An invalid snapshot is a FAIL even when both sides are the same
            // invalid snapshot (`part()` would silently use the first copy).
            let mut malformed = false;
            for side in [("before", before), ("after", after)] {
                for problem in side.1.problems() {
                    malformed = true;
                    let (label, what) = problem.split_once(": ").unwrap_or(("snapshot", &problem));
                    fail(
                        &mut report,
                        format!("{label}: FAIL {what} in the {} snapshot", side.0),
                    );
                }
            }
            if malformed {
                return Verdict {
                    pass: false,
                    report,
                };
            }
            for label in REQUIRED {
                let (Some(b), Some(a)) = (before.part(label), after.part(label)) else {
                    continue;
                };
                let (bt, at) = match (&b.content, &a.content) {
                    (Ok(bt), Ok(at)) => (bt, at),
                    (bc, ac) => {
                        fail(
                            &mut report,
                            format!(
                                "{label}: FAIL snapshot not captured (before: {}; after: {})",
                                bc.as_ref().err().map_or("ok", String::as_str),
                                ac.as_ref().err().map_or("ok", String::as_str)
                            ),
                        );
                        continue;
                    }
                };
                if b.judge != a.judge {
                    fail(
                        &mut report,
                        format!("{label}: FAIL the two snapshots judge this part differently"),
                    );
                    continue;
                }
                if b.judge == Judge::Exact {
                    if bt == at {
                        report.push_str(&format!("{label}: PASS identical\n"));
                    } else {
                        fail(
                            &mut report,
                            format!("{label}: FAIL changed\n  before: {bt:?}\n  after:  {at:?}"),
                        );
                    }
                    continue;
                }
                let scratch = match &scratch {
                    Ok(scratch) => scratch,
                    Err(error) => {
                        fail(
                            &mut report,
                            format!("{label}: FAIL cannot create a scratch directory: {error}"),
                        );
                        continue;
                    }
                };
                match judge_with_script(scratch, interpreter, script, label, bt, at) {
                    Ok(line) => report.push_str(&format!("{label}: PASS {line}\n")),
                    Err(why) => fail(&mut report, format!("{label}: FAIL {why}")),
                }
            }
            Verdict { pass, report }
        }

        /// Run the script on one part. `Ok` only for exit 0 with stdout exactly
        /// one of the script's two "stable" verdict lines and an empty stderr.
        fn judge_with_script(
            scratch: &Scratch,
            interpreter: &str,
            script: &str,
            label: &str,
            before: &str,
            after: &str,
        ) -> Result<String, String> {
            let script_path = scratch.path().join("mgmt-net-compare.sh");
            let before_path = scratch.path().join(format!("{label}.before"));
            let after_path = scratch.path().join(format!("{label}.after"));
            for (path, text) in [
                (&script_path, script),
                (&before_path, before),
                (&after_path, after),
            ] {
                std::fs::write(path, text)
                    .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
            }
            // Explicit program, arguments, working directory and environment.
            let output = Command::new(interpreter)
                .arg(&script_path)
                .arg(&before_path)
                .arg(&after_path)
                .current_dir(scratch.path())
                .env_clear()
                .env("PATH", CHILD_PATH)
                .env("TMPDIR", scratch.path())
                .env("LC_ALL", "C")
                .stdin(Stdio::null())
                .output()
                .map_err(|error| format!("cannot run the comparison ({interpreter}): {error}"))?;
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            let first = stdout.lines().next().unwrap_or("").to_string();
            match output.status.code() {
                // Exit 0 is not enough: stdout must be exactly one verdict
                // line and stderr must be empty (the shell driver's rule too).
                Some(0)
                    if stderr.is_empty()
                        && (stdout == format!("{VERDICT_IDENTICAL}\n")
                            || stdout == format!("{VERDICT_STABLE}\n")) =>
                {
                    Ok(first)
                }
                Some(0) => Err(format!(
                    "the comparison exited 0 without exactly one known verdict line \
                     (stdout {stdout:?}, stderr {stderr:?})"
                )),
                Some(1) => Err(format!("management network changed\n{}", stdout.trim_end())),
                Some(code) => Err(format!(
                    "comparison error (exit {code}): {}",
                    stderr.trim_end()
                )),
                None => Err(format!(
                    "comparison killed by a signal ({:?}): {}",
                    output.status,
                    stderr.trim_end()
                )),
            }
        }

        // ---- which lines belong to a device the lab itself created -------------
        //
        // MC-1 R3 (remaining findings): a device is scoped out of a snapshot only
        // when the lab's OWNERSHIP RECORD of it — written when the lab's own
        // create step succeeded: name, ifindex and MAC as the kernel reported
        // them — matches what this very capture shows. A name proves nothing
        // (`vh-uplink`; a device re-created under the lab's name), and neither
        // does "absent before the run". A recorded device that the capture shows
        // with another identity (ifindex or MAC), twice, or whose ifindex now
        // carries another name, is an ownership LOSS: the `link` part of the
        // capture FAILS (so the comparison cannot pass, whatever the other side
        // shows) and nothing at all is scoped out. A device the lab has no
        // record of is never scoped out.

        fn bare_name(token: &str) -> &str {
            let name = token.trim_end_matches(':');
            name.split('@').next().unwrap_or(name)
        }

        /// The interface index of an `ip -o addr` / `ip -o link` line.
        fn line_index(line: &str) -> Option<u32> {
            let index = line.split_whitespace().next()?.strip_suffix(':')?;
            if index.is_empty() || !index.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            index.parse().ok()
        }

        /// The device names a line of part `label` refers to (`ip -o addr`,
        /// `ip -o link`: the interface after `<index>:`; routes: every `dev`;
        /// rules: every `iif` / `oif`). Empty: the line names no device we can
        /// read, so it is never scoped out.
        pub(super) fn line_devices(label: &str, line: &str) -> Vec<String> {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            match label {
                "addr" | "link" => match tokens.as_slice() {
                    [_, name, ..] if line_index(line).is_some() => {
                        vec![bare_name(name).to_string()]
                    }
                    _ => Vec::new(),
                },
                "route4" | "route6" => tokens
                    .windows(2)
                    .filter(|pair| pair[0] == "dev")
                    .map(|pair| bare_name(pair[1]).to_string())
                    .collect(),
                "rule" => tokens
                    .windows(2)
                    .filter(|pair| matches!(pair[0], "iif" | "oif"))
                    .map(|pair| bare_name(pair[1]).to_string())
                    .collect(),
                _ => Vec::new(),
            }
        }

        /// A network device as `ip -o link show` (or `ip -d -o link show`)
        /// prints it: what the lab records when it creates one, and what a
        /// capture is checked against.
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub(super) struct LinkId {
            pub(super) name: String,
            pub(super) ifindex: u32,
            /// The `link/<type>` address ("" when the line shows none).
            pub(super) mac: String,
            /// `<name>@if<N>`: the peer's ifindex (in the peer's own netns).
            pub(super) peer: Option<u32>,
            /// `master <bridge>`.
            pub(super) master: Option<String>,
            /// The kind (`veth`, `bridge`, `dummy`, ...): only `-d` shows it.
            pub(super) kind: Option<String>,
        }

        /// One line of `ip [-d] -o link show`; `None` if it is not one.
        pub(super) fn link_id(line: &str) -> Option<LinkId> {
            let ifindex = line_index(line)?;
            let tokens: Vec<&str> = line.split_whitespace().collect();
            let token = tokens.get(1)?.strip_suffix(':')?;
            let (name, peer) = match token.split_once('@') {
                Some((name, peer)) => (name, peer.strip_prefix("if").and_then(|n| n.parse().ok())),
                None => (token, None),
            };
            if name.is_empty() {
                return None;
            }
            let after = |key: &str| {
                tokens
                    .windows(2)
                    .find(|pair| pair[0] == key)
                    .map(|pair| pair[1].to_string())
            };
            let mac = tokens
                .windows(2)
                .find(|pair| pair[0].starts_with("link/"))
                .map(|pair| pair[1].to_string())
                .unwrap_or_default();
            // `-d`: the kind follows `maxmtu <n>` (a device without one, such
            // as `lo`, shows `addrgenmode` there).
            let kind = tokens
                .iter()
                .position(|token| *token == "maxmtu")
                .and_then(|at| tokens.get(at + 2..))
                .and_then(|rest| rest.iter().find(|token| **token != "\\"))
                .filter(|token| **token != "addrgenmode")
                .map(|token| token.to_string());
            Some(LinkId {
                name: name.to_string(),
                ifindex,
                mac,
                peer,
                master: after("master"),
                kind,
            })
        }

        /// Which of the lab's `recorded` devices this `ip -o link show` text
        /// shows with exactly their recorded identity (name -> ifindex). A
        /// recorded device the text does not show at all is simply absent
        /// (nothing of it to scope out). `Err` is an ownership LOSS: a recorded
        /// device shown with another ifindex or MAC, shown twice, or its
        /// recorded ifindex carrying another name.
        pub(super) fn verify_owned(
            recorded: &[LinkId],
            link_text: &str,
        ) -> Result<BTreeMap<String, u32>, String> {
            let shown: Vec<LinkId> = link_text.lines().filter_map(link_id).collect();
            let mut verified = BTreeMap::new();
            let mut lost = Vec::new();
            for record in recorded {
                let named: Vec<&LinkId> = shown.iter().filter(|d| d.name == record.name).collect();
                match named.as_slice() {
                    [] => {}
                    [device] if device.ifindex == record.ifindex && device.mac == record.mac => {
                        verified.insert(record.name.clone(), record.ifindex);
                    }
                    [device] => lost.push(format!(
                        "{} is shown as ifindex {} MAC {:?}, but the lab created ifindex {} MAC {:?}",
                        record.name, device.ifindex, device.mac, record.ifindex, record.mac
                    )),
                    many => lost.push(format!("{} is shown {} times", record.name, many.len())),
                }
                for other in shown
                    .iter()
                    .filter(|d| d.ifindex == record.ifindex && d.name != record.name)
                {
                    lost.push(format!(
                        "the lab's {} (ifindex {}) is shown under the name {}",
                        record.name, record.ifindex, other.name
                    ));
                }
            }
            if lost.is_empty() {
                Ok(verified)
            } else {
                Err(lost.join("; "))
            }
        }

        /// `text` without the lines of the lab's `verified` devices (name ->
        /// ifindex, from `verify_owned` on the same capture). A line goes only
        /// if it names at least one device and EVERY device it names is
        /// verified — and an `addr` / `link` line only if its interface index
        /// is the verified one too. Everything else stays and is compared.
        pub(super) fn scope_out(
            label: &str,
            text: &str,
            verified: &BTreeMap<String, u32>,
        ) -> String {
            text.lines()
                .filter(|line| !is_the_labs(label, line, verified))
                .map(|line| format!("{line}\n"))
                .collect()
        }

        fn is_the_labs(label: &str, line: &str, verified: &BTreeMap<String, u32>) -> bool {
            let devices = line_devices(label, line);
            if devices.is_empty() || !devices.iter().all(|device| verified.contains_key(device)) {
                return false;
            }
            match label {
                "addr" | "link" => line_index(line) == verified.get(&devices[0]).copied(),
                _ => true,
            }
        }

        /// The five `ip` parts of one capture, the lab's devices scoped out.
        /// `owned`: the lab's ownership records (empty: nothing is scoped out
        /// and `link_first` is not needed). `link_first`: the `link` part taken
        /// BEFORE the other four, `texts` holding the one taken after them; a
        /// recorded device must show the same recorded identity in both (a
        /// device replaced while the parts were taken cannot slip through).
        /// Any ownership loss — or a link capture that failed — makes the
        /// `link` part a FAILED capture carrying the reason, and scopes out
        /// nothing at all.
        pub(super) fn scoped_ip_parts(
            owned: &[LinkId],
            link_first: Option<Result<String, String>>,
            texts: Vec<(&'static str, Result<String, String>)>,
        ) -> Vec<Part> {
            let ownership: Result<BTreeMap<String, u32>, String> = if owned.is_empty() {
                Ok(BTreeMap::new())
            } else {
                let last = texts
                    .iter()
                    .find(|(label, _)| *label == "link")
                    .map(|(_, content)| content.clone());
                match (link_first, last) {
                    (Some(Ok(first)), Some(Ok(last))) => {
                        match (verify_owned(owned, &first), verify_owned(owned, &last)) {
                            (Ok(a), Ok(b)) if a == b => Ok(a),
                            (Ok(_), Ok(_)) => Err(
                                "the lab's devices are not the same in the two link captures"
                                    .to_string(),
                            ),
                            (Err(why), _) | (_, Err(why)) => Err(why),
                        }
                    }
                    (Some(Err(why)), _) | (_, Some(Err(why))) => {
                        Err(format!("a link capture failed: {why}"))
                    }
                    _ => Err("a link capture is missing".to_string()),
                }
            };
            texts
                .into_iter()
                .map(|(label, content)| Part {
                    label,
                    judge: Judge::Script,
                    content: match &ownership {
                        Err(why) if label == "link" => Err(format!(
                            "lab device ownership NOT shown by this capture: {why} \
                             (nothing was scoped out)"
                        )),
                        Err(_) => content,
                        Ok(verified) => content.map(|text| scope_out(label, &text, verified)),
                    },
                })
                .collect()
        }

        // ---- tests (no root, no network access: stored snapshots only) ----

        macro_rules! fixture {
            ($name:literal) => {
                include_str!(concat!("../tests/lab/vf/fixtures/mgmt-net/", $name))
            };
        }
        /// Stored `ip` output captured by the Phase 14.12 independent audit
        /// (`real-*`) and the single-change variants derived from it.
        const REAL_ADDR_BEFORE: &str = fixture!("real-addr-before.txt");
        const REAL_ADDR_AFTER: &str = fixture!("real-addr-after.txt");
        const REAL_ROUTE_BEFORE: &str = fixture!("real-route-before.txt");
        const REAL_ROUTE_AFTER: &str = fixture!("real-route-after.txt");
        const DRIVER_ROUTE6: &str = fixture!("driver-route6.txt");
        const DRIVER_RULE: &str = fixture!("driver-rule.txt");
        const DRIVER_LINK: &str = fixture!("driver-link.txt");
        const RA_ROUTE_1790: &str =
            "default via fe80::1 dev ens4 proto ra metric 1024 expires 1790sec pref medium\n";

        #[derive(Clone)]
        struct Net {
            addr: String,
            route4: String,
            route6: String,
            rule: String,
            link: String,
            ip_forward: String,
            listen: String,
        }

        fn base() -> Net {
            Net {
                addr: REAL_ADDR_BEFORE.to_string(),
                route4: REAL_ROUTE_BEFORE.to_string(),
                route6: DRIVER_ROUTE6.to_string(),
                rule: DRIVER_RULE.to_string(),
                link: DRIVER_LINK.to_string(),
                ip_forward: "0".to_string(),
                listen: "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*".to_string(),
            }
        }

        fn snapshot(net: &Net) -> Snapshot {
            let ip = |label, text: &String| Part {
                label,
                judge: Judge::Script,
                content: Ok(text.clone()),
            };
            let exact = |label, text: &String| Part {
                label,
                judge: Judge::Exact,
                content: Ok(text.clone()),
            };
            Snapshot {
                parts: vec![
                    ip("addr", &net.addr),
                    ip("route4", &net.route4),
                    ip("route6", &net.route6),
                    ip("rule", &net.rule),
                    ip("link", &net.link),
                    exact("ip_forward", &net.ip_forward),
                    exact("listen", &net.listen),
                ],
            }
        }

        struct Case {
            name: &'static str,
            /// The expected verdict for the whole snapshot.
            pass: bool,
            /// The change is only in a part the script does not see
            /// (`ip_forward` / listening sockets).
            exact_only: bool,
            before: Net,
            after: Net,
        }

        fn case(name: &'static str, pass: bool, edit: impl FnOnce(&mut Net, &mut Net)) -> Case {
            let (mut before, mut after) = (base(), base());
            edit(&mut before, &mut after);
            Case {
                name,
                pass,
                exact_only: false,
                before,
                after,
            }
        }

        /// The required cases 1-13 (and the rest of the audited script's own
        /// list) as before / after pairs.
        fn cases() -> Vec<Case> {
            let lease = "valid_lft 2159sec preferred_lft 2159sec";
            vec![
                case("01 identical", true, |_, _| {}),
                case("02 lease seconds only (addr + route)", true, |_, a| {
                    a.addr = REAL_ADDR_AFTER.to_string();
                    a.route4 = REAL_ROUTE_AFTER.to_string();
                }),
                case("03 valid_lft 0sec", false, |_, a| {
                    a.addr = a
                        .addr
                        .replace(lease, "valid_lft 0sec preferred_lft 2159sec");
                }),
                case("04 preferred_lft 0sec", false, |_, a| {
                    a.addr = a
                        .addr
                        .replace(lease, "valid_lft 2159sec preferred_lft 0sec");
                }),
                case("05 forever", false, |_, a| {
                    a.addr = a
                        .addr
                        .replace(lease, "valid_lft forever preferred_lft forever");
                }),
                case("06a route expires seconds only", true, |b, a| {
                    b.route6 = RA_ROUTE_1790.to_string();
                    a.route6 = RA_ROUTE_1790.replace("1790", "1700");
                }),
                case("06b route expires 0sec", false, |b, a| {
                    b.route6 = RA_ROUTE_1790.to_string();
                    a.route6 = RA_ROUTE_1790.replace("1790", "0");
                }),
                case("06c route expiry removed (became static)", false, |b, a| {
                    b.route6 = RA_ROUTE_1790.to_string();
                    a.route6 = RA_ROUTE_1790.replace(" expires 1790sec", "");
                }),
                case("07 IP changed", false, |_, a| {
                    a.addr = a.addr.replace("10.146.0.21/32", "10.146.0.22/32");
                }),
                case("08 prefix changed", false, |_, a| {
                    a.addr = a.addr.replace("10.146.0.21/32", "10.146.0.21/24");
                }),
                case("09 gateway changed", false, |_, a| {
                    a.route4 = a.route4.replace("via 10.146.0.1", "via 10.146.0.2");
                }),
                case("10 route metric changed", false, |_, a| {
                    a.route4 = a.route4.replace("metric 100", "metric 300");
                }),
                case("11a interface renamed (addr)", false, |_, a| {
                    a.addr = a.addr.replace("ens4", "ens5");
                }),
                case("11b interface renamed (link)", false, |_, a| {
                    a.link = a.link.replace("ens4", "ens5");
                }),
                case("12 policy rule added", false, |_, a| {
                    a.rule.push_str("100:\tfrom 10.0.0.0/8 lookup 100\n");
                }),
                case("13 link state changed", false, |_, a| {
                    a.link = a.link.replace("state UP", "state DOWN");
                }),
                case("14a address metric changed", false, |_, a| {
                    a.addr = a.addr.replace("metric 100", "metric 200");
                }),
                case("14b default route removed", false, |_, a| a.route4.clear()),
                case("14c route device changed", false, |_, a| {
                    a.route4 = a.route4.replace("dev ens4", "dev ens5");
                }),
                case("14d dynamic flag lost", false, |_, a| {
                    a.addr = a.addr.replace("scope global dynamic", "scope global");
                }),
                case("14e lease seconds AND IP changed", false, |_, a| {
                    a.addr = REAL_ADDR_AFTER.replace("10.146.0.21/32", "10.146.0.22/32");
                }),
                case("14f IPv6 route added", false, |_, a| {
                    a.route6
                        .push_str("default via fe80::1 dev ens4 proto ra metric 1024\n");
                }),
                case("14g link MTU changed", false, |_, a| {
                    a.link = a.link.replace("mtu 1460", "mtu 1500");
                }),
                Case {
                    exact_only: true,
                    ..case("15a ip_forward changed", false, |_, a| {
                        a.ip_forward = "1".to_string();
                    })
                },
                Case {
                    exact_only: true,
                    ..case("15b a listener appeared", false, |_, a| {
                        a.listen.push_str("\nLISTEN 0 128 0.0.0.0:2222 0.0.0.0:*");
                    })
                },
                Case {
                    exact_only: true,
                    ..case("15c a listener disappeared", false, |_, a| a.listen.clear())
                },
            ]
        }

        /// The audited FILE (not the embedded copy) run directly on one pair.
        fn shell_exit(scratch: &Scratch, label: &str, before: &str, after: &str) -> i32 {
            let (b, a) = (
                scratch.path().join(format!("{label}.sb")),
                scratch.path().join(format!("{label}.sa")),
            );
            std::fs::write(&b, before).unwrap();
            std::fs::write(&a, after).unwrap();
            let status = Command::new("/bin/sh")
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/lab/vf/mgmt-net-compare.sh"
                ))
                .arg(&b)
                .arg(&a)
                .env_clear()
                .env("PATH", CHILD_PATH)
                .env("TMPDIR", scratch.path())
                .stdin(Stdio::null())
                .output()
                .unwrap()
                .status;
            status.code().unwrap_or(-1)
        }

        /// The embedded script IS the audited file, byte for byte.
        #[test]
        fn mgmt_net_embedded_script_is_the_audited_file() {
            let on_disk = std::fs::read_to_string(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/lab/vf/mgmt-net-compare.sh"
            ))
            .unwrap();
            assert_eq!(COMPARE_SH, on_disk);
        }

        /// Cases 1-13 (and more): the Rust lab's verdict, the audited script run
        /// directly on the same text, and the expectation all agree.
        #[test]
        fn mgmt_net_rust_verdict_matches_the_audited_script_on_every_case() {
            let scratch = Scratch::new().unwrap();
            let mut mismatches = Vec::new();
            for case in cases() {
                let (before, after) = (snapshot(&case.before), snapshot(&case.after));
                let verdict = compare(&before, &after);
                let mut shell_pass = true;
                for (label, b, a) in [
                    ("addr", &case.before.addr, &case.after.addr),
                    ("route4", &case.before.route4, &case.after.route4),
                    ("route6", &case.before.route6, &case.after.route6),
                    ("rule", &case.before.rule, &case.after.rule),
                    ("link", &case.before.link, &case.after.link),
                ] {
                    shell_pass &= shell_exit(&scratch, label, b, a) == 0;
                }
                let shell_expected = if case.exact_only { true } else { case.pass };
                if verdict.pass != case.pass
                    || shell_pass != shell_expected
                    || (!case.exact_only && verdict.pass != shell_pass)
                {
                    mismatches.push(format!(
                        "{}: expected pass={}, rust={}, shell={}\n{}",
                        case.name, case.pass, verdict.pass, shell_pass, verdict.report
                    ));
                }
            }
            assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
        }

        /// Case 2 / 6a in words: only the finite seconds are volatile, and the
        /// verdict says which script verdict it was.
        #[test]
        fn mgmt_net_lease_seconds_only_is_stable_and_reported_as_such() {
            let mut after = base();
            after.addr = REAL_ADDR_AFTER.to_string();
            let verdict = compare(&snapshot(&base()), &snapshot(&after));
            assert!(verdict.pass, "{}", verdict.report);
            assert!(
                verdict
                    .report
                    .contains("addr: PASS mgmt-net-compare: STABLE-IDENTICAL"),
                "{}",
                verdict.report
            );
            assert!(
                verdict
                    .report
                    .contains("route4: PASS mgmt-net-compare: IDENTICAL")
            );
        }

        /// A changed part is named with the script's own diff.
        #[test]
        fn mgmt_net_changed_part_is_named_with_the_scripts_diff() {
            let mut after = base();
            after.addr = after.addr.replace("10.146.0.21/32", "10.146.0.22/32");
            let verdict = compare(&snapshot(&base()), &snapshot(&after));
            assert!(!verdict.pass);
            assert!(
                verdict
                    .report
                    .contains("addr: FAIL management network changed")
            );
            assert!(verdict.report.contains("mgmt-net-compare: CHANGED"));
            assert!(verdict.report.contains("10.146.0.22/32"));
            assert!(
                verdict.report.contains("route4: PASS"),
                "other parts judged too"
            );
        }

        /// Case 14: a snapshot that is missing or was not captured is a FAIL —
        /// even when both sides failed identically (an empty text equal to
        /// itself must never read as "unchanged").
        #[test]
        fn mgmt_net_snapshot_failure_or_absence_is_a_fail() {
            // captured on neither side
            for label in REQUIRED {
                let mut broken = snapshot(&base());
                for part in &mut broken.parts {
                    if part.label == label {
                        part.content = Err("ip: command failed".to_string());
                    }
                }
                let ok = snapshot(&base());
                for (name, b, a) in [
                    ("before failed", &broken, &ok),
                    ("after failed", &ok, &broken),
                    ("both failed", &broken, &broken),
                ] {
                    let verdict = compare(b, a);
                    assert!(!verdict.pass, "{label} {name}: {}", verdict.report);
                    assert!(
                        verdict
                            .report
                            .contains(&format!("{label}: FAIL snapshot not captured"))
                    );
                }
            }
            // a part absent from one side, from both, an extra part, no parts
            let full = snapshot(&base());
            for label in REQUIRED {
                let mut missing = full.clone();
                missing.parts.retain(|part| part.label != label);
                assert!(!compare(&full, &missing).pass, "{label} missing after");
                assert!(!compare(&missing, &full).pass, "{label} missing before");
                assert!(!compare(&missing, &missing).pass, "{label} missing on both");
            }
            let mut extra = full.clone();
            extra.parts.push(Part {
                label: "surprise",
                judge: Judge::Exact,
                content: Ok(String::new()),
            });
            assert!(!compare(&full, &extra).pass);
            assert!(!compare(&Snapshot::default(), &Snapshot::default()).pass);
        }

        /// Case 15: a comparison that cannot run, fails, is killed, exits with
        /// anything but 0 / 1, or exits 0 without one of the script's "stable"
        /// verdicts is a FAIL.
        #[test]
        fn mgmt_net_a_failing_comparison_is_a_fail() {
            let (a, b) = (snapshot(&base()), snapshot(&base()));
            assert!(compare(&a, &b).pass, "control: identical snapshots pass");
            for (what, interpreter, script) in [
                ("exit 2", "/bin/sh", "exit 2\n"),
                ("exit 126", "/bin/sh", "exit 126\n"),
                ("exit 127", "/bin/sh", "exit 127\n"),
                ("exit 1, no output", "/bin/sh", "exit 1\n"),
                ("killed by a signal", "/bin/sh", "kill -9 $$\n"),
                ("exit 0, empty output", "/bin/sh", "exit 0\n"),
                (
                    "exit 0, unrecognised output",
                    "/bin/sh",
                    "echo fine\nexit 0\n",
                ),
                (
                    "exit 0 with CHANGED output",
                    "/bin/sh",
                    "echo 'mgmt-net-compare: CHANGED'\nexit 0\n",
                ),
                ("syntax error", "/bin/sh", "if then\n"),
                ("interpreter missing", "/nonexistent/sh", "exit 0\n"),
            ] {
                let verdict = compare_with(&a, &b, interpreter, script);
                assert!(!verdict.pass, "{what} must be a FAIL:\n{}", verdict.report);
                for label in ["addr", "route4", "route6", "rule", "link"] {
                    assert!(
                        verdict.report.contains(&format!("{label}: FAIL")),
                        "{what}: {label}\n{}",
                        verdict.report
                    );
                }
            }
        }

        /// The comparison is run with absolute paths, a private working
        /// directory, a fixed environment, and is the only thing that decides:
        /// a substitute that checks all of that and says "IDENTICAL" passes, so
        /// the failures above are really the comparison's.
        #[test]
        fn mgmt_net_comparison_is_run_explicitly() {
            let script = r#"
case "$1" in /*) ;; *) exit 3 ;; esac
case "$2" in /*) ;; *) exit 3 ;; esac
[ -r "$1" ] && [ -r "$2" ] || exit 3
[ "$#" -eq 2 ] || exit 3
case "$TMPDIR" in *mkm-mgmt-compare-*) ;; *) exit 3 ;; esac
[ "$(cd "$TMPDIR" && pwd -P)" = "$(pwd -P)" ] || exit 3
[ "$PATH" = "/usr/sbin:/usr/bin:/sbin:/bin" ] || exit 3
[ "$LC_ALL" = "C" ] || exit 3
[ -z "$HOME" ] || exit 3
echo "mgmt-net-compare: IDENTICAL"
exit 0
"#;
            let verdict = compare_with(&snapshot(&base()), &snapshot(&base()), "/bin/sh", script);
            assert!(verdict.pass, "{}", verdict.report);
        }

        /// The scratch directory: private, unique across threads, removed on
        /// normal exit and when the test panics.
        #[test]
        fn mgmt_net_scratch_is_private_unique_and_always_removed() {
            use std::os::unix::fs::PermissionsExt;
            let threads: Vec<_> = (0..8)
                .map(|_| std::thread::spawn(|| Scratch::new().unwrap().path().to_path_buf()))
                .collect();
            let paths: std::collections::BTreeSet<_> =
                threads.into_iter().map(|t| t.join().unwrap()).collect();
            assert_eq!(paths.len(), 8, "concurrent scratch directories collided");
            assert!(
                paths.iter().all(|path| !path.exists()),
                "dropped => removed"
            );

            let scratch = Scratch::new().unwrap();
            let mode = std::fs::metadata(scratch.path())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700);
            let kept = scratch.path().to_path_buf();
            std::fs::write(kept.join("leftover"), "x").unwrap();
            drop(scratch);
            assert!(!kept.exists(), "removed with its contents");

            let seen = std::cell::RefCell::new(None);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let scratch = Scratch::new().unwrap();
                *seen.borrow_mut() = Some(scratch.path().to_path_buf());
                std::fs::write(scratch.path().join("x"), "y").unwrap();
                panic!("expected: the scratch must still be removed");
            }));
            assert!(result.is_err());
            let path = seen.borrow().clone().unwrap();
            assert!(!path.exists(), "removed on panic");
        }

        /// No usable scratch directory => the comparison cannot run => FAIL
        /// (never "nothing to compare, so nothing changed").
        #[test]
        fn mgmt_net_scratch_creation_failure_is_a_fail() {
            let (a, b) = (snapshot(&base()), snapshot(&base()));
            let verdict = compare_in(
                std::path::Path::new("/nonexistent/parent"),
                &a,
                &b,
                "/bin/sh",
                COMPARE_SH,
            );
            assert!(!verdict.pass, "{}", verdict.report);
            for label in ["addr", "route4", "route6", "rule", "link"] {
                assert!(
                    verdict
                        .report
                        .contains(&format!("{label}: FAIL cannot create a scratch directory")),
                    "{}",
                    verdict.report
                );
            }
            // the exact parts are still judged (and pass) without a scratch
            assert!(verdict.report.contains("ip_forward: PASS"));
            assert!(compare(&a, &b).pass, "control");
        }

        /// A comparison leaves nothing behind: a substitute script records the
        /// scratch directory it ran in (outside that directory) and the
        /// directory is gone afterwards, whether the comparison passed or failed.
        #[test]
        fn mgmt_net_compare_removes_its_scratch() {
            let outside = Scratch::new().unwrap();
            for (what, tail) in [
                ("passing", "echo 'mgmt-net-compare: IDENTICAL'\nexit 0\n"),
                ("failing", "exit 2\n"),
            ] {
                let record = outside.path().join(format!("{what}.dir"));
                let script = format!("printf '%s' \"$TMPDIR\" > '{}'\n{tail}", record.display());
                let verdict =
                    compare_with(&snapshot(&base()), &snapshot(&base()), "/bin/sh", &script);
                assert_eq!(verdict.pass, what == "passing", "{}", verdict.report);
                let ran_in = std::fs::read_to_string(&record).unwrap();
                assert!(ran_in.contains("mkm-mgmt-compare-"), "{ran_in}");
                assert!(
                    !std::path::Path::new(&ran_in).exists(),
                    "{what}: scratch {ran_in} left behind"
                );
            }
        }

        // ---- MC-1 five-findings remediation tests (F-MC-C0/S1/R1/R3) ----

        fn driver_path() -> &'static str {
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/lab/vf/closeout-lab.sh")
        }

        /// The two verdict lines are the script's, the shell driver's and this
        /// module's: one contract, three places.
        #[test]
        fn mgmt_net_verdict_lines_are_the_scripts_and_the_drivers() {
            assert!(COMPARE_SH.contains(&format!("echo \"{VERDICT_IDENTICAL}\"")));
            assert!(COMPARE_SH.contains(&format!("echo \"{VERDICT_STABLE}\"")));
            let driver = include_str!("../tests/lab/vf/closeout-lab.sh");
            assert!(driver.contains(&format!("MGMT_VERDICT_IDENTICAL=\"{VERDICT_IDENTICAL}\"")));
            assert!(driver.contains(&format!("MGMT_VERDICT_STABLE=\"{VERDICT_STABLE}\"")));
            // the only stdout lines the script prints are the two verdicts and
            // CHANGED; every other message goes to stderr
            let stdout_lines: Vec<&str> = COMPARE_SH
                .lines()
                .filter(|line| line.contains("echo \"mgmt-net-compare: "))
                .filter(|line| !line.contains(">&2"))
                .collect();
            assert_eq!(stdout_lines.len(), 3, "{stdout_lines:?}");
        }

        /// F-MC-S1 (Rust side of the shared contract): exit 0 passes only with
        /// stdout EXACTLY one verdict line and an empty stderr.
        #[test]
        fn mgmt_net_exit_zero_needs_exactly_one_known_verdict_line() {
            let (a, b) = (snapshot(&base()), snapshot(&base()));
            let run = |body: &str| compare_with(&a, &b, "/bin/sh", &format!("{body}\nexit 0\n"));
            for (what, body) in [
                ("unknown text", "echo 'all good'".to_string()),
                ("empty output", "true".to_string()),
                (
                    "extra line",
                    format!("echo '{VERDICT_IDENTICAL}'; echo extra"),
                ),
                (
                    "trailing blank line",
                    format!("echo '{VERDICT_IDENTICAL}'; echo"),
                ),
                (
                    "verdict twice",
                    format!("echo '{VERDICT_IDENTICAL}'; echo '{VERDICT_IDENTICAL}'"),
                ),
                (
                    "failing verdict",
                    "echo 'mgmt-net-compare: CHANGED'".to_string(),
                ),
                (
                    "no final newline",
                    format!("printf '%s' '{VERDICT_IDENTICAL}'"),
                ),
                ("trailing space", format!("echo '{VERDICT_IDENTICAL} '")),
                ("leading space", format!("echo ' {VERDICT_IDENTICAL}'")),
                (
                    "short STABLE line",
                    "echo 'mgmt-net-compare: STABLE-IDENTICAL'".to_string(),
                ),
                (
                    "padded STABLE line",
                    format!("echo '{VERDICT_STABLE} and more'"),
                ),
                (
                    "other case",
                    "echo 'mgmt-net-compare: identical'".to_string(),
                ),
                (
                    "stderr noise",
                    format!("echo '{VERDICT_IDENTICAL}'; echo warning >&2"),
                ),
            ] {
                let verdict = run(&body);
                assert!(!verdict.pass, "{what} must be a FAIL:\n{}", verdict.report);
                for label in ["addr", "route4", "route6", "rule", "link"] {
                    assert!(
                        verdict.report.contains(&format!("{label}: FAIL")),
                        "{what}: {label}\n{}",
                        verdict.report
                    );
                }
            }
            for body in [
                format!("echo '{VERDICT_IDENTICAL}'"),
                format!("echo '{VERDICT_STABLE}'"),
            ] {
                let verdict = run(&body);
                assert!(verdict.pass, "{body}: {}", verdict.report);
            }
            // exit 1 / 2 / 126 / 127 after a success line, and a signal after one
            for tail in ["exit 1", "exit 2", "exit 126", "exit 127", "kill -9 $$"] {
                let verdict = compare_with(
                    &a,
                    &b,
                    "/bin/sh",
                    &format!("echo '{VERDICT_IDENTICAL}'\n{tail}\n"),
                );
                assert!(!verdict.pass, "success line + {tail}:\n{}", verdict.report);
            }
            // one unknown part of five fails the whole snapshot and is named
            let script = format!(
                "case \"$1\" in */rule.before) echo odd ;; *) echo '{VERDICT_IDENTICAL}' ;; esac\nexit 0\n"
            );
            let verdict = compare_with(&a, &b, "/bin/sh", &script);
            assert!(!verdict.pass);
            assert!(verdict.report.contains("rule: FAIL"), "{}", verdict.report);
            assert!(verdict.report.contains("addr: PASS"), "{}", verdict.report);
        }

        /// F-MC-C0 through the Rust lab: the REAL (embedded) script with a
        /// failing normalisation tool is a FAIL on every `ip` part, also when
        /// both snapshots are identical; never an "unchanged" PASS.
        #[test]
        fn mgmt_net_a_failing_normalisation_is_a_fail() {
            let outside = Scratch::new().unwrap();
            let mut changed = base();
            changed.addr = changed.addr.replace("10.146.0.21/32", "10.146.0.22/32");
            let first_stage_fails = "case \"$1\" in -E) /usr/bin/sed \"$@\"; exit 2 ;; esac\nexec /usr/bin/sed \"$@\"\n";
            let blank_stage_fails = "case \"$*\" in *'/^$/d'*) /usr/bin/sed \"$@\"; exit 2 ;; esac\nexec /usr/bin/sed \"$@\"\n";
            for (n, (tool, body)) in [
                ("sort", "exit 2\n"),
                ("sed", "exit 2\n"),
                ("sort", "exit 0\n"), // silently empty
                ("sed", "exit 0\n"),  // silently empty
                ("diff", "exit 2\n"),
                ("grep", "exit 2\n"),
                // the tool does its work and only its exit status reports the failure
                ("sort", "/usr/bin/sort \"$@\"\nexit 2\n"),
                ("grep", "/usr/bin/grep \"$@\"\nexit 2\n"),
                ("diff", "/usr/bin/diff \"$@\"\nexit 2\n"),
                ("sed", first_stage_fails),
                ("sed", blank_stage_fails),
            ]
            .into_iter()
            .enumerate()
            {
                let bin = outside.path().join(format!("bin-{n}-{tool}"));
                std::fs::create_dir_all(&bin).unwrap();
                write_executable(&bin.join(tool), &format!("#!/bin/sh\n{body}"));
                let script = format!(
                    "PATH='{}':\"$PATH\"\nexport PATH\n{COMPARE_SH}",
                    bin.display()
                );
                for (what, after) in [("IP changed", changed.clone()), ("identical", base())] {
                    let verdict =
                        compare_with(&snapshot(&base()), &snapshot(&after), "/bin/sh", &script);
                    assert!(
                        !verdict.pass,
                        "{tool} {body:?} / {what}: must be a FAIL\n{}",
                        verdict.report
                    );
                    assert!(
                        !verdict.report.contains("addr: PASS"),
                        "{tool} {body:?} / {what}\n{}",
                        verdict.report
                    );
                }
            }
            // control: no sabotage, IP changed => the script reports the change
            let verdict = compare(&snapshot(&base()), &snapshot(&changed));
            assert!(
                verdict
                    .report
                    .contains("addr: FAIL management network changed"),
                "{}",
                verdict.report
            );
        }

        /// F-MC-R1: the shape of a snapshot is part of the contract.
        #[test]
        fn mgmt_net_snapshot_shape_is_validated_before_comparing() {
            let good = snapshot(&base());
            assert!(good.problems().is_empty());
            assert!(compare(&good, &good).pass, "control");
            // a second `addr` with different content (the audit's counter-example)
            let mut duplicated = good.clone();
            duplicated.parts.push(Part {
                label: "addr",
                judge: Judge::Script,
                content: Ok("9: evil    inet 6.6.6.6/32 scope global evil\n".to_string()),
            });
            let verdict = compare(&good, &duplicated);
            assert!(!verdict.pass, "{}", verdict.report);
            assert!(
                verdict
                    .report
                    .contains("addr: FAIL duplicate part (2 copies) in the after snapshot"),
                "{}",
                verdict.report
            );
            // refused before anything is compared: no part was judged
            assert!(
                !verdict.report.contains("PASS"),
                "a malformed snapshot must not reach the comparison:\n{}",
                verdict.report
            );
            // the same invalid snapshot on both sides is still invalid
            assert!(!compare(&duplicated, &duplicated).pass);
            assert!(!compare(&duplicated, &good).pass);
            // every required label, duplicated with the SAME or other content
            for label in REQUIRED {
                let original = good.part(label).unwrap().clone();
                for text in [original.content.clone().unwrap(), "x\n".to_string()] {
                    let mut twice = good.clone();
                    twice.parts.push(Part {
                        content: Ok(text),
                        ..original.clone()
                    });
                    assert!(!compare(&good, &twice).pass, "{label} duplicated");
                    assert!(!compare(&twice, &twice).pass, "{label} duplicated on both");
                }
            }
            // an unknown label, with either judge
            for judge in [Judge::Script, Judge::Exact] {
                let mut unknown = good.clone();
                unknown.parts.push(Part {
                    label: "surprise",
                    judge,
                    content: Ok(String::new()),
                });
                let verdict = compare(&good, &unknown);
                assert!(!verdict.pass);
                assert!(
                    verdict.report.contains("surprise: FAIL unexpected part"),
                    "{}",
                    verdict.report
                );
                assert!(!compare(&unknown, &unknown).pass);
            }
            // missing parts (one at a time) and no parts at all
            for label in REQUIRED {
                let mut missing = good.clone();
                missing.parts.retain(|part| part.label != label);
                let verdict = compare(&good, &missing);
                assert!(!verdict.pass);
                assert!(
                    verdict
                        .report
                        .contains(&format!("{label}: FAIL part missing")),
                    "{}",
                    verdict.report
                );
                assert!(!compare(&missing, &missing).pass);
            }
            assert!(!compare(&Snapshot::default(), &Snapshot::default()).pass);
            // too few and too many parts, by count
            let mut fewer = good.clone();
            fewer.parts.truncate(REQUIRED.len() - 1);
            assert!(!compare(&fewer, &fewer).pass);
            let mut more = good.clone();
            more.parts.extend(good.parts.clone());
            assert!(!compare(&more, &more).pass);
            // a required label carrying the wrong judge (an `ip` part judged by
            // plain equality would bypass the audited script)
            let mut wrong = good.clone();
            wrong.parts[0].judge = Judge::Exact;
            let verdict = compare(&good, &wrong);
            assert!(!verdict.pass);
            assert!(
                verdict.report.contains("part carries the wrong judge"),
                "{}",
                verdict.report
            );
            // ORDER is not a contract: the comparison looks parts up by label
            let mut reordered = good.clone();
            reordered.parts.reverse();
            assert!(reordered.problems().is_empty());
            assert!(compare(&good, &reordered).pass);
            assert!(compare(&reordered, &good).pass);
        }

        // ---- F-MC-R3 / F-AUD-R3-IDENTITY: only the lab's RECORDED devices, ----
        // ---- shown with their recorded identity, are scoped out           ----

        const LAB_ADDR: &str = "5: br-mkm    inet6 fe80::1/64 scope link \\       valid_lft forever preferred_lft forever\n6: vh-node-a    inet6 fe80::2/64 scope link \\       valid_lft forever preferred_lft forever\n";
        const LAB_LINK: &str = "5: br-mkm: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP\\    link/ether aa:bb:cc:dd:ee:01 brd ff:ff:ff:ff:ff:ff\n6: vh-node-a@if7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-mkm state UP\\    link/ether aa:bb:cc:dd:ee:02 brd ff:ff:ff:ff:ff:ff link-netns node-a\n";

        /// The lab's ownership records of the two devices in `LAB_LINK`.
        fn lab_records() -> Vec<LinkId> {
            LAB_LINK.lines().filter_map(link_id).collect()
        }

        fn verified(pairs: &[(&str, u32)]) -> BTreeMap<String, u32> {
            pairs
                .iter()
                .map(|(name, index)| (name.to_string(), *index))
                .collect()
        }

        /// A capture the way `capture_mgmt_snapshot` builds it: the `link` part
        /// taken twice (`first_link` before the other four, `net.link` after),
        /// the lab's `records` scoped out, `ip_forward` / `listen` as is.
        fn capture(net: &Net, records: &[LinkId], first_link: &str) -> Snapshot {
            let mut parts = scoped_ip_parts(
                records,
                (!records.is_empty()).then(|| Ok(first_link.to_string())),
                vec![
                    ("addr", Ok(net.addr.clone())),
                    ("route4", Ok(net.route4.clone())),
                    ("route6", Ok(net.route6.clone())),
                    ("rule", Ok(net.rule.clone())),
                    ("link", Ok(net.link.clone())),
                ],
            );
            for (label, text) in [("ip_forward", &net.ip_forward), ("listen", &net.listen)] {
                parts.push(Part {
                    label,
                    judge: Judge::Exact,
                    content: Ok(text.clone()),
                });
            }
            Snapshot { parts }
        }

        fn part_of<'a>(snapshot: &'a Snapshot, label: &str) -> &'a Result<String, String> {
            &snapshot
                .parts
                .iter()
                .find(|part| part.label == label)
                .expect("part")
                .content
        }

        /// Real `ip -d -o link show` lines (lab VM, inside an isolated sandbox
        /// netns: bridge with a MAC set at creation, veth whose peer is in the
        /// lab netns, that peer seen from inside, `lo`, a dummy).
        const REAL_D_BRIDGE: &str = "2: br-mkm: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000\\    link/ether 02:6d:6b:01:02:03 brd ff:ff:ff:ff:ff:ff promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 \\    bridge forward_delay 1500 hello_time 200 max_age 2000 ageing_time 30000 stp_state 0 priority 32768 addrgenmode eui64 numtxqueues 1 numrxqueues 1";
        const REAL_D_VETH: &str = "3: vh-node-a@if2: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue master br-mkm state LOWERLAYERDOWN mode DEFAULT group default qlen 1000\\    link/ether 5e:e8:56:25:19:c9 brd ff:ff:ff:ff:ff:ff link-netns node-a promiscuity 1  allmulti 1 minmtu 68 maxmtu 65535 \\    veth bridge_slave state disabled priority 32 addrgenmode eui64 numtxqueues 2 numrxqueues 2";
        const REAL_D_PEER: &str = "2: eth0@if3: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000\\    link/ether 62:00:1a:17:7d:76 brd ff:ff:ff:ff:ff:ff link-netnsid 0 promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 \\    veth addrgenmode eui64 numtxqueues 2 numrxqueues 2";
        const REAL_D_LO: &str = "1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN mode DEFAULT group default qlen 1000\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 promiscuity 0  allmulti 0 minmtu 0 maxmtu 0 addrgenmode eui64 numtxqueues 1 numrxqueues 1";
        const REAL_D_DUMMY: &str = "77: dummyx: <BROADCAST,NOARP> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000\\    link/ether 5e:89:97:ff:cd:fa brd ff:ff:ff:ff:ff:ff promiscuity 0  allmulti 0 minmtu 0 maxmtu 0 \\    dummy addrgenmode eui64 numtxqueues 1 numrxqueues 1";

        #[test]
        fn mgmt_net_link_id_reads_identity_kind_peer_and_master() {
            let bridge = link_id(REAL_D_BRIDGE).unwrap();
            assert_eq!(
                (bridge.name.as_str(), bridge.ifindex, bridge.mac.as_str()),
                ("br-mkm", 2, "02:6d:6b:01:02:03")
            );
            assert_eq!(
                (bridge.kind.as_deref(), bridge.peer, bridge.master),
                (Some("bridge"), None, None)
            );
            let veth = link_id(REAL_D_VETH).unwrap();
            assert_eq!(
                (
                    veth.name.as_str(),
                    veth.ifindex,
                    veth.peer,
                    veth.master.as_deref()
                ),
                ("vh-node-a", 3, Some(2), Some("br-mkm"))
            );
            assert_eq!(
                (veth.mac.as_str(), veth.kind.as_deref()),
                ("5e:e8:56:25:19:c9", Some("veth"))
            );
            let peer = link_id(REAL_D_PEER).unwrap();
            assert_eq!(
                (peer.name.as_str(), peer.ifindex, peer.peer),
                ("eth0", 2, Some(3))
            );
            assert_eq!(peer.kind.as_deref(), Some("veth"));
            let lo = link_id(REAL_D_LO).unwrap();
            assert_eq!((lo.name.as_str(), lo.kind), ("lo", None));
            assert_eq!(
                link_id(REAL_D_DUMMY).unwrap().kind.as_deref(),
                Some("dummy")
            );
            // without -d: no kind, the rest as with it
            let plain = link_id(LAB_LINK.lines().nth(1).unwrap()).unwrap();
            assert_eq!(
                (plain.ifindex, plain.mac.as_str(), plain.peer, plain.kind),
                (6, "aa:bb:cc:dd:ee:02", Some(7), None)
            );
            for not_a_link in ["", "garbage", "x: ens4: <UP>", "2:", "2: : <UP>"] {
                assert_eq!(link_id(not_a_link), None, "{not_a_link:?}");
            }
        }

        #[test]
        fn mgmt_net_scope_out_removes_verified_devices_only() {
            let lab = verified(&[("br-mkm", 5), ("vh-node-a", 6)]);
            // the lab's own devices go, in every part
            assert_eq!(scope_out("addr", LAB_ADDR, &lab), "");
            assert_eq!(scope_out("link", LAB_LINK, &lab), "");
            assert_eq!(
                scope_out("route4", "192.168.77.0/24 dev br-mkm proto kernel\n", &lab),
                ""
            );
            assert_eq!(
                scope_out("rule", "100:\tfrom all iif vh-node-a lookup 100\n", &lab),
                ""
            );
            // everything else stays, byte for byte
            let mine = format!("{REAL_ADDR_BEFORE}{LAB_ADDR}");
            assert_eq!(scope_out("addr", &mine, &lab), REAL_ADDR_BEFORE);
            assert_eq!(scope_out("link", DRIVER_LINK, &lab), DRIVER_LINK);
            // a verified NAME on an addr / link line of another interface index
            // is not the lab's device
            let other_index = "9: vh-node-a    inet 10.9.9.9/24 scope global vh-node-a\n";
            assert_eq!(scope_out("addr", other_index, &lab), other_index);
            let other_link = "9: vh-node-a@if3: <UP> mtu 1500 state UP\n";
            assert_eq!(scope_out("link", other_link, &lab), other_link);
            // names that merely LOOK like the lab's are kept: a management NIC
            // `vh-uplink` / `vp-uplink`, a prefix or suffix match, other cases
            for name in [
                "vh-uplink",
                "vp-node-a",
                "vh-node-b",
                "br-mkm0",
                "xbr-mkm",
                "br-mkm-uplink",
                "vh-node-a2",
                "VH-NODE-A",
                "mkm0",
                "eth0",
            ] {
                let addr = format!(
                    "9: {name}    inet 10.9.9.9/24 scope global {name}\\       valid_lft forever preferred_lft forever\n"
                );
                assert_eq!(scope_out("addr", &addr, &lab), addr, "addr {name}");
                let link = format!("9: {name}@if3: <UP> mtu 1500 state UP\n");
                assert_eq!(scope_out("link", &link, &lab), link, "link {name}");
                let route =
                    format!("10.9.9.0/24 dev {name} proto kernel scope link src 10.9.9.9\n");
                assert_eq!(scope_out("route4", &route, &lab), route, "route {name}");
                let rule = format!("100:\tfrom all iif {name} lookup 100\n");
                assert_eq!(scope_out("rule", &rule, &lab), rule, "rule {name}");
            }
            // an owned name outside the device position proves nothing
            let tricky = "default via 10.0.0.1 dev ens4 proto static metric 100 src 10.0.0.2 # vh-node-a br-mkm\n";
            assert_eq!(scope_out("route4", tricky, &lab), tricky);
            // a rule naming an owned AND a foreign device is not exclusively the lab's
            let mixed = "100:\tfrom all iif vh-node-a oif ens4 lookup 100\n";
            assert_eq!(scope_out("rule", mixed, &lab), mixed);
            // nothing verified => nothing removed
            assert_eq!(scope_out("addr", LAB_ADDR, &BTreeMap::new()), LAB_ADDR);
            assert_eq!(scope_out("link", LAB_LINK, &BTreeMap::new()), LAB_LINK);
        }

        /// Negative tests 6-10: a same-named replacement, ifindex reuse, MAC
        /// reuse, a duplicate, a rename, and a record that does not match the
        /// device are all ownership LOSSES; a device that is merely absent is
        /// not.
        #[test]
        fn mgmt_net_verify_owned_detects_every_identity_loss() {
            let records = lab_records();
            assert_eq!(records.len(), 2);
            assert_eq!(
                verify_owned(&records, LAB_LINK),
                Ok(verified(&[("br-mkm", 5), ("vh-node-a", 6)]))
            );
            // absent (not created yet / already removed): no loss, nothing to scope
            assert_eq!(verify_owned(&records, DRIVER_LINK), Ok(BTreeMap::new()));
            assert_eq!(verify_owned(&[], LAB_LINK), Ok(BTreeMap::new()));
            let replaced = LAB_LINK
                .replace("6: vh-node-a@if7", "200: vh-node-a@if7")
                .replace("aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:99");
            let index_reused = LAB_LINK.replace("aa:bb:cc:dd:ee:02", "02:00:00:00:00:99");
            let mac_reused = LAB_LINK.replace("6: vh-node-a@if7", "201: vh-node-a@if7");
            let twice = format!(
                "{LAB_LINK}201: vh-node-a: <UP> mtu 1500\\    link/ether aa:bb:cc:dd:ee:02 brd ff:ff:ff:ff:ff:ff\n"
            );
            let renamed = LAB_LINK.replace("6: vh-node-a@if7", "6: vh-renamed@if7");
            let bridge_reindexed = LAB_LINK.replace("5: br-mkm:", "55: br-mkm:");
            for (what, text) in [
                ("same-name replacement", replaced.as_str()),
                ("ifindex reuse", index_reused.as_str()),
                ("MAC reuse", mac_reused.as_str()),
                ("shown twice", twice.as_str()),
                ("renamed", renamed.as_str()),
                ("bridge re-created", bridge_reindexed.as_str()),
            ] {
                let lost = verify_owned(&records, text).expect_err(what);
                assert!(
                    lost.contains("vh-node-a") || lost.contains("br-mkm"),
                    "{what}: {lost}"
                );
            }
            // the record does not match the device (10): a loss as well
            let mut wrong_mac = records.clone();
            wrong_mac[1].mac = "02:de:ad:be:ef:00".to_string();
            assert!(verify_owned(&wrong_mac, LAB_LINK).is_err());
            let mut wrong_index = records.clone();
            wrong_index[0].ifindex = 50;
            assert!(verify_owned(&wrong_index, LAB_LINK).is_err());
        }

        /// The capture-level rule: an ownership loss fails the `link` part —
        /// so the comparison FAILS, even when BOTH sides show the same foreign
        /// device — and nothing at all is scoped out. A device without a record
        /// is never scoped out (9).
        #[test]
        fn mgmt_net_ownership_loss_fails_the_capture_and_scopes_nothing() {
            let records = lab_records();
            let before = snapshot(&base());
            let mut during = base();
            during.addr.push_str(LAB_ADDR);
            during.link.push_str(LAB_LINK);
            during
                .route4
                .push_str("192.168.77.0/24 dev br-mkm proto kernel scope link\n");
            // control: the lab's devices exactly as recorded => PASS
            let control = capture(&during, &records, &during.link);
            assert!(
                compare(&before, &control).pass,
                "{}",
                compare(&before, &control).report
            );
            // replaced under the same name while the lab runs
            let mut replaced = during.clone();
            replaced.link = replaced
                .link
                .replace("6: vh-node-a@if7", "200: vh-node-a@if7")
                .replace("aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:99");
            let snap = capture(&replaced, &records, &replaced.link);
            match part_of(&snap, "link") {
                Err(why) => assert!(
                    why.contains("ownership NOT shown") && why.contains("vh-node-a"),
                    "{why}"
                ),
                Ok(text) => panic!("an ownership loss must fail the link part: {text}"),
            }
            // nothing scoped out: the lab's lines are all still there
            assert!(part_of(&snap, "addr").as_ref().unwrap().contains("br-mkm"));
            assert!(
                part_of(&snap, "route4")
                    .as_ref()
                    .unwrap()
                    .contains("dev br-mkm")
            );
            let verdict = compare(&before, &snap);
            assert!(
                !verdict.pass && verdict.report.contains("ownership NOT shown"),
                "{}",
                verdict.report
            );
            // the same invalid capture on BOTH sides can never pass
            assert!(!compare(&snap, &snap).pass);
            // replaced between the two link captures (first as recorded, then not)
            assert!(!compare(&before, &capture(&replaced, &records, &during.link)).pass);
            assert!(!compare(&before, &capture(&during, &records, &replaced.link)).pass);
            // a failed first link capture: ownership not shown
            let failed_first = scoped_ip_parts(
                &records,
                Some(Err("ip failed".to_string())),
                vec![("link", Ok(during.link.clone()))],
            );
            assert!(
                matches!(&failed_first[0].content, Err(why) if why.contains("a link capture failed"))
            );
            // no record of vh-node-a (9): it is not scoped out => a difference
            let only_bridge = vec![records[0].clone()];
            let verdict = compare(&before, &capture(&during, &only_bridge, &during.link));
            assert!(!verdict.pass, "{}", verdict.report);
            assert!(
                verdict
                    .report
                    .contains("link: FAIL management network changed")
            );
            // no records at all: nothing scoped out
            assert!(!compare(&before, &capture(&during, &[], &during.link)).pass);
        }

        /// Negative tests 11 / 12: while the lab's devices are scoped out, a
        /// change of an unrelated NIC that LOOKS like the lab's (`vh-uplink`)
        /// or of the management NIC `ens4` is still a FAIL.
        #[test]
        fn mgmt_net_unrelated_nics_survive_the_scoping_and_are_compared() {
            let records = lab_records();
            let uplink_addr = "4: vh-uplink    inet 10.5.5.5/24 scope global vh-uplink\\       valid_lft forever preferred_lft forever\n";
            // the management network has a NIC called vh-uplink
            let mut with_uplink = base();
            with_uplink.addr.push_str(uplink_addr);
            with_uplink.link.push_str(
                "4: vh-uplink: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\\    link/ether 02:55:55:55:55:55 brd ff:ff:ff:ff:ff:ff\n",
            );
            with_uplink
                .route4
                .push_str("10.5.5.0/24 dev vh-uplink proto kernel scope link src 10.5.5.5\n");
            let before = snapshot(&with_uplink);
            // control: the lab's devices appear during the run and are scoped out
            let mut during = with_uplink.clone();
            during.addr.push_str(LAB_ADDR);
            during.link.push_str(LAB_LINK);
            let run = |net: &Net| compare(&before, &capture(net, &records, &net.link));
            assert!(
                run(&during).pass,
                "lab devices only: {}",
                run(&during).report
            );
            // the audit's counter-example: the uplink's address changes => FAIL
            let mut moved = during.clone();
            moved.addr = moved.addr.replace("10.5.5.5/24", "10.5.5.6/24");
            let verdict = run(&moved);
            assert!(!verdict.pass, "{}", verdict.report);
            assert!(
                verdict
                    .report
                    .contains("addr: FAIL management network changed"),
                "{}",
                verdict.report
            );
            // ... its link, its route, its disappearance
            let mut down = during.clone();
            down.link = down
                .link
                .replace("fq_codel state UP", "fq_codel state DOWN");
            assert!(!run(&down).pass);
            let mut rerouted = during.clone();
            rerouted.route4 = rerouted.route4.replace("10.5.5.5", "10.5.5.6");
            assert!(!run(&rerouted).pass);
            let mut gone = during.clone();
            gone.addr = gone.addr.replace(uplink_addr, "");
            assert!(!run(&gone).pass);
            // the management NIC itself: address, link state, default route
            let mut ens4 = during.clone();
            ens4.addr = ens4.addr.replace("10.146.0.21/32", "10.146.0.22/32");
            assert!(!run(&ens4).pass);
            let mut ens4_down = during.clone();
            ens4_down.link = ens4_down
                .link
                .replace("qdisc mq state UP", "qdisc mq state DOWN");
            assert!(!run(&ens4_down).pass);
            let mut ens4_route = during.clone();
            ens4_route.route4 = ens4_route.route4.replace("metric 100", "metric 300");
            assert!(!run(&ens4_route).pass);
        }

        #[test]
        fn mgmt_net_line_devices_reads_the_device_of_each_part() {
            assert_eq!(
                line_devices(
                    "addr",
                    "2: ens4    inet 10.0.0.1/32 scope global ens4\\ ..."
                ),
                ["ens4"]
            );
            assert_eq!(
                line_devices("addr", "6: vh-node-a    inet6 fe80::2/64 scope link"),
                ["vh-node-a"]
            );
            assert_eq!(
                line_devices("link", "6: vh-node-a@if7: <UP> mtu 1500"),
                ["vh-node-a"]
            );
            assert_eq!(line_devices("link", "5: br-mkm: <UP> mtu 1500"), ["br-mkm"]);
            assert_eq!(
                line_devices("route4", "192.0.2.0/24 dev mkm0 proto kernel scope link"),
                ["mkm0"]
            );
            assert_eq!(
                line_devices(
                    "route6",
                    "default via fe80::1 dev ens4 proto ra metric 1024"
                ),
                ["ens4"]
            );
            assert_eq!(
                line_devices("rule", "100:\tfrom all iif vh-uplink lookup 100"),
                ["vh-uplink"]
            );
            assert_eq!(
                line_devices("rule", "0:\tfrom all lookup local"),
                Vec::<String>::new()
            );
            // unparsable / no device => nothing (never scoped out)
            assert!(line_devices("addr", "garbage").is_empty());
            assert!(line_devices("addr", "").is_empty());
            assert!(line_devices("addr", "x: ens4 inet").is_empty());
            assert!(line_devices("route4", "blackhole 10.9.0.0/16").is_empty());
            assert!(line_devices("ip_forward", "2: ens4 inet").is_empty());
        }

        // ---- cross-layer: script, shell driver and Rust agree ----

        /// Write `text` as an executable file through a separate process (a
        /// multi-threaded test process must not exec a file it wrote itself).
        fn write_executable(path: &std::path::Path, text: &str) {
            let status = Command::new("/bin/sh")
                .arg("-c")
                .arg("printf '%s' \"$2\" > \"$1\" && chmod 755 \"$1\"")
                .arg("sh")
                .arg(path)
                .arg(text)
                .status()
                .unwrap();
            assert!(status.success());
        }

        /// The REAL shell driver (`closeout-lab.sh mgmt-before-capture` then
        /// `mgmt-after-check`, a stub `ip` serving the stored text) on one pair.
        fn driver_exit(scratch: &Scratch, tag: &str, before: &Net, after: &Net) -> i32 {
            let stub = scratch.path().join(format!("ip-{tag}.sh"));
            write_executable(
                &stub,
                "#!/bin/sh\ncase \"$*\" in\n\"-o addr show\") f=addr ;;\n\"-4 route show\") f=route4 ;;\n\"-6 route show\") f=route6 ;;\n\"rule show\") f=rule ;;\n\"-o link show\") f=link ;;\n*) exit 99 ;;\nesac\ncat \"$STUB_DIR/$f.txt\"\n",
            );
            let serve = |name: &str, net: &Net| {
                let dir = scratch.path().join(format!("{tag}-{name}"));
                std::fs::create_dir_all(&dir).unwrap();
                for (part, text) in [
                    ("addr", &net.addr),
                    ("route4", &net.route4),
                    ("route6", &net.route6),
                    ("rule", &net.rule),
                    ("link", &net.link),
                ] {
                    std::fs::write(dir.join(format!("{part}.txt")), text).unwrap();
                }
                dir
            };
            let (bdir, adir) = (serve("b", before), serve("a", after));
            let runtime = scratch.path().join(format!("{tag}-rt"));
            std::fs::create_dir_all(&runtime).unwrap();
            let step = |mode: &str, stub_dir: &std::path::Path, extra: &[&std::path::Path]| {
                Command::new("bash")
                    .arg(driver_path())
                    .arg(mode)
                    .arg(&runtime)
                    .args(extra)
                    .env_clear()
                    .env("PATH", CHILD_PATH)
                    .env("TMPDIR", scratch.path())
                    .env("MKM_MGMT_TEST_MODE", "1")
                    .env("MKM_IP", &stub)
                    .env("STUB_DIR", stub_dir)
                    .stdin(Stdio::null())
                    .output()
                    .unwrap()
                    .status
                    .code()
                    .unwrap_or(-1)
            };
            assert_eq!(
                step("mgmt-before-capture", &bdir, &[]),
                0,
                "{tag}: before capture"
            );
            let evidence = scratch.path().join(format!("{tag}-ev"));
            step("mgmt-after-check", &adir, &[evidence.as_path()])
        }

        /// Every case of the shared table through all three layers: the audited
        /// script run directly, the real shell driver, and the Rust lab
        /// (embedded script). The verdicts must be the same, and the expected
        /// one. (The `ip_forward` / listener cases are Rust-only.)
        #[test]
        fn mgmt_net_driver_script_and_rust_agree_on_every_case() {
            let scratch = Scratch::new().unwrap();
            let mut mismatches = Vec::new();
            for (n, case) in cases().into_iter().enumerate() {
                if case.exact_only {
                    continue;
                }
                let rust = compare(&snapshot(&case.before), &snapshot(&case.after)).pass;
                let mut script = true;
                for (label, b, a) in [
                    ("addr", &case.before.addr, &case.after.addr),
                    ("route4", &case.before.route4, &case.after.route4),
                    ("route6", &case.before.route6, &case.after.route6),
                    ("rule", &case.before.rule, &case.after.rule),
                    ("link", &case.before.link, &case.after.link),
                ] {
                    script &= shell_exit(&scratch, label, b, a) == 0;
                }
                let driver =
                    driver_exit(&scratch, &format!("c{n}"), &case.before, &case.after) == 0;
                if !(rust == case.pass && script == case.pass && driver == case.pass) {
                    mismatches.push(format!(
                        "{}: expected {}, rust {rust}, script {script}, driver {driver}",
                        case.name, case.pass
                    ));
                }
            }
            assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
        }
    }

    // ---- Phase 14.12 MC-1 (remaining findings): what the VF lab may delete ------
    //
    // TEST-ONLY and platform-independent. The Linux VF lab (`vf_lab`) builds its
    // topology through `Topology` and tears itself down through `run_steps`; the
    // real kernel is plugged in there. The in-memory `FakeKernel` below lets
    // every ownership and cleanup rule be checked on any host, touching no
    // network at all.
    //
    // Ownership and the right to delete (F-AUD-R3-PREEXISTING-DELETE / -IDENTITY):
    //   1. Before anything is created, every name the topology would create
    //      (br-mkm, vh-<ns>, netns <ns>) must be free and the pre-run
    //      management snapshot complete — or nothing is created (`preflight`).
    //      This is the early refusal only; it proves nothing about later.
    //   2. Every step is create-only (the kernel refuses an existing name). A
    //      resource is RECORDED only after its step succeeded AND its identity
    //      was read back and matched what the step made: the bridge by the
    //      run-unique MAC it was created with; a netns is created by the lab
    //      itself, unnamed, through a holder process, and held from then on
    //      (its inode cannot be reused while held) — the step only attaches
    //      the name to it, and the name must then point to exactly the held
    //      namespace; a veth by its pairing with `eth0` INSIDE that held
    //      netns (each end names the other's ifindex). A pre-existing resource
    //      can therefore never be recorded: its name made the create fail,
    //      and a replacement in between does not match what the lab holds.
    //   3. Only recorded resources are ever deleted, newest first, each after
    //      showing again that it is still the recorded one. A veth is deleted
    //      only through the held netns (its `eth0` there; the kernel takes the
    //      pair), never by its host name. Anything else under a lab name —
    //      a replacement, a re-used ifindex or MAC, a renamed device, a netns
    //      name pointing elsewhere — is LEFT IN PLACE and reported: residue
    //      and FAIL, never a deletion.
    //   Residual (stated, not hidden): the bridge and a netns NAME are removed
    //   by name right after their identity check. A concurrent root actor who,
    //   in that window, deletes the lab's own resource and re-creates one under
    //   the same name with the same ifindex AND MAC (bridge) or mounts another
    //   namespace under the name (netns), defeats the check. That requires
    //   deliberately forging kernel identifiers in a microsecond window; it is
    //   outside what this lab can prevent with name-addressed `ip` commands.
    mod lab_own {
        use super::mgmt_net::{self, LinkId};
        use std::collections::BTreeMap;
        use std::path::Path;
        use std::process::{Command, Stdio};

        /// The topology script, byte for byte (create-only steps; no `down`).
        pub(super) const TOPOLOGY_SH: &str = include_str!("../tests/lab/vf/vf-topology.sh");
        pub(super) const BRIDGE: &str = "br-mkm";
        pub(super) const NAMESPACES: [&str; 4] = ["node-a", "node-b", "witness", "client"];
        /// The name of each veth's peer inside its lab netns.
        pub(super) const PEER: &str = "eth0";

        pub(super) fn host_veth(ns: &str) -> String {
            format!("vh-{ns}")
        }

        /// Every device name the topology creates in the host netns.
        pub(super) fn lab_link_names() -> Vec<String> {
            let mut names = vec![BRIDGE.to_string()];
            names.extend(NAMESPACES.iter().map(|ns| host_veth(ns)));
            names
        }

        /// A netns: (st_dev, st_ino) of its nsfs inode.
        pub(super) type NsId = (u64, u64);

        /// What the lab needs from the kernel: the real one (`vf_lab`), or
        /// `FakeKernel` in the tests.
        pub(super) trait Kernel {
            /// Every device of the host netns (`ip -d -o link show`).
            fn links(&mut self) -> Result<Vec<LinkId>, String>;
            /// Every named netns.
            fn netns_names(&mut self) -> Result<Vec<String>, String>;
            /// One `vf-topology.sh` step.
            fn step(&mut self, args: &[String]) -> Result<(), String>;
            /// A NEW, still unnamed network namespace that only the lab holds
            /// (kept under the key `name`): its identity, and the reference the
            /// `netns <name> <reference>` step attaches the name to.
            fn fresh_netns(&mut self, name: &str) -> Result<(NsId, String), String>;
            /// The identity the name `name` points to now (`None`: no such name).
            fn netns_id(&mut self, name: &str) -> Result<Option<NsId>, String>;
            /// A path naming the HELD netns `name` (for `netns <path>` /
            /// `nsenter --net=<path>`); `None` if the lab holds none.
            fn handle(&self, name: &str) -> Option<String>;
            /// The devices inside the held netns `name`.
            fn links_in(&mut self, name: &str) -> Result<Vec<LinkId>, String>;
            /// Delete device `dev` inside the held netns `name`.
            fn delete_in(&mut self, name: &str, dev: &str) -> Result<(), String>;
            /// Delete a host device by name.
            fn delete_link(&mut self, name: &str) -> Result<(), String>;
            /// Remove the netns name `name`.
            fn delete_netns(&mut self, name: &str) -> Result<(), String>;
            /// Drop the handle on netns `name` (and its holder process).
            fn release(&mut self, name: &str);
            /// Every process inside the held netns `name`.
            fn pids_in(&mut self, name: &str) -> Result<Vec<i32>, String>;
        }

        /// A recorded resource: written only after its create step succeeded
        /// and its identity was read back.
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub(super) enum Created {
            Bridge(LinkId),
            Netns {
                name: String,
                id: NsId,
            },
            Veth {
                ns: String,
                host: LinkId,
                peer: LinkId,
            },
        }

        impl Created {
            pub(super) fn describe(&self) -> String {
                match self {
                    Created::Bridge(link) => format!("bridge {}", describe(link)),
                    Created::Netns { name, id } => {
                        format!("netns {name} (inode {}:{})", id.0, id.1)
                    }
                    Created::Veth { ns, host, peer } => format!(
                        "veth {} <-> {PEER} in netns {ns} (ifindex {})",
                        describe(host),
                        peer.ifindex
                    ),
                }
            }
        }

        pub(super) fn describe(link: &LinkId) -> String {
            format!(
                "{} ifindex {} MAC {} kind {}",
                link.name,
                link.ifindex,
                link.mac,
                link.kind.as_deref().unwrap_or("?")
            )
        }

        /// `now` is the device `record` describes: same name, ifindex, MAC and
        /// kind (a device whose kind cannot be read is NOT the same).
        pub(super) fn same_device(now: &LinkId, record: &LinkId) -> bool {
            now.name == record.name
                && now.ifindex == record.ifindex
                && now.mac == record.mac
                && now.kind.is_some()
                && now.kind == record.kind
        }

        /// The early refusal, before anything is created: the pre-run
        /// management snapshot must be complete (a baseline that cannot be
        /// compared is no baseline), and no name the topology would create may
        /// exist. `Err`: nothing may be created (BLOCKED).
        pub(super) fn preflight(
            kernel: &mut dyn Kernel,
            baseline: &mgmt_net::Snapshot,
        ) -> Result<(), String> {
            let mut problems = baseline.problems();
            for part in &baseline.parts {
                if let Err(why) = &part.content {
                    problems.push(format!("{}: not captured ({why})", part.label));
                }
            }
            if !problems.is_empty() {
                return Err(format!(
                    "the pre-run management snapshot is incomplete: {}",
                    problems.join("; ")
                ));
            }
            let links = kernel
                .links()
                .map_err(|why| format!("the host devices cannot be listed: {why}"))?;
            let netns = kernel
                .netns_names()
                .map_err(|why| format!("the named netns cannot be listed: {why}"))?;
            let mut conflicts = Vec::new();
            for name in lab_link_names() {
                for link in links.iter().filter(|link| link.name == name) {
                    conflicts.push(format!("device {} already exists", describe(link)));
                }
            }
            for ns in NAMESPACES {
                if netns.iter().any(|name| name == ns) {
                    conflicts.push(format!("netns {ns} already exists"));
                }
            }
            if conflicts.is_empty() {
                Ok(())
            } else {
                Err(conflicts.join("; "))
            }
        }

        /// What the lab created, in creation order, and what happened to it.
        #[derive(Default)]
        pub(super) struct Topology {
            pub(super) created: Vec<Created>,
            /// Step by step: run, recorded, verified, removed, left (evidence).
            pub(super) log: Vec<String>,
        }

        impl Topology {
            fn note(&mut self, line: String) {
                self.log.push(line);
            }

            fn record(&mut self, created: Created) {
                self.note(format!("recorded {}", created.describe()));
                self.created.push(created);
            }

            fn run(&mut self, kernel: &mut dyn Kernel, args: &[&str]) -> Result<(), String> {
                let args: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
                let result = kernel.step(&args);
                self.note(format!(
                    "step {}: {}",
                    args.join(" "),
                    match &result {
                        Ok(()) => "ok".to_string(),
                        Err(why) => format!("FAILED: {why}"),
                    }
                ));
                result.map_err(|why| format!("topology step `{}` failed: {why}", args.join(" ")))
            }

            /// The one host device named `name`, as the kernel shows it now.
            fn host_device(kernel: &mut dyn Kernel, name: &str) -> Result<LinkId, String> {
                let links = kernel.links()?;
                let mut named = links.into_iter().filter(|link| link.name == name);
                match (named.next(), named.next()) {
                    (Some(one), None) => Ok(one),
                    (None, _) => Err(format!("{name} is not shown")),
                    (Some(_), Some(_)) => Err(format!("{name} is shown more than once")),
                }
            }

            /// `record` is still exactly the device the lab created (checked
            /// right before the lab acts on it by name).
            fn still(kernel: &mut dyn Kernel, record: &LinkId) -> Result<(), String> {
                let now = Self::host_device(kernel, &record.name)?;
                if same_device(&now, record) {
                    Ok(())
                } else {
                    Err(format!(
                        "{} is no longer the device the lab created (now {}, created {})",
                        record.name,
                        describe(&now),
                        describe(record)
                    ))
                }
            }

            /// Create the topology one create-only step at a time, recording
            /// each result only once its identity is shown (see the module
            /// comment). `Err` stops at the first failure: what was recorded
            /// until then is all the teardown may delete.
            pub(super) fn up(
                &mut self,
                kernel: &mut dyn Kernel,
                bridge_mac: &str,
            ) -> Result<(), String> {
                self.run(kernel, &["bridge", bridge_mac])?;
                let bridge = Self::host_device(kernel, BRIDGE).map_err(|why| {
                    format!("{BRIDGE} was created but cannot be identified ({why}); not recorded")
                })?;
                if bridge.mac != bridge_mac || bridge.kind.as_deref() != Some("bridge") {
                    return Err(format!(
                        "the {BRIDGE} shown ({}) is not the bridge this step created \
                         (MAC {bridge_mac}); not recorded",
                        describe(&bridge)
                    ));
                }
                self.record(Created::Bridge(bridge.clone()));
                Self::still(kernel, &bridge)?;
                self.run(kernel, &["bridge-up"])?;
                for ns in NAMESPACES {
                    let (id, reference) = kernel.fresh_netns(ns).map_err(|why| {
                        format!("a new namespace for {ns} cannot be created ({why})")
                    })?;
                    if let Err(why) = self.run(kernel, &["netns", ns, &reference]) {
                        kernel.release(ns);
                        return Err(why);
                    }
                    // the name must point to exactly the namespace the lab holds
                    match kernel.netns_id(ns) {
                        Ok(Some(now)) if now == id => {}
                        other => {
                            kernel.release(ns);
                            return Err(format!(
                                "netns {ns} does not name the namespace the lab created \
                                 ({other:?}, the lab's is {}:{}); not recorded",
                                id.0, id.1
                            ));
                        }
                    }
                    let inside = match kernel.links_in(ns) {
                        Ok(inside) => inside,
                        Err(why) => {
                            kernel.release(ns);
                            return Err(format!(
                                "netns {ns}: its devices cannot be listed ({why}); not recorded"
                            ));
                        }
                    };
                    if !(inside.len() == 1 && inside[0].name == "lo") {
                        kernel.release(ns);
                        return Err(format!(
                            "netns {ns} is not the empty namespace the lab created \
                             ({} devices inside); not recorded",
                            inside.len()
                        ));
                    }
                    self.record(Created::Netns {
                        name: ns.to_string(),
                        id,
                    });
                    let handle = kernel
                        .handle(ns)
                        .ok_or_else(|| format!("no handle on the lab's netns {ns}"))?;
                    self.run(kernel, &["veth", ns, &handle])?;
                    let name = host_veth(ns);
                    let host = Self::host_device(kernel, &name).map_err(|why| {
                        format!("{name} was created but cannot be identified ({why}); not recorded")
                    })?;
                    let peers: Vec<LinkId> = kernel
                        .links_in(ns)?
                        .into_iter()
                        .filter(|link| link.name == PEER)
                        .collect();
                    let [peer] = peers.as_slice() else {
                        return Err(format!(
                            "{PEER} inside the lab's netns {ns} is shown {} times; {name} not recorded",
                            peers.len()
                        ));
                    };
                    if host.kind.as_deref() != Some("veth")
                        || peer.kind.as_deref() != Some("veth")
                        || host.peer != Some(peer.ifindex)
                        || peer.peer != Some(host.ifindex)
                    {
                        return Err(format!(
                            "{} is not paired with {PEER} ({}) inside the lab's netns {ns}; \
                             not recorded",
                            describe(&host),
                            describe(peer)
                        ));
                    }
                    let peer = peer.clone();
                    self.record(Created::Veth {
                        ns: ns.to_string(),
                        host: host.clone(),
                        peer,
                    });
                    Self::still(kernel, &host)?;
                    self.run(kernel, &["port", ns])?;
                    self.run(kernel, &["inside", ns, &handle])?;
                }
                for record in self.owned_links() {
                    Self::still(kernel, &record)?;
                }
                self.note("topology up: every created resource recorded and verified".into());
                Ok(())
            }

            /// The recorded host devices (what a during-run snapshot may scope
            /// out, if it shows them with exactly this identity).
            pub(super) fn owned_links(&self) -> Vec<LinkId> {
                self.created
                    .iter()
                    .filter_map(|created| match created {
                        Created::Bridge(link) => Some(link.clone()),
                        Created::Veth { host, .. } => Some(host.clone()),
                        Created::Netns { .. } => None,
                    })
                    .collect()
            }

            /// The recorded netns names.
            pub(super) fn netns(&self) -> Vec<String> {
                self.created
                    .iter()
                    .filter_map(|created| match created {
                        Created::Netns { name, .. } => Some(name.clone()),
                        _ => None,
                    })
                    .collect()
            }

            /// The recorded resources, newest first: one teardown step each.
            pub(super) fn removal_order(&self) -> Vec<Created> {
                self.created.iter().rev().cloned().collect()
            }

            /// Remove ONE recorded resource, only after showing it is still the
            /// one the lab created. Anything else found under a lab name is
            /// left in place and reported (`Err`).
            pub(super) fn remove(
                &mut self,
                kernel: &mut dyn Kernel,
                created: &Created,
            ) -> Result<(), String> {
                let result = match created {
                    Created::Veth { ns, host, peer } => Self::remove_veth(kernel, ns, host, peer),
                    Created::Netns { name, id } => Self::remove_netns(kernel, name, *id),
                    Created::Bridge(record) => Self::remove_bridge(kernel, record),
                };
                self.note(format!(
                    "remove {}: {}",
                    created.describe(),
                    match &result {
                        Ok(()) => "removed".to_string(),
                        Err(why) => format!("NOT removed: {why}"),
                    }
                ));
                result
            }

            /// Through the held netns only: its `eth0` (the recorded peer) is
            /// deleted there and the kernel takes the pair. The host name is
            /// never used to delete anything.
            fn remove_veth(
                kernel: &mut dyn Kernel,
                ns: &str,
                host: &LinkId,
                peer: &LinkId,
            ) -> Result<(), String> {
                if kernel.handle(ns).is_none() {
                    return Err(format!(
                        "the lab holds no handle on netns {ns}: {} cannot be reached through it; \
                         left in place",
                        host.name
                    ));
                }
                let links = kernel.links()?;
                if let Some(now) = links.iter().find(|link| link.ifindex == host.ifindex)
                    && !same_device(now, host)
                {
                    return Err(format!(
                        "the record of {} does not match the device now at its ifindex ({}); \
                         left in place",
                        describe(host),
                        describe(now)
                    ));
                }
                let inside: Vec<LinkId> = kernel
                    .links_in(ns)?
                    .into_iter()
                    .filter(|link| link.name == PEER)
                    .collect();
                match inside.as_slice() {
                    // no peer in the lab's netns: no pair left to delete through it
                    [] => {}
                    [now]
                        if now.ifindex == peer.ifindex
                            && now.mac == peer.mac
                            && now.peer == Some(host.ifindex) =>
                    {
                        kernel.delete_in(ns, PEER)?
                    }
                    _ => {
                        return Err(format!(
                            "{PEER} inside the lab's netns {ns} is not the recorded peer of {}; \
                             left in place",
                            host.name
                        ));
                    }
                }
                let links = kernel.links()?;
                if let Some(still) = links
                    .iter()
                    .find(|link| link.ifindex == host.ifindex && link.mac == host.mac)
                {
                    return Err(format!(
                        "the lab's {} is still present ({}); its peer is not in the lab's netns; \
                         left in place",
                        host.name,
                        describe(still)
                    ));
                }
                if let Some(other) = links.iter().find(|link| link.name == host.name) {
                    return Err(format!(
                        "a device named {} that the lab did not create is present ({}); left in place",
                        host.name,
                        describe(other)
                    ));
                }
                Ok(())
            }

            /// The name is removed only while it still names the namespace the
            /// lab holds (whose inode cannot have been reused).
            fn remove_netns(kernel: &mut dyn Kernel, name: &str, id: NsId) -> Result<(), String> {
                match kernel.netns_id(name)? {
                    Some(now) if now == id => kernel.delete_netns(name)?,
                    Some(now) => {
                        kernel.release(name);
                        return Err(format!(
                            "netns {name} now names a namespace the lab did not create \
                             (inode {}:{}, the lab's was {}:{}); left in place",
                            now.0, now.1, id.0, id.1
                        ));
                    }
                    None => {}
                }
                kernel.release(name);
                match kernel.netns_id(name)? {
                    None => Ok(()),
                    Some(now) => Err(format!(
                        "netns {name} is still present (inode {}:{})",
                        now.0, now.1
                    )),
                }
            }

            /// Only the recorded bridge (name, ifindex, run-unique MAC, kind),
            /// and only once it has no port left (a port the lab did not
            /// remove is somebody's device).
            fn remove_bridge(kernel: &mut dyn Kernel, record: &LinkId) -> Result<(), String> {
                let links = kernel.links()?;
                let named: Vec<&LinkId> = links.iter().filter(|link| link.name == BRIDGE).collect();
                match named.as_slice() {
                    [] => match links
                        .iter()
                        .find(|link| link.ifindex == record.ifindex && link.mac == record.mac)
                    {
                        Some(renamed) => Err(format!(
                            "the lab's {BRIDGE} is present under another name ({}); left in place",
                            describe(renamed)
                        )),
                        None => Ok(()),
                    },
                    [now] if same_device(now, record) => {
                        let ports: Vec<&str> = links
                            .iter()
                            .filter(|link| link.master.as_deref() == Some(BRIDGE))
                            .map(|link| link.name.as_str())
                            .collect();
                        if !ports.is_empty() {
                            return Err(format!(
                                "{BRIDGE} still has ports the lab did not remove ({}); left in place",
                                ports.join(", ")
                            ));
                        }
                        kernel.delete_link(BRIDGE)?;
                        if kernel
                            .links()?
                            .iter()
                            .any(|link| link.ifindex == record.ifindex)
                        {
                            return Err(format!("{BRIDGE} is still present after its deletion"));
                        }
                        Ok(())
                    }
                    [now] => Err(format!(
                        "a {BRIDGE} that the lab did not create is present ({}; the lab's was {}); \
                         left in place",
                        describe(now),
                        describe(record)
                    )),
                    many => Err(format!(
                        "{BRIDGE} is shown {} times; left in place",
                        many.len()
                    )),
                }
            }

            /// After the teardown: anything left of the topology. A device or
            /// netns under a lab name (the lab's own or not: either way a FAIL,
            /// never deleted here), a recorded device under another name, a
            /// netns handle the lab still holds. What cannot be listed is
            /// unknown (a FAIL too).
            pub(super) fn probe(&self, kernel: &mut dyn Kernel, residue: &mut Residue) {
                match kernel.links() {
                    Err(why) => residue
                        .unknown
                        .push(format!("the host devices cannot be listed: {why}")),
                    Ok(links) => {
                        for name in lab_link_names() {
                            for link in links.iter().filter(|link| link.name == name) {
                                residue.left.push(format!("device {}", describe(link)));
                            }
                        }
                        for record in self.owned_links() {
                            for link in links.iter().filter(|link| {
                                link.ifindex == record.ifindex
                                    && link.mac == record.mac
                                    && link.name != record.name
                            }) {
                                residue.left.push(format!(
                                    "the lab's {} under the name {}",
                                    record.name, link.name
                                ));
                            }
                        }
                    }
                }
                match kernel.netns_names() {
                    Err(why) => residue
                        .unknown
                        .push(format!("the named netns cannot be listed: {why}")),
                    Ok(names) => {
                        for ns in NAMESPACES {
                            if names.iter().any(|name| name == ns) {
                                residue.left.push(format!("netns {ns}"));
                            }
                        }
                    }
                }
                for ns in self.netns() {
                    if kernel.handle(&ns).is_some() {
                        residue.left.push(format!(
                            "the lab still holds netns {ns} (it was not removed)"
                        ));
                    }
                }
            }

            /// Drop every netns handle the lab still holds (after the probe).
            pub(super) fn release_all(&self, kernel: &mut dyn Kernel) {
                for ns in self.netns() {
                    kernel.release(&ns);
                }
            }
        }

        // ---- the cleanup: separate failure boundaries, nothing hidden ----------

        #[derive(Clone, Debug, PartialEq, Eq)]
        pub(super) enum StepEnd {
            Done,
            /// The step returned an error (a command that failed or could not
            /// be started, a resource left in place, ...).
            Failed(String),
            /// The step panicked; the message is kept.
            Panicked(String),
        }

        #[derive(Clone, Debug, PartialEq, Eq)]
        pub(super) struct StepReport {
            pub(super) name: String,
            pub(super) end: StepEnd,
        }

        /// One cleanup step: its name and what it does to the context.
        pub(super) type Step<C> = (String, Box<dyn FnOnce(&mut C) -> Result<(), String>>);

        pub(super) fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
            payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|text| text.to_string()))
                .unwrap_or_else(|| "a panic without a message".to_string())
        }

        /// Run every step, each inside its OWN failure boundary
        /// (`catch_unwind` around exactly that step): `Err` is FAILED, a panic
        /// is PANICKED (message kept) — and either way the next step still
        /// runs, so one broken step cannot keep the others (or the evidence,
        /// or the report) from happening. `fault` is called first inside each
        /// boundary (tests inject a panic there). Nothing escapes: a panic
        /// inside a boundary while the thread is already unwinding is caught
        /// the same way (no second panic leaves `drop`, so no abort). What a
        /// boundary cannot cover — a process abort, a kill by the OS — is not
        /// claimed.
        pub(super) fn run_steps<C>(
            ctx: &mut C,
            steps: Vec<Step<C>>,
            fault: &dyn Fn(&str),
        ) -> Vec<StepReport> {
            let mut reports = Vec::new();
            for (name, body) in steps {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    fault(&name);
                    body(&mut *ctx)
                }));
                let end = match outcome {
                    Ok(Ok(())) => StepEnd::Done,
                    Ok(Err(why)) => StepEnd::Failed(why),
                    Err(payload) => StepEnd::Panicked(panic_message(&*payload)),
                };
                reports.push(StepReport { name, end });
            }
            reports
        }

        /// One cleanup command: `Ok` only for exit 0. A command that cannot be
        /// started, exits non-zero or is killed by a signal is `Err` (with its
        /// output): a failed cleanup command is never a success.
        pub(super) fn command(program: &str, args: &[&str]) -> Result<(), String> {
            match Command::new(program)
                .args(args)
                .stdin(Stdio::null())
                .output()
            {
                Ok(output) if output.status.success() => Ok(()),
                Ok(output) => Err(format!(
                    "{program} {args:?} ended with {}: {}{}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout).trim_end(),
                    String::from_utf8_lossy(&output.stderr).trim_end()
                )),
                Err(error) => Err(format!("cannot run {program}: {error}")),
            }
        }

        /// What was found after the cleanup.
        #[derive(Clone, Debug, Default, PartialEq, Eq)]
        pub(super) struct Residue {
            /// Still present (the lab's own, or something under a lab name).
            pub(super) left: Vec<String>,
            /// Could not be checked.
            pub(super) unknown: Vec<String>,
        }

        impl Residue {
            pub(super) fn is_clean(&self) -> bool {
                self.left.is_empty() && self.unknown.is_empty()
            }
        }

        /// A path the lab created must be gone: present => left; cannot tell
        /// => unknown.
        pub(super) fn probe_path(path: &Path, what: &str, residue: &mut Residue) {
            match std::fs::symlink_metadata(path) {
                Ok(_) => residue
                    .left
                    .push(format!("{what} {} still exists", path.display())),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => residue
                    .unknown
                    .push(format!("{what} {}: {error}", path.display())),
            }
        }

        /// The outcome of a teardown, judged as three SEPARATE verdicts:
        /// management network unchanged, every cleanup step done, nothing left.
        #[derive(Clone, Debug)]
        pub(super) struct Teardown {
            /// The management network equals its pre-run state (audited
            /// comparison). A comparison that could not be made is NOT clean.
            pub(super) mgmt_clean: bool,
            pub(super) mgmt_report: String,
            pub(super) steps: Vec<StepReport>,
            pub(super) residue: Residue,
        }

        pub(super) const CHECK_MGMT: &str = "MGMT-NET after-teardown snapshot equals pre-run";
        pub(super) const CHECK_CLEANUP: &str = "LAB cleanup completed (every step)";
        pub(super) const CHECK_RESIDUE: &str = "LAB nothing left after cleanup";

        impl Teardown {
            /// The steps that did not end `Done`.
            pub(super) fn failed_steps(&self) -> Vec<String> {
                self.steps
                    .iter()
                    .filter_map(|step| match &step.end {
                        StepEnd::Done => None,
                        StepEnd::Failed(why) => Some(format!("{}: FAILED: {why}", step.name)),
                        StepEnd::Panicked(why) => Some(format!("{}: PANICKED: {why}", step.name)),
                    })
                    .collect()
            }

            /// (check id, pass, detail) for each of the three verdicts.
            pub(super) fn verdicts(&self) -> Vec<(&'static str, bool, String)> {
                let failed = self.failed_steps();
                let residue = &self.residue;
                vec![
                    (
                        CHECK_MGMT,
                        self.mgmt_clean,
                        if self.mgmt_clean {
                            "identical (audited comparison)".to_string()
                        } else {
                            "DIFFERENT or not comparable (see mgmt-after-compare.txt)".to_string()
                        },
                    ),
                    (
                        CHECK_CLEANUP,
                        failed.is_empty(),
                        if failed.is_empty() {
                            format!("{} steps done", self.steps.len())
                        } else {
                            failed.join("; ")
                        },
                    ),
                    (
                        CHECK_RESIDUE,
                        residue.is_clean(),
                        if residue.is_clean() {
                            "nothing left".to_string()
                        } else {
                            format!(
                                "left: [{}] unknown: [{}] (see teardown.txt)",
                                residue.left.join("; "),
                                residue.unknown.join("; ")
                            )
                        },
                    ),
                ]
            }

            /// The evidence file (`teardown.txt`).
            pub(super) fn render(&self) -> String {
                let mut text = String::new();
                for (id, pass, detail) in self.verdicts() {
                    text.push_str(&format!(
                        "{} {id}: {detail}\n",
                        if pass { "PASS" } else { "FAIL" }
                    ));
                }
                text.push_str("[steps]\n");
                for step in &self.steps {
                    text.push_str(&format!("{:?} {}\n", step.end, step.name));
                }
                text.push_str("[left]\n");
                for line in &self.residue.left {
                    text.push_str(&format!("{line}\n"));
                }
                text.push_str("[unknown]\n");
                for line in &self.residue.unknown {
                    text.push_str(&format!("{line}\n"));
                }
                text.push_str("[mgmt-after]\n");
                text.push_str(&self.mgmt_report);
                text
            }
        }

        // ---- an in-memory kernel (tests) ---------------------------------------

        #[derive(Clone, Debug, PartialEq, Eq)]
        pub(super) struct FakeDev {
            pub(super) id: LinkId,
            /// `None`: the host netns; `Some(inode)`: inside that netns.
            pub(super) netns: Option<u64>,
        }

        /// Devices and named netns. Deleting one end of a veth deletes the pair,
        /// and a netns that is neither named nor held is destroyed with its
        /// devices (and their peers) — as the kernel does.
        #[derive(Clone, Debug, Default)]
        pub(super) struct FakeNet {
            pub(super) devs: Vec<FakeDev>,
            pub(super) named: BTreeMap<String, u64>,
            pub(super) held: BTreeMap<String, u64>,
            next: u64,
        }

        impl FakeNet {
            fn next(&mut self) -> u64 {
                self.next += 1;
                self.next
            }

            /// Add a device; `index` / `mac` forced, or fresh ones.
            pub(super) fn add_dev(
                &mut self,
                name: &str,
                kind: &str,
                netns: Option<u64>,
                index: Option<u32>,
                mac: Option<&str>,
            ) -> LinkId {
                let n = self.next();
                let id = LinkId {
                    name: name.to_string(),
                    ifindex: index.unwrap_or(100 + n as u32),
                    mac: mac.map(str::to_string).unwrap_or_else(|| {
                        format!("02:00:00:00:{:02x}:{:02x}", (n >> 8) & 0xff, n & 0xff)
                    }),
                    peer: None,
                    master: None,
                    kind: (!kind.is_empty()).then(|| kind.to_string()),
                };
                self.devs.push(FakeDev {
                    id: id.clone(),
                    netns,
                });
                id
            }

            /// A new named netns (with its `lo`); its inode.
            pub(super) fn add_netns(&mut self, name: &str) -> u64 {
                let inode = self.new_namespace();
                self.named.insert(name.to_string(), inode);
                inode
            }

            /// A new namespace object (with its `lo`), not named; its inode.
            pub(super) fn new_namespace(&mut self) -> u64 {
                let inode = 4_026_532_000 + self.next();
                self.devs.push(FakeDev {
                    id: LinkId {
                        name: "lo".to_string(),
                        ifindex: 1,
                        mac: "00:00:00:00:00:00".to_string(),
                        peer: None,
                        master: None,
                        kind: None,
                    },
                    netns: Some(inode),
                });
                inode
            }

            /// A veth pair: `host` in the host netns, `peer` inside `netns`.
            pub(super) fn add_veth(&mut self, host: &str, peer: &str, netns: u64) {
                let a = self.add_dev(host, "veth", None, None, None);
                let b = self.add_dev(peer, "veth", Some(netns), None, None);
                for dev in &mut self.devs {
                    if dev.id == a {
                        dev.id.peer = Some(b.ifindex);
                    } else if dev.id == b {
                        dev.id.peer = Some(a.ifindex);
                    }
                }
            }

            pub(super) fn in_netns(&self, netns: Option<u64>) -> Vec<LinkId> {
                self.devs
                    .iter()
                    .filter(|dev| dev.netns == netns)
                    .map(|dev| dev.id.clone())
                    .collect()
            }

            pub(super) fn host(&self, name: &str) -> Option<LinkId> {
                self.in_netns(None)
                    .into_iter()
                    .find(|link| link.name == name)
            }

            /// Delete a device by name in `netns`, and its veth peer.
            pub(super) fn del_dev(&mut self, netns: Option<u64>, name: &str) -> bool {
                let Some(at) = self
                    .devs
                    .iter()
                    .position(|dev| dev.netns == netns && dev.id.name == name)
                else {
                    return false;
                };
                let gone = self.devs.remove(at);
                if let (Some("veth"), Some(peer)) = (gone.id.kind.as_deref(), gone.id.peer) {
                    self.devs.retain(|dev| {
                        !(dev.id.ifindex == peer && dev.id.peer == Some(gone.id.ifindex))
                    });
                }
                if gone.id.kind.as_deref() == Some("bridge") {
                    for dev in &mut self.devs {
                        if dev.netns.is_none() && dev.id.master.as_deref() == Some(name) {
                            dev.id.master = None;
                        }
                    }
                }
                true
            }

            /// Destroy netns `inode` unless it is still named or held.
            fn reap(&mut self, inode: u64) {
                if self.named.values().any(|i| *i == inode)
                    || self.held.values().any(|i| *i == inode)
                {
                    return;
                }
                let inside: Vec<String> = self
                    .devs
                    .iter()
                    .filter(|dev| dev.netns == Some(inode))
                    .map(|dev| dev.id.name.clone())
                    .collect();
                for name in inside {
                    self.del_dev(Some(inode), &name);
                }
            }

            /// Remove a netns name (someone else's action, or the kernel's).
            pub(super) fn del_netns(&mut self, name: &str) -> bool {
                match self.named.remove(name) {
                    Some(inode) => {
                        self.reap(inode);
                        true
                    }
                    None => false,
                }
            }
        }

        /// `FakeNet` behind the `Kernel` interface, with faults to inject.
        #[derive(Default)]
        pub(super) struct FakeKernel {
            pub(super) net: FakeNet,
            /// Every mutating operation, in order.
            pub(super) ops: Vec<String>,
            /// The step that fails, changing nothing: its arguments joined by
            /// ' ' (a prefix of whole arguments matches too).
            pub(super) fail_step: Option<String>,
            /// Run right after the named step succeeded (another actor); named
            /// like `fail_step`.
            pub(super) after_step: Vec<(String, Box<dyn FnMut(&mut FakeNet)>)>,
            /// Listing the host devices / netns fails (inventory unknown).
            pub(super) blind: bool,
        }

        impl FakeKernel {
            fn handle_inode(&self, handle: &str) -> Result<u64, String> {
                handle
                    .strip_prefix("fake-handle:")
                    .and_then(|inode| inode.parse().ok())
                    .filter(|inode| self.net.held.values().any(|held| held == inode))
                    .ok_or_else(|| format!("not a held netns handle: {handle}"))
            }

            fn held_inode(&self, name: &str) -> Result<u64, String> {
                self.net
                    .held
                    .get(name)
                    .copied()
                    .ok_or_else(|| format!("no handle on netns {name}"))
            }

            fn exists(&self, name: &str) -> Result<(), String> {
                if self.net.host(name).is_some() {
                    Err(format!("RTNETLINK answers: File exists ({name})"))
                } else {
                    Ok(())
                }
            }
        }

        impl Kernel for FakeKernel {
            fn links(&mut self) -> Result<Vec<LinkId>, String> {
                if self.blind {
                    return Err("injected: cannot list devices".to_string());
                }
                Ok(self.net.in_netns(None))
            }

            fn netns_names(&mut self) -> Result<Vec<String>, String> {
                if self.blind {
                    return Err("injected: cannot list netns".to_string());
                }
                Ok(self.net.named.keys().cloned().collect())
            }

            fn step(&mut self, args: &[String]) -> Result<(), String> {
                let key = args.join(" ");
                if let Some(fail) = &self.fail_step
                    && (key == *fail || key.starts_with(&format!("{fail} ")))
                {
                    return Err(format!("injected failure of `{key}`"));
                }
                let arg = |n: usize| args.get(n).cloned().unwrap_or_default();
                match arg(0).as_str() {
                    "bridge" => {
                        self.exists(BRIDGE)?;
                        self.net
                            .add_dev(BRIDGE, "bridge", None, None, Some(&arg(1)));
                    }
                    "bridge-up" => {
                        self.net.host(BRIDGE).ok_or("Cannot find device br-mkm")?;
                    }
                    "netns" => {
                        if self.net.named.contains_key(&arg(1)) {
                            return Err(format!(
                                "Cannot create namespace file: File exists ({})",
                                arg(1)
                            ));
                        }
                        let inode = arg(2)
                            .strip_prefix("fake-holder:")
                            .and_then(|inode| inode.parse::<u64>().ok())
                            .ok_or_else(|| format!("not a namespace holder: {}", arg(2)))?;
                        self.net.named.insert(arg(1), inode);
                    }
                    "veth" => {
                        let inode = self.handle_inode(&arg(2))?;
                        let host = host_veth(&arg(1));
                        self.exists(&host)?;
                        if self
                            .net
                            .in_netns(Some(inode))
                            .iter()
                            .any(|l| l.name == PEER)
                        {
                            return Err("RTNETLINK answers: File exists (eth0)".to_string());
                        }
                        self.net.add_veth(&host, PEER, inode);
                    }
                    "port" => {
                        let host = host_veth(&arg(1));
                        let dev = self
                            .net
                            .devs
                            .iter_mut()
                            .find(|dev| dev.netns.is_none() && dev.id.name == host)
                            .ok_or_else(|| format!("Cannot find device {host}"))?;
                        dev.id.master = Some(BRIDGE.to_string());
                    }
                    "inside" => {
                        self.handle_inode(&arg(2))?;
                    }
                    other => return Err(format!("unknown step {other}")),
                }
                self.ops.push(format!("step {key}"));
                for (after, action) in self.after_step.iter_mut() {
                    if key == *after || key.starts_with(&format!("{after} ")) {
                        action(&mut self.net);
                    }
                }
                Ok(())
            }

            fn fresh_netns(&mut self, name: &str) -> Result<(NsId, String), String> {
                if self.net.held.contains_key(name) {
                    return Err(format!("the lab already holds a namespace for {name}"));
                }
                let inode = self.net.new_namespace();
                self.net.held.insert(name.to_string(), inode);
                Ok(((7, inode), format!("fake-holder:{inode}")))
            }

            fn netns_id(&mut self, name: &str) -> Result<Option<NsId>, String> {
                if self.blind {
                    return Err("injected: cannot stat netns".to_string());
                }
                Ok(self.net.named.get(name).map(|inode| (7, *inode)))
            }

            fn handle(&self, name: &str) -> Option<String> {
                self.net
                    .held
                    .get(name)
                    .map(|inode| format!("fake-handle:{inode}"))
            }

            fn links_in(&mut self, name: &str) -> Result<Vec<LinkId>, String> {
                let inode = self.held_inode(name)?;
                Ok(self.net.in_netns(Some(inode)))
            }

            fn delete_in(&mut self, name: &str, dev: &str) -> Result<(), String> {
                let inode = self.held_inode(name)?;
                self.ops.push(format!("delete-in {name} {dev}"));
                if self.net.del_dev(Some(inode), dev) {
                    Ok(())
                } else {
                    Err(format!("Cannot find device {dev}"))
                }
            }

            fn delete_link(&mut self, name: &str) -> Result<(), String> {
                self.ops.push(format!("delete-link {name}"));
                if self.net.del_dev(None, name) {
                    Ok(())
                } else {
                    Err(format!("Cannot find device {name}"))
                }
            }

            fn delete_netns(&mut self, name: &str) -> Result<(), String> {
                self.ops.push(format!("delete-netns {name}"));
                if self.net.del_netns(name) {
                    Ok(())
                } else {
                    Err(format!("Cannot remove namespace file {name}"))
                }
            }

            fn release(&mut self, name: &str) {
                if let Some(inode) = self.net.held.remove(name) {
                    self.net.reap(inode);
                }
            }

            fn pids_in(&mut self, name: &str) -> Result<Vec<i32>, String> {
                self.held_inode(name).map(|_| Vec::new())
            }
        }

        // ---- tests (no root, no network: the in-memory kernel) -----------------

        use super::mgmt_net::{Judge, Part, REQUIRED, Snapshot, judge_of};

        const MAC: &str = "02:6d:6b:00:00:01";

        /// A host with its management NIC, an unrelated `vh-uplink`, and
        /// someone else's netns with someone else's veth into it.
        fn host_net() -> FakeNet {
            let mut net = FakeNet::default();
            net.add_dev("lo", "", None, Some(1), Some("00:00:00:00:00:00"));
            net.add_dev("ens4", "", None, Some(2), Some("42:01:0a:92:00:15"));
            net.add_dev(
                "vh-uplink",
                "dummy",
                None,
                Some(4),
                Some("02:55:55:55:55:55"),
            );
            let other = net.add_netns("other");
            net.add_veth("vh-other", PEER, other);
            net
        }

        fn kernel(net: FakeNet) -> FakeKernel {
            FakeKernel {
                net,
                ..Default::default()
            }
        }

        fn complete_baseline() -> Snapshot {
            Snapshot {
                parts: REQUIRED
                    .iter()
                    .map(|label| Part {
                        label,
                        judge: judge_of(label).unwrap(),
                        content: Ok(String::new()),
                    })
                    .collect(),
            }
        }

        /// Every recorded resource, newest first, through `remove`.
        fn teardown(topology: &mut Topology, kernel: &mut FakeKernel) -> Vec<Result<(), String>> {
            topology
                .removal_order()
                .iter()
                .map(|created| topology.remove(kernel, created))
                .collect()
        }

        fn residue_of(topology: &Topology, kernel: &mut FakeKernel) -> Residue {
            let mut residue = Residue::default();
            topology.probe(kernel, &mut residue);
            residue
        }

        /// The host's devices as `ip -o link show` prints them.
        fn link_text(net: &FakeNet) -> String {
            net.in_netns(None)
                .iter()
                .map(|link| {
                    format!(
                        "{}: {}{}: <BROADCAST,MULTICAST,UP> mtu 1500{} state UP\\    link/ether {} brd ff:ff:ff:ff:ff:ff\n",
                        link.ifindex,
                        link.name,
                        link.peer.map(|p| format!("@if{p}")).unwrap_or_default(),
                        link.master
                            .as_ref()
                            .map(|m| format!(" master {m}"))
                            .unwrap_or_default(),
                        link.mac
                    )
                })
                .collect()
        }

        fn up(kernel: &mut FakeKernel) -> Topology {
            let mut topology = Topology::default();
            topology.up(kernel, MAC).unwrap();
            topology
        }

        /// 25 (normal path): everything the topology creates is recorded with
        /// the identity the kernel shows, and removed — every veth through the
        /// lab's own netns, never by its host name — and nothing else changes.
        #[test]
        fn lab_own_up_and_teardown_create_and_remove_only_their_own() {
            let mut k = kernel(host_net());
            let before = k.net.clone();
            preflight(&mut k, &complete_baseline()).unwrap();
            let mut topology = up(&mut k);
            assert_eq!(topology.created.len(), 1 + 2 * NAMESPACES.len());
            let owned = topology.owned_links();
            let names: Vec<String> = owned.iter().map(|link| link.name.clone()).collect();
            assert_eq!(names, lab_link_names());
            assert_eq!(owned[0].mac, MAC);
            for ns in NAMESPACES {
                let host = k.net.host(&host_veth(ns)).unwrap();
                assert_eq!(host.master.as_deref(), Some(BRIDGE), "{ns}");
                assert!(k.handle(ns).is_some(), "{ns} is held");
                assert_eq!(k.pids_in(ns), Ok(Vec::new()), "{ns}");
            }
            // the snapshot rule sees exactly the recorded identities
            assert_eq!(
                mgmt_net::verify_owned(&owned, &link_text(&k.net))
                    .unwrap()
                    .len(),
                owned.len()
            );
            let results = teardown(&mut topology, &mut k);
            assert!(results.iter().all(Result::is_ok), "{results:?}");
            let residue = residue_of(&topology, &mut k);
            assert!(residue.is_clean(), "{residue:?}");
            topology.release_all(&mut k);
            // exactly the state before: management NIC, vh-uplink, someone
            // else's netns and veth — byte for byte
            assert_eq!(k.net.devs, before.devs);
            assert_eq!(k.net.named, before.named);
            assert!(k.net.held.is_empty());
            assert!(
                !k.ops.iter().any(|op| op.starts_with("delete-link vh-")),
                "a veth was deleted by its host name: {:?}",
                k.ops
            );
            assert_eq!(
                k.ops
                    .iter()
                    .filter(|op| op.starts_with("delete-in "))
                    .count(),
                NAMESPACES.len()
            );
        }

        /// 1-3: a device or netns that already exists under a lab name stops
        /// everything before anything is created. If it appears only AFTER the
        /// preflight (concurrent creation), the create step fails and the
        /// teardown removes exactly what this run recorded: the other resource
        /// stays, unchanged, and is reported — never deleted.
        #[test]
        fn lab_own_preexisting_resources_are_refused_and_never_deleted() {
            type Plant = fn(&mut FakeNet);
            let cases: [(&str, &str, Plant, usize); 3] = [
                (
                    "existing vh-node-a",
                    "vh-node-a",
                    |net| {
                        let theirs = net.add_netns("theirs");
                        net.add_veth("vh-node-a", "p0", theirs);
                    },
                    2,
                ),
                (
                    "existing br-mkm",
                    "br-mkm",
                    |net| {
                        net.add_dev("br-mkm", "bridge", None, None, None);
                    },
                    0,
                ),
                (
                    "existing netns node-b",
                    "netns node-b",
                    |net| {
                        net.add_netns("node-b");
                    },
                    3,
                ),
            ];
            for (what, name, plant, recorded) in cases {
                let mut net = host_net();
                plant(&mut net);
                let mut k = kernel(net);
                let before = k.net.clone();
                // (a) there before the run: refused, nothing created
                let refused = preflight(&mut k, &complete_baseline()).expect_err(what);
                assert!(
                    refused.contains(name.trim_start_matches("netns ")),
                    "{what}: {refused}"
                );
                assert!(k.ops.is_empty(), "{what}: {:?}", k.ops);
                // (b) appeared after the preflight: the create step fails
                let mut topology = Topology::default();
                let failed = topology.up(&mut k, MAC).expect_err(what);
                assert!(failed.contains("File exists"), "{what}: {failed}");
                assert_eq!(topology.created.len(), recorded, "{what}");
                let results = teardown(&mut topology, &mut k);
                assert!(results.iter().all(Result::is_ok), "{what}: {results:?}");
                topology.release_all(&mut k);
                // the other resource is unchanged (identity and all), nothing
                // of the run is left, and the resource is reported as left
                assert_eq!(k.net.devs, before.devs, "{what}");
                assert_eq!(k.net.named, before.named, "{what}");
                let residue = residue_of(&topology, &mut k);
                assert_eq!(residue.left.len(), 1, "{what}: {residue:?}");
                assert!(residue.left[0].contains(name), "{what}: {residue:?}");
            }
        }

        /// 4 / 5: `up` fails halfway — at every step in turn. Exactly what was
        /// recorded is removed; nothing else is touched.
        #[test]
        fn lab_own_partial_up_removes_exactly_what_was_recorded() {
            let failing = [
                ("bridge", 0),
                ("bridge-up", 1),
                ("netns node-a", 1),
                ("veth node-a", 2),
                ("port node-a", 3),
                ("inside node-a", 3),
                ("netns witness", 5),
                ("veth client", 8),
                ("inside client", 9),
            ];
            for (step, recorded) in failing {
                let mut k = kernel(host_net());
                let before = k.net.clone();
                k.fail_step = Some(step.to_string());
                let mut topology = Topology::default();
                let failed = topology.up(&mut k, MAC).expect_err(step);
                assert!(failed.contains("injected failure"), "{step}: {failed}");
                assert_eq!(topology.created.len(), recorded, "{step}");
                let results = teardown(&mut topology, &mut k);
                assert!(results.iter().all(Result::is_ok), "{step}: {results:?}");
                assert!(residue_of(&topology, &mut k).is_clean(), "{step}");
                topology.release_all(&mut k);
                assert_eq!(k.net.devs, before.devs, "{step}");
                assert_eq!(k.net.named, before.named, "{step}");
            }
        }

        /// 5 / 6: a step "succeeds" but what its name shows right after is not
        /// what the lab made (replaced by someone else in between). It is NOT
        /// recorded, so it is never deleted: it is left and reported.
        #[test]
        fn lab_own_a_result_replaced_right_after_its_step_is_never_recorded() {
            type Swap = fn(&mut FakeNet);
            let cases: [(&str, &str, Swap, &str); 4] = [
                (
                    "veth node-b",
                    "vh-node-b",
                    |net| {
                        net.del_dev(None, "vh-node-b");
                        net.add_dev("vh-node-b", "dummy", None, None, None);
                    },
                    "vh-node-b not recorded",
                ),
                (
                    // the lab's veth renamed away and another VETH created
                    // under its name: its peer is not the lab's eth0
                    "veth node-b",
                    "vh-node-b",
                    |net| {
                        for dev in &mut net.devs {
                            if dev.netns.is_none() && dev.id.name == "vh-node-b" {
                                dev.id.name = "vh-renamed".to_string();
                            }
                        }
                        let theirs = net.add_netns("theirs");
                        net.add_veth("vh-node-b", "x-peer", theirs);
                    },
                    "is not paired with eth0",
                ),
                (
                    "netns witness",
                    "netns witness",
                    |net| {
                        net.del_netns("witness");
                        net.add_netns("witness");
                    },
                    "does not name the namespace the lab created",
                ),
                (
                    "bridge",
                    "br-mkm",
                    |net| {
                        net.del_dev(None, "br-mkm");
                        net.add_dev("br-mkm", "bridge", None, None, None);
                    },
                    "is not the bridge this step created",
                ),
            ];
            for (step, name, swap, why) in cases {
                let mut k = kernel(host_net());
                k.after_step.push((step.to_string(), Box::new(swap)));
                let mut topology = Topology::default();
                let failed = topology.up(&mut k, MAC).expect_err(step);
                assert!(failed.contains(why), "{step}: {failed}");
                let theirs_dev = k.net.host(name).clone();
                let theirs_ns = k.net.named.get("witness").copied();
                let results = teardown(&mut topology, &mut k);
                assert!(results.iter().all(Result::is_ok), "{step}: {results:?}");
                topology.release_all(&mut k);
                // the replacement is untouched and reported
                assert_eq!(k.net.host(name), theirs_dev, "{step}");
                assert_eq!(k.net.named.get("witness").copied(), theirs_ns, "{step}");
                let residue = residue_of(&topology, &mut k);
                assert_eq!(residue.left.len(), 1, "{step}: {residue:?}");
                assert!(residue.left[0].contains(name), "{step}: {residue:?}");
                assert!(
                    !k.ops
                        .iter()
                        .any(|op| op.ends_with(name.trim_start_matches("netns "))
                            && op.starts_with("delete")),
                    "{step}: {:?}",
                    k.ops
                );
            }
        }

        /// 6-8 / 10: after `up`, a lab device is replaced under its name — by
        /// a new device, by one re-using its ifindex, by one re-using its MAC —
        /// or its record no longer matches it. The snapshot rule reports an
        /// ownership loss, and the teardown leaves the device in place (FAIL),
        /// removing everything that IS still the lab's.
        #[test]
        fn lab_own_a_replaced_or_mismatched_device_is_left_in_place() {
            type Change = fn(&mut FakeNet, &LinkId);
            // (what, device, change, the snapshot rule sees it): a device that
            // forges BOTH the ifindex and the MAC differs only in its kind,
            // which `ip -o link show` (the snapshot's form) does not print —
            // the teardown (`ip -d`) still refuses it.
            let cases: [(&str, &str, Change, bool); 6] = [
                (
                    "same-name replacement",
                    "vh-node-a",
                    |net, old| {
                        net.del_dev(None, &old.name);
                        net.add_dev(&old.name, "dummy", None, None, None);
                    },
                    true,
                ),
                (
                    "ifindex reuse",
                    "vh-node-a",
                    |net, old| {
                        net.del_dev(None, &old.name);
                        net.add_dev(&old.name, "veth", None, Some(old.ifindex), None);
                    },
                    true,
                ),
                (
                    "MAC reuse",
                    "vh-node-a",
                    |net, old| {
                        net.del_dev(None, &old.name);
                        net.add_dev(&old.name, "veth", None, None, Some(&old.mac));
                    },
                    true,
                ),
                (
                    "bridge: ifindex reuse",
                    "br-mkm",
                    |net, old| {
                        net.del_dev(None, &old.name);
                        net.add_dev(&old.name, "bridge", None, Some(old.ifindex), None);
                    },
                    true,
                ),
                (
                    "bridge: MAC reuse",
                    "br-mkm",
                    |net, old| {
                        net.del_dev(None, &old.name);
                        net.add_dev(&old.name, "bridge", None, None, Some(&old.mac));
                    },
                    true,
                ),
                (
                    "bridge: same index, other kind",
                    "br-mkm",
                    |net, old| {
                        net.del_dev(None, &old.name);
                        net.add_dev(&old.name, "dummy", None, Some(old.ifindex), Some(&old.mac));
                    },
                    false,
                ),
            ];
            for (what, name, change, seen_by_snapshot) in cases {
                let mut k = kernel(host_net());
                let mut topology = up(&mut k);
                let old = k.net.host(name).unwrap();
                change(&mut k.net, &old);
                let theirs = k.net.host(name).unwrap();
                // the snapshot rule: ownership lost
                let lost = mgmt_net::verify_owned(&topology.owned_links(), &link_text(&k.net));
                assert_eq!(lost.is_err(), seen_by_snapshot, "{what}: {lost:?}");
                // the teardown: everything else removed, this one left
                let results = teardown(&mut topology, &mut k);
                let failed: Vec<&String> =
                    results.iter().filter_map(|r| r.as_ref().err()).collect();
                assert_eq!(failed.len(), 1, "{what}: {results:?}");
                assert!(failed[0].contains("left in place"), "{what}: {failed:?}");
                topology.release_all(&mut k);
                assert_eq!(
                    k.net.host(name),
                    Some(theirs),
                    "{what}: the device was touched"
                );
                let residue = residue_of(&topology, &mut k);
                assert!(
                    residue.left.iter().any(|l| l.contains(name)),
                    "{what}: {residue:?}"
                );
                for other in lab_link_names().iter().filter(|other| *other != name) {
                    assert!(k.net.host(other).is_none(), "{what}: {other} left");
                }
            }
            // 10: the record is wrong (the device is untouched, its record is not)
            for field in ["mac", "ifindex", "peer"] {
                let mut k = kernel(host_net());
                let mut topology = up(&mut k);
                for created in &mut topology.created {
                    if let Created::Veth { ns, host, peer } = created
                        && ns == "node-a"
                    {
                        match field {
                            "mac" => host.mac = "02:de:ad:be:ef:00".to_string(),
                            "ifindex" => host.ifindex += 1000,
                            _ => peer.ifindex += 1000,
                        }
                    }
                }
                assert!(
                    mgmt_net::verify_owned(&topology.owned_links(), &link_text(&k.net)).is_err()
                        || field == "peer",
                    "{field}"
                );
                let device = k.net.host("vh-node-a").unwrap();
                let results = teardown(&mut topology, &mut k);
                assert!(
                    results
                        .iter()
                        .any(|r| r.as_ref().is_err_and(|why| why.contains("left in place"))),
                    "{field}: {results:?}"
                );
                topology.release_all(&mut k);
                // left in place, never deleted by the lab: either still there
                // or gone only with the lab's own netns (its peer was there)
                assert!(
                    !k.ops.iter().any(|op| op == "delete-link vh-node-a"),
                    "{field}: {:?}",
                    k.ops
                );
                let _ = device;
            }
        }

        /// 6 (netns): a lab netns NAME re-pointed to someone else's namespace
        /// is left in place; the lab's own namespace (held) goes.
        #[test]
        fn lab_own_a_netns_name_pointing_elsewhere_is_left_in_place() {
            let mut k = kernel(host_net());
            let mut topology = up(&mut k);
            k.net.del_netns("node-b");
            let theirs = k.net.add_netns("node-b");
            let results = teardown(&mut topology, &mut k);
            let failed: Vec<&String> = results.iter().filter_map(|r| r.as_ref().err()).collect();
            assert_eq!(failed.len(), 1, "{results:?}");
            assert!(
                failed[0].contains("names a namespace the lab did not create"),
                "{failed:?}"
            );
            topology.release_all(&mut k);
            assert_eq!(k.net.named.get("node-b"), Some(&theirs));
            assert!(
                !k.ops.iter().any(|op| op == "delete-netns node-b"),
                "{:?}",
                k.ops
            );
            let residue = residue_of(&topology, &mut k);
            assert_eq!(residue.left, vec!["netns node-b".to_string()]);
        }

        /// 9: a lab-named device the lab holds no record of is never deleted
        /// (and, through the snapshot rule, never scoped out).
        #[test]
        fn lab_own_a_device_without_a_record_is_never_deleted() {
            let mut k = kernel(host_net());
            let mut topology = up(&mut k);
            topology
                .created
                .retain(|created| !matches!(created, Created::Bridge(_)));
            let results = teardown(&mut topology, &mut k);
            assert!(results.iter().all(Result::is_ok), "{results:?}");
            topology.release_all(&mut k);
            assert!(
                k.net.host(BRIDGE).is_some(),
                "an unrecorded bridge was deleted"
            );
            assert!(!k.ops.iter().any(|op| op == "delete-link br-mkm"));
            let residue = residue_of(&topology, &mut k);
            assert_eq!(residue.left.len(), 1, "{residue:?}");
            assert!(residue.left[0].contains(BRIDGE));
            assert!(
                mgmt_net::verify_owned(&topology.owned_links(), &link_text(&k.net))
                    .unwrap()
                    .is_empty()
            );
        }

        /// 13 (and the preflight's other refusals): an incomplete pre-run
        /// snapshot or an unknown inventory creates nothing.
        #[test]
        fn lab_own_preflight_refuses_an_incomplete_baseline_or_an_unknown_inventory() {
            let mut k = kernel(host_net());
            for label in REQUIRED {
                let mut baseline = complete_baseline();
                for part in &mut baseline.parts {
                    if part.label == label {
                        part.content = Err("ip failed".to_string());
                    }
                }
                let refused = preflight(&mut k, &baseline).expect_err(label);
                assert!(
                    refused.contains("pre-run management snapshot is incomplete"),
                    "{refused}"
                );
                assert!(refused.contains(label), "{refused}");
            }
            let mut short = complete_baseline();
            short.parts.pop();
            assert!(preflight(&mut k, &short).is_err());
            let mut wrong = complete_baseline();
            wrong.parts[0].judge = Judge::Exact;
            assert!(preflight(&mut k, &wrong).is_err());
            k.blind = true;
            let refused = preflight(&mut k, &complete_baseline()).unwrap_err();
            assert!(refused.contains("cannot be listed"), "{refused}");
            assert!(k.ops.is_empty());
        }

        /// 20: a residue check that cannot be made is "unknown" — a FAIL.
        #[test]
        fn lab_own_an_unknown_inventory_is_never_clean() {
            let mut k = kernel(host_net());
            let mut topology = up(&mut k);
            let results = teardown(&mut topology, &mut k);
            assert!(results.iter().all(Result::is_ok));
            topology.release_all(&mut k);
            k.blind = true;
            let residue = residue_of(&topology, &mut k);
            assert!(!residue.is_clean());
            assert_eq!(residue.unknown.len(), 2, "{residue:?}");
            let dir =
                std::env::temp_dir().join(format!("mkm-lab-own-probe-{}", std::process::id()));
            let mut paths = Residue::default();
            probe_path(&dir.join("absent"), "runtime dir", &mut paths);
            assert!(paths.is_clean());
            probe_path(Path::new("/"), "runtime dir", &mut paths);
            assert_eq!(paths.left.len(), 1);
        }

        // ---- the cleanup runner ----

        #[derive(Default)]
        struct Ctx {
            ran: Vec<String>,
        }

        fn step(name: &str, body: fn(&mut Ctx) -> Result<(), String>) -> Step<Ctx> {
            let label = name.to_string();
            (
                name.to_string(),
                Box::new(move |ctx: &mut Ctx| {
                    ctx.ran.push(label);
                    body(ctx)
                }),
            )
        }

        fn no_fault(_: &str) {}

        /// 14 / 15 / 16 / 18: a cleanup command that exits 1, one that cannot
        /// be started, a step that panics, a step that returns an error: each
        /// is reported as what it is, and every later step still runs.
        #[test]
        fn lab_own_every_cleanup_step_has_its_own_failure_boundary() {
            let mut ctx = Ctx::default();
            let steps = vec![
                step("exits 1", |_| command("/usr/bin/false", &[])),
                step("cannot start", |_| {
                    command("/nonexistent/mikagami-systemctl", &["stop", "x"])
                }),
                step("panics", |_| panic!("cleanup body exploded")),
                step("returns an error", |_| Err("left in place".to_string())),
                step("succeeds", |_| command("/usr/bin/true", &[])),
            ];
            let reports = run_steps(&mut ctx, steps, &no_fault);
            assert_eq!(
                ctx.ran,
                [
                    "exits 1",
                    "cannot start",
                    "panics",
                    "returns an error",
                    "succeeds"
                ]
            );
            assert!(
                matches!(&reports[0].end, StepEnd::Failed(why) if why.contains("/usr/bin/false")),
                "{reports:?}"
            );
            assert!(
                matches!(&reports[1].end, StepEnd::Failed(why) if why.contains("cannot run")),
                "{reports:?}"
            );
            assert_eq!(
                reports[2].end,
                StepEnd::Panicked("cleanup body exploded".to_string())
            );
            assert_eq!(reports[3].end, StepEnd::Failed("left in place".to_string()));
            assert_eq!(reports[4].end, StepEnd::Done);
            // the injected fault fires inside the boundary of the step it names
            let mut ctx = Ctx::default();
            let fault = |name: &str| {
                if name == "second" {
                    panic!("injected in {name}");
                }
            };
            let reports = run_steps(
                &mut ctx,
                vec![
                    step("first", |_| Ok(())),
                    step("second", |_| Ok(())),
                    step("third", |_| Ok(())),
                ],
                &fault,
            );
            assert_eq!(ctx.ran, ["first", "third"]);
            assert_eq!(
                reports[1].end,
                StepEnd::Panicked("injected in second".to_string())
            );
            assert_eq!(reports[2].end, StepEnd::Done);
        }

        /// 19 / 20: the three verdicts are separate. A clean management network
        /// does not make a cleanup with residue (or an unknown residue, or a
        /// failed step) a success.
        #[test]
        fn lab_own_residue_and_failed_steps_fail_even_with_a_clean_mgmt_network() {
            let done = vec![StepReport {
                name: "x".to_string(),
                end: StepEnd::Done,
            }];
            let verdict = |teardown: &Teardown| -> Vec<bool> {
                teardown
                    .verdicts()
                    .iter()
                    .map(|(_, pass, _)| *pass)
                    .collect()
            };
            let clean = Teardown {
                mgmt_clean: true,
                mgmt_report: String::new(),
                steps: done.clone(),
                residue: Residue::default(),
            };
            assert_eq!(verdict(&clean), [true, true, true]);
            let mut left = clean.clone();
            left.residue.left.push("netns node-a".to_string());
            assert_eq!(verdict(&left), [true, true, false]);
            assert!(
                left.render()
                    .contains("FAIL LAB nothing left after cleanup")
            );
            let mut unknown = clean.clone();
            unknown.residue.unknown.push("cannot list".to_string());
            assert_eq!(verdict(&unknown), [true, true, false]);
            let mut failed = clean.clone();
            failed.steps.push(StepReport {
                name: "systemctl stop".to_string(),
                end: StepEnd::Failed("exit 1".to_string()),
            });
            assert_eq!(verdict(&failed), [true, false, true]);
            let mut panicked = clean.clone();
            panicked.steps.push(StepReport {
                name: "remove".to_string(),
                end: StepEnd::Panicked("boom".to_string()),
            });
            assert_eq!(verdict(&panicked), [true, false, true]);
            assert!(panicked.failed_steps()[0].contains("PANICKED: boom"));
            let mut mgmt = clean.clone();
            mgmt.mgmt_clean = false;
            assert_eq!(verdict(&mgmt), [false, true, true]);
            assert_eq!(
                [CHECK_MGMT, CHECK_CLEANUP, CHECK_RESIDUE],
                [
                    clean.verdicts()[0].0,
                    clean.verdicts()[1].0,
                    clean.verdicts()[2].0
                ]
            );
        }

        /// 17: a cleanup step panics while the thread is ALREADY unwinding from
        /// the scenario's own panic (a `Drop`). The boundary catches it: no
        /// second panic leaves `drop`, the process does not abort, the later
        /// steps run, and the scenario's own panic is what the test reports.
        /// Run in a child process (an abort would otherwise kill the test run).
        #[test]
        fn lab_own_a_cleanup_panic_during_unwinding_does_not_abort() {
            const CHILD: &str = "MKM_LAB_OWN_UNWIND_CHILD";
            if let Some(marker) = std::env::var_os(CHILD) {
                struct Guard(std::path::PathBuf);
                impl Drop for Guard {
                    fn drop(&mut self) {
                        assert!(std::thread::panicking());
                        let mut ctx = Ctx::default();
                        let reports = run_steps(
                            &mut ctx,
                            vec![
                                step("first", |_| panic!("cleanup panic while unwinding")),
                                step("second", |_| Ok(())),
                            ],
                            &no_fault,
                        );
                        let text = format!("ran {:?}\nreports {:?}\n", ctx.ran, reports);
                        std::fs::write(&self.0, text).unwrap();
                    }
                }
                let _guard = Guard(std::path::PathBuf::from(marker));
                panic!("the scenario itself failed");
            }
            let marker = std::env::temp_dir().join(format!(
                "mkm-lab-own-unwind-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "daemon_run::tests::lab_own::lab_own_a_cleanup_panic_during_unwinding_does_not_abort",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD, &marker)
                .stdin(Stdio::null())
                .output()
                .unwrap();
            let written = std::fs::read_to_string(&marker).unwrap_or_default();
            let _ = std::fs::remove_file(&marker);
            let stderr = String::from_utf8_lossy(&output.stderr);
            // the child FAILED its test normally (exit 101), it did not abort
            assert_eq!(
                output.status.code(),
                Some(101),
                "{:?}\n{stderr}",
                output.status
            );
            assert!(stderr.contains("the scenario itself failed"), "{stderr}");
            assert!(written.contains("ran [\"first\", \"second\"]"), "{written}");
            assert!(
                written.contains("Panicked(\"cleanup panic while unwinding\")"),
                "{written}"
            );
            assert!(written.contains("Done"), "{written}");
        }

        /// The topology script holds create-only steps and nothing that deletes
        /// the lab topology: no `up` / `down` mode, no `del` outside the
        /// unchanged closeout `down-min`. Its names are the lab's names.
        #[test]
        fn lab_own_the_topology_script_only_creates() {
            let line = |prefix: &str| {
                TOPOLOGY_SH
                    .lines()
                    .find_map(|line| line.strip_prefix(prefix))
                    .unwrap_or_else(|| panic!("{prefix} not in vf-topology.sh"))
            };
            assert_eq!(line("BR="), BRIDGE);
            let namespaces: Vec<&str> = line("NS_LIST=\"")
                .trim_end_matches('"')
                .split_whitespace()
                .collect();
            assert_eq!(namespaces, NAMESPACES);
            let (before_min, min) = TOPOLOGY_SH.split_once("down_min() {").unwrap();
            let after_min = &min[min.find("\n}\n").unwrap()..];
            for text in [before_min, after_min] {
                for forbidden in [" del ", " del\n", "link del", "netns del"] {
                    assert!(!text.contains(forbidden), "`{forbidden}` in vf-topology.sh");
                }
            }
            for mode in ["    up)", "    down)"] {
                assert!(
                    !TOPOLOGY_SH.contains(mode),
                    "{mode} still in vf-topology.sh"
                );
            }
            for create in [
                "$IP link add \"$BR\" address \"${2:?bridge MAC}\" type bridge",
                "$IP netns attach \"$2\"",
                "$IP link add \"vh-$2\" type veth peer name eth0 netns \"${3:?netns handle}\"",
            ] {
                assert!(TOPOLOGY_SH.contains(create), "{create}");
            }
            assert!(!TOPOLOGY_SH.contains("netns add"));
            // and it parses (bash -n), every mode
            let dir = mgmt_net::Scratch::new().unwrap();
            let script = dir.path().join("vf-topology.sh");
            std::fs::write(&script, TOPOLOGY_SH).unwrap();
            let check = Command::new("bash")
                .arg("-n")
                .arg(&script)
                .output()
                .unwrap();
            assert!(
                check.status.success(),
                "bash -n: {}",
                String::from_utf8_lossy(&check.stderr)
            );
            let usage = Command::new("bash")
                .arg(&script)
                .arg("down")
                .output()
                .unwrap();
            assert_eq!(usage.status.code(), Some(64), "`down` is not a mode");
            // the inside of a lab netns is reached through the handle only
            assert!(!TOPOLOGY_SH.contains("$IP -n "));
        }
    }

    // ---- Phase 14.12 Linux virtual fencing lab (VF-1/2/3/4/6/7/8) ---------------
    //
    // TEST-ONLY. Environment construction, process control, input and
    // observation only. The system under test is the PRODUCTION binary
    // (`mikagami daemon run`, `mikagami status`, `mikagami recover`), its
    // PRODUCTION command backend (fence / verify spawned by the daemon), and
    // the existing Witness authority (through `u1_witness_host`). Nothing here
    // decides a grant, a rejection, an expiry, a promotion or a fencing state:
    // those are read back from the daemons' own log lines, `mikagami status`,
    // the Witness host's event log and the operating system.
    //
    // Topology (Rev5 §34.9): netns node-a / node-b / witness / client on the
    // host bridge br-mkm; the fence script sets the TARGET's host-side veth
    // down, the verify script reads that state. Run as root on the dedicated
    // lab VM only:
    //
    //   sudo MKM_VF_BIN=<target>/debug/mikagami <test-binary> \
    //        --ignored --exact daemon_run::tests::vf_lab::<vf-test> --nocapture
    #[cfg(target_os = "linux")]
    mod vf_lab {
        use super::lab_own::{self, Kernel, NsId, Teardown};
        use super::mgmt_net::{self, LinkId};
        use std::collections::BTreeMap;
        use std::io::{BufRead, BufReader, Write};
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        use std::os::unix::process::CommandExt;
        use std::path::{Path, PathBuf};
        use std::process::{Child, Command, Stdio};
        use std::sync::{Arc, Mutex};
        use std::thread::JoinHandle;
        use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

        const LIBEXEC: &str = "/usr/local/libexec/mikagami-vf";
        const RUNTIME: &str = "/run/mikagami-vf";
        const STATE_ROOT: &str = "/var/lib/mikagami-vf";
        const UNIT_DIR: &str = "/run/systemd/system";
        const VIP: &str = "192.0.2.50";
        const NAMESPACES: [&str; 4] = lab_own::NAMESPACES;
        const SERVE_TEST: &str = "daemon_run::tests::u1_witness_host::u1_lab_witness_host_serve";

        const LIBEXEC_FILES: [(&str, &str); 6] = [
            ("vf-common.sh", include_str!("../tests/lab/vf/vf-common.sh")),
            ("fence.sh", include_str!("../tests/lab/vf/fence.sh")),
            ("verify.sh", include_str!("../tests/lab/vf/verify.sh")),
            (
                "verify-forced-not-isolated.sh",
                include_str!("../tests/lab/vf/verify-forced-not-isolated.sh"),
            ),
            (
                "fence-hang.sh",
                include_str!("../tests/lab/vf/fence-hang.sh"),
            ),
            (
                "arping-stub.sh",
                include_str!("../tests/lab/vf/arping-stub.sh"),
            ),
        ];

        fn now_ms() -> u128 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        }

        /// Run a program and return (success, stdout + stderr).
        fn run(program: &str, args: &[&str]) -> (bool, String) {
            match Command::new(program).args(args).output() {
                Ok(output) => {
                    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
                    text.push_str(&String::from_utf8_lossy(&output.stderr));
                    (output.status.success(), text)
                }
                Err(error) => (false, format!("cannot run {program}: {error}")),
            }
        }

        fn run_ok(program: &str, args: &[&str]) -> String {
            let (ok, text) = run(program, args);
            assert!(ok, "{program} {args:?} failed: {text}");
            text
        }

        fn signal(pid: i32, sig: libc::c_int) {
            // SAFETY: plain kill(2) on a process this lab spawned.
            unsafe {
                libc::kill(pid, sig);
            }
        }

        fn pid_alive(pid: i32) -> bool {
            // SAFETY: signal 0 only probes existence.
            unsafe { libc::kill(pid, 0) == 0 }
        }

        /// Management-network snapshot (everything except the lab's own
        /// devices), compared before setup / during the run / after teardown.
        /// Phase 14.12 MC-1: the snapshot is raw text (nothing is normalised
        /// here) and the comparison is the audited `mgmt-net-compare.sh`
        /// (`mgmt_net::compare`).
        fn mgmt_snapshot(owned: &[LinkId]) -> mgmt_net::Snapshot {
            mgmt_snapshot_of(owned)
        }

        fn mgmt_snapshot_of(owned: &[LinkId]) -> mgmt_net::Snapshot {
            capture_mgmt_snapshot(
                &["/usr/sbin/ip"],
                &["/usr/bin/ss"],
                "/proc/sys/net/ipv4/ip_forward",
                owned,
            )
        }

        /// Read-only capture. `ip` / `ss` are a program plus leading arguments
        /// (the tests substitute `/bin/sh <stub>`). Only a successful command's
        /// stdout counts; a command that cannot run or exits non-zero is a part
        /// that FAILED to be captured (never an empty, equal-to-itself text).
        fn capture_mgmt_snapshot(
            ip: &[&str],
            ss: &[&str],
            ip_forward: &str,
            owned: &[LinkId],
        ) -> mgmt_net::Snapshot {
            use mgmt_net::{Judge, Part};
            fn stdout_of(command: &[&str], args: &[&str]) -> Result<String, String> {
                let (program, lead) = command.split_first().ok_or("empty command")?;
                match Command::new(program).args(lead).args(args).output() {
                    Ok(output) if output.status.success() => {
                        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
                    }
                    Ok(output) => Err(format!(
                        "{program} {args:?} exited with {}: {}",
                        output.status,
                        String::from_utf8_lossy(&output.stderr).trim_end()
                    )),
                    Err(error) => Err(format!("cannot run {program}: {error}")),
                }
            }
            // Only the lab's RECORDED devices that this very capture shows with
            // their recorded identity are excluded (`mgmt_net::scoped_ip_parts`):
            // the `link` part is taken before and after the other four.
            let link_first = (!owned.is_empty()).then(|| stdout_of(ip, &["-o", "link", "show"]));
            let mut texts = Vec::new();
            for (label, args) in [
                ("addr", vec!["-o", "addr", "show"]),
                ("route4", vec!["-4", "route", "show"]),
                ("route6", vec!["-6", "route", "show"]),
                ("rule", vec!["rule", "show"]),
                ("link", vec!["-o", "link", "show"]),
            ] {
                texts.push((label, stdout_of(ip, &args)));
            }
            let mut parts = mgmt_net::scoped_ip_parts(owned, link_first, texts);
            parts.push(Part {
                label: "ip_forward",
                judge: Judge::Exact,
                content: std::fs::read_to_string(ip_forward)
                    .map(|text| text.trim().to_string())
                    .map_err(|error| format!("cannot read {ip_forward}: {error}")),
            });
            parts.push(Part {
                label: "listen",
                judge: Judge::Exact,
                content: stdout_of(ss, &["-Hltn"]).map(|text| {
                    let mut listeners: Vec<&str> = text.lines().collect();
                    listeners.sort();
                    listeners.join("\n")
                }),
            });
            mgmt_net::Snapshot { parts }
        }

        // ---- MC-1 (remaining findings): the real kernel behind `lab_own` ------

        const IP: &str = "/usr/sbin/ip";
        const NSENTER: &str = "/usr/bin/nsenter";
        const UNSHARE: &str = "/usr/bin/unshare";

        fn nsid(meta: &std::fs::Metadata) -> NsId {
            (meta.dev(), meta.ino())
        }

        fn stdout_ok(program: &str, args: &[&str]) -> Result<String, String> {
            match Command::new(program)
                .args(args)
                .stdin(Stdio::null())
                .output()
            {
                Ok(output) if output.status.success() => {
                    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
                }
                Ok(output) => Err(format!(
                    "{program} {args:?} ended with {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim_end()
                )),
                Err(error) => Err(format!("cannot run {program}: {error}")),
            }
        }

        fn parse_links(text: &str) -> Vec<LinkId> {
            text.lines().filter_map(mgmt_net::link_id).collect()
        }

        /// A namespace the lab holds: an open handle (`/proc/<pid>/fd/<n>`
        /// names it), and, until its name is attached, the process that
        /// created it.
        struct Held {
            file: std::fs::File,
            holder: Option<Child>,
        }

        fn retire(holder: &mut Option<Child>) {
            if let Some(mut child) = holder.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }

        /// The real kernel: `ip` / `nsenter` / `unshare`, the topology script,
        /// and the netns run directory (`/run/netns`).
        pub(super) struct RealKernel {
            script: PathBuf,
            netns_dir: PathBuf,
            held: BTreeMap<String, Held>,
        }

        impl RealKernel {
            pub(super) fn new(script: PathBuf) -> Self {
                Self {
                    script,
                    netns_dir: PathBuf::from("/run/netns"),
                    held: BTreeMap::new(),
                }
            }

            fn held_path(&self, name: &str) -> Result<String, String> {
                self.handle(name)
                    .ok_or_else(|| format!("the lab holds no handle on netns {name}"))
            }
        }

        impl Kernel for RealKernel {
            fn links(&mut self) -> Result<Vec<LinkId>, String> {
                stdout_ok(IP, &["-d", "-o", "link", "show"]).map(|text| parse_links(&text))
            }

            fn netns_names(&mut self) -> Result<Vec<String>, String> {
                match std::fs::read_dir(&self.netns_dir) {
                    Ok(entries) => entries
                        .map(|entry| {
                            entry
                                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                                .map_err(|error| error.to_string())
                        })
                        .collect(),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
                    Err(error) => Err(format!("cannot read {}: {error}", self.netns_dir.display())),
                }
            }

            fn step(&mut self, args: &[String]) -> Result<(), String> {
                let mut full = vec![self.script.to_string_lossy().into_owned()];
                full.extend(args.iter().cloned());
                let full: Vec<&str> = full.iter().map(String::as_str).collect();
                let result = lab_own::command("/usr/bin/bash", &full);
                // the name is attached (or not): the holder process is done
                if args.first().map(String::as_str) == Some("netns")
                    && let Some(held) = args.get(1).and_then(|name| self.held.get_mut(name))
                {
                    retire(&mut held.holder);
                }
                result
            }

            fn fresh_netns(&mut self, name: &str) -> Result<(NsId, String), String> {
                if self.held.contains_key(name) {
                    return Err(format!("the lab already holds a namespace for {name}"));
                }
                let mut holder = Command::new(UNSHARE)
                    .args([
                        "--net",
                        "--",
                        "/bin/sh",
                        "-c",
                        "echo ready; exec /usr/bin/sleep 3600",
                    ])
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                    .map_err(|error| format!("cannot start a namespace holder: {error}"))?;
                let mut line = String::new();
                let ready = holder
                    .stdout
                    .take()
                    .map(|out| BufReader::new(out).read_line(&mut line));
                let pid = holder.id();
                let opened = if matches!(ready, Some(Ok(_))) && line.trim() == "ready" {
                    std::fs::File::open(format!("/proc/{pid}/ns/net"))
                        .and_then(|file| file.metadata().map(|meta| (nsid(&meta), file)))
                        .map_err(|error| format!("cannot hold the new namespace: {error}"))
                } else {
                    Err(format!("the namespace holder did not start ({line:?})"))
                };
                let own = std::fs::metadata("/proc/self/ns/net").map(|meta| nsid(&meta));
                match (opened, own) {
                    // a NEW namespace, never the one the lab itself runs in
                    (Ok((id, file)), Ok(own)) if id != own => {
                        self.held.insert(
                            name.to_string(),
                            Held {
                                file,
                                holder: Some(holder),
                            },
                        );
                        Ok((id, pid.to_string()))
                    }
                    (opened, own) => {
                        let mut holder = Some(holder);
                        retire(&mut holder);
                        Err(format!(
                            "no new namespace for {name} (held: {:?}; own: {own:?})",
                            opened.map(|(id, _)| id)
                        ))
                    }
                }
            }

            fn netns_id(&mut self, name: &str) -> Result<Option<NsId>, String> {
                match std::fs::metadata(self.netns_dir.join(name)) {
                    Ok(meta) => Ok(Some(nsid(&meta))),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    Err(error) => Err(format!("cannot stat netns {name}: {error}")),
                }
            }

            fn handle(&self, name: &str) -> Option<String> {
                self.held.get(name).map(|held| {
                    format!("/proc/{}/fd/{}", std::process::id(), held.file.as_raw_fd())
                })
            }

            fn links_in(&mut self, name: &str) -> Result<Vec<LinkId>, String> {
                let net = format!("--net={}", self.held_path(name)?);
                stdout_ok(NSENTER, &[&net, "--", IP, "-d", "-o", "link", "show"])
                    .map(|text| parse_links(&text))
            }

            fn delete_in(&mut self, name: &str, dev: &str) -> Result<(), String> {
                let net = format!("--net={}", self.held_path(name)?);
                lab_own::command(NSENTER, &[&net, "--", IP, "link", "del", "dev", dev])
            }

            fn delete_link(&mut self, name: &str) -> Result<(), String> {
                lab_own::command(IP, &["link", "del", "dev", name])
            }

            fn delete_netns(&mut self, name: &str) -> Result<(), String> {
                lab_own::command(IP, &["netns", "del", name])
            }

            fn release(&mut self, name: &str) {
                if let Some(mut held) = self.held.remove(name) {
                    retire(&mut held.holder);
                }
            }

            fn pids_in(&mut self, name: &str) -> Result<Vec<i32>, String> {
                let target = self
                    .held
                    .get(name)
                    .ok_or_else(|| format!("the lab holds no handle on netns {name}"))?
                    .file
                    .metadata()
                    .map(|meta| nsid(&meta))
                    .map_err(|error| error.to_string())?;
                let mut pids = Vec::new();
                for entry in std::fs::read_dir("/proc").map_err(|error| error.to_string())? {
                    let Ok(entry) = entry else { continue };
                    let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
                        continue;
                    };
                    if let Ok(meta) = std::fs::metadata(format!("/proc/{pid}/ns/net"))
                        && nsid(&meta) == target
                    {
                        pids.push(pid);
                    }
                }
                Ok(pids)
            }
        }

        impl Drop for RealKernel {
            fn drop(&mut self) {
                for held in self.held.values_mut() {
                    retire(&mut held.holder);
                }
            }
        }

        /// A run-unique, locally administered unicast MAC for the bridge.
        fn run_unique_mac() -> String {
            let mut random = [0u8; 3];
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut random))
                .expect("/dev/urandom");
            format!(
                "02:6d:6b:{:02x}:{:02x}:{:02x}",
                random[0], random[1], random[2]
            )
        }

        // ---- Phase 14.12 MC-1: the capture on stored data (no root, no network) ----

        macro_rules! mgmt_fixture {
            ($name:literal) => {
                include_str!(concat!("../tests/lab/vf/fixtures/mgmt-net/", $name))
            };
        }

        /// A stand-in for `ip` (run as `/bin/sh <file>`, so no freshly written
        /// executable is ever exec'd by a multi-threaded test process): it
        /// serves stored text for the five read-only forms, can fail one of
        /// them, and refuses every other invocation with exit 99.
        fn stub_ip(parts: &[(&str, &str)], failing: Option<&str>) -> String {
            let mut script = String::from("case \"$*\" in\n");
            for (args, text) in parts {
                if Some(*args) == failing {
                    script.push_str(&format!(
                        "\"{args}\") echo 'stub: forced failure' >&2; exit 1 ;;\n"
                    ));
                } else {
                    script.push_str(&format!(
                        "\"{args}\") cat <<'__MKM_END__'\n{text}__MKM_END__\n;;\n"
                    ));
                }
            }
            script.push_str("*) echo \"stub: not a read-only form: $*\" >&2; exit 99 ;;\nesac\n");
            script
        }

        const STUB_FORMS: [&str; 5] = [
            "-o addr show",
            "-4 route show",
            "-6 route show",
            "rule show",
            "-o link show",
        ];

        struct Stored {
            addr: String,
            route4: String,
            route6: String,
            rule: String,
            link: String,
        }

        fn stored() -> Stored {
            Stored {
                addr: mgmt_fixture!("real-addr-before.txt").to_string(),
                route4: mgmt_fixture!("real-route-before.txt").to_string(),
                route6: mgmt_fixture!("driver-route6.txt").to_string(),
                rule: mgmt_fixture!("driver-rule.txt").to_string(),
                link: mgmt_fixture!("driver-link.txt").to_string(),
            }
        }

        /// Capture `net` through the stub; `failing` makes one form exit 1.
        /// Nothing is scoped out (the pre-run capture).
        fn capture_stored(net: &Stored, failing: Option<&str>) -> mgmt_net::Snapshot {
            capture_stored_owned(net, failing, &[])
        }

        /// What the earlier Rust comparison could not see now FAILs (link state,
        /// 0sec / forever) and what it wrongly flagged now passes (route expiry
        /// seconds) — through the capture and the comparison together.
        #[test]
        fn mgmt_snapshot_end_to_end_verdicts_follow_the_audited_script() {
            let before = capture_stored(&stored(), None);
            let mutate = |edit: &dyn Fn(&mut Stored)| {
                let mut net = stored();
                edit(&mut net);
                mgmt_net::compare(&before, &capture_stored(&net, None))
            };
            let lease = "valid_lft 2159sec preferred_lft 2159sec";
            assert!(mutate(&|n| n.addr = mgmt_fixture!("real-addr-after.txt").to_string()).pass);
            assert!(!mutate(&|n| n.addr = n.addr.replace("10.146.0.21/32", "10.146.0.22/32")).pass);
            assert!(
                !mutate(&|n| n.addr = n
                    .addr
                    .replace(lease, "valid_lft 0sec preferred_lft 2159sec"))
                .pass
            );
            assert!(
                !mutate(&|n| n.addr = n
                    .addr
                    .replace(lease, "valid_lft forever preferred_lft forever"))
                .pass
            );
            assert!(!mutate(&|n| n.link = n.link.replace("state UP", "state DOWN")).pass);
            assert!(!mutate(&|n| n.rule.push_str("100:\tfrom 10.0.0.0/8 lookup 100\n")).pass);
            assert!(!mutate(&|n| n.route4 = n.route4.replace("metric 100", "metric 300")).pass);
            // route expiry seconds only: the earlier comparison flagged this
            let ra =
                "default via fe80::1 dev ens4 proto ra metric 1024 expires 1790sec pref medium\n";
            let mut with_ra = stored();
            with_ra.route6 = ra.to_string();
            let ra_before = capture_stored(&with_ra, None);
            with_ra.route6 = ra.replace("1790", "1600");
            assert!(mgmt_net::compare(&ra_before, &capture_stored(&with_ra, None)).pass);
        }

        /// A capture that cannot be taken is a failed snapshot, never an empty
        /// text equal to itself: every `ip` form failing in turn, a missing
        /// program, and an unreadable /proc file all make the comparison FAIL
        /// even when both sides failed the same way.
        #[test]
        fn mgmt_snapshot_capture_failure_is_a_fail() {
            for form in STUB_FORMS {
                let broken = capture_stored(&stored(), Some(form));
                assert!(
                    broken.parts.iter().any(|part| part.content.is_err()),
                    "{form}: {broken}"
                );
                assert!(
                    !mgmt_net::compare(&broken, &broken).pass,
                    "{form}: both failed"
                );
                let good = capture_stored(&stored(), None);
                assert!(
                    !mgmt_net::compare(&good, &broken).pass,
                    "{form}: after failed"
                );
                assert!(
                    !mgmt_net::compare(&broken, &good).pass,
                    "{form}: before failed"
                );
            }
            let missing = capture_mgmt_snapshot(
                &["/nonexistent/ip"],
                &["/nonexistent/ss"],
                "/nonexistent/ip_forward",
                &[],
            );
            assert!(
                missing.parts.iter().all(|part| part.content.is_err()),
                "{missing}"
            );
            assert!(!mgmt_net::compare(&missing, &missing).pass);
        }

        /// LIVE, read-only (`ip ... show`, `ss -Hltn`, /proc): two snapshots of
        /// the real management network a moment apart compare as stable. Run on
        /// the lab VM: `<test-binary> --ignored --exact
        /// daemon_run::tests::vf_lab::mgmt_snapshot_live_is_stable`.
        #[test]
        #[ignore = "reads the live management network (read-only); run on the lab VM"]
        fn mgmt_snapshot_live_is_stable() {
            let nothing_owned: Vec<LinkId> = Vec::new();
            let first = mgmt_snapshot(&nothing_owned);
            assert!(
                first.parts.iter().all(|part| part.content.is_ok()),
                "{first}"
            );
            std::thread::sleep(Duration::from_secs(3));
            let verdict = mgmt_net::compare(&first, &mgmt_snapshot(&nothing_owned));
            assert!(verdict.pass, "{}", verdict.report);
        }

        // ---- MC-1 remaining findings (R3 identity / R2 cleanup), no root, no lab ----

        /// Two lab devices as the topology makes them (bridge with its
        /// run-unique MAC, a veth enslaved to it).
        const LAB_LINK_LINES: &str = "5: br-mkm: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000\\    link/ether 02:6d:6b:00:00:05 brd ff:ff:ff:ff:ff:ff\n6: vh-node-a@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-mkm state UP mode DEFAULT group default qlen 1000\\    link/ether 02:00:00:00:00:06 brd ff:ff:ff:ff:ff:ff link-netns node-a\n";

        /// The lab's ownership records of `LAB_LINK_LINES`.
        fn lab_records() -> Vec<LinkId> {
            LAB_LINK_LINES
                .lines()
                .filter_map(mgmt_net::link_id)
                .collect()
        }

        /// `capture_stored` with the lab's recorded devices scoped out.
        fn capture_stored_owned(
            net: &Stored,
            failing: Option<&str>,
            owned: &[LinkId],
        ) -> mgmt_net::Snapshot {
            let dir = mgmt_net::Scratch::new().unwrap();
            let ip_script = dir.path().join("ip.sh");
            let ss_script = dir.path().join("ss.sh");
            let forward = dir.path().join("ip_forward");
            let texts = [&net.addr, &net.route4, &net.route6, &net.rule, &net.link];
            let served: Vec<(&str, &str)> = STUB_FORMS
                .iter()
                .zip(texts)
                .map(|(form, text)| (*form, text.as_str()))
                .collect();
            std::fs::write(&ip_script, stub_ip(&served, failing)).unwrap();
            std::fs::write(&ss_script, "exit 0\n").unwrap();
            std::fs::write(&forward, "0\n").unwrap();
            capture_mgmt_snapshot(
                &["/bin/sh", ip_script.to_str().unwrap()],
                &["/bin/sh", ss_script.to_str().unwrap()],
                forward.to_str().unwrap(),
                owned,
            )
        }

        fn with_lab_devices(net: &mut Stored) {
            net.addr.push_str("5: br-mkm    inet6 fe80::1/64 scope link \\       valid_lft forever preferred_lft forever\n6: vh-node-a    inet6 fe80::2/64 scope link \\       valid_lft forever preferred_lft forever\n");
            net.route4
                .push_str("192.168.77.0/24 dev br-mkm proto kernel scope link\n");
            net.link.push_str(LAB_LINK_LINES);
        }

        /// Through the real capture (stub `ip`): the management NIC called
        /// `vh-uplink` (and other lab-looking names) survives the scoping, so a
        /// change of it while the lab runs is a FAIL (11), and so is a change
        /// of `ens4` (12), whereas the lab's recorded devices are scoped out.
        #[test]
        fn mgmt_snapshot_keeps_an_unrelated_nic_that_looks_like_a_lab_device() {
            let mut base_net = stored();
            base_net.addr.push_str("4: vh-uplink    inet 10.5.5.5/24 scope global vh-uplink\\       valid_lft forever preferred_lft forever\n");
            base_net.link.push_str("4: vh-uplink: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\\    link/ether 02:55:55:55:55:55 brd ff:ff:ff:ff:ff:ff\n");
            base_net
                .route4
                .push_str("10.5.5.0/24 dev vh-uplink proto kernel scope link src 10.5.5.5\n");
            let before = capture_stored_owned(&base_net, None, &[]);
            let owned = lab_records();
            // control: only the lab's devices appeared => PASS
            let mut during = stored();
            during.addr = base_net.addr.clone();
            during.link = base_net.link.clone();
            during.route4 = base_net.route4.clone();
            with_lab_devices(&mut during);
            let verdict = mgmt_net::compare(&before, &capture_stored_owned(&during, None, &owned));
            assert!(verdict.pass, "{}", verdict.report);
            // the uplink's address changes while the lab runs => FAIL
            let mut moved = stored();
            moved.addr = during.addr.replace("10.5.5.5/24", "10.5.5.6/24");
            moved.link = during.link.clone();
            moved.route4 = during.route4.clone();
            let verdict = mgmt_net::compare(&before, &capture_stored_owned(&moved, None, &owned));
            assert!(!verdict.pass, "{}", verdict.report);
            assert!(
                verdict
                    .report
                    .contains("addr: FAIL management network changed"),
                "{}",
                verdict.report
            );
            // every other part of that NIC too
            let mut down = stored();
            down.addr = during.addr.clone();
            down.route4 = during.route4.clone();
            down.link = during
                .link
                .replace("fq_codel state UP", "fq_codel state DOWN");
            assert!(!mgmt_net::compare(&before, &capture_stored_owned(&down, None, &owned)).pass);
            let mut rerouted = stored();
            rerouted.addr = during.addr.clone();
            rerouted.link = during.link.clone();
            rerouted.route4 = during.route4.replace("src 10.5.5.5", "src 10.5.5.6");
            assert!(
                !mgmt_net::compare(&before, &capture_stored_owned(&rerouted, None, &owned)).pass
            );
            // the management NIC itself
            let mut ens4 = stored();
            ens4.addr = during.addr.replace("10.146.0.21/32", "10.146.0.22/32");
            ens4.link = during.link.clone();
            ens4.route4 = during.route4.clone();
            assert!(!mgmt_net::compare(&before, &capture_stored_owned(&ens4, None, &owned)).pass);
        }

        /// F-AUD-R3-IDENTITY through the real capture: a lab device replaced
        /// under its name while the lab runs (a new ifindex/MAC), or one the lab
        /// holds no record of, is NOT scoped out — and an ownership loss makes
        /// the capture itself fail, so the same replacement on both sides
        /// cannot pass either. `mkm0` (not the lab's) is never scoped out.
        #[test]
        fn mgmt_snapshot_never_hides_a_replaced_or_unrecorded_device() {
            let before = capture_stored(&stored(), None);
            let owned = lab_records();
            let mut during = stored();
            with_lab_devices(&mut during);
            assert!(mgmt_net::compare(&before, &capture_stored_owned(&during, None, &owned)).pass);
            let mut replaced = during.clone_net();
            replaced.link = replaced
                .link
                .replace("6: vh-node-a@if2", "200: vh-node-a@if2")
                .replace("02:00:00:00:00:06", "aa:bb:cc:dd:ee:ff");
            replaced.addr = replaced.addr.replace("6: vh-node-a", "200: vh-node-a");
            let snapshot = capture_stored_owned(&replaced, None, &owned);
            let link = snapshot
                .parts
                .iter()
                .find(|part| part.label == "link")
                .unwrap();
            assert!(
                matches!(&link.content, Err(why) if why.contains("ownership NOT shown")),
                "{snapshot}"
            );
            assert!(!mgmt_net::compare(&before, &snapshot).pass);
            assert!(!mgmt_net::compare(&snapshot, &snapshot).pass);
            // no record of vh-node-a: it stays in the snapshot => a difference
            let verdict =
                mgmt_net::compare(&before, &capture_stored_owned(&during, None, &owned[..1]));
            assert!(!verdict.pass, "{}", verdict.report);
            // a device the lab did not create (mkm0) is compared like any other
            let mut with_mkm0 = during.clone_net();
            with_mkm0.addr.push_str("7: mkm0    inet 192.0.2.50/24 scope global mkm0\\       valid_lft forever preferred_lft forever\n");
            assert!(
                !mgmt_net::compare(&before, &capture_stored_owned(&with_mkm0, None, &owned)).pass
            );
        }

        impl Stored {
            fn clone_net(&self) -> Stored {
                Stored {
                    addr: self.addr.clone(),
                    route4: self.route4.clone(),
                    route6: self.route6.clone(),
                    rule: self.rule.clone(),
                    link: self.link.clone(),
                }
            }
        }

        // ---- F-MC-R2 / F-AUD-R2-*: the teardown decides the scenario ----

        #[derive(Clone, Copy)]
        enum Seen {
            Same,
            Changed,
            NotComparable,
            Panics,
        }

        impl Lab {
            /// A lab for tests: everything it "created" lives in an in-memory
            /// kernel (`kernel`, `topology`) or under `dir`; its cleanup is the
            /// REAL cleanup (`cleanup_steps`, `run_steps`, `probe_residue`),
            /// run against those; snapshots come from `source`.
            fn inert(
                dir: &Path,
                mgmt_before: mgmt_net::Snapshot,
                topology: lab_own::Topology,
                kernel: Box<dyn Kernel>,
                source: Box<dyn Fn(&[LinkId]) -> mgmt_net::Snapshot>,
            ) -> Self {
                let open = |name: &str| {
                    std::fs::OpenOptions::new()
                        .create_new(true)
                        .append(true)
                        .open(dir.join(name))
                        .unwrap()
                };
                Self {
                    name: "inert".to_string(),
                    dir: dir.to_path_buf(),
                    bin: PathBuf::new(),
                    test_bin: PathBuf::new(),
                    procs: Vec::new(),
                    attempts: Default::default(),
                    created_runtime: false,
                    created_libexec_parent: false,
                    created_libexec: false,
                    created_state_root: false,
                    units: Vec::new(),
                    mgmt_before,
                    topology,
                    kernel,
                    snapshot_source: source,
                    systemctl: "/usr/bin/true".to_string(),
                    runtime: dir.join("runtime"),
                    libexec: dir.join("libexec"),
                    unit_dir: dir.join("units"),
                    cleanup_fault: None,
                    teardown_started: false,
                    teardown_report: None,
                    timeline: open("timeline.txt"),
                    checks: Vec::new(),
                    checks_file: open("checks.txt"),
                }
            }
        }

        /// Every set of recorded devices a snapshot was taken with, in order.
        type Calls = std::rc::Rc<std::cell::RefCell<Vec<Vec<LinkId>>>>;

        fn new_calls() -> Calls {
            Default::default()
        }

        /// The in-memory kernel the inert labs run against, and the topology
        /// the lab "created" in it (recorded by the real `Topology::up`).
        fn fake_topology() -> (lab_own::Topology, lab_own::FakeKernel) {
            let mut kernel = lab_own::FakeKernel::default();
            kernel
                .net
                .add_dev("ens4", "", None, Some(2), Some("42:01:0a:92:00:15"));
            let mut topology = lab_own::Topology::default();
            topology.up(&mut kernel, "02:6d:6b:00:00:01").unwrap();
            (topology, kernel)
        }

        /// An inert lab whose `during` / `after` snapshots are `during` /
        /// `after` (call 0 = the during-run snapshot in `finish`, call 1 = the
        /// after-teardown one); `calls` records the devices of every snapshot.
        fn inert_lab(dir: &Path, during: Seen, after: Seen, calls: &Calls) -> Lab {
            let (topology, kernel) = fake_topology();
            inert_lab_with(dir, during, after, calls, topology, Box::new(kernel))
        }

        fn inert_lab_with(
            dir: &Path,
            during: Seen,
            after: Seen,
            calls: &Calls,
            topology: lab_own::Topology,
            kernel: Box<dyn Kernel>,
        ) -> Lab {
            let before = capture_stored(&stored(), None);
            let record = std::rc::Rc::clone(calls);
            let source = move |owned: &[LinkId]| {
                let n = record.borrow().len();
                record.borrow_mut().push(owned.to_vec());
                match if n == 0 { during } else { after } {
                    Seen::Same => capture_stored(&stored(), None),
                    Seen::Changed => {
                        let mut net = stored();
                        net.addr = net.addr.replace("10.146.0.21/32", "10.146.0.22/32");
                        capture_stored(&net, None)
                    }
                    Seen::NotComparable => capture_stored(&stored(), Some("-o link show")),
                    Seen::Panics => panic!("the snapshot source exploded"),
                }
            };
            Lab::inert(dir, before, topology, kernel, Box::new(source))
        }

        fn panic_text(result: Result<(), Box<dyn std::any::Any + Send>>) -> Option<String> {
            result
                .err()
                .map(|payload| lab_own::panic_message(&*payload))
        }

        fn finish_outcome(lab: &mut Lab) -> Option<String> {
            panic_text(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || lab.finish(),
            )))
        }

        fn read(dir: &Path, name: &str) -> String {
            std::fs::read_to_string(dir.join(name)).unwrap_or_default()
        }

        #[test]
        fn lab_finish_passes_only_when_the_teardown_is_clean() {
            let dir = mgmt_net::Scratch::new().unwrap();
            let calls = new_calls();
            let mut lab = inert_lab(dir.path(), Seen::Same, Seen::Same, &calls);
            let owned = lab.topology.owned_links();
            assert_eq!(owned.len(), 1 + NAMESPACES.len());
            assert_eq!(finish_outcome(&mut lab), None, "a clean run passes");
            assert_eq!(
                calls.borrow().len(),
                2,
                "during-run snapshot + after-teardown snapshot"
            );
            // the during-run snapshot scopes out the lab's RECORDED devices; the
            // after-teardown one scopes out NOTHING
            assert_eq!(calls.borrow()[0], owned);
            assert!(calls.borrow()[1].is_empty());
            let teardown = lab.teardown_report.clone().expect("the teardown ran");
            assert!(teardown.failed_steps().is_empty(), "{:?}", teardown.steps);
            assert!(teardown.residue.is_clean(), "{:?}", teardown.residue);
            drop(lab);
            assert_eq!(calls.borrow().len(), 2, "Drop repeats nothing");
            let checks = read(dir.path(), "checks.txt");
            for id in [
                "MGMT-NET during-run snapshot equals pre-run",
                lab_own::CHECK_MGMT,
                lab_own::CHECK_CLEANUP,
                lab_own::CHECK_RESIDUE,
            ] {
                assert!(checks.contains(&format!("PASS {id}")), "{id}: {checks}");
            }
            assert!(read(dir.path(), "timeline.txt").contains("teardown: mgmt-net identical"));
            assert!(read(dir.path(), "teardown.txt").contains("PASS LAB nothing left"));
            assert!(read(dir.path(), "topology.txt").contains("remove bridge br-mkm"));
            assert!(!dir.path().join("mgmt-after-compare.txt").exists());
        }

        #[test]
        fn lab_finish_fails_when_the_management_network_differs_after_teardown() {
            let dir = mgmt_net::Scratch::new().unwrap();
            let calls = new_calls();
            let mut lab = inert_lab(dir.path(), Seen::Same, Seen::Changed, &calls);
            let message = finish_outcome(&mut lab).expect("the scenario must FAIL");
            assert!(message.contains("VF scenario inert FAILED"), "{message}");
            assert!(message.contains(lab_own::CHECK_MGMT), "{message}");
            // the evidence is kept
            assert!(
                read(dir.path(), "mgmt-after-compare.txt")
                    .contains("addr: FAIL management network changed")
            );
            assert!(read(dir.path(), "mgmt-after.txt").contains("10.146.0.22/32"));
            assert!(
                read(dir.path(), "checks.txt")
                    .contains("FAIL MGMT-NET after-teardown snapshot equals pre-run")
            );
            assert!(read(dir.path(), "timeline.txt").contains("teardown: mgmt-net DIFFERENT"));
            let teardown = lab.teardown_report.clone().expect("the teardown ran");
            assert!(!teardown.mgmt_clean && teardown.residue.is_clean());
            assert!(teardown.mgmt_report.contains("addr: FAIL"));
            drop(lab);
            assert_eq!(calls.borrow().len(), 2, "the cleanup did not run twice");
        }

        #[test]
        fn lab_finish_fails_when_the_teardown_comparison_cannot_be_made() {
            for after in [Seen::NotComparable, Seen::Panics] {
                let dir = mgmt_net::Scratch::new().unwrap();
                let calls = new_calls();
                let mut lab = inert_lab(dir.path(), Seen::Same, after, &calls);
                let message = finish_outcome(&mut lab).expect("not comparable => FAIL");
                assert!(message.contains("VF scenario inert FAILED"), "{message}");
                assert!(message.contains(lab_own::CHECK_MGMT), "{message}");
                let report = read(dir.path(), "mgmt-after-compare.txt");
                assert!(
                    report.contains("snapshot not captured") || report.contains("panicked"),
                    "{report}"
                );
                drop(lab);
            }
        }

        /// The existing verdicts are kept, and the cleanup still ran: a
        /// during-run difference, or a failed scenario check, fails the
        /// scenario; the teardown comparison is made in every case.
        #[test]
        fn lab_finish_keeps_its_other_verdicts_and_always_tears_down() {
            let dir = mgmt_net::Scratch::new().unwrap();
            let calls = new_calls();
            let mut lab = inert_lab(dir.path(), Seen::Changed, Seen::Same, &calls);
            let message = finish_outcome(&mut lab).expect("during-run difference => FAIL");
            assert!(
                message.contains("MGMT-NET during-run snapshot equals pre-run"),
                "{message}"
            );
            assert!(!message.contains("after-teardown"), "{message}");
            assert!(lab.teardown_report.is_some(), "the teardown ran");
            assert_eq!(calls.borrow().len(), 2);
            drop(lab);

            let dir = mgmt_net::Scratch::new().unwrap();
            let calls = new_calls();
            let mut lab = inert_lab(dir.path(), Seen::Same, Seen::Same, &calls);
            lab.check("SCENARIO-X something observed", false, "it did not happen");
            let message = finish_outcome(&mut lab).expect("a failed check => FAIL");
            assert!(
                message.contains("SCENARIO-X something observed"),
                "{message}"
            );
            assert!(lab.teardown_report.is_some(), "the teardown ran");
            drop(lab);

            // everything wrong at once: all of it is reported
            let dir = mgmt_net::Scratch::new().unwrap();
            let calls = new_calls();
            let mut lab = inert_lab(dir.path(), Seen::Changed, Seen::NotComparable, &calls);
            let message = finish_outcome(&mut lab).expect("FAIL");
            assert!(message.contains("during-run") && message.contains("after-teardown"));
            drop(lab);
        }

        /// 19: residue FAILS the scenario even when the management network is
        /// unchanged and every cleanup step succeeded — whether the residue is
        /// found by the real probe, or reported by a teardown (the audit's
        /// `mgmt_clean: true, residue: true` counter-example).
        #[test]
        fn lab_finish_fails_on_residue_even_with_a_clean_mgmt_network() {
            // something under a path the lab must leave empty
            let dir = mgmt_net::Scratch::new().unwrap();
            let calls = new_calls();
            let mut lab = inert_lab(dir.path(), Seen::Same, Seen::Same, &calls);
            std::fs::create_dir(dir.path().join("runtime")).unwrap();
            let message = finish_outcome(&mut lab).expect("residue => FAIL");
            assert!(message.contains(lab_own::CHECK_RESIDUE), "{message}");
            assert!(!message.contains(lab_own::CHECK_MGMT), "{message}");
            assert!(!message.contains(lab_own::CHECK_CLEANUP), "{message}");
            assert!(read(dir.path(), "teardown.txt").contains("runtime dir"));
            drop(lab);
            // a device left under a lab name (not removed: not the lab's)
            let dir = mgmt_net::Scratch::new().unwrap();
            let calls = new_calls();
            let (topology, mut kernel) = fake_topology();
            kernel.net.del_netns("client");
            kernel.net.add_netns("client");
            let mut lab = inert_lab_with(
                dir.path(),
                Seen::Same,
                Seen::Same,
                &calls,
                topology,
                Box::new(kernel),
            );
            let message = finish_outcome(&mut lab).expect("left in place => FAIL");
            assert!(message.contains(lab_own::CHECK_RESIDUE), "{message}");
            assert!(message.contains("netns client"), "{message}");
            drop(lab);
            // the teardown report itself says residue
            let dir = mgmt_net::Scratch::new().unwrap();
            let calls = new_calls();
            let mut lab = inert_lab(dir.path(), Seen::Same, Seen::Same, &calls);
            lab.teardown_report = Some(Teardown {
                mgmt_clean: true,
                mgmt_report: "same host network; a namespace remains\n".to_string(),
                steps: Vec::new(),
                residue: lab_own::Residue {
                    left: vec!["netns node-a".to_string()],
                    unknown: Vec::new(),
                },
            });
            let message = finish_outcome(&mut lab).expect("residue=true => FAIL");
            assert!(message.contains(lab_own::CHECK_RESIDUE), "{message}");
            std::mem::forget(lab);
        }

        /// 20: a residue check that cannot be made FAILS the scenario.
        #[test]
        fn lab_finish_fails_when_the_residue_cannot_be_checked() {
            let dir = mgmt_net::Scratch::new().unwrap();
            let calls = new_calls();
            let (topology, mut kernel) = fake_topology();
            kernel.blind = true;
            let mut lab = inert_lab_with(
                dir.path(),
                Seen::Same,
                Seen::Same,
                &calls,
                topology,
                Box::new(kernel),
            );
            let message = finish_outcome(&mut lab).expect("unknown => FAIL");
            assert!(message.contains(lab_own::CHECK_RESIDUE), "{message}");
            assert!(message.contains("cannot be listed"), "{message}");
            drop(lab);
        }

        /// 14 / 15 / 18: a cleanup command that exits 1 or cannot be started
        /// FAILS the scenario; every later step still runs.
        #[test]
        fn lab_finish_fails_when_a_cleanup_command_fails() {
            for (systemctl, why) in [
                ("/usr/bin/false", "ended with exit status: 1"),
                ("/nonexistent/mikagami-systemctl", "cannot run"),
            ] {
                let dir = mgmt_net::Scratch::new().unwrap();
                let calls = new_calls();
                let mut lab = inert_lab(dir.path(), Seen::Same, Seen::Same, &calls);
                lab.systemctl = systemctl.to_string();
                lab.units = vec!["mkm-test.service".to_string()];
                std::fs::create_dir(dir.path().join("units")).unwrap();
                std::fs::write(dir.path().join("units/mkm-test.service"), "").unwrap();
                std::fs::create_dir(dir.path().join("runtime")).unwrap();
                lab.created_runtime = true;
                let message = finish_outcome(&mut lab).expect("a failed cleanup command => FAIL");
                assert!(message.contains(lab_own::CHECK_CLEANUP), "{message}");
                assert!(
                    message.contains("stop unit mkm-test.service: FAILED"),
                    "{message}"
                );
                assert!(message.contains(why), "{message}");
                assert!(
                    message.contains("systemctl daemon-reload: FAILED"),
                    "{message}"
                );
                // the later steps ran: the topology, the runtime dir, the unit file
                assert!(!dir.path().join("runtime").exists(), "{systemctl}");
                assert!(
                    !dir.path().join("units/mkm-test.service").exists(),
                    "{systemctl}"
                );
                assert!(read(dir.path(), "topology.txt").contains("remove bridge br-mkm"));
                let teardown = lab.teardown_report.clone().unwrap();
                assert!(
                    teardown.mgmt_clean && teardown.residue.is_clean(),
                    "{:?}",
                    teardown.residue
                );
                drop(lab);
            }
        }

        /// 16 / 18: a cleanup step that PANICS is reported as such, the later
        /// steps still run, the after-teardown snapshot and the evidence are
        /// still taken, the report is final (cached) — and the scenario FAILS.
        #[test]
        fn lab_finish_fails_when_a_cleanup_step_panics() {
            for at in [
                "kill what is left",
                "remove veth vh-node-b",
                "keep the script",
            ] {
                let dir = mgmt_net::Scratch::new().unwrap();
                let calls = new_calls();
                let mut lab = inert_lab(dir.path(), Seen::Same, Seen::Same, &calls);
                std::fs::create_dir(dir.path().join("runtime")).unwrap();
                lab.created_runtime = true;
                lab.cleanup_fault = Some(at.to_string());
                let message = finish_outcome(&mut lab).expect("a cleanup panic => FAIL");
                assert!(message.contains(lab_own::CHECK_CLEANUP), "{at}: {message}");
                assert!(
                    message.contains("PANICKED: injected cleanup panic"),
                    "{at}: {message}"
                );
                assert!(
                    !dir.path().join("runtime").exists(),
                    "{at}: later steps did not run"
                );
                assert_eq!(
                    calls.borrow().len(),
                    2,
                    "{at}: the after-teardown snapshot was taken"
                );
                assert!(
                    read(dir.path(), "teardown.txt").contains("Panicked"),
                    "{at}"
                );
                assert!(lab.teardown_report.is_some(), "{at}: the report is final");
                drop(lab);
                assert_eq!(calls.borrow().len(), 2, "{at}: Drop repeats nothing");
            }
        }

        /// 17: the scenario panics, and while the thread unwinds, `Drop`'s
        /// cleanup panics too. No abort: the child test fails with the
        /// scenario's own panic (exit 101), and the teardown completed and
        /// kept its evidence.
        #[test]
        fn lab_drop_with_a_cleanup_panic_while_unwinding_does_not_abort() {
            const CHILD: &str = "MKM_VF_LAB_UNWIND_CHILD";
            if let Some(dir) = std::env::var_os(CHILD) {
                let calls = new_calls();
                let mut lab = inert_lab(Path::new(&dir), Seen::Same, Seen::Same, &calls);
                lab.cleanup_fault = Some("remove veth vh-node-a".to_string());
                let _lab = lab;
                panic!("the scenario itself failed");
            }
            let dir = mgmt_net::Scratch::new().unwrap();
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "daemon_run::tests::vf_lab::lab_drop_with_a_cleanup_panic_while_unwinding_does_not_abort",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD, dir.path())
                .stdin(Stdio::null())
                .output()
                .unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(
                output.status.code(),
                Some(101),
                "{:?}\n{stderr}",
                output.status
            );
            assert!(stderr.contains("the scenario itself failed"), "{stderr}");
            let teardown = read(dir.path(), "teardown.txt");
            assert!(
                teardown.contains("Panicked(\"injected cleanup panic"),
                "{teardown}"
            );
            assert!(
                teardown.contains("FAIL LAB cleanup completed"),
                "{teardown}"
            );
            assert!(read(dir.path(), "topology.txt").contains("remove bridge br-mkm"));
        }

        /// `Drop` never panics. A scenario that panics (thread unwinding) with a
        /// management network that differs after teardown is cleaned up without
        /// a second panic, and keeps its evidence. A lab dropped without
        /// `finish` (22) does not panic either, and tears down once.
        #[test]
        fn lab_drop_never_panics_even_when_the_teardown_comparison_fails() {
            let dir = mgmt_net::Scratch::new().unwrap();
            let calls = new_calls();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _lab = inert_lab(dir.path(), Seen::Changed, Seen::Changed, &calls);
                panic!("the scenario itself failed");
            }));
            assert_eq!(
                panic_text(result).as_deref(),
                Some("the scenario itself failed"),
                "the scenario's own panic is what surfaces"
            );
            assert!(read(dir.path(), "mgmt-after-compare.txt").contains("FAIL"));
            assert!(read(dir.path(), "timeline.txt").contains("teardown: mgmt-net DIFFERENT"));

            for after in [Seen::Changed, Seen::NotComparable, Seen::Panics] {
                let dir = mgmt_net::Scratch::new().unwrap();
                let calls = new_calls();
                let lab = inert_lab(dir.path(), after, after, &calls);
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(lab)));
                assert!(result.is_ok(), "Drop must not panic");
                assert_eq!(calls.borrow().len(), 1, "one after-teardown snapshot");
                assert!(dir.path().join("mgmt-after-compare.txt").exists());
                assert!(dir.path().join("teardown.txt").exists());
            }
        }

        /// 21 / 23: `teardown` runs once; a second call (or `Drop` after
        /// `finish`) returns the same report and touches nothing again.
        #[test]
        fn lab_teardown_twice_repeats_nothing() {
            let dir = mgmt_net::Scratch::new().unwrap();
            let calls = new_calls();
            let mut lab = inert_lab(dir.path(), Seen::Same, Seen::Same, &calls);
            let first = lab.teardown();
            let steps = first.steps.len();
            assert!(steps > 9, "{:?}", first.steps);
            let second = lab.teardown();
            assert_eq!(second.steps, first.steps);
            assert_eq!(calls.borrow().len(), 1);
            assert_eq!(finish_outcome(&mut lab), None);
            assert_eq!(
                calls.borrow().len(),
                2,
                "finish adds only its during-run snapshot"
            );
            let log = lab.topology.log.len();
            drop(lab);
            assert_eq!(calls.borrow().len(), 2);
            let _ = log;
            // a teardown that was cut short is never repeated, never clean
            let dir = mgmt_net::Scratch::new().unwrap();
            let calls = new_calls();
            let mut lab = inert_lab(dir.path(), Seen::Same, Seen::Same, &calls);
            lab.teardown_started = true;
            let cut = lab.teardown();
            assert!(!cut.mgmt_clean && !cut.residue.is_clean() && !cut.failed_steps().is_empty());
            assert!(calls.borrow().is_empty(), "nothing was repeated");
            std::mem::forget(lab);
        }

        /// The real cleanup plan covers everything the lab creates, in order:
        /// processes, what is left in its netns, units, every recorded
        /// topology resource (newest first), runtime / script dirs, unit files.
        #[test]
        fn the_cleanup_plan_covers_everything_the_lab_creates() {
            let dir = mgmt_net::Scratch::new().unwrap();
            let calls = new_calls();
            let mut lab = inert_lab(dir.path(), Seen::Same, Seen::Same, &calls);
            lab.units = vec!["a.service".to_string()];
            lab.created_runtime = true;
            lab.created_libexec = true;
            lab.created_libexec_parent = true;
            let names: Vec<String> = lab
                .cleanup_steps()
                .into_iter()
                .map(|(name, _)| name)
                .collect();
            let expect_prefix = [
                "kill what is left inside the lab's netns node-a",
                "kill what is left inside the lab's netns node-b",
                "kill what is left inside the lab's netns witness",
                "kill what is left inside the lab's netns client",
                "kill the hang-script processes",
                "stop unit a.service",
                "remove veth vh-client",
                "remove netns client",
                "remove veth vh-witness",
                "remove netns witness",
                "remove veth vh-node-b",
                "remove netns node-b",
                "remove veth vh-node-a",
                "remove netns node-a",
                "remove bridge br-mkm",
                "keep the script / arping logs",
                "remove the runtime dir",
                "remove the script dir",
                "remove the script dir's parent",
                "remove unit file a.service",
                "systemctl daemon-reload",
            ];
            assert_eq!(names.len(), expect_prefix.len(), "{names:#?}");
            for (name, prefix) in names.iter().zip(expect_prefix) {
                assert!(name.starts_with(prefix), "{name} vs {prefix}");
            }
            lab.created_libexec_parent = false;
            lab.created_libexec = false;
            lab.created_runtime = false;
            lab.units.clear();
            drop(lab);
        }

        /// 13: `Lab::new` refuses (BLOCKED) before it creates anything when the
        /// preflight fails — an incomplete pre-run snapshot or an existing lab
        /// name: the preflight comes before the first thing it creates.
        #[test]
        fn lab_new_runs_the_preflight_before_creating_anything() {
            let source = include_str!("daemon_run.rs");
            let new = &source[source
                .find(concat!("pub(super) fn ", "new(name: &str) -> Self {"))
                .expect("Lab::new")..];
            let new = &new[..new.find("fn record_environment").expect("end of Lab::new")];
            let preflight = new
                .find(concat!("lab_own::", "preflight("))
                .expect("preflight");
            let snapshot = new
                .find("let mgmt_before = mgmt_snapshot(&[]);")
                .expect("baseline");
            for create in ["create_dir(", "std::fs::write(", "topology.up("] {
                let first = new.find(create).unwrap_or_else(|| panic!("{create}"));
                assert!(preflight < first, "{create} before the preflight");
            }
            assert!(snapshot < preflight, "the preflight judges the baseline");
            assert!(
                new[preflight..].starts_with(concat!("lab_own::", "preflight(&mut RealKernel"))
            );
            assert!(new.contains("panic!(\"BLOCKED: {why}\")"));
        }

        // ---- MC-1 remaining findings: the REAL kernel, in an isolated sandbox ----
        //
        // Root, inside a network AND mount namespace of its own with a private
        // /run (nothing here can reach the host's network or its /run/netns;
        // everything is gone with the sandbox):
        //
        //   sudo unshare --mount --net --propagation private -- /bin/sh -c \
        //     'mount -t tmpfs mkm-sandbox /run && MKM_TOPOLOGY_SANDBOX=1 \
        //      exec <test-binary> --ignored --test-threads=1 vf_lab::topology_real_'

        /// The kernel of the sandbox, refusing anything else: root, a network
        /// and a mount namespace that are not init's, holding only `lo` and no
        /// named netns. The topology script lives in `dir`.
        fn sandbox(dir: &mgmt_net::Scratch) -> RealKernel {
            assert_eq!(
                unsafe { libc::geteuid() },
                0,
                "BLOCKED: needs root, inside the sandbox"
            );
            assert!(
                std::env::var_os("MKM_TOPOLOGY_SANDBOX").is_some(),
                "BLOCKED: run inside the sandbox (see above)"
            );
            for ns in ["net", "mnt"] {
                let own = std::fs::metadata(format!("/proc/self/ns/{ns}"))
                    .unwrap()
                    .ino();
                let init = std::fs::metadata(format!("/proc/1/ns/{ns}")).unwrap().ino();
                assert_ne!(own, init, "BLOCKED: not in a private {ns} namespace");
            }
            let script = dir.path().join("vf-topology.sh");
            std::fs::write(&script, lab_own::TOPOLOGY_SH).unwrap();
            let mut kernel = RealKernel::new(script);
            assert_clean(&mut kernel);
            kernel
        }

        /// Nothing but `lo`, no named netns.
        fn assert_clean(kernel: &mut RealKernel) {
            let names: Vec<String> = kernel
                .links()
                .unwrap()
                .into_iter()
                .map(|l| l.name)
                .collect();
            assert_eq!(names, ["lo"], "the sandbox is not clean");
            assert!(
                kernel.netns_names().unwrap().is_empty(),
                "the sandbox is not clean"
            );
        }

        /// "Someone else" acting on the sandbox's network.
        fn others(args: &[&str]) {
            run_ok(IP, args);
        }

        fn shown(kernel: &mut RealKernel, name: &str) -> Option<LinkId> {
            kernel
                .links()
                .unwrap()
                .into_iter()
                .find(|link| link.name == name)
        }

        fn remove_all(
            topology: &mut lab_own::Topology,
            kernel: &mut RealKernel,
        ) -> Vec<Result<(), String>> {
            topology
                .removal_order()
                .iter()
                .map(|created| topology.remove(kernel, created))
                .collect()
        }

        fn residue_of(topology: &lab_own::Topology, kernel: &mut RealKernel) -> lab_own::Residue {
            let mut residue = lab_own::Residue::default();
            topology.probe(kernel, &mut residue);
            residue
        }

        /// 25 on the real kernel: the steps make the fixed topology, the
        /// records match it, the during-run snapshot scopes out exactly the
        /// recorded devices, and the teardown leaves the sandbox as it was.
        #[test]
        #[ignore = "root + isolated sandbox (see above)"]
        fn topology_real_up_and_teardown_leave_nothing() {
            let dir = mgmt_net::Scratch::new().unwrap();
            let mut kernel = sandbox(&dir);
            let baseline = mgmt_snapshot(&[]);
            lab_own::preflight(&mut kernel, &baseline).unwrap();
            let mut topology = lab_own::Topology::default();
            let mac = run_unique_mac();
            topology.up(&mut kernel, &mac).unwrap();
            let bridge = shown(&mut kernel, "br-mkm").unwrap();
            assert_eq!(
                (bridge.mac.as_str(), bridge.kind.as_deref()),
                (mac.as_str(), Some("bridge"))
            );
            for ns in NAMESPACES {
                let host = shown(&mut kernel, &format!("vh-{ns}")).unwrap();
                assert_eq!(host.master.as_deref(), Some("br-mkm"), "{ns}");
                let net = format!("--net=/run/netns/{ns}");
                let addr = run_ok(
                    NSENTER,
                    &[&net, "--", IP, "-o", "addr", "show", "dev", "eth0"],
                );
                assert!(addr.contains(&format!("192.168.77.")), "{ns}: {addr}");
                assert!(
                    !kernel
                        .pids_in(ns)
                        .unwrap()
                        .iter()
                        .any(|pid| *pid == std::process::id() as i32)
                );
            }
            let owned = topology.owned_links();
            assert_eq!(owned.len(), 1 + NAMESPACES.len());
            let verdict = mgmt_net::compare(&baseline, &mgmt_snapshot(&owned));
            assert!(verdict.pass, "{}", verdict.report);
            assert!(!mgmt_net::compare(&baseline, &mgmt_snapshot(&[])).pass);
            let results = remove_all(&mut topology, &mut kernel);
            assert!(results.iter().all(Result::is_ok), "{results:?}");
            let residue = residue_of(&topology, &mut kernel);
            assert!(residue.is_clean(), "{residue:?}");
            topology.release_all(&mut kernel);
            let verdict = mgmt_net::compare(&baseline, &mgmt_snapshot(&[]));
            assert!(verdict.pass, "{}", verdict.report);
            assert_clean(&mut kernel);
        }

        /// 1-3 on the real kernel: an existing vh-node-a (someone's veth), an
        /// existing br-mkm, an existing netns node-b. Refused before anything is
        /// created; and when it appears only after the preflight, the create
        /// step fails, the teardown removes exactly what was recorded, and the
        /// other resource keeps its identity (ifindex, MAC, kind / inode).
        #[test]
        #[ignore = "root + isolated sandbox (see above)"]
        fn topology_real_existing_resources_are_refused_and_left_untouched() {
            let cases: [(&str, &[&str], &[&str]); 3] = [
                (
                    "vh-node-a",
                    &[
                        "link",
                        "add",
                        "vh-node-a",
                        "type",
                        "veth",
                        "peer",
                        "name",
                        "vp-theirs",
                    ],
                    &["link", "del", "vh-node-a"],
                ),
                (
                    "br-mkm",
                    &["link", "add", "br-mkm", "type", "bridge"],
                    &["link", "del", "br-mkm"],
                ),
                (
                    "node-b",
                    &["netns", "add", "node-b"],
                    &["netns", "del", "node-b"],
                ),
            ];
            for (name, plant, unplant) in cases {
                let dir = mgmt_net::Scratch::new().unwrap();
                let mut kernel = sandbox(&dir);
                others(plant);
                let theirs = (shown(&mut kernel, name), kernel.netns_id(name).unwrap());
                let baseline = mgmt_snapshot(&[]);
                let refused = lab_own::preflight(&mut kernel, &baseline).expect_err(name);
                assert!(refused.contains(name), "{name}: {refused}");
                let mut topology = lab_own::Topology::default();
                let failed = topology.up(&mut kernel, &run_unique_mac()).expect_err(name);
                assert!(failed.contains("failed"), "{name}: {failed}");
                let results = remove_all(&mut topology, &mut kernel);
                assert!(results.iter().all(Result::is_ok), "{name}: {results:?}");
                topology.release_all(&mut kernel);
                assert_eq!(
                    (shown(&mut kernel, name), kernel.netns_id(name).unwrap()),
                    theirs,
                    "{name}: someone else's resource changed"
                );
                let residue = residue_of(&topology, &mut kernel);
                assert_eq!(residue.left.len(), 1, "{name}: {residue:?}");
                others(unplant);
                assert_clean(&mut kernel);
            }
        }

        /// `RealKernel` with "someone else" acting right after one step, or
        /// right after the lab has looked inside one of its netns (`armed`).
        struct Hooked {
            inner: RealKernel,
            after: &'static str,
            action: Option<Box<dyn FnOnce()>>,
            armed: Option<(&'static str, Box<dyn FnOnce()>)>,
        }

        impl Kernel for Hooked {
            fn links(&mut self) -> Result<Vec<LinkId>, String> {
                self.inner.links()
            }
            fn netns_names(&mut self) -> Result<Vec<String>, String> {
                self.inner.netns_names()
            }
            fn step(&mut self, args: &[String]) -> Result<(), String> {
                let result = self.inner.step(args);
                let key = args.join(" ");
                if result.is_ok()
                    && (key == self.after || key.starts_with(&format!("{} ", self.after)))
                    && let Some(action) = self.action.take()
                {
                    action();
                }
                result
            }
            fn fresh_netns(&mut self, name: &str) -> Result<(NsId, String), String> {
                self.inner.fresh_netns(name)
            }
            fn netns_id(&mut self, name: &str) -> Result<Option<NsId>, String> {
                self.inner.netns_id(name)
            }
            fn handle(&self, name: &str) -> Option<String> {
                self.inner.handle(name)
            }
            fn links_in(&mut self, name: &str) -> Result<Vec<LinkId>, String> {
                let result = self.inner.links_in(name);
                if self.armed.as_ref().is_some_and(|(ns, _)| *ns == name)
                    && let Some((_, action)) = self.armed.take()
                {
                    action();
                }
                result
            }
            fn delete_in(&mut self, name: &str, dev: &str) -> Result<(), String> {
                self.inner.delete_in(name, dev)
            }
            fn delete_link(&mut self, name: &str) -> Result<(), String> {
                self.inner.delete_link(name)
            }
            fn delete_netns(&mut self, name: &str) -> Result<(), String> {
                self.inner.delete_netns(name)
            }
            fn release(&mut self, name: &str) {
                self.inner.release(name)
            }
            fn pids_in(&mut self, name: &str) -> Result<Vec<i32>, String> {
                self.inner.pids_in(name)
            }
        }

        /// 4 / 5 / concurrent creation on the real kernel: someone else creates
        /// vh-witness right after the lab's netns witness step (the veth step
        /// then fails), or replaces the lab's new netns witness name before
        /// the lab checks it. Exactly what was recorded is removed; the other
        /// resource keeps its identity and is reported, never deleted.
        #[test]
        #[ignore = "root + isolated sandbox (see above)"]
        fn topology_real_partial_up_removes_only_what_it_recorded() {
            type Act = fn();
            // (after which step, the other resource, what is done, its own
            // cleanup, how many resources the lab recorded before failing)
            let cases: [(&str, &str, Act, &[&str], usize); 2] = [
                (
                    "netns witness",
                    "vh-witness",
                    || others(&["link", "add", "vh-witness", "type", "dummy"]),
                    &["link", "del", "vh-witness"],
                    6,
                ),
                (
                    "netns witness",
                    "witness",
                    || {
                        others(&["netns", "del", "witness"]);
                        others(&["netns", "add", "witness"]);
                    },
                    &["netns", "del", "witness"],
                    5,
                ),
            ];
            for (after, name, act, unplant, recorded) in cases {
                let dir = mgmt_net::Scratch::new().unwrap();
                let mut kernel = Hooked {
                    inner: sandbox(&dir),
                    after,
                    action: Some(Box::new(act)),
                    armed: None,
                };
                let mut topology = lab_own::Topology::default();
                let failed = topology.up(&mut kernel, &run_unique_mac()).expect_err(name);
                assert_eq!(topology.created.len(), recorded, "{name}: {failed}");
                let theirs = (
                    shown(&mut kernel.inner, name),
                    kernel.netns_id(name).unwrap(),
                );
                assert!(theirs.0.is_some() || theirs.1.is_some(), "{name}");
                let results = remove_all(&mut topology, &mut kernel.inner);
                assert!(results.iter().all(Result::is_ok), "{name}: {results:?}");
                topology.release_all(&mut kernel);
                assert_eq!(
                    (
                        shown(&mut kernel.inner, name),
                        kernel.netns_id(name).unwrap()
                    ),
                    theirs,
                    "{name}: someone else's resource changed"
                );
                let residue = residue_of(&topology, &mut kernel.inner);
                assert_eq!(residue.left.len(), 1, "{name}: {residue:?}");
                others(unplant);
                assert_clean(&mut kernel.inner);
            }
        }

        /// The check-then-delete window of a veth, made deterministic on the
        /// real kernel: right after the teardown has looked inside the lab's
        /// netns node-a, someone renames the lab's vh-node-a away and creates
        /// another vh-node-a. The lab deletes through its netns handle: its own
        /// (renamed) pair goes, the newcomer stays untouched and is reported.
        /// A deletion by the host NAME would have removed the newcomer.
        #[test]
        #[ignore = "root + isolated sandbox (see above)"]
        fn topology_real_a_rename_race_never_deletes_the_newcomer() {
            let dir = mgmt_net::Scratch::new().unwrap();
            let mut kernel = Hooked {
                inner: sandbox(&dir),
                after: "never",
                action: None,
                armed: None,
            };
            let mut topology = lab_own::Topology::default();
            topology.up(&mut kernel, &run_unique_mac()).unwrap();
            let veth = topology
                .created
                .iter()
                .find(|created| matches!(created, lab_own::Created::Veth { ns, .. } if ns == "node-a"))
                .cloned()
                .unwrap();
            kernel.armed = Some((
                "node-a",
                Box::new(|| {
                    others(&["link", "set", "vh-node-a", "down"]);
                    others(&["link", "set", "vh-node-a", "name", "vh-moved"]);
                    others(&["link", "add", "vh-node-a", "type", "dummy"]);
                }),
            ));
            let result = topology.remove(&mut kernel, &veth);
            assert!(kernel.armed.is_none(), "the race was not staged");
            let newcomer = shown(&mut kernel.inner, "vh-node-a");
            assert!(
                newcomer
                    .as_ref()
                    .is_some_and(|link| link.kind.as_deref() == Some("dummy")),
                "the newcomer was deleted: {result:?}"
            );
            assert!(
                shown(&mut kernel.inner, "vh-moved").is_none(),
                "the lab's own (renamed) pair is still there: {result:?}"
            );
            assert!(
                result
                    .as_ref()
                    .is_err_and(|why| why.contains("left in place")),
                "{result:?}"
            );
            for created in topology.removal_order() {
                if created != veth {
                    topology.remove(&mut kernel, &created).unwrap();
                }
            }
            topology.release_all(&mut kernel);
            assert_eq!(shown(&mut kernel.inner, "vh-node-a"), newcomer);
            others(&["link", "del", "vh-node-a"]);
            assert_clean(&mut kernel.inner);
        }

        /// 6-8 on the real kernel: after `up`, someone else replaces a lab
        /// device under its name — a new device, one forcing the old ifindex,
        /// one forcing the old MAC; the bridge re-created with its old ifindex;
        /// a lab netns name re-pointed to another namespace. The during-run
        /// snapshot reports the ownership loss, and the teardown removes
        /// everything that is still the lab's and leaves the replacement in
        /// place (its identity unchanged).
        #[test]
        #[ignore = "root + isolated sandbox (see above)"]
        fn topology_real_replaced_resources_are_left_in_place() {
            type Replace = fn(&LinkId);
            let cases: [(&str, &str, Replace, &[&str], bool); 5] = [
                (
                    "same-name replacement",
                    "vh-node-a",
                    |_| {
                        others(&["link", "del", "vh-node-a"]);
                        others(&["link", "add", "vh-node-a", "type", "dummy"]);
                    },
                    &["link", "del", "vh-node-a"],
                    true,
                ),
                (
                    "ifindex reuse",
                    "vh-node-a",
                    |old| {
                        others(&["link", "del", "vh-node-a"]);
                        let index = old.ifindex.to_string();
                        others(&["link", "add", "vh-node-a", "index", &index, "type", "dummy"]);
                    },
                    &["link", "del", "vh-node-a"],
                    true,
                ),
                (
                    "MAC reuse",
                    "vh-node-a",
                    |old| {
                        others(&["link", "del", "vh-node-a"]);
                        others(&[
                            "link",
                            "add",
                            "vh-node-a",
                            "address",
                            &old.mac,
                            "type",
                            "dummy",
                        ]);
                    },
                    &["link", "del", "vh-node-a"],
                    true,
                ),
                (
                    "bridge ifindex reuse",
                    "br-mkm",
                    |old| {
                        others(&["link", "del", "br-mkm"]);
                        let index = old.ifindex.to_string();
                        others(&["link", "add", "br-mkm", "index", &index, "type", "bridge"]);
                    },
                    &["link", "del", "br-mkm"],
                    true,
                ),
                (
                    "netns re-pointed",
                    "node-b",
                    |_| {
                        others(&["netns", "del", "node-b"]);
                        others(&["netns", "add", "node-b"]);
                    },
                    &["netns", "del", "node-b"],
                    false,
                ),
            ];
            for (what, name, replace, unplant, device) in cases {
                let dir = mgmt_net::Scratch::new().unwrap();
                let mut kernel = sandbox(&dir);
                let baseline = mgmt_snapshot(&[]);
                let mut topology = lab_own::Topology::default();
                topology.up(&mut kernel, &run_unique_mac()).unwrap();
                let old = shown(&mut kernel, name);
                replace(old.as_ref().unwrap_or(&topology.owned_links()[0]));
                let theirs = (shown(&mut kernel, name), kernel.netns_id(name).unwrap());
                if device {
                    let during = mgmt_snapshot(&topology.owned_links());
                    let link = during
                        .parts
                        .iter()
                        .find(|part| part.label == "link")
                        .unwrap();
                    assert!(
                        matches!(&link.content, Err(why) if why.contains("ownership NOT shown")),
                        "{what}: {during}"
                    );
                    assert!(!mgmt_net::compare(&baseline, &during).pass, "{what}");
                }
                let results = remove_all(&mut topology, &mut kernel);
                let failed: Vec<&String> =
                    results.iter().filter_map(|r| r.as_ref().err()).collect();
                assert_eq!(failed.len(), 1, "{what}: {results:?}");
                assert!(failed[0].contains("left in place"), "{what}: {failed:?}");
                topology.release_all(&mut kernel);
                assert_eq!(
                    (shown(&mut kernel, name), kernel.netns_id(name).unwrap()),
                    theirs,
                    "{what}: the replacement was touched"
                );
                let residue = residue_of(&topology, &mut kernel);
                assert!(
                    residue.left.iter().any(|left| left.contains(name)),
                    "{what}: {residue:?}"
                );
                others(unplant);
                assert_clean(&mut kernel);
            }
        }

        /// Every scenario that builds a lab ends in `finish()` as its last
        /// statement: that call is the only place a teardown comparison can fail
        /// the test (not `Drop`), so a scenario that forgot it would pass
        /// whatever the teardown found.
        #[test]
        fn every_scenario_that_builds_a_lab_ends_in_finish() {
            let source = include_str!("daemon_run.rs");
            let vf = &source[source.find("mod vf_lab {").expect("vf_lab module")..];
            let builds = concat!("Lab", "::new(");
            let ends = concat!("lab.fin", "ish();");
            let mut scenarios = 0;
            for chunk in vf.split("\n        #[test]").skip(1) {
                // a test function ends where the next 8-space-indented item starts
                let body = match chunk.find("\n        }\n") {
                    Some(end) => &chunk[..end + "\n        }\n".len()],
                    None => chunk,
                };
                if !body.contains(builds) {
                    continue;
                }
                scenarios += 1;
                let last = body
                    .rfind(ends)
                    .unwrap_or_else(|| panic!("no finish() in:\n{body}"));
                assert_eq!(
                    body.matches(builds).count(),
                    1,
                    "one lab per scenario:\n{body}"
                );
                assert!(
                    body[last + ends.len()..].trim() == "}",
                    "finish() is not the last statement of:\n{body}"
                );
            }
            assert!(scenarios >= 15, "only {scenarios} scenarios found");
        }

        fn sha256_of(path: &Path) -> String {
            run("/usr/bin/sha256sum", &[path.to_str().unwrap()])
                .1
                .split_whitespace()
                .next()
                .unwrap_or("?")
                .to_string()
        }

        pub(super) fn field(status: &str, key: &str) -> Option<String> {
            let prefix = format!("{key}: ");
            status
                .lines()
                .find_map(|line| line.strip_prefix(prefix.as_str()).map(str::to_string))
        }

        // ---- processes ---------------------------------------------------------

        struct Proc {
            label: String,
            child: Child,
            lines: Arc<Mutex<Vec<(u128, String)>>>,
            reader: Option<JoinHandle<()>>,
        }

        impl Proc {
            fn pid(&self) -> i32 {
                self.child.id() as i32
            }

            fn alive(&mut self) -> bool {
                matches!(self.child.try_wait(), Ok(None))
            }

            fn lines(&self) -> Vec<(u128, String)> {
                self.lines.lock().unwrap().clone()
            }
        }

        /// Fencing configuration of one node (what `[fencing]` contains).
        #[derive(Clone)]
        pub(super) enum Fencing {
            /// No `[fencing]` section: operator attestation is the only path.
            None,
            Command {
                fence_script: &'static str,
                verify_script: &'static str,
                fence_timeout_sec: u32,
                verify_timeout_sec: u32,
                verify_polls: u32,
            },
        }

        impl Fencing {
            pub(super) fn standard() -> Self {
                Self::Command {
                    fence_script: "fence.sh",
                    verify_script: "verify.sh",
                    fence_timeout_sec: 5,
                    verify_timeout_sec: 5,
                    verify_polls: 6,
                }
            }
        }

        fn peer_of(node: &str) -> &'static str {
            if node == "node-a" { "node-b" } else { "node-a" }
        }

        fn unit_of(node: &str) -> String {
            format!("mikagami-vf-{}.service", node.trim_start_matches("node-"))
        }

        fn address_of(node: &str) -> &'static str {
            match node {
                "node-a" => "192.168.77.11",
                "node-b" => "192.168.77.12",
                _ => unreachable!(),
            }
        }

        pub(super) struct Lab {
            pub(super) name: String,
            pub(super) dir: PathBuf,
            bin: PathBuf,
            test_bin: PathBuf,
            procs: Vec<Proc>,
            attempts: std::collections::BTreeMap<String, u64>,
            created_runtime: bool,
            created_libexec_parent: bool,
            created_libexec: bool,
            created_state_root: bool,
            units: Vec<String>,
            mgmt_before: mgmt_net::Snapshot,
            /// What the lab created of its topology — each resource recorded
            /// with the identity the kernel showed right after its create step —
            /// and the kernel it talks to (MC-1: only recorded resources are
            /// ever deleted, and only while still the recorded ones).
            topology: lab_own::Topology,
            kernel: Box<dyn Kernel>,
            /// How a management snapshot is taken, given the lab's recorded
            /// devices (`mgmt_snapshot` for a real lab; the tests substitute it).
            snapshot_source: Box<dyn Fn(&[LinkId]) -> mgmt_net::Snapshot>,
            /// Where the cleanup acts (the real ones; temporary ones in tests).
            systemctl: String,
            runtime: PathBuf,
            libexec: PathBuf,
            unit_dir: PathBuf,
            /// Tests only: the cleanup step (by name prefix) that panics.
            cleanup_fault: Option<String>,
            /// Set when the first `teardown()` starts / ends; later calls
            /// (`Drop`) repeat nothing.
            teardown_started: bool,
            teardown_report: Option<Teardown>,
            timeline: std::fs::File,
            checks: Vec<(String, bool, String)>,
            checks_file: std::fs::File,
        }

        impl Lab {
            pub(super) fn new(name: &str) -> Self {
                assert_eq!(
                    unsafe { libc::geteuid() },
                    0,
                    "BLOCKED: the VF lab requires root (run the test binary with sudo)"
                );
                let bin = std::env::var("MKM_VF_BIN")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| {
                        std::env::current_exe()
                            .unwrap()
                            .parent()
                            .unwrap()
                            .parent()
                            .unwrap()
                            .join("mikagami")
                    });
                assert!(
                    bin.is_file(),
                    "BLOCKED: production binary not found at {} (set MKM_VF_BIN)",
                    bin.display()
                );
                let test_bin = std::env::current_exe().unwrap();
                for tool in [
                    "/usr/sbin/ip",
                    "/usr/bin/nsenter",
                    "/usr/bin/bash",
                    "/usr/bin/systemctl",
                    "/usr/bin/ss",
                    "/usr/bin/sha256sum",
                    "/usr/bin/unshare",
                ] {
                    assert!(
                        Path::new(tool).exists(),
                        "BLOCKED: required tool {tool} missing"
                    );
                }

                // Refuse to run over leftovers or a concurrent lab: every
                // resource below is created with create-only semantics.
                assert!(
                    !Path::new(RUNTIME).exists(),
                    "BLOCKED: {RUNTIME} exists (another VF lab is active, or an earlier run \
                     left it; inspect and clean it explicitly)"
                );
                assert!(
                    !Path::new(LIBEXEC).exists(),
                    "BLOCKED: {LIBEXEC} already exists"
                );

                // Taken before the lab creates anything: nothing is scoped out.
                let mgmt_before = mgmt_snapshot(&[]);
                // MC-1: a complete baseline, and every name the topology would
                // create free (br-mkm, vh-<ns>, netns <ns>) — or NOTHING is
                // created. The early refusal only: what makes a later deletion
                // safe is the ownership record of each create step.
                if let Err(why) =
                    lab_own::preflight(&mut RealKernel::new(PathBuf::new()), &mgmt_before)
                {
                    panic!("BLOCKED: {why}");
                }

                // Run directory (evidence; never removed by the lab).
                let created_state_root = !Path::new(STATE_ROOT).exists();
                if created_state_root {
                    std::fs::create_dir(STATE_ROOT).unwrap();
                    std::fs::set_permissions(STATE_ROOT, std::fs::Permissions::from_mode(0o755))
                        .unwrap();
                }
                let mut dir = PathBuf::new();
                for attempt in 0..64u32 {
                    let candidate = Path::new(STATE_ROOT).join(format!(
                        "{name}-{}-{}-{attempt}",
                        std::process::id(),
                        now_ms()
                    ));
                    match std::fs::create_dir(&candidate) {
                        Ok(()) => {
                            dir = candidate;
                            break;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                        Err(e) => panic!("cannot create run dir: {e}"),
                    }
                }
                assert!(!dir.as_os_str().is_empty(), "no unique run directory");
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

                let timeline = std::fs::OpenOptions::new()
                    .create_new(true)
                    .append(true)
                    .open(dir.join("timeline.txt"))
                    .unwrap();
                let checks_file = std::fs::OpenOptions::new()
                    .create_new(true)
                    .append(true)
                    .open(dir.join("checks.txt"))
                    .unwrap();
                // From here on `Drop` tears down exactly what the flags say
                // this lab created.
                let mut lab = Self {
                    name: name.to_string(),
                    dir,
                    bin,
                    test_bin,
                    procs: Vec::new(),
                    attempts: Default::default(),
                    created_runtime: false,
                    created_libexec_parent: false,
                    created_libexec: false,
                    created_state_root,
                    units: Vec::new(),
                    mgmt_before,
                    topology: lab_own::Topology::default(),
                    kernel: Box::new(RealKernel::new(PathBuf::new())),
                    snapshot_source: Box::new(mgmt_snapshot_of),
                    systemctl: "/usr/bin/systemctl".to_string(),
                    runtime: PathBuf::from(RUNTIME),
                    libexec: PathBuf::from(LIBEXEC),
                    unit_dir: PathBuf::from(UNIT_DIR),
                    cleanup_fault: None,
                    teardown_started: false,
                    teardown_report: None,
                    timeline,
                    checks: Vec::new(),
                    checks_file,
                };
                lab.note(format!("lab {name} run dir {}", lab.dir.display()));

                std::fs::create_dir(RUNTIME).unwrap();
                lab.created_runtime = true;
                std::fs::set_permissions(RUNTIME, std::fs::Permissions::from_mode(0o755)).unwrap();

                // Trusted script directory: root:root 0755 all the way up.
                let parent = Path::new(LIBEXEC).parent().unwrap();
                if !parent.exists() {
                    std::fs::create_dir(parent).unwrap();
                    lab.created_libexec_parent = true;
                    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755))
                        .unwrap();
                }
                std::fs::create_dir(LIBEXEC).unwrap();
                lab.created_libexec = true;
                std::fs::set_permissions(LIBEXEC, std::fs::Permissions::from_mode(0o755)).unwrap();
                for (file, content) in LIBEXEC_FILES {
                    let path = Path::new(LIBEXEC).join(file);
                    std::fs::write(&path, content).unwrap();
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                        .unwrap();
                }
                lab.record_environment();

                // Placeholder systemd units: loaded and inactive, as the
                // production recovery gate requires (never started by the lab).
                for node in ["node-a", "node-b"] {
                    let unit = unit_of(node);
                    let path = Path::new(UNIT_DIR).join(&unit);
                    assert!(!path.exists(), "BLOCKED: {} exists", path.display());
                    std::fs::write(
                        &path,
                        format!(
                            "[Unit]\nDescription=Mikagami VF placeholder service for {node}\n\n\
                             [Service]\nType=simple\nExecStart=/usr/bin/sleep infinity\n"
                        ),
                    )
                    .unwrap();
                    lab.units.push(unit);
                }
                run_ok("/usr/bin/systemctl", &["daemon-reload"]);

                // PSK: random, root-owned, 0600.
                let mut random = [0u8; 32];
                std::fs::File::open("/dev/urandom")
                    .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut random))
                    .unwrap();
                let hex: String = random.iter().map(|b| format!("{b:02x}")).collect();
                let psk = lab.dir.join("cluster.psk");
                std::fs::write(&psk, format!("{hex}\n")).unwrap();
                std::fs::set_permissions(&psk, std::fs::Permissions::from_mode(0o600)).unwrap();

                // Topology: create-only steps, each result recorded with the
                // identity the kernel shows (lab_own). If a step fails, `Drop`
                // removes what was recorded — and nothing else.
                let script = lab.dir.join("vf-topology.sh");
                std::fs::write(&script, lab_own::TOPOLOGY_SH).unwrap();
                std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
                lab.kernel = Box::new(RealKernel::new(script));
                let mac = run_unique_mac();
                let up = {
                    let Lab {
                        topology, kernel, ..
                    } = &mut lab;
                    topology.up(&mut **kernel, &mac)
                };
                let _ = std::fs::write(
                    lab.dir.join("topology.txt"),
                    lab.topology.log.join("\n") + "\n",
                );
                if let Err(why) = up {
                    panic!("topology up failed (only what was recorded is removed): {why}");
                }
                lab.note("topology up (br-mkm, node-a, node-b, witness, client; recorded)".into());
                lab
            }

            fn record_environment(&mut self) {
                let mut text = String::new();
                for (label, program, args) in [
                    ("uname", "/usr/bin/uname", vec!["-a"]),
                    ("os-release", "/usr/bin/cat", vec!["/etc/os-release"]),
                    ("systemd", "/usr/bin/systemctl", vec!["--version"]),
                    ("ip", "/usr/sbin/ip", vec!["-V"]),
                    ("modules", "/usr/bin/cat", vec!["/proc/modules"]),
                ] {
                    let (_, out) = run(program, &args);
                    text.push_str(&format!("[{label}]\n{out}\n"));
                }
                text.push_str(&format!(
                    "[binaries]\nproduction {} {}\ntest-binary {} {}\n",
                    self.bin.display(),
                    sha256_of(&self.bin),
                    self.test_bin.display(),
                    sha256_of(&self.test_bin)
                ));
                for (file, _) in LIBEXEC_FILES {
                    text.push_str(&format!(
                        "script {file} {}\n",
                        sha256_of(&Path::new(LIBEXEC).join(file))
                    ));
                }
                text.push_str(&format!("[mgmt-before]\n{}\n", self.mgmt_before));
                std::fs::write(self.dir.join("environment.txt"), text).unwrap();
            }

            pub(super) fn note(&mut self, text: String) {
                let line = format!("{} {text}\n", now_ms());
                eprint!("VF {line}");
                let _ = self.timeline.write_all(line.as_bytes());
                let _ = self.timeline.flush();
            }

            /// Record one acceptance criterion. Does not stop the run.
            pub(super) fn check(&mut self, id: &str, ok: bool, detail: impl AsRef<str>) {
                let line = format!(
                    "{} {id}: {}",
                    if ok { "PASS" } else { "FAIL" },
                    detail.as_ref()
                );
                eprintln!("VF CHECK {line}");
                let _ = writeln!(self.checks_file, "{} {line}", now_ms());
                let _ = self.checks_file.flush();
                self.checks
                    .push((id.to_string(), ok, detail.as_ref().to_string()));
            }

            /// A precondition that, if unmet, makes the scenario BLOCKED (not
            /// failed and never passed).
            pub(super) fn require(&mut self, what: &str, ok: bool, detail: impl AsRef<str>) {
                self.check(&format!("PRECONDITION {what}"), ok, detail.as_ref());
                assert!(
                    ok,
                    "BLOCKED: precondition {what} not met: {}",
                    detail.as_ref()
                );
            }

            pub(super) fn wait_until(
                &mut self,
                what: &str,
                timeout: Duration,
                mut condition: impl FnMut(&mut Self) -> bool,
            ) -> bool {
                let started = Instant::now();
                loop {
                    if condition(self) {
                        self.note(format!(
                            "wait ok: {what} after {:.1}s",
                            started.elapsed().as_secs_f64()
                        ));
                        return true;
                    }
                    if started.elapsed() >= timeout {
                        self.note(format!(
                            "wait TIMEOUT: {what} after {:.1}s",
                            started.elapsed().as_secs_f64()
                        ));
                        return false;
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
            }

            pub(super) fn sleep(&mut self, seconds: f64, why: &str) {
                self.note(format!("sleep {seconds:.1}s ({why})"));
                std::thread::sleep(Duration::from_secs_f64(seconds));
            }

            // ---- configuration --------------------------------------------------

            fn state_dir(&self, node: &str) -> PathBuf {
                self.dir.join(node)
            }

            pub(super) fn config_path(&self, node: &str) -> PathBuf {
                self.dir.join(format!("{node}.toml"))
            }

            pub(super) fn write_config(&mut self, node: &str, fencing: &Fencing) {
                let peer = peer_of(node);
                // v1.0: node-a is the fixed preferred node; priorities are
                // derived (100 / 50). The lab's fast heartbeat cadence is no
                // longer configurable, so lab timings use the fixed 3 s / 10 s.
                let preferred = if node == "node-a" {
                    "preferred = true\n"
                } else {
                    ""
                };
                let state_dir = self.state_dir(node);
                std::fs::create_dir_all(&state_dir).unwrap();
                std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o755))
                    .unwrap();
                // Inbound role (node-b) names its listen address; the outbound
                // node (node-a) names the address it dials.
                let (listen, dial) = if node == "node-b" {
                    (
                        format!("listen = \"{}:7946\"\n", address_of("node-b")),
                        String::new(),
                    )
                } else {
                    (
                        String::new(),
                        format!("address = \"{}:7946\"\n", address_of(peer)),
                    )
                };
                let target_if = format!("vh-{peer}");
                let fencing_section = match fencing {
                    Fencing::None => String::new(),
                    Fencing::Command {
                        fence_script,
                        verify_script,
                        fence_timeout_sec,
                        verify_timeout_sec,
                        verify_polls,
                    } => format!(
                        "\n[fencing]\nbackend = \"command\"\n\
                         fence = [\"/usr/bin/bash\", \"{LIBEXEC}/{fence_script}\", \"{target_if}\"]\n\
                         verify = [\"/usr/bin/bash\", \"{LIBEXEC}/{verify_script}\", \"{target_if}\"]\n\
                         fence_timeout_sec = {fence_timeout_sec}\n\
                         verify_timeout_sec = {verify_timeout_sec}\n\
                         verify_polls = {verify_polls}\n"
                    ),
                };
                let toml = format!(
                    "[cluster]\nid = \"example-ha\"\n\n\
                     [node]\nid = \"{node}\"\n{preferred}{listen}\n\
                     [peer]\nid = \"{peer}\"\n{dial}\n\
                     [witness]\nid = \"witness-1\"\naddress = \"192.168.77.13:7947\"\n\n\
                     [vip]\naddress = \"{VIP}/24\"\ninterface = \"eth0\"\narp_count = 1\n\n\
                     [service]\nmanager = \"systemd\"\nunit = \"{}\"\n\n\
                     [health]\ncommand = [\"/usr/bin/true\"]\n\n\
                     [security]\npsk_file = \"{}\"\n\n\
                     [state]\npath = \"{}\"\n{fencing_section}",
                    unit_of(node),
                    self.dir.join("cluster.psk").display(),
                    state_dir.join("state.toml").display(),
                );
                std::fs::write(self.config_path(node), toml).unwrap();
            }

            // ---- processes ------------------------------------------------------

            fn spawn(&mut self, label: &str, mut command: Command) -> usize {
                command
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped())
                    .process_group(0);
                let mut child = command
                    .spawn()
                    .unwrap_or_else(|e| panic!("spawn {label}: {e}"));
                let stderr = child.stderr.take().unwrap();
                let lines: Arc<Mutex<Vec<(u128, String)>>> = Arc::new(Mutex::new(Vec::new()));
                let sink = lines.clone();
                let log_path = self.dir.join(format!("{label}.log"));
                let reader = std::thread::spawn(move || {
                    let mut file = std::fs::OpenOptions::new()
                        .create_new(true)
                        .append(true)
                        .open(log_path)
                        .expect("create process log (never overwritten)");
                    for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                        let at = now_ms();
                        let _ = writeln!(file, "{at} {line}");
                        sink.lock().unwrap().push((at, line));
                    }
                });
                self.procs.push(Proc {
                    label: label.to_string(),
                    child,
                    lines,
                    reader: Some(reader),
                });
                self.procs.len() - 1
            }

            fn proc_index(&self, label: &str) -> usize {
                self.procs
                    .iter()
                    .position(|p| p.label == label)
                    .unwrap_or_else(|| panic!("no process {label}"))
            }

            /// Start the authority-backed Witness host inside netns `witness`.
            pub(super) fn start_witness(&mut self) {
                let state = self.dir.join("witness-state.toml");
                let events = self.dir.join("witness-events.log");
                let stop = self.dir.join("witness.stop");
                let mut command = Command::new("/usr/sbin/ip");
                command
                    .args(["netns", "exec", "witness"])
                    .arg(&self.test_bin)
                    .args([SERVE_TEST, "--ignored", "--exact", "--nocapture"])
                    .env("MKM_U1_BIND", "192.168.77.13:7947")
                    .env("MKM_U1_SECS", "1800")
                    .env("MKM_U1_PSK", self.dir.join("cluster.psk"))
                    .env("MKM_U1_STATE", &state)
                    .env("MKM_U1_EVENT_LOG", &events)
                    .env("MKM_U1_STOPFILE", &stop)
                    .env("MKM_U1_ALLOWED", "node-a:100,node-b:90");
                self.spawn("witness", command);
                let ready = self.wait_until("witness host READY", Duration::from_secs(60), |lab| {
                    lab.witness_lines().iter().any(|l| l.contains("READY"))
                });
                assert!(ready, "BLOCKED: the Witness host did not become ready");
            }

            pub(super) fn start_daemon(&mut self, node: &str) {
                let config = self.config_path(node);
                let mut command = Command::new("/usr/sbin/ip");
                command
                    .args(["netns", "exec", node])
                    .arg(&self.bin)
                    .args(["daemon", "run", "--config"])
                    .arg(&config)
                    .arg("--arping")
                    .arg(format!("{LIBEXEC}/arping-stub.sh"));
                let index = self.spawn(node, command);
                let pid = self.procs[index].pid();
                self.note(format!("started production daemon {node} pid {pid}"));
                let hello = format!("HELLO/HELLO_ACK {node}");
                let connected = self.wait_until(
                    &format!("{node} reaches the Witness"),
                    Duration::from_secs(40),
                    |lab| {
                        lab.witness_lines().iter().any(|l| l.contains(&hello))
                            || !lab.procs[index].alive()
                    },
                );
                assert!(
                    connected && self.procs[index].alive(),
                    "BLOCKED: daemon {node} did not start (see {node}.log)"
                );
                self.sleep(2.0, "let the daemon enter its loop");
                assert!(
                    self.procs[index].alive(),
                    "BLOCKED: daemon {node} exited during startup"
                );
            }

            pub(super) fn pid(&self, node: &str) -> i32 {
                self.procs[self.proc_index(node)].pid()
            }

            /// Alive = exists and is not a zombie (a stopped process is alive).
            pub(super) fn daemon_alive(&self, node: &str) -> bool {
                !matches!(self.proc_state(self.pid(node)), None | Some('Z'))
            }

            pub(super) fn daemon_lines(&self, node: &str) -> Vec<(u128, String)> {
                self.procs[self.proc_index(node)].lines()
            }

            pub(super) fn sigstop(&mut self, node: &str) {
                let pid = self.pid(node);
                self.note(format!("SIGSTOP -> {node} (pid {pid})"));
                signal(pid, libc::SIGSTOP);
            }

            pub(super) fn sigcont(&mut self, node: &str) {
                let pid = self.pid(node);
                self.note(format!("SIGCONT -> {node} (pid {pid})"));
                signal(pid, libc::SIGCONT);
            }

            /// Pids inside a lab network namespace (the "netns processes").
            pub(super) fn ns_pids(&self, ns: &str) -> Vec<i32> {
                run("/usr/sbin/ip", &["netns", "pids", ns])
                    .1
                    .split_whitespace()
                    .filter_map(|p| p.parse().ok())
                    .collect()
            }

            /// Process state letter from /proc (T = stopped).
            pub(super) fn proc_state(&self, pid: i32) -> Option<char> {
                let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
                let after = stat.rsplit(')').next()?;
                after.trim().chars().next()
            }

            // ---- operator inputs ------------------------------------------------

            /// One explicit operator SIGUSR1 to the daemon. Waits for the
            /// daemon's own result line and returns it.
            pub(super) fn sigusr1(&mut self, node: &str) -> String {
                let count = |lab: &Self| {
                    lab.daemon_lines(node)
                        .iter()
                        .filter(|(_, l)| l.contains("manual promotion attempt"))
                        .count()
                };
                let before = count(self);
                let pid = self.pid(node);
                *self.attempts.entry(node.to_string()).or_default() += 1;
                self.note(format!(
                    "SIGUSR1 -> {node} (pid {pid}); attempt #{}",
                    before + 1
                ));
                signal(pid, libc::SIGUSR1);
                let arrived = self.wait_until(
                    &format!("{node} reports its promotion attempt result"),
                    Duration::from_secs(90),
                    |lab| count(lab) > before,
                );
                if !arrived {
                    return "<no result line>".to_string();
                }
                self.daemon_lines(node)
                    .into_iter()
                    .filter(|(_, l)| l.contains("manual promotion attempt"))
                    .nth(before)
                    .map(|(_, l)| l)
                    .unwrap()
            }

            /// `mikagami recover` (the production operator CLI).
            pub(super) fn recover(&mut self, node: &str, incident: u64) -> (bool, String) {
                let peer = peer_of(node);
                let config = self.config_path(node);
                let unit = unit_of(node);
                let result = run(
                    self.bin.to_str().unwrap(),
                    &[
                        "recover",
                        &unit,
                        "--confirm-fenced",
                        peer,
                        "--incident",
                        &incident.to_string(),
                        "--config",
                        config.to_str().unwrap(),
                    ],
                );
                self.note(format!(
                    "recover {node} -> {peer} incident {incident}: ok={}",
                    result.0
                ));
                result
            }

            /// Operator/harness fence actions that are NOT the production
            /// backend (used only where the scenario defines a manual step).
            pub(super) fn link_down(&mut self, ifname: &str) {
                assert!(matches!(ifname, "vh-node-a" | "vh-node-b"));
                self.note(format!("operator: ip link set {ifname} down"));
                run_ok("/usr/sbin/ip", &["link", "set", "dev", ifname, "down"]);
            }

            pub(super) fn link_up(&mut self, ifname: &str) {
                assert!(matches!(ifname, "vh-node-a" | "vh-node-b"));
                self.note(format!("operator: ip link set {ifname} up (unfence)"));
                run_ok("/usr/sbin/ip", &["link", "set", "dev", ifname, "up"]);
            }

            // ---- observation ----------------------------------------------------

            pub(super) fn status(&self, node: &str) -> String {
                run(
                    self.bin.to_str().unwrap(),
                    &[
                        "status",
                        "--config",
                        self.config_path(node).to_str().unwrap(),
                    ],
                )
                .1
            }

            pub(super) fn fencing_state(&self, node: &str) -> String {
                field(&self.status(node), "fencing.state").unwrap_or_else(|| "?".into())
            }

            pub(super) fn incident(&self, node: &str) -> String {
                field(&self.status(node), "fencing.incident").unwrap_or_else(|| "?".into())
            }

            pub(super) fn role_active(&self, node: &str) -> bool {
                field(&self.status(node), "node.role")
                    .is_some_and(|r| r.starts_with("active or releasing"))
            }

            pub(super) fn witness_lines(&self) -> Vec<String> {
                std::fs::read_to_string(self.dir.join("witness-events.log"))
                    .unwrap_or_default()
                    .lines()
                    .map(str::to_string)
                    .collect()
            }

            /// Witness events of `node` for `kind` (`GetTerm`, `LeaseRequest`,
            /// `LeaseRenew`, `LeaseRelease`), optionally only after `since_ms`.
            pub(super) fn witness_events(
                &self,
                node: &str,
                kind: &str,
                since_ms: u128,
            ) -> Vec<String> {
                let needle = format!("event: {node} {kind} before-send");
                self.witness_lines()
                    .into_iter()
                    .filter(|l| l.contains(&needle))
                    .filter(|l| {
                        l.split_whitespace()
                            .next()
                            .and_then(|t| t.parse::<u128>().ok())
                            .is_some_and(|t| t >= since_ms)
                    })
                    .collect()
            }

            pub(super) fn script_events(&self) -> Vec<String> {
                std::fs::read_to_string(Path::new(RUNTIME).join("script-events.log"))
                    .unwrap_or_default()
                    .lines()
                    .map(str::to_string)
                    .collect()
            }

            pub(super) fn arping_calls(&self) -> Vec<String> {
                std::fs::read_to_string(Path::new(RUNTIME).join("arping.log"))
                    .unwrap_or_default()
                    .lines()
                    .map(str::to_string)
                    .collect()
            }

            /// Administrative state of a host-side veth, read independently of
            /// the verify script.
            pub(super) fn link_is_up(&self, ifname: &str) -> Option<bool> {
                let (ok, out) = run("/usr/sbin/ip", &["-o", "link", "show", "dev", ifname]);
                if !ok {
                    return None;
                }
                let flags = out.split('<').nth(1)?.split('>').next()?.to_string();
                Some(flags.split(',').any(|f| f == "UP"))
            }

            pub(super) fn vip_present(&self, ns: &str) -> bool {
                run(
                    "/usr/sbin/ip",
                    &["-n", ns, "-o", "-4", "addr", "show", "dev", "eth0"],
                )
                .1
                .contains(VIP)
            }

            pub(super) fn unit_active(&self, node: &str) -> String {
                run("/usr/bin/systemctl", &["is-active", &unit_of(node)])
                    .1
                    .trim()
                    .to_string()
            }

            pub(super) fn established_between_nodes(&self) -> bool {
                run(
                    "/usr/sbin/ip",
                    &[
                        "netns",
                        "exec",
                        "node-a",
                        "/usr/bin/ss",
                        "-Htn",
                        "state",
                        "established",
                    ],
                )
                .1
                .contains(":7946")
            }

            pub(super) fn witness_final_state(&mut self) -> String {
                let stop = self.dir.join("witness.stop");
                let _ = std::fs::write(&stop, b"stop");
                let index = self.proc_index("witness");
                let done =
                    self.wait_until("witness host STOPPED", Duration::from_secs(20), |lab| {
                        lab.witness_lines().iter().any(|l| l.contains("STOPPED"))
                    });
                let _ = done;
                let _ = self.procs[index].child.wait();
                self.witness_lines()
                    .into_iter()
                    .find(|l| l.contains("final state:"))
                    .unwrap_or_default()
            }

            // ---- shared sequences ----------------------------------------------

            pub(super) fn start_standby_pair(&mut self, fencing: &Fencing) {
                self.write_config("node-a", fencing);
                self.write_config("node-b", fencing);
                self.start_witness();
                self.start_daemon("node-a");
                self.start_daemon("node-b");
                let up = self.wait_until(
                    "peer connection node-a <-> node-b established",
                    Duration::from_secs(40),
                    |lab| lab.established_between_nodes(),
                );
                self.require("peers connected", up, "node-a dials node-b:7946");
                // Let authenticated heartbeats make the peer Healthy.
                self.sleep(8.0, "heartbeats make the peer Healthy");
                let alive = self.daemon_alive("node-a") && self.daemon_alive("node-b");
                self.require("both daemons running", alive, "node-a and node-b alive");
            }

            /// Operator loop: SIGUSR1 on `node` until the daemon opened a
            /// fencing incident (each signal is one explicit operator action;
            /// the harness never retries after a blocking verdict other than
            /// "no incident yet").
            pub(super) fn sigusr1_until_incident(
                &mut self,
                node: &str,
                max_tries: u32,
                spacing: f64,
            ) -> (u32, String) {
                let mut last = String::new();
                for attempt in 1..=max_tries {
                    last = self.sigusr1(node);
                    if self.incident(node) != "none" {
                        return (attempt, last);
                    }
                    self.sleep(spacing, "no incident yet; operator waits and signals again");
                }
                (max_tries, last)
            }

            pub(super) fn finish(&mut self) {
                let owned = self.topology.owned_links();
                let mid = (self.snapshot_source)(&owned);
                let verdict = mgmt_net::compare(&self.mgmt_before, &mid);
                let unchanged = verdict.pass;
                self.check(
                    "MGMT-NET during-run snapshot equals pre-run",
                    unchanged,
                    if unchanged {
                        "identical (audited comparison)"
                    } else {
                        "DIFFERENT (see mgmt-during-compare.txt)"
                    },
                );
                if !unchanged {
                    let _ = std::fs::write(self.dir.join("mgmt-during.txt"), mid.to_string());
                    let _ =
                        std::fs::write(self.dir.join("mgmt-during-compare.txt"), &verdict.report);
                }
                // The cleanup runs HERE, inside the test body, so that what it
                // finds is part of the verdict — as three SEPARATE checks: the
                // management network after teardown, every cleanup step done,
                // nothing left. `Drop` cannot do that (a panic there would abort
                // the process when the thread is already unwinding); it only
                // repeats nothing, because the cleanup has run.
                let teardown = self.teardown();
                for (id, ok, detail) in teardown.verdicts() {
                    self.check(id, ok, detail);
                }
                let failed: Vec<String> = self
                    .checks
                    .iter()
                    .filter(|(_, ok, _)| !ok)
                    .map(|(id, _, d)| format!("{id}: {d}"))
                    .collect();
                let summary = format!(
                    "scenario {}: {} checks, {} failed\n{}\n",
                    self.name,
                    self.checks.len(),
                    failed.len(),
                    failed.join("\n")
                );
                eprintln!("VF SUMMARY {summary}");
                assert!(
                    failed.is_empty(),
                    "VF scenario {} FAILED:\n{}",
                    self.name,
                    failed.join("\n")
                );
            }

            /// Tear down everything this lab created, ONCE (later calls return
            /// the first report). Never panics: every cleanup step runs inside
            /// its own failure boundary (`lab_own::run_steps`: a failed or
            /// panicking step is recorded and the next one still runs), and so
            /// do the after-teardown comparison and the residue check. Evidence
            /// (run dir) is kept, `teardown.txt` always.
            fn teardown(&mut self) -> Teardown {
                if let Some(done) = &self.teardown_report {
                    return done.clone();
                }
                if self.teardown_started {
                    // An earlier teardown was cut short outside every boundary:
                    // never repeat it, and never call it clean.
                    return Teardown {
                        mgmt_clean: false,
                        mgmt_report: "the teardown was interrupted\n".to_string(),
                        steps: vec![lab_own::StepReport {
                            name: "teardown".to_string(),
                            end: lab_own::StepEnd::Panicked(
                                "interrupted before its report".to_string(),
                            ),
                        }],
                        residue: lab_own::Residue {
                            left: Vec::new(),
                            unknown: vec!["the teardown was interrupted".to_string()],
                        },
                    };
                }
                self.teardown_started = true;
                let steps = self.cleanup_steps();
                let fault = self.cleanup_fault.clone();
                let inject = move |name: &str| {
                    if let Some(at) = &fault
                        && name.starts_with(at.as_str())
                    {
                        panic!("injected cleanup panic in step `{name}`");
                    }
                };
                let steps = lab_own::run_steps(self, steps, &inject);
                let (mgmt_clean, mgmt_report) = self.mgmt_after_cleanup();
                let residue =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.probe_residue()))
                        .unwrap_or_else(|payload| lab_own::Residue {
                            left: Vec::new(),
                            unknown: vec![format!(
                                "the residue check panicked: {}",
                                lab_own::panic_message(&*payload)
                            )],
                        });
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let Lab {
                        topology, kernel, ..
                    } = self;
                    topology.release_all(&mut **kernel);
                }));
                let report = Teardown {
                    mgmt_clean,
                    mgmt_report,
                    steps,
                    residue,
                };
                let line = format!(
                    "teardown: mgmt-net {} cleanup {} residue {}\n",
                    if report.mgmt_clean {
                        "identical"
                    } else {
                        "DIFFERENT"
                    },
                    if report.failed_steps().is_empty() {
                        "complete"
                    } else {
                        "FAILED"
                    },
                    if report.residue.is_clean() {
                        "none"
                    } else {
                        "LEFT-OR-UNKNOWN"
                    }
                );
                eprint!("VF {line}");
                let _ = self.timeline.write_all(line.as_bytes());
                let _ = std::fs::write(self.dir.join("teardown.txt"), report.render());
                let _ = std::fs::write(
                    self.dir.join("topology.txt"),
                    self.topology.log.join("\n") + "\n",
                );
                self.teardown_report = Some(report.clone());
                report
            }

            /// Every cleanup step, in order, for what this lab created. Each one
            /// is its own failure boundary (see `teardown`).
            fn cleanup_steps(&self) -> Vec<lab_own::Step<Lab>> {
                let mut steps: Vec<lab_own::Step<Lab>> = Vec::new();
                // Processes first: resume stopped ones so they can exit, then
                // terminate their whole process group.
                for index in 0..self.procs.len() {
                    steps.push((
                        format!("stop process {}", self.procs[index].label),
                        Box::new(move |lab: &mut Lab| lab.stop_process(index)),
                    ));
                }
                // Anything still inside the lab's OWN namespaces (the ones it
                // holds, by inode — not by name) belongs to this lab.
                for ns in self.topology.netns() {
                    steps.push((
                        format!("kill what is left inside the lab's netns {ns}"),
                        Box::new(move |lab: &mut Lab| {
                            for pid in lab.kernel.pids_in(&ns)? {
                                signal(pid, libc::SIGKILL);
                            }
                            Ok(())
                        }),
                    ));
                }
                steps.push((
                    "kill the hang-script processes".to_string(),
                    Box::new(|lab: &mut Lab| {
                        for file in ["hang-leader.pid", "hang-child.pid"] {
                            if let Ok(pid) = std::fs::read_to_string(lab.runtime.join(file))
                                && let Ok(pid) = pid.trim().parse::<i32>()
                                && pid_alive(pid)
                            {
                                signal(pid, libc::SIGKILL);
                            }
                        }
                        Ok(())
                    }),
                ));
                // Units the daemons may have started.
                for unit in self.units.clone() {
                    steps.push((
                        format!("stop unit {unit}"),
                        Box::new(move |lab: &mut Lab| {
                            lab_own::command(&lab.systemctl, &["stop", &unit])
                        }),
                    ));
                }
                // The topology: only what was recorded, newest first.
                for created in self.topology.removal_order() {
                    steps.push((
                        format!("remove {}", created.describe()),
                        Box::new(move |lab: &mut Lab| {
                            let Lab {
                                topology, kernel, ..
                            } = lab;
                            topology.remove(&mut **kernel, &created)
                        }),
                    ));
                }
                // Keep the script / arping logs as evidence before removing RUNTIME.
                steps.push((
                    "keep the script / arping logs".to_string(),
                    Box::new(|lab: &mut Lab| {
                        for file in ["script-events.log", "arping.log"] {
                            let from = lab.runtime.join(file);
                            if from.exists() {
                                std::fs::copy(&from, lab.dir.join(file))
                                    .map_err(|error| format!("{}: {error}", from.display()))?;
                            }
                        }
                        Ok(())
                    }),
                ));
                if self.created_runtime {
                    steps.push((
                        "remove the runtime dir".to_string(),
                        Box::new(|lab: &mut Lab| {
                            std::fs::remove_dir_all(&lab.runtime)
                                .map_err(|error| format!("{}: {error}", lab.runtime.display()))
                        }),
                    ));
                }
                if self.created_libexec {
                    steps.push((
                        "remove the script dir".to_string(),
                        Box::new(|lab: &mut Lab| {
                            std::fs::remove_dir_all(&lab.libexec)
                                .map_err(|error| format!("{}: {error}", lab.libexec.display()))
                        }),
                    ));
                }
                if self.created_libexec_parent {
                    steps.push((
                        "remove the script dir's parent".to_string(),
                        Box::new(|lab: &mut Lab| {
                            let parent = lab.libexec.parent().ok_or("no parent")?.to_path_buf();
                            std::fs::remove_dir(&parent)
                                .map_err(|error| format!("{}: {error}", parent.display()))
                        }),
                    ));
                }
                if !self.units.is_empty() {
                    for unit in self.units.clone() {
                        steps.push((
                            format!("remove unit file {unit}"),
                            Box::new(move |lab: &mut Lab| {
                                let path = lab.unit_dir.join(&unit);
                                match std::fs::remove_file(&path) {
                                    Ok(()) => Ok(()),
                                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                                        Ok(())
                                    }
                                    Err(error) => Err(format!("{}: {error}", path.display())),
                                }
                            }),
                        ));
                    }
                    steps.push((
                        "systemctl daemon-reload".to_string(),
                        Box::new(|lab: &mut Lab| {
                            lab_own::command(&lab.systemctl, &["daemon-reload"])
                        }),
                    ));
                }
                if self.created_state_root {
                    // Only the root we created, and only if empty: the run dir
                    // inside it is evidence (normally it stays, by design).
                    steps.push((
                        "remove the evidence root if empty".to_string(),
                        Box::new(|_: &mut Lab| match std::fs::remove_dir(STATE_ROOT) {
                            Ok(()) => Ok(()),
                            Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => {
                                Ok(())
                            }
                            Err(error) => Err(format!("{STATE_ROOT}: {error}")),
                        }),
                    ));
                }
                steps
            }

            /// Stop one process the lab started (and its whole process group).
            fn stop_process(&mut self, index: usize) -> Result<(), String> {
                let pid = self.procs[index].pid();
                if self.procs[index].alive() {
                    signal(pid, libc::SIGCONT);
                    signal(pid, libc::SIGTERM);
                    let deadline = Instant::now() + Duration::from_secs(8);
                    while self.procs[index].alive() && Instant::now() < deadline {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    if self.procs[index].alive() {
                        // SAFETY: kill(2) on the process group this lab created.
                        unsafe {
                            libc::kill(-pid, libc::SIGKILL);
                        }
                        self.procs[index]
                            .child
                            .wait()
                            .map_err(|error| format!("pid {pid}: {error}"))?;
                    }
                }
                if let Some(reader) = self.procs[index].reader.take() {
                    reader
                        .join()
                        .map_err(|_| format!("pid {pid}: its output reader panicked"))?;
                }
                if self.procs[index].alive() {
                    Err(format!("pid {pid} is still alive"))
                } else {
                    Ok(())
                }
            }

            /// After the cleanup: everything the lab created must be gone. A
            /// path that still exists, a process still alive, anything of the
            /// topology (see `Topology::probe`) is LEFT; what cannot be checked
            /// is UNKNOWN. Either is a FAIL.
            fn probe_residue(&mut self) -> lab_own::Residue {
                let mut residue = lab_own::Residue::default();
                for proc in &mut self.procs {
                    if proc.alive() {
                        residue
                            .left
                            .push(format!("process {} (pid {})", proc.label, proc.pid()));
                    }
                }
                {
                    let Lab {
                        topology, kernel, ..
                    } = self;
                    topology.probe(&mut **kernel, &mut residue);
                }
                lab_own::probe_path(&self.runtime, "runtime dir", &mut residue);
                lab_own::probe_path(&self.libexec, "script dir", &mut residue);
                if self.created_libexec_parent
                    && let Some(parent) = self.libexec.parent()
                {
                    lab_own::probe_path(parent, "script dir's parent", &mut residue);
                }
                for unit in &self.units {
                    lab_own::probe_path(&self.unit_dir.join(unit), "unit file", &mut residue);
                }
                residue
            }

            /// After the cleanup: the management network against its pre-run
            /// state. NOTHING is scoped out here — every device the lab created
            /// must be gone, so a leftover lab device is a difference too. A
            /// snapshot or comparison that fails (or panics) is "not clean",
            /// never "nothing to compare". Never panics itself.
            fn mgmt_after_cleanup(&mut self) -> (bool, String) {
                let compared = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let after = (self.snapshot_source)(&[]);
                    let verdict = mgmt_net::compare(&self.mgmt_before, &after);
                    (after, verdict)
                }));
                let (clean, report, after_text) = match compared {
                    Ok((after, verdict)) => (verdict.pass, verdict.report, after.to_string()),
                    Err(_) => (
                        false,
                        "the after-teardown snapshot or comparison panicked: the management \
                         network could not be compared\n"
                            .to_string(),
                        String::from("<<no after-teardown snapshot>>\n"),
                    ),
                };
                if !clean {
                    let _ = std::fs::write(self.dir.join("mgmt-after.txt"), after_text);
                    let _ = std::fs::write(self.dir.join("mgmt-after-compare.txt"), &report);
                }
                (clean, report)
            }
        }

        impl Drop for Lab {
            fn drop(&mut self) {
                if std::thread::panicking() {
                    eprintln!(
                        "VF evidence preserved (scenario panicked or was BLOCKED): {}",
                        self.dir.display()
                    );
                }
                // `teardown` never panics (every step, the comparison and the
                // residue check have their own boundary). This outer boundary
                // only makes sure that not even a bug there unwinds out of
                // `drop` — which would abort a thread that is already unwinding.
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    self.teardown();
                }))
                .is_err()
                {
                    eprintln!(
                        "VF teardown panicked outside its boundaries; evidence kept in {}",
                        self.dir.display()
                    );
                }
            }
        }

        // ---- scenario helpers (observation only) -------------------------------

        fn daemon_has(lab: &Lab, node: &str, needle: &str) -> bool {
            lab.daemon_lines(node)
                .iter()
                .any(|(_, line)| line.contains(needle))
        }

        fn daemon_lines_after(lab: &Lab, node: &str, since_ms: u128) -> Vec<String> {
            lab.daemon_lines(node)
                .into_iter()
                .filter(|(at, _)| *at >= since_ms)
                .map(|(_, line)| line)
                .collect()
        }

        fn attempt_results(lab: &Lab, node: &str) -> Vec<String> {
            lab.daemon_lines(node)
                .into_iter()
                .filter(|(_, line)| line.contains("manual promotion attempt"))
                .map(|(_, line)| line)
                .collect()
        }

        fn dump(lab: &mut Lab, label: &str, lines: &[String]) {
            lab.note(format!("evidence {label}: {} line(s)", lines.len()));
            for line in lines {
                lab.note(format!("  | {line}"));
            }
        }

        fn wait_state(lab: &mut Lab, node: &str, wanted: &str, timeout: u64) -> bool {
            let wanted = wanted.to_string();
            let node = node.to_string();
            lab.wait_until(
                &format!("{node} fencing.state == {wanted}"),
                Duration::from_secs(timeout),
                |lab| lab.fencing_state(&node) == wanted,
            )
        }

        /// Standby pair; node-b frozen (SIGSTOP) so node-a loses it; loss given
        /// time to form (suspect 2 s + unreachable 4 s + margin).
        fn freeze_node_b_and_let_loss_form(lab: &mut Lab) -> u128 {
            let at = now_ms();
            lab.sigstop("node-b");
            let stopped = lab.ns_pids("node-b");
            let all_stopped =
                !stopped.is_empty() && stopped.iter().all(|pid| lab.proc_state(*pid) == Some('T'));
            lab.check(
                "SETUP node-b netns processes are all stopped",
                all_stopped,
                format!("pids {stopped:?}"),
            );
            lab.sleep(8.0, "peer-loss confirmation window on node-a");
            at
        }

        // ======================================================================
        // P14.12-F1 probe: what ONE SIGUSR1 does at chosen times (observation
        // only; no fencing, no peer, no authority is involved: node-b is not
        // started, so every attempt is expected to end BlockedBeforeMutation).
        // ======================================================================
        #[test]
        #[ignore = "Phase 14.12 F1 probe: root + lab VM; run via the lab driver"]
        fn f1_probe_single_sigusr1_at_chosen_times() {
            let mut lab = Lab::new("f1");
            lab.write_config("node-a", &Fencing::standard());
            lab.write_config("node-b", &Fencing::standard());
            lab.start_witness();
            lab.start_daemon("node-a");
            let mut summary = Vec::new();
            let mut run = |lab: &mut Lab, label: &str| {
                let before = lab.daemon_lines("node-a").len();
                let result = lab.sigusr1("node-a");
                let reason = lab.daemon_lines("node-a")[before..]
                    .iter()
                    .find(|(_, l)| l.contains("activation attempt blocked"))
                    .map(|(_, l)| l.replace("mikagami: WARN activation attempt blocked: ", ""))
                    .unwrap_or_default();
                let get_terms = lab.witness_events("node-a", "GetTerm", 0).len();
                let line = format!(
                    "{label}: {} | reason: {reason} | Witness GetTerm total {get_terms} | LeaseRequest {} | incident {}",
                    result.rsplit("-> ").next().unwrap_or(""),
                    lab.witness_events("node-a", "LeaseRequest", 0).len(),
                    lab.incident("node-a")
                );
                lab.note(line.clone());
                summary.push(line);
            };
            // Within 5 s of the daemon's first prime.
            run(&mut lab, "A1 (+~2.5 s after daemon start)");
            lab.sleep(1.5, "next signal 1.5 s later");
            run(&mut lab, "A2 (+1.5 s)");
            lab.sleep(8.0, "idle for 8 s (> 5 s observation deadline)");
            run(&mut lab, "B1 (after 8 s idle)");
            lab.sleep(1.5, "next signal 1.5 s later");
            run(&mut lab, "B2 (+1.5 s)");
            lab.sleep(1.5, "next signal 1.5 s later");
            run(&mut lab, "B3 (+1.5 s)");
            lab.sleep(8.0, "idle for 8 s");
            run(&mut lab, "C1 (after 8 s idle)");
            let log = lab
                .daemon_lines("node-a")
                .into_iter()
                .map(|(_, l)| l)
                .collect::<Vec<_>>();
            dump(&mut lab, "node-a daemon log", &log);
            let witness = lab.witness_lines();
            dump(&mut lab, "witness events", &witness);
            lab.check("F1-OBS observation recorded", true, summary.join(" || "));
            lab.finish();
        }

        // ======================================================================
        // T-F1-4 (Linux real process), changed by Phase 14.12 E3b. It used to
        // require that an idle Standby KEEPS its Witness observation current
        // (the loop's background GET_TERM: >= 2 further requests in 22 s).
        // That background request is retired: an idle Standby sends the
        // Witness nothing, and a manual attempt issues its own GET_TERM. The
        // test now requires exactly that. Observation only: node-b is not
        // started.
        // ======================================================================
        #[test]
        #[ignore = "Phase 14.12 F1 T-F1-4 (E3b): root + lab VM; run via the lab driver"]
        fn f1_idle_standby_keeps_the_witness_observation_current() {
            let mut lab = Lab::new("f1idle");
            lab.write_config("node-a", &Fencing::standard());
            lab.write_config("node-b", &Fencing::standard());
            lab.start_witness();
            lab.start_daemon("node-a");
            let before = lab.witness_events("node-a", "GetTerm", 0).len();
            lab.sleep(
                22.0,
                "idle across four 5 s observation deadlines; no SIGUSR1",
            );
            let after = lab.witness_events("node-a", "GetTerm", 0).len();
            lab.note(format!("GetTerm requests from node-a: {before} -> {after}"));
            lab.check(
                "F1-T4a E3b: an idle Standby sends the Witness no GET_TERM (no background request)",
                after == before,
                format!("{before} -> {after}"),
            );
            lab.check(
                "F1-T4c no promotion attempt was made",
                attempt_results(&lab, "node-a").is_empty(),
                "no SIGUSR1 sent",
            );
            lab.check(
                "F1-T4d zero LeaseRequest",
                lab.witness_events("node-a", "LeaseRequest", 0).is_empty(),
                "no LeaseRequest",
            );
            lab.finish();
        }

        // ======================================================================
        // F1/F2 residual-window MEASUREMENT (no acceptance criterion). One
        // healthy peer, so every attempt ends BlockedBeforeMutation for the
        // same reason ("local loss not fresh") and nothing else can happen.
        // Each trial sends ONE SIGUSR1 at a chosen delay after the latest
        // observation GET_TERM and records whether the attempt reached the
        // authority evaluation or was refused for lack of a fresh observation.
        // The phase is measured from the daemon's own result-line time and the
        // Witness event times, not from the harness clock.
        // ======================================================================
        #[test]
        #[ignore = "Phase 14.12 F1/F2 residual-window measurement: root + lab VM; run via the lab driver"]
        fn f1_residual_window_measurement() {
            let mut lab = Lab::new("f1win");
            lab.start_standby_pair(&Fencing::standard());
            let offsets = [
                0.5, 1.5, 2.5, 3.5, 4.5, 4.9, 5.1, 5.3, 5.5, 5.7, 5.9, 6.2, 6.6, 7.0,
            ];
            let repeats: usize = std::env::var("MKM_F1_REPEATS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3);
            let at = |line: &str| -> u128 {
                line.split_whitespace()
                    .next()
                    .and_then(|t| t.parse().ok())
                    .unwrap_or(0)
            };
            let get_term_times = |lab: &Lab| -> Vec<u128> {
                lab.witness_events("node-a", "GetTerm", 0)
                    .iter()
                    .map(|l| at(l))
                    .collect()
            };
            let mut rows: Vec<(f64, f64, String)> = Vec::new();
            for repeat in 0..repeats {
                for (index, offset) in offsets.iter().enumerate() {
                    // Wait for a NEW observation request to start a fresh cycle.
                    let seen = get_term_times(&lab).len();
                    let began = lab.wait_until(
                        "a new observation request",
                        Duration::from_secs(30),
                        |lab| get_term_times(lab).len() > seen,
                    );
                    if !began {
                        rows.push((*offset, -1.0, "no-new-observation-request".into()));
                        continue;
                    }
                    lab.sleep(*offset, "delay after the newest observation request");
                    let before = lab.daemon_lines("node-a").len();
                    let result = lab.sigusr1("node-a");
                    let lines = lab.daemon_lines("node-a");
                    let attempted_at = lines
                        .iter()
                        .skip(before)
                        .find(|(_, l)| l.contains("manual promotion attempt"))
                        .map(|(t, _)| *t)
                        .unwrap_or(0);
                    let reason = lines[before..]
                        .iter()
                        .find(|(_, l)| l.contains("activation attempt blocked"))
                        .map(|(_, l)| l.replace("mikagami: WARN activation attempt blocked: ", ""))
                        .unwrap_or_else(|| result.clone());
                    let latest = get_term_times(&lab)
                        .into_iter()
                        .filter(|t| *t <= attempted_at)
                        .max()
                        .unwrap_or(0);
                    let phase = attempted_at.saturating_sub(latest) as f64 / 1000.0;
                    let outcome = if reason.contains("no fresh authority observation") {
                        "REFUSED:no-fresh-observation"
                    } else if reason.contains("authority evaluation failed") {
                        "REFUSED:evaluation-failed"
                    } else if reason.contains("local loss not fresh") {
                        "evaluated"
                    } else {
                        "other"
                    };
                    lab.note(format!(
                        "trial r{repeat}.{index}: delay {offset:.1}s phase {phase:.2}s -> {outcome} ({reason})"
                    ));
                    rows.push((*offset, phase, outcome.to_string()));
                }
            }
            let total = rows.len();
            let refused = rows.iter().filter(|r| r.2.starts_with("REFUSED")).count();
            let mut table = String::new();
            let mut sorted = rows.clone();
            sorted.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
            for (offset, phase, outcome) in &sorted {
                table.push_str(&format!(
                    "phase {phase:5.2}s (delay {offset:.1}s): {outcome}\n"
                ));
            }
            lab.note(format!(
                "MEASUREMENT trials {total}, refused {refused}, single environment\n{table}"
            ));
            lab.check(
                "F1-MEAS measurement recorded",
                total > 0,
                format!("{refused}/{total} refused"),
            );
            lab.check(
                "F1-MEAS no promotion, no LeaseRequest during the measurement",
                lab.witness_events("node-a", "LeaseRequest", 0).is_empty()
                    && !lab.role_active("node-a"),
                "peer healthy throughout",
            );
            lab.finish();
        }

        // ======================================================================
        // Phase 14.12 E3b probes (implementation-owner probes, NOT VF
        // acceptance). One healthy peer, so an attempt that reaches the
        // authority evaluation ends "local loss not fresh"; the Witness
        // answers GET_TERM after MKM_LAB_WITNESS_DELAY_MS (default 0).
        // ======================================================================
        fn e3b_outcome(reason: &str) -> &'static str {
            if reason.contains("local loss not fresh") {
                "evaluated"
            } else if reason.contains("no fresh authority observation")
                || reason.contains("authority evaluation failed")
                || reason.contains("could not be issued")
                || reason.contains("Witness")
                || reason.contains("shutdown")
            {
                "refused"
            } else {
                "other"
            }
        }

        /// One SIGUSR1; (outcome, blocked-reason, latency seconds, result line).
        fn e3b_attempt(lab: &mut Lab) -> (&'static str, String, f64, String) {
            let before = lab.daemon_lines("node-a").len();
            let started = Instant::now();
            let result = lab.sigusr1("node-a");
            let latency = started.elapsed().as_secs_f64();
            let reason = lab.daemon_lines("node-a")[before..]
                .iter()
                .find(|(_, l)| l.contains("activation attempt blocked"))
                .map(|(_, l)| l.replace("mikagami: WARN activation attempt blocked: ", ""))
                .unwrap_or_default();
            (e3b_outcome(&reason), reason, latency, result)
        }

        fn e3b_no_mutation(lab: &Lab) -> bool {
            lab.witness_events("node-a", "LeaseRequest", 0).is_empty()
                && !lab.role_active("node-a")
                && !lab.vip_present("node-a")
        }

        // Single SIGUSR1s at pseudo-random times (MKM_E3B_N, MKM_E3B_SEED).
        // MKM_E3B_EXPECT=evaluated (default) requires every attempt to reach
        // the evaluation; =refused requires every attempt to fail closed
        // (a Witness slower than the 5 s timeout). The Witness must see
        // exactly one GET_TERM per attempt and none in between.
        #[test]
        #[ignore = "Phase 14.12 E3b probe: root + lab VM; run via the lab driver"]
        fn e3b_lab_sweep() {
            let mut lab = Lab::new("e3bsweep");
            lab.start_standby_pair(&Fencing::standard());
            let n: usize = std::env::var("MKM_E3B_N")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(24);
            let mut state: u64 = std::env::var("MKM_E3B_SEED")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(12345);
            let expect = std::env::var("MKM_E3B_EXPECT").unwrap_or_else(|_| "evaluated".into());
            let base = lab.witness_events("node-a", "GetTerm", 0).len();
            let mut rows = Vec::new();
            for i in 0..n {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let gap = 1.2 + ((state >> 33) % 7600) as f64 / 1000.0; // 1.2 .. 8.8 s
                lab.sleep(gap, "pseudo-random gap before the next SIGUSR1");
                let (outcome, reason, latency, _) = e3b_attempt(&mut lab);
                lab.note(format!(
                    "trial {i}: gap {gap:.2}s -> {outcome} latency {latency:.2}s ({reason})"
                ));
                rows.push((outcome, latency));
            }
            // The Witness host reports through a pipe; let its last line land.
            lab.sleep(1.5, "let the Witness event log settle");
            let seen = lab.witness_events("node-a", "GetTerm", 0).len() - base;
            let count = |p: &str| rows.iter().filter(|r| r.0 == p).count();
            let max_latency = rows.iter().map(|r| r.1).fold(0.0, f64::max);
            lab.note(format!(
                "SWEEP trials {} evaluated {} refused {} other {} GetTerm-at-Witness {seen} max-latency {max_latency:.2}s",
                rows.len(),
                count("evaluated"),
                count("refused"),
                count("other"),
            ));
            lab.check(
                "E3B-SWEEP every attempt ended as expected",
                count(expect.as_str()) == rows.len(),
                format!(
                    "expect {expect}: {} of {}",
                    count(expect.as_str()),
                    rows.len()
                ),
            );
            lab.check(
                "E3B-SWEEP exactly one GET_TERM per attempt, none in between",
                seen == rows.len(),
                format!("{seen} GET_TERM for {} attempts", rows.len()),
            );
            lab.check(
                "E3B-SWEEP no promotion, no LeaseRequest",
                e3b_no_mutation(&lab),
                "peer healthy throughout",
            );
            lab.finish();
        }

        // Idle (MKM_E3B_IDLE seconds, default 100), then single SIGUSR1s: the
        // Witness sees no GET_TERM during the idle and one per attempt after.
        #[test]
        #[ignore = "Phase 14.12 E3b probe: root + lab VM; run via the lab driver"]
        fn e3b_lab_idle_then_single_attempts() {
            let mut lab = Lab::new("e3bidle");
            lab.start_standby_pair(&Fencing::standard());
            let idle: f64 = std::env::var("MKM_E3B_IDLE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(100.0);
            let before = lab.witness_events("node-a", "GetTerm", 0).len();
            let mut left = idle;
            while left > 0.0 {
                let step = left.min(10.0);
                lab.sleep(step, "idle Standby, no SIGUSR1");
                left -= step;
            }
            let after_idle = lab.witness_events("node-a", "GetTerm", 0).len();
            let mut outcomes = Vec::new();
            for i in 0..4 {
                let (outcome, reason, latency, _) = e3b_attempt(&mut lab);
                lab.note(format!(
                    "attempt {i}: {outcome} latency {latency:.2}s ({reason})"
                ));
                outcomes.push(outcome);
                lab.sleep(2.0, "gap before the next single SIGUSR1");
            }
            lab.sleep(1.5, "let the Witness event log settle");
            let after = lab.witness_events("node-a", "GetTerm", 0).len();
            lab.note(format!(
                "idle {idle:.0}s: GetTerm at the Witness {before} -> {after_idle} -> {after}; outcomes {outcomes:?}"
            ));
            lab.check(
                "E3B-IDLE no GET_TERM during the idle",
                after_idle == before,
                format!("{before} -> {after_idle}"),
            );
            lab.check(
                "E3B-IDLE every attempt after the idle reached the evaluation",
                outcomes.iter().all(|o| *o == "evaluated"),
                format!("{outcomes:?}"),
            );
            lab.check(
                "E3B-IDLE one GET_TERM per attempt",
                after - after_idle == 4,
                format!("{after_idle} -> {after}"),
            );
            lab.check(
                "E3B-IDLE no promotion, no LeaseRequest",
                e3b_no_mutation(&lab),
                "peer healthy throughout",
            );
            lab.finish();
        }

        // Failure probes (MKM_E3B_CASE):
        //   stall      the Witness is stopped (SIGSTOP): the attempt waits its
        //              5 s deadline and fails closed; after SIGCONT the late
        //              answer is discarded and the next attempt is evaluated.
        //   disconnect the Witness is killed: attempts fail closed at once.
        //   shutdown   the Witness is stopped and the daemon gets SIGTERM
        //              1 s into the wait: the daemon stops promptly, the
        //              attempt never reaches a gate / lease / mutation.
        #[test]
        #[ignore = "Phase 14.12 E3b probe: root + lab VM; run via the lab driver"]
        fn e3b_lab_failures() {
            let case = std::env::var("MKM_E3B_CASE").unwrap_or_else(|_| "stall".into());
            let mut lab = Lab::new(&format!("e3bfail{case}"));
            lab.start_standby_pair(&Fencing::standard());
            match case.as_str() {
                "stall" => {
                    lab.sigstop("witness");
                    let (outcome, reason, latency, _) = e3b_attempt(&mut lab);
                    lab.note(format!(
                        "stalled Witness: {outcome} after {latency:.2}s ({reason})"
                    ));
                    lab.check(
                        "E3B-STALL the attempt waited for its 5 s deadline and failed closed",
                        outcome == "refused" && (4.8..7.0).contains(&latency),
                        format!("{outcome} after {latency:.2}s: {reason}"),
                    );
                    lab.sigcont("witness");
                    lab.sleep(2.0, "the Witness answers the late request");
                    let (outcome, reason, latency, _) = e3b_attempt(&mut lab);
                    lab.note(format!(
                        "after SIGCONT: {outcome} after {latency:.2}s ({reason})"
                    ));
                    lab.check(
                        "E3B-STALL the next attempt discards the late answer and is evaluated",
                        outcome == "evaluated" && latency < 3.0,
                        format!("{outcome} after {latency:.2}s: {reason}"),
                    );
                    lab.sleep(1.5, "let the Witness event log settle");
                    let get_terms = lab.witness_events("node-a", "GetTerm", 0).len();
                    lab.check(
                        "E3B-STALL one GET_TERM per attempt (no retry)",
                        get_terms == 2,
                        format!("{get_terms} GET_TERM for 2 attempts"),
                    );
                }
                "disconnect" => {
                    let pid = lab.pid("witness");
                    signal(pid, libc::SIGKILL);
                    lab.sleep(1.0, "the Witness is gone");
                    let mut all_refused = true;
                    for i in 0..2 {
                        let (outcome, reason, latency, _) = e3b_attempt(&mut lab);
                        lab.note(format!(
                            "disconnected Witness, attempt {i}: {outcome} after {latency:.2}s ({reason})"
                        ));
                        all_refused &= outcome == "refused" && latency < 6.0;
                        lab.sleep(1.0, "gap");
                    }
                    lab.check(
                        "E3B-DISCONNECT every attempt failed closed",
                        all_refused,
                        "no Witness",
                    );
                }
                "shutdown" => {
                    lab.sigstop("witness");
                    let pid = lab.pid("node-a");
                    let before = lab.daemon_lines("node-a").len();
                    signal(pid, libc::SIGUSR1);
                    // The loop sleeps up to its 1 s interval before it consumes
                    // the intent; by 2.5 s the attempt is certainly inside its
                    // 5 s wait for the stopped Witness.
                    lab.sleep(2.5, "the attempt is waiting for the stopped Witness");
                    let started = Instant::now();
                    signal(pid, libc::SIGTERM);
                    let mut stopped_after = None;
                    while started.elapsed() < Duration::from_secs(30) {
                        if !lab.daemon_alive("node-a") {
                            stopped_after = Some(started.elapsed().as_secs_f64());
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    lab.sleep(1.0, "let the daemon's last lines land");
                    let lines: Vec<String> = lab.daemon_lines("node-a")[before..]
                        .iter()
                        .map(|(_, l)| l.clone())
                        .collect();
                    dump(&mut lab, "node-a log after the signals", &lines);
                    lab.sigcont("witness");
                    lab.check(
                        "E3B-SHUTDOWN the daemon stopped promptly while the attempt waited",
                        stopped_after.is_some_and(|t| t < 2.0),
                        format!("stopped after {stopped_after:?} s"),
                    );
                    lab.check(
                        "E3B-SHUTDOWN the attempt was blocked by the shutdown",
                        lines
                            .iter()
                            .any(|l| l.contains("activation attempt blocked: shutdown requested"))
                            && lines.iter().any(|l| l.contains("BlockedBeforeMutation")),
                        "operator log names the shutdown and the BlockedBeforeMutation result",
                    );
                    lab.check(
                        "E3B-SHUTDOWN no fencing step, no LeaseRequest, no promotion",
                        e3b_no_mutation(&lab)
                            && !lines
                                .iter()
                                .any(|l| l.contains("fenc") && !l.contains("shutdown")),
                        "nothing past the observation step",
                    );
                }
                other => panic!("unknown MKM_E3B_CASE {other}"),
            }
            lab.check("E3B-FAIL no mutation", e3b_no_mutation(&lab), "no mutation");
            lab.finish();
        }

        // ======================================================================
        // Phase 14.12 F7 probes (implementation-owner probes, NOT VF
        // acceptance). A stopped Witness while the operator keeps sending
        // SIGUSR1 (MKM_F7_STALLS attempts, each waiting out its 5 s deadline),
        // then the Witness is resumed and answers every queued GET_TERM at once.
        // ======================================================================
        fn f7_gap(lab: &mut Lab) {
            lab.sleep(7.0, "gap: the previous attempt's request has expired");
        }

        #[test]
        #[ignore = "F7 probe: root + lab VM; run via the lab driver"]
        fn f7_lab_stall_recovery() {
            let stalls: usize = std::env::var("MKM_F7_STALLS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10);
            let mut lab = Lab::new("f7stall");
            lab.start_standby_pair(&Fencing::standard());
            lab.sigstop("witness");
            let mut stalled = Vec::new();
            for i in 0..stalls {
                let (outcome, reason, latency, _) = e3b_attempt(&mut lab);
                if i < 3 || i + 1 == stalls {
                    lab.note(format!(
                        "stalled attempt {i}: {outcome} after {latency:.2}s ({reason})"
                    ));
                }
                stalled.push(outcome);
            }
            lab.sigcont("witness");
            lab.sleep(3.0, "the resumed Witness answers every queued GET_TERM");
            let mut after = Vec::new();
            for i in 0..8 {
                let (outcome, reason, latency, _) = e3b_attempt(&mut lab);
                lab.note(format!(
                    "after resume, attempt {i}: {outcome} after {latency:.2}s ({reason})"
                ));
                after.push(outcome);
                lab.sleep(2.0, "gap before the next single SIGUSR1");
            }
            lab.sleep(1.5, "let the Witness event log settle");
            let get_terms = lab.witness_events("node-a", "GetTerm", 0).len();
            lab.note(format!(
                "F7SUMMARY stalls={stalls} stalled_refused={} after_resume_evaluated={} of {} witness_get_term={get_terms}",
                stalled.iter().filter(|o| **o == "refused").count(),
                after.iter().filter(|o| **o == "evaluated").count(),
                after.len(),
            ));
            lab.check(
                "F7-LAB every stalled attempt failed closed",
                stalled.iter().all(|o| *o == "refused"),
                format!(
                    "{} of {}",
                    stalled.iter().filter(|o| **o == "refused").count(),
                    stalled.len()
                ),
            );
            lab.check(
                "F7-LAB the first attempt after the Witness resumed reached the authority evaluation",
                after.first() == Some(&"evaluated"),
                format!("{after:?}"),
            );
            lab.check(
                "F7-LAB every later single SIGUSR1 reached the evaluation",
                after.iter().all(|o| *o == "evaluated"),
                format!("{after:?}"),
            );
            lab.check(
                "F7-LAB exactly one GET_TERM per attempt, none in between (no retry, one outstanding)",
                get_terms == stalls + after.len(),
                format!("{get_terms} GET_TERM for {} attempts", stalls + after.len()),
            );
            lab.check(
                "F7-LAB no promotion, no LeaseRequest",
                e3b_no_mutation(&lab),
                "peer healthy throughout",
            );
            lab.finish();
        }

        // Invalid late answers: after the stall the resumed Witness signs every
        // answer with a wrong key (lab flag file). Each such frame fails the
        // attempt that reads it closed, none becomes evidence, and once the
        // Witness signs correctly again the daemon recovers on its own.
        #[test]
        #[ignore = "F7 probe: root + lab VM; run via the lab driver"]
        fn f7_lab_invalid_late_answers() {
            let stalls = 6;
            let mut lab = Lab::new("f7bad");
            lab.start_standby_pair(&Fencing::standard());
            lab.sigstop("witness");
            for _ in 0..stalls {
                let _ = e3b_attempt(&mut lab);
            }
            let flag = lab.dir.join("witness.badauth");
            std::fs::write(&flag, b"1").expect("flag file");
            lab.sigcont("witness");
            lab.sleep(
                3.0,
                "the resumed Witness answers every queued GET_TERM with a wrong key",
            );
            let mut while_invalid = Vec::new();
            for _ in 0..3 {
                let (outcome, reason, _, _) = e3b_attempt(&mut lab);
                lab.note(format!("invalid answers: {outcome} ({reason})"));
                while_invalid.push(outcome);
                f7_gap(&mut lab);
            }
            std::fs::remove_file(&flag).expect("flag removed");
            let mut recovered_after = None;
            for i in 0..14 {
                let (outcome, reason, _, _) = e3b_attempt(&mut lab);
                lab.note(format!("valid again, attempt {i}: {outcome} ({reason})"));
                if outcome == "evaluated" {
                    recovered_after = Some(i);
                    break;
                }
                f7_gap(&mut lab);
            }
            lab.check(
                "F7-LAB attempts that read only invalid answers failed closed",
                while_invalid.iter().all(|o| *o == "refused"),
                format!("{while_invalid:?}"),
            );
            lab.check(
                "F7-LAB the daemon recovered once the Witness answered validly again",
                recovered_after.is_some(),
                format!("recovered at attempt {recovered_after:?}"),
            );
            lab.check(
                "F7-LAB no promotion, no LeaseRequest",
                e3b_no_mutation(&lab),
                "peer healthy throughout",
            );
            lab.finish();
        }

        // ======================================================================
        // VF-7: CONFIRMED + 20 idle iterations -> no LeaseRequest
        // ======================================================================
        #[test]
        #[ignore = "Phase 14.12 VF-7: root + lab VM (netns/veth); run via the lab driver"]
        fn vf7_confirmed_plus_idle_iterations_sends_no_lease_request() {
            let mut lab = Lab::new("vf7");
            lab.start_standby_pair(&Fencing::standard());
            freeze_node_b_and_let_loss_form(&mut lab);
            let (tries, first) = lab.sigusr1_until_incident("node-a", 1, 0.0);
            lab.note(format!(
                "incident opened after {tries} SIGUSR1; result: {first}"
            ));
            lab.require(
                "incident open",
                lab.incident("node-a") != "none",
                format!("fencing.incident = {}", lab.incident("node-a")),
            );
            let confirmed = wait_state(&mut lab, "node-a", "CONFIRMED", 40);
            lab.require("CONFIRMED reached", confirmed, lab.fencing_state("node-a"));
            let t_confirmed = now_ms();
            let requests_before = lab.witness_events("node-a", "LeaseRequest", 0).len();
            let attempts_before = attempt_results(&lab, "node-a").len();
            let get_terms_before = lab.witness_events("node-a", "GetTerm", 0).len();

            // 30 s of idle at a 1 s iteration interval: >= 20 iterations. No
            // SIGUSR1 is sent in this window.
            lab.sleep(30.0, "idle window: CONFIRMED, no operator input");
            let elapsed = (now_ms() - t_confirmed) as f64 / 1000.0;

            let requests = lab.witness_events("node-a", "LeaseRequest", 0);
            let get_terms = lab.witness_events("node-a", "GetTerm", 0).len();
            lab.check(
                "VF7-01 CONFIRMED held while idle",
                lab.fencing_state("node-a") == "CONFIRMED",
                lab.fencing_state("node-a"),
            );
            lab.check(
                "VF7-02 zero LeaseRequest from node-a at the Witness (whole run)",
                requests.is_empty() && requests_before == 0,
                format!("LeaseRequest events from node-a: {}", requests.len()),
            );
            lab.check(
                "VF7-03 idle window long enough for >= 20 iterations (interval 1 s)",
                elapsed >= 20.0,
                format!("{elapsed:.1}s elapsed with heartbeat.interval_sec = 1"),
            );
            lab.check(
                "VF7-04 no promotion attempt ran in the idle window",
                attempt_results(&lab, "node-a").len() == attempts_before,
                format!("attempts before={attempts_before}"),
            );
            lab.check(
                "VF7-05 node-a stayed Standby (no role, no unit, no VIP)",
                !lab.role_active("node-a")
                    && lab.unit_active("node-a") != "active"
                    && !lab.vip_present("node-a"),
                format!(
                    "role_active={} unit={} vip={}",
                    lab.role_active("node-a"),
                    lab.unit_active("node-a"),
                    lab.vip_present("node-a")
                ),
            );
            lab.check(
                "VF7-06 daemon still running",
                lab.daemon_alive("node-a"),
                "alive",
            );
            lab.note(format!(
                "info: GetTerm from node-a before/after idle: {get_terms_before} -> {get_terms}"
            ));
            let final_state = lab.witness_final_state();
            lab.note(format!("witness {final_state}"));
            lab.finish();
        }

        // ======================================================================
        // VF-8: hanging fence script -> group killed at the bound
        // ======================================================================
        #[test]
        #[ignore = "Phase 14.12 VF-8: root + lab VM (netns/veth); run via the lab driver"]
        fn vf8_hanging_fence_script_is_group_killed_at_the_bound() {
            let mut lab = Lab::new("vf8");
            let fencing = Fencing::Command {
                fence_script: "fence-hang.sh",
                verify_script: "verify.sh",
                fence_timeout_sec: 1,
                verify_timeout_sec: 5,
                verify_polls: 6,
            };
            lab.start_standby_pair(&fencing);
            freeze_node_b_and_let_loss_form(&mut lab);

            // Poller: watch the hanging leader appear and disappear.
            let seen: Arc<Mutex<(Option<u128>, Option<u128>, Option<i32>)>> =
                Arc::new(Mutex::new((None, None, None)));
            let seen_in = seen.clone();
            let stop_poll = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stop_in = stop_poll.clone();
            let poller = std::thread::spawn(move || {
                let pid_file = Path::new(RUNTIME).join("hang-leader.pid");
                while !stop_in.load(std::sync::atomic::Ordering::SeqCst) {
                    let mut seen = seen_in.lock().unwrap();
                    if seen.0.is_none() {
                        if let Ok(text) = std::fs::read_to_string(&pid_file)
                            && let Ok(pid) = text.trim().parse::<i32>()
                            && pid_alive(pid)
                        {
                            seen.0 = Some(now_ms());
                            seen.2 = Some(pid);
                        }
                    } else if seen.1.is_none() {
                        let pid = seen.2.unwrap();
                        // A killed leader is reaped by the daemon; a zombie
                        // (state Z) counts as already dead for this purpose.
                        let state = std::fs::read_to_string(format!("/proc/{pid}/stat"))
                            .ok()
                            .and_then(|s| s.rsplit(')').next().map(|t| t.trim().to_string()))
                            .and_then(|t| t.chars().next());
                        if state.is_none() || state == Some('Z') {
                            seen.1 = Some(now_ms());
                        }
                    }
                    drop(seen);
                    std::thread::sleep(Duration::from_millis(20));
                }
            });

            let (tries, first) = lab.sigusr1_until_incident("node-a", 1, 0.0);
            lab.sleep(
                3.0,
                "let the bounded step and the first verify polls settle",
            );
            stop_poll.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = poller.join();
            let (appeared, vanished, leader) = *seen.lock().unwrap();
            lab.note(format!(
                "hang leader pid {leader:?} appeared {appeared:?} vanished {vanished:?}; \
                 attempt result: {first}; SIGUSR1 tries {tries}"
            ));

            let script_log = lab.script_events();
            dump(&mut lab, "script-events", &script_log);
            let started = script_log
                .iter()
                .filter(|l| l.contains("fence-hang start"))
                .count();
            // Step bound as the daemon's own log shows it: from the fence
            // action's start to the attempt's result line.
            let fence_started_at = script_log
                .iter()
                .find(|l| l.contains("fence-hang start"))
                .and_then(|l| {
                    l.split_whitespace()
                        .next()
                        .and_then(|t| t.parse::<u128>().ok())
                });
            let result_at = fence_started_at.and_then(|started_at| {
                lab.daemon_lines("node-a")
                    .into_iter()
                    .find(|(at, l)| *at >= started_at && l.contains("manual promotion attempt"))
                    .map(|(at, _)| at)
            });
            let step_seconds = match (fence_started_at, result_at) {
                (Some(a), Some(b)) => Some(b.saturating_sub(a) as f64 / 1000.0),
                _ => None,
            };
            lab.check(
                "VF8-01 the hanging fence action was spawned exactly once",
                started == 1,
                format!("{started} start event(s)"),
            );
            let lifetime = match (appeared, vanished) {
                (Some(a), Some(v)) => Some(v.saturating_sub(a) as f64 / 1000.0),
                _ => None,
            };
            // fence_timeout_sec = 1: TERM at 1 s; the script ignores TERM, so the
            // group dies at the KILL escalation (1 s + 2 s grace = 3 s).
            lab.check(
                "VF8-02 process group killed at the bound (>= TERM+grace, <= hard deadline)",
                lifetime.is_some_and(|l| (2.5..=5.5).contains(&l)),
                format!("leader lifetime {lifetime:?} s (expected ~3 s; bound 1+2+2 = 5 s)"),
            );
            let child_alive = std::fs::read_to_string(Path::new(RUNTIME).join("hang-child.pid"))
                .ok()
                .and_then(|t| t.trim().parse::<i32>().ok())
                .is_some_and(|pid| pid_alive(pid) && lab.proc_state(pid).is_some_and(|s| s != 'Z'));
            lab.check(
                "VF8-02b the attempt returned within the end-to-end bound (3 s KILL .. 5.5 s return)",
                step_seconds.is_some_and(|d| (2.5..=6.0).contains(&d)),
                format!("fence start -> attempt result {step_seconds:?} s (timeout 1 s + 2 s + 2 s + 0.5 s)"),
            );
            lab.check(
                "VF8-03 the TERM-ignoring child in the same group is gone",
                !child_alive,
                format!("child alive = {child_alive}"),
            );
            let survivors = run("/usr/bin/pgrep", &["-f", "sleep 600"]).1;
            lab.check(
                "VF8-04 no `sleep 600` left behind by the hanging script",
                survivors.trim().is_empty(),
                format!("pgrep: {:?}", survivors.trim()),
            );
            lab.check(
                "VF8-05 daemon alive; attempt ended blocked (no activation)",
                lab.daemon_alive("node-a")
                    && first.contains("BlockedBeforeMutation")
                    && !lab.role_active("node-a"),
                first.clone(),
            );
            lab.check(
                "VF8-06 verification followed the bounded action (state advanced past REQUESTED)",
                daemon_has(&lab, "node-a", "REQUESTED -> VERIFYING"),
                format!("fencing.state = {}", lab.fencing_state("node-a")),
            );
            lab.check(
                "VF8-07 zero LeaseRequest from node-a",
                lab.witness_events("node-a", "LeaseRequest", 0).is_empty(),
                "no LeaseRequest at the Witness",
            );
            let log = lab
                .daemon_lines("node-a")
                .into_iter()
                .map(|(_, l)| l)
                .collect::<Vec<_>>();
            dump(&mut lab, "node-a daemon log", &log);
            lab.finish();
        }

        // ======================================================================
        // VF-3: verify forced `not-isolated` -> FAILED -> blocked
        // ======================================================================
        #[test]
        #[ignore = "Phase 14.12 VF-3: root + lab VM (netns/veth); run via the lab driver"]
        fn vf3_verify_forced_not_isolated_is_failed_and_blocks() {
            let mut lab = Lab::new("vf3");
            let fencing = Fencing::Command {
                fence_script: "fence.sh",
                verify_script: "verify-forced-not-isolated.sh",
                fence_timeout_sec: 5,
                verify_timeout_sec: 5,
                verify_polls: 6,
            };
            lab.start_standby_pair(&fencing);
            freeze_node_b_and_let_loss_form(&mut lab);
            let (tries, first) = lab.sigusr1_until_incident("node-a", 1, 0.0);
            lab.note(format!(
                "incident opened after {tries} SIGUSR1; result: {first}"
            ));
            lab.require(
                "incident open",
                lab.incident("node-a") != "none",
                format!("fencing.incident = {}", lab.incident("node-a")),
            );
            let failed = wait_state(&mut lab, "node-a", "FAILED", 40);
            lab.check(
                "VF3-01 FAILED reached (verify reported not-isolated)",
                failed,
                lab.fencing_state("node-a"),
            );
            let script_log = lab.script_events();
            dump(&mut lab, "script-events", &script_log);
            lab.check(
                "VF3-02 the production backend ran the fence action and the verify command",
                script_log
                    .iter()
                    .any(|l| l.contains("fence interface=vh-node-b target=node-b"))
                    && script_log.iter().any(|l| l.contains("verify-forced")),
                "fence + forced verify observed",
            );
            lab.check(
                "VF3-03 the log shows VERIFYING -> FAILED and never CONFIRMED",
                daemon_has(&lab, "node-a", "VERIFYING -> FAILED")
                    && !daemon_has(&lab, "node-a", "-> CONFIRMED"),
                "transition log",
            );
            let status = lab.status("node-a");
            lab.check(
                "VF3-04 status: activation blocked, state FAILED",
                field(&status, "activation.blocked").is_some_and(|b| b.starts_with("yes"))
                    && field(&status, "fencing.state").as_deref() == Some("FAILED"),
                format!(
                    "activation.blocked={:?} fencing.state={:?}",
                    field(&status, "activation.blocked"),
                    field(&status, "fencing.state")
                ),
            );
            // A second explicit SIGUSR1: still blocked, nothing activates.
            let second = lab.sigusr1("node-a");
            lab.sleep(3.0, "let any new fencing step settle");
            lab.check(
                "VF3-05 second SIGUSR1 is blocked (BlockedBeforeMutation)",
                second.contains("BlockedBeforeMutation"),
                second.clone(),
            );
            lab.check(
                "VF3-06 never CONFIRMED, never active, zero LeaseRequest",
                lab.fencing_state("node-a") != "CONFIRMED"
                    && !lab.role_active("node-a")
                    && lab.witness_events("node-a", "LeaseRequest", 0).is_empty(),
                format!("fencing.state = {}", lab.fencing_state("node-a")),
            );
            let log = lab
                .daemon_lines("node-a")
                .into_iter()
                .map(|(_, l)| l)
                .collect::<Vec<_>>();
            dump(&mut lab, "node-a daemon log", &log);
            lab.finish();
        }

        // ======================================================================
        // VF-4: peer returns before the second SIGUSR1 -> retired, blocked
        // ======================================================================
        #[test]
        #[ignore = "Phase 14.12 VF-4: root + lab VM (netns/veth); run via the lab driver"]
        fn vf4_peer_return_before_second_sigusr1_retires_and_blocks() {
            let mut lab = Lab::new("vf4");
            lab.start_standby_pair(&Fencing::standard());
            freeze_node_b_and_let_loss_form(&mut lab);
            let (tries, first) = lab.sigusr1_until_incident("node-a", 1, 0.0);
            lab.note(format!(
                "incident opened after {tries} SIGUSR1; result: {first}"
            ));
            lab.require(
                "incident open",
                lab.incident("node-a") != "none",
                format!("fencing.incident = {}", lab.incident("node-a")),
            );
            let confirmed = wait_state(&mut lab, "node-a", "CONFIRMED", 40);
            lab.require("CONFIRMED reached", confirmed, lab.fencing_state("node-a"));
            lab.check(
                "VF4-00 the fence took effect (host-side veth DOWN)",
                lab.link_is_up("vh-node-b") == Some(false),
                format!("vh-node-b up = {:?}", lab.link_is_up("vh-node-b")),
            );

            // The peer returns: unfence and resume it.
            let t_return = now_ms();
            lab.link_up("vh-node-b");
            lab.sigcont("node-b");
            lab.sleep(
                12.0,
                "node-b resumes; authenticated heartbeats reach node-a",
            );
            let retired_before_second = daemon_has(&lab, "node-a", "retired");
            lab.note(format!(
                "incident retired before the second SIGUSR1: {retired_before_second}; status incident = {}",
                lab.incident("node-a")
            ));

            let second = lab.sigusr1("node-a");
            lab.sleep(3.0, "settle");
            lab.check(
                "VF4-01 second SIGUSR1 is blocked (BlockedBeforeMutation)",
                second.contains("BlockedBeforeMutation"),
                second.clone(),
            );
            let retired_line: Vec<String> = daemon_lines_after(&lab, "node-a", t_return)
                .into_iter()
                .filter(|l| l.contains("retired"))
                .collect();
            dump(&mut lab, "retirement log lines", &retired_line);
            lab.check(
                "VF4-02 the incident is retired (log line, and status shows no incident)",
                !retired_line.is_empty() && lab.incident("node-a") == "none",
                format!(
                    "retired lines={} status incident={}",
                    retired_line.len(),
                    lab.incident("node-a")
                ),
            );
            lab.check(
                "VF4-03 zero LeaseRequest, node-a not active",
                lab.witness_events("node-a", "LeaseRequest", 0).is_empty()
                    && !lab.role_active("node-a")
                    && lab.unit_active("node-a") != "active",
                "no activation",
            );
            lab.check(
                "VF4-04 both daemons still running",
                lab.daemon_alive("node-a") && lab.daemon_alive("node-b"),
                "alive",
            );
            let log = lab
                .daemon_lines("node-a")
                .into_iter()
                .map(|(_, l)| l)
                .collect::<Vec<_>>();
            dump(&mut lab, "node-a daemon log", &log);
            lab.finish();
        }

        // ======================================================================
        // VF-2: B=none -> attestation path -> CONFIRMED -> SIGUSR1 -> Active
        // ======================================================================
        #[test]
        #[ignore = "Phase 14.12 VF-2: root + lab VM (netns/veth); run via the lab driver"]
        fn vf2_backend_none_attestation_path_reaches_active() {
            let mut lab = Lab::new("vf2");
            lab.start_standby_pair(&Fencing::None);
            freeze_node_b_and_let_loss_form(&mut lab);
            let (tries, first) = lab.sigusr1_until_incident("node-a", 1, 0.0);
            lab.note(format!(
                "incident opened after {tries} SIGUSR1; result: {first}"
            ));
            lab.require(
                "incident open",
                lab.incident("node-a") != "none",
                format!("fencing.incident = {}", lab.incident("node-a")),
            );
            let incident: u64 = lab.incident("node-a").parse().unwrap_or(0);
            lab.check(
                "VF2-01 B=none: incident opens UNKNOWN(not-attempted); no fence action ran",
                lab.fencing_state("node-a") == "UNKNOWN" && lab.script_events().is_empty(),
                format!(
                    "state={} script events={}",
                    lab.fencing_state("node-a"),
                    lab.script_events().len()
                ),
            );
            // Operator step: isolate node-b by other means, then attest.
            lab.link_down("vh-node-b");
            let (ok, text) = lab.recover("node-a", incident);
            lab.check(
                "VF2-02 `mikagami recover --confirm-fenced` accepted (intent file written)",
                ok,
                text.lines().last().unwrap_or("").to_string(),
            );
            let confirmed = wait_state(&mut lab, "node-a", "CONFIRMED", 30);
            lab.check(
                "VF2-03 daemon ingested the attestation: CONFIRMED (operator)",
                confirmed && daemon_has(&lab, "node-a", "-> CONFIRMED"),
                lab.fencing_state("node-a"),
            );
            let status = lab.status("node-a");
            lab.check(
                "VF2-04 intent file consumed (no attestation pending)",
                field(&status, "fencing.attestation").as_deref() == Some("none pending"),
                format!("{:?}", field(&status, "fencing.attestation")),
            );
            lab.require(
                "CONFIRMED before the second SIGUSR1",
                confirmed,
                "CONFIRMED",
            );
            lab.check(
                "VF2-05 CONFIRMED alone created no authority (zero LeaseRequest before SIGUSR1)",
                lab.witness_events("node-a", "LeaseRequest", 0).is_empty(),
                "no LeaseRequest yet",
            );
            let second = lab.sigusr1("node-a");
            lab.check(
                "VF2-06 second SIGUSR1 -> promotion Succeeded",
                second.contains("Succeeded"),
                second.clone(),
            );
            let grants = lab.witness_events("node-a", "LeaseRequest", 0);
            dump(&mut lab, "Witness LeaseRequest events", &grants);
            lab.check(
                "VF2-07 Witness granted the lease at term 1 (anchor 0 + 1)",
                grants.iter().any(|l| l.contains("=> grant term=1")),
                format!("{} LeaseRequest event(s)", grants.len()),
            );
            lab.check(
                "VF2-08 incident consumed by ARM; node active (role, unit, VIP, arping)",
                daemon_has(&lab, "node-a", "consumed")
                    && lab.incident("node-a") == "none"
                    && lab.role_active("node-a")
                    && lab.unit_active("node-a") == "active"
                    && lab.vip_present("node-a")
                    && !lab.arping_calls().is_empty(),
                format!(
                    "incident={} role_active={} unit={} vip={} arping calls={}",
                    lab.incident("node-a"),
                    lab.role_active("node-a"),
                    lab.unit_active("node-a"),
                    lab.vip_present("node-a"),
                    lab.arping_calls().len()
                ),
            );
            lab.sleep(5.0, "observe renewal");
            let renewals = lab.witness_events("node-a", "LeaseRenew", 0);
            lab.check(
                "VF2-09 the production daemon renews its own lease at the Witness",
                renewals.iter().any(|l| l.contains("=> renewed")),
                format!("{} LeaseRenew event(s)", renewals.len()),
            );
            let log = lab
                .daemon_lines("node-a")
                .into_iter()
                .map(|(_, l)| l)
                .collect::<Vec<_>>();
            dump(&mut lab, "node-a daemon log", &log);
            let final_state = lab.witness_final_state();
            lab.note(format!("witness {final_state}"));
            lab.finish();
        }

        // ======================================================================
        // VF-1 and VF-6: takeover by the Outbound survivor, then the old Active
        // resumes. VF-6 re-performs the VF-1 sequence as its own precondition.
        // ======================================================================

        /// Phase A+B: make node-b (Inbound) the production Active through the
        /// production promotion path (fenced by the production backend), then
        /// start node-a as Standby. Returns the time node-b's lease was last
        /// renewed (epoch ms) as the Witness logged it.
        fn establish_node_b_active(lab: &mut Lab) {
            lab.write_config("node-a", &Fencing::standard());
            lab.write_config("node-b", &Fencing::standard());
            lab.start_witness();
            lab.start_daemon("node-b");
            lab.sleep(
                24.0,
                "node-b alone: two verified-listen windows form peer loss",
            );
            let (tries, first) = lab.sigusr1_until_incident("node-b", 1, 0.0);
            lab.note(format!(
                "node-b incident after {tries} SIGUSR1; result: {first}"
            ));
            lab.require(
                "A1 node-b opened a fencing incident",
                lab.incident("node-b") != "none",
                format!("fencing.incident = {}", lab.incident("node-b")),
            );
            let confirmed = wait_state(lab, "node-b", "CONFIRMED", 40);
            lab.require(
                "A2 node-b CONFIRMED (production backend fenced node-a)",
                confirmed,
                lab.fencing_state("node-b"),
            );
            let second = lab.sigusr1("node-b");
            lab.require(
                "A3 node-b promotion Succeeded (production lease acquisition)",
                second.contains("Succeeded"),
                second,
            );
            let renewed = lab.wait_until(
                "node-b renews its own lease twice",
                Duration::from_secs(30),
                |lab| {
                    lab.witness_events("node-b", "LeaseRenew", 0)
                        .iter()
                        .filter(|l| l.contains("=> renewed"))
                        .count()
                        >= 2
                },
            );
            lab.require(
                "A4 node-b renews its lease (production daemon)",
                renewed,
                "2 renewals",
            );
            lab.require(
                "A5 node-b is Active (role, unit, VIP)",
                lab.role_active("node-b")
                    && lab.unit_active("node-b") == "active"
                    && lab.vip_present("node-b"),
                format!(
                    "role_active={} unit={} vip={}",
                    lab.role_active("node-b"),
                    lab.unit_active("node-b"),
                    lab.vip_present("node-b")
                ),
            );
            // node-a is brought up as Standby after the operator un-fences it.
            lab.link_up("vh-node-a");
            lab.start_daemon("node-a");
            let up = lab.wait_until(
                "peer connection node-a <-> node-b established",
                Duration::from_secs(40),
                |lab| lab.established_between_nodes(),
            );
            lab.require("B1 node-a joined as Standby", up, "connected");
            lab.sleep(8.0, "node-a observes the Active peer's heartbeats");
            lab.require(
                "B2 both daemons running; node-a not active",
                lab.daemon_alive("node-a")
                    && lab.daemon_alive("node-b")
                    && !lab.role_active("node-a"),
                "alive",
            );
        }

        /// Returns the epoch ms of the SIGSTOP of node-b.
        fn vf1_takeover(lab: &mut Lab) -> u128 {
            establish_node_b_active(lab);
            let renews_before_stop = lab.witness_events("node-b", "LeaseRenew", 0).len();
            let t_stop = now_ms();
            lab.sigstop("node-b");
            let stopped = lab.ns_pids("node-b");
            let all_stopped =
                !stopped.is_empty() && stopped.iter().all(|pid| lab.proc_state(*pid) == Some('T'));
            lab.check(
                "VF1-01 SIGSTOP stopped every process in netns node-b (the Active's)",
                all_stopped,
                format!("pids {stopped:?}"),
            );
            lab.sleep(
                14.0,
                "node-b's lease expires at the Witness (TTL 10 s); node-a's loss forms",
            );
            let renews_after = lab.witness_events("node-b", "LeaseRenew", 0).len();
            lab.check(
                "VF1-02 node-b stopped renewing (no renewal after SIGSTOP)",
                lab.witness_events("node-b", "LeaseRenew", t_stop + 1500)
                    .is_empty(),
                format!("renewals before stop {renews_before_stop}, total {renews_after}"),
            );
            let (tries, first) = lab.sigusr1_until_incident("node-a", 1, 0.0);
            lab.note(format!(
                "node-a incident after {tries} SIGUSR1; result: {first}"
            ));
            lab.require(
                "VF1-03 SIGUSR1 -> an incident opens on node-a",
                lab.incident("node-a") != "none",
                format!("fencing.incident = {}", lab.incident("node-a")),
            );
            let confirmed = wait_state(lab, "node-a", "CONFIRMED", 40);
            let log_a: Vec<String> = lab
                .daemon_lines("node-a")
                .into_iter()
                .map(|(_, l)| l)
                .collect();
            let order: Vec<usize> = [
                "opened: REQUESTED",
                "REQUESTED -> VERIFYING",
                "VERIFYING -> CONFIRMED",
            ]
            .iter()
            .filter_map(|needle| log_a.iter().position(|l| l.contains(needle)))
            .collect();
            lab.check(
                "VF1-04 REQUESTED -> VERIFYING -> CONFIRMED (daemon transition log, in order)",
                confirmed && order.len() == 3 && order.windows(2).all(|w| w[0] < w[1]),
                format!("log positions {order:?}"),
            );
            let script_log = lab.script_events();
            dump(lab, "script-events", &script_log);
            lab.check(
                "VF1-05 the production backend ran the fence action for node-b, then verify (env allowlist observed)",
                script_log.iter().any(|l| {
                    l.contains("fence interface=vh-node-b target=node-b")
                        && l.contains("cluster=example-ha")
                        && l.contains("attempt=1")
                }) && script_log.iter().any(|l| l.contains("verify interface=vh-node-b result=isolated")),
                format!("{} script event(s)", script_log.len()),
            );
            lab.check(
                "VF1-06 vh-node-b is DOWN (observed independently of the verify script)",
                lab.link_is_up("vh-node-b") == Some(false),
                format!("vh-node-b up = {:?}", lab.link_is_up("vh-node-b")),
            );
            lab.check(
                "VF1-07 CONFIRMED created no authority: zero LeaseRequest from node-a so far",
                lab.witness_events("node-a", "LeaseRequest", 0).is_empty(),
                "no LeaseRequest",
            );
            let second = lab.sigusr1("node-a");
            lab.check(
                "VF1-08 second SIGUSR1 -> promotion Succeeded",
                second.contains("Succeeded"),
                second.clone(),
            );
            let requests = lab.witness_events("node-a", "LeaseRequest", 0);
            dump(lab, "node-a LeaseRequest events at the Witness", &requests);
            lab.check(
                "VF1-09 Witness granted node-a at term 2 (= prior term 1 + 1)",
                requests.iter().any(|l| l.contains("=> grant term=2")),
                format!("{} LeaseRequest event(s)", requests.len()),
            );
            let last_node_b_renew = lab
                .witness_events("node-b", "LeaseRenew", 0)
                .last()
                .and_then(|l| {
                    l.split_whitespace()
                        .next()
                        .and_then(|t| t.parse::<u128>().ok())
                });
            let grant_at = requests
                .iter()
                .find(|l| l.contains("=> grant"))
                .and_then(|l| {
                    l.split_whitespace()
                        .next()
                        .and_then(|t| t.parse::<u128>().ok())
                });
            lab.check(
                "VF1-10 the grant came only after node-b's lease lapsed (>= 10 s after its last renewal)",
                matches!((last_node_b_renew, grant_at), (Some(r), Some(g)) if g >= r + 10_000),
                format!("last node-b renew {last_node_b_renew:?}, node-a grant {grant_at:?}"),
            );
            lab.check(
                "VF1-11 ARM consumed the incident; node-a Active (incident none, role, unit, VIP, arping)",
                daemon_has(lab, "node-a", "consumed")
                    && lab.incident("node-a") == "none"
                    && lab.role_active("node-a")
                    && lab.unit_active("node-a") == "active"
                    && lab.vip_present("node-a")
                    && !lab.arping_calls().is_empty(),
                format!(
                    "incident={} role_active={} unit={} vip={} arping calls={}",
                    lab.incident("node-a"),
                    lab.role_active("node-a"),
                    lab.unit_active("node-a"),
                    lab.vip_present("node-a"),
                    lab.arping_calls().len()
                ),
            );
            lab.sleep(6.0, "observe node-a's own renewals");
            let renewed = lab
                .witness_events("node-a", "LeaseRenew", 0)
                .iter()
                .filter(|l| l.contains("=> renewed"))
                .count();
            lab.check(
                "VF1-12 the production daemon renews its lease at the Witness",
                renewed >= 1,
                format!("{renewed} renewal(s)"),
            );
            lab.check(
                "VF1-13 node-b stayed frozen; no automatic action on it (no new node-b Witness traffic)",
                lab.witness_events("node-b", "LeaseRenew", t_stop + 1500).is_empty()
                    && lab.witness_events("node-b", "LeaseRequest", t_stop).is_empty(),
                "no node-b requests after SIGSTOP",
            );
            t_stop
        }

        #[test]
        #[ignore = "Phase 14.12 VF-1: root + lab VM (netns/veth); run via the lab driver"]
        fn vf1_outbound_survivor_takes_over_with_virtual_fencing() {
            let mut lab = Lab::new("vf1");
            vf1_takeover(&mut lab);
            let log = lab
                .daemon_lines("node-a")
                .into_iter()
                .map(|(_, l)| l)
                .collect::<Vec<_>>();
            dump(&mut lab, "node-a daemon log", &log);
            let log = lab
                .daemon_lines("node-b")
                .into_iter()
                .map(|(_, l)| l)
                .collect::<Vec<_>>();
            dump(&mut lab, "node-b daemon log", &log);
            let final_state = lab.witness_final_state();
            lab.note(format!("witness {final_state}"));
            lab.finish();
        }

        #[test]
        #[ignore = "Phase 14.12 VF-6: root + lab VM (netns/veth); run via the lab driver"]
        fn vf6_old_active_resumes_after_takeover_renew_rejected_and_demotes() {
            let mut lab = Lab::new("vf6");
            // Precondition: the VF-1 sequence (its own criteria are recorded as
            // VF1-* checks; VF-6 is judged only on the VF6-* criteria below and
            // is BLOCKED, not passed, if the takeover did not happen).
            vf1_takeover(&mut lab);
            lab.require(
                "VF6-P takeover completed (node-a Active, node-b frozen)",
                lab.role_active("node-a") && lab.unit_active("node-a") == "active",
                "VF-1 sequence reached Active on node-a",
            );

            let script_events_before = lab.script_events().len();
            let attempts_a = attempt_results(&lab, "node-a").len();
            let attempts_b = attempt_results(&lab, "node-b").len();
            let t_unfence = now_ms();
            lab.link_up("vh-node-b");
            lab.sigcont("node-b");
            let t_resume = now_ms();
            lab.check(
                "VF6-01 vh-node-b is UP again (unfenced by the operator)",
                lab.link_is_up("vh-node-b") == Some(true),
                format!("vh-node-b up = {:?}", lab.link_is_up("vh-node-b")),
            );

            let demoted = lab.wait_until(
                "node-b demotes (unit inactive and VIP removed)",
                Duration::from_secs(60),
                |lab| lab.unit_active("node-b") != "active" && !lab.vip_present("node-b"),
            );
            lab.sleep(5.0, "settle");
            let b_events: Vec<String> = ["GetTerm", "LeaseRequest", "LeaseRenew", "LeaseRelease"]
                .iter()
                .flat_map(|kind| lab.witness_events("node-b", kind, t_resume))
                .collect();
            dump(&mut lab, "node-b Witness events after resume", &b_events);
            let renew_rejected = b_events
                .iter()
                .any(|l| l.contains("LeaseRenew before-send") && l.contains("=> reject"));
            lab.check(
                "VF6-02 the resumed old Active's renew is REJECTED by the Witness (existing authority)",
                renew_rejected,
                format!("{} node-b event(s) after resume", b_events.len()),
            );
            lab.check(
                "VF6-03 the old Active demotes (service stopped, VIP removed)",
                demoted && lab.unit_active("node-b") != "active" && !lab.vip_present("node-b"),
                format!(
                    "unit={} vip={}",
                    lab.unit_active("node-b"),
                    lab.vip_present("node-b")
                ),
            );
            lab.check(
                "VF6-04 the old Active did not obtain a new lease (zero LeaseRequest from node-b after resume)",
                lab.witness_events("node-b", "LeaseRequest", t_resume).is_empty(),
                "no LeaseRequest",
            );
            lab.check(
                "VF6-05 the new Active kept its authority (node-a Active, renewing after the resume)",
                lab.role_active("node-a")
                    && lab.unit_active("node-a") == "active"
                    && lab.vip_present("node-a")
                    && lab
                        .witness_events("node-a", "LeaseRenew", t_resume)
                        .iter()
                        .any(|l| l.contains("=> renewed")),
                format!(
                    "role_active={} unit={}",
                    lab.role_active("node-a"),
                    lab.unit_active("node-a")
                ),
            );
            let script_after = lab.script_events();
            lab.check(
                "VF6-06 no automatic action anywhere: no fence/verify, no promotion attempt, no new incident",
                script_after.len() == script_events_before
                    && attempt_results(&lab, "node-a").len() == attempts_a
                    && attempt_results(&lab, "node-b").len() == attempts_b
                    && lab.incident("node-a") == "none"
                    && lab.incident("node-b") == "none",
                format!(
                    "script events {} -> {}; attempts a {} -> {}, b {} -> {}; incidents a={} b={}",
                    script_events_before,
                    script_after.len(),
                    attempts_a,
                    attempt_results(&lab, "node-a").len(),
                    attempts_b,
                    attempt_results(&lab, "node-b").len(),
                    lab.incident("node-a"),
                    lab.incident("node-b")
                ),
            );
            lab.note(format!("t_unfence={t_unfence} t_resume={t_resume}"));
            lab.check(
                "VF6-07 both daemons still running",
                lab.daemon_alive("node-a") && lab.daemon_alive("node-b"),
                "alive",
            );
            let log = lab
                .daemon_lines("node-b")
                .into_iter()
                .map(|(_, l)| l)
                .collect::<Vec<_>>();
            dump(&mut lab, "node-b daemon log", &log);
            let log = lab
                .daemon_lines("node-a")
                .into_iter()
                .map(|(_, l)| l)
                .collect::<Vec<_>>();
            dump(&mut lab, "node-a daemon log", &log);
            let final_state = lab.witness_final_state();
            lab.note(format!("witness {final_state}"));
            lab.finish();
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod startup_control_gate_tests {
    use super::*;
    use crate::config::Config;
    use crate::control_lock::ControlLock;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    fn config_at(dir: &Path) -> Config {
        // Self-contained: the test binary may run on a Linux host where the
        // development tree's absolute paths do not exist.
        let text = format!(
            r#"
[cluster]
id = "test-v05"

[node]
id = "node-a"
preferred = true

[peer]
id = "node-b"
address = "127.0.0.1:7946"

[witness]
id = "witness-1"
address = "127.0.0.1:7947"

[vip]
address = "10.0.0.130/32"
interface = "eth0"

[service]
manager = "systemd"
unit = "nginx.service"

[health]
command = ["/bin/true"]

[security]
psk_file = "/tmp/test.psk"

[state]
path = "{state}"

[control]
lock_path = "{lock}"
manual_barrier_path = "{barrier}"
"#,
            state = dir.join("state.toml").display(),
            lock = dir.join("control/control.lock").display(),
            barrier = dir.join("control/manual-operation.json").display(),
        );
        Config::parse_str(&text).expect("test config with [control]")
    }

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "mkg-startup-gate-{label}-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[test]
    fn a_held_control_lock_refuses_startup_before_any_other_construction() {
        let dir = temp_dir("busy");
        let config = config_at(&dir);
        let lock = ControlLock::acquire(
            Path::new(&config.control.lock_path),
            crate::attestation::ROOT_UID,
        )
        .unwrap();
        let error = super::linux::startup_control_gate(&config)
            .err()
            .expect("refused");
        assert!(error.contains("control lock"), "{error}");
        drop(lock);
        super::linux::startup_control_gate(&config).expect("clear after release");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_open_manual_barrier_refuses_startup_and_names_the_operation() {
        let dir = temp_dir("barrier");
        let config = config_at(&dir);
        let record = crate::manual_barrier::ManualOperation {
            schema: crate::manual_barrier::SCHEMA.to_string(),
            cluster: config.cluster.id.clone(),
            node: config.node.id.clone(),
            op_id: "move-test".to_string(),
            source: "node-a".to_string(),
            target: "node-b".to_string(),
            epoch: 1,
            controller: "test".to_string(),
            created_at: 1_700_000_000,
        };
        crate::manual_barrier::begin(
            Path::new(&config.control.manual_barrier_path),
            crate::attestation::ROOT_UID,
            &record,
        )
        .unwrap();
        let error = super::linux::startup_control_gate(&config)
            .err()
            .expect("refused");
        assert!(
            error.contains("move-test") && error.contains("in flight"),
            "{error}"
        );
        crate::manual_barrier::resolve(
            Path::new(&config.control.manual_barrier_path),
            crate::attestation::ROOT_UID,
            &config.cluster.id,
            &config.node.id,
            "move-test",
        )
        .unwrap();
        super::linux::startup_control_gate(&config).expect("clear after resolve");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_malformed_barrier_refuses_startup_instead_of_being_ignored() {
        let dir = temp_dir("bad-barrier");
        let config = config_at(&dir);
        let control = dir.join("control");
        std::fs::create_dir_all(&control).unwrap();
        std::fs::set_permissions(&control, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = Path::new(&config.control.manual_barrier_path);
        std::fs::write(path, b"{not json").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let error = super::linux::startup_control_gate(&config)
            .err()
            .expect("refused");
        assert!(error.contains("not provably clear"), "{error}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(all(test, target_os = "linux"))]
mod continuous_lock_tests {
    use super::*;
    use crate::config::Config;
    use crate::control_lock::ControlLock;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::sync::Mutex;

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "mkg-lock-loop-{label}-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn config_at(dir: &Path) -> Config {
        let text = format!(
            r#"
[cluster]
id = "test-v05"
[node]
id = "node-a"
preferred = true
[peer]
id = "node-b"
address = "127.0.0.1:7946"
[witness]
id = "witness-1"
address = "127.0.0.1:7947"
[vip]
address = "10.0.0.130/32"
interface = "eth0"
[service]
manager = "systemd"
unit = "nginx.service"
[health]
command = ["/bin/true"]
[security]
psk_file = "/tmp/test.psk"
[state]
path = "{state}"
[control]
lock_path = "{lock}"
manual_barrier_path = "{barrier}"
"#,
            state = dir.join("state.toml").display(),
            lock = dir.join("control/control.lock").display(),
            barrier = dir.join("control/manual-operation.json").display(),
        );
        Config::parse_str(&text).unwrap()
    }

    #[test]
    fn the_loop_predicate_detects_a_replaced_control_directory() {
        let dir = temp_dir("dir");
        let config = config_at(&dir);
        let lock = ControlLock::acquire(
            Path::new(&config.control.lock_path),
            crate::attestation::ROOT_UID,
        )
        .unwrap();
        let error = Mutex::new(None);
        assert!(super::linux::verify_lock(&lock, &error));
        let control = dir.join("control");
        std::fs::rename(&control, dir.join("control.old")).unwrap();
        std::fs::create_dir(&control).unwrap();
        std::fs::set_permissions(&control, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(control.join("control.lock"), b"").unwrap();
        std::fs::set_permissions(
            control.join("control.lock"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(!super::linux::verify_lock(&lock, &error));
        assert!(error.lock().unwrap().is_some());
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
mod control_lock_loss_tests {
    use super::*;
    use crate::daemon::{
        Daemon, DaemonHealth, DaemonService, DaemonSnapshot, DaemonState, DaemonVip, ShutdownResult,
    };
    use crate::state_machine::NodeState;
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    struct Probe {
        observe_results: Arc<Mutex<VecDeque<Result<DaemonSnapshot, String>>>>,
        peer_ticks: Arc<Mutex<Vec<Instant>>>,
        shutdown_calls: Arc<Mutex<u32>>,
    }

    impl Default for Probe {
        fn default() -> Self {
            Self {
                observe_results: Arc::new(Mutex::new(VecDeque::new())),
                peer_ticks: Arc::new(Mutex::new(Vec::new())),
                shutdown_calls: Arc::new(Mutex::new(0)),
            }
        }
    }

    struct FakeRuntime {
        probe: Probe,
    }

    fn standby() -> DaemonSnapshot {
        DaemonSnapshot {
            node_state: NodeState::Standby,
            health: DaemonHealth::Healthy,
            vip: DaemonVip::Absent,
            service: DaemonService::Stopped,
            resource_owning: false,
            recovery_reconciled: true,
            unresolved_mutation: false,
        }
    }

    impl DaemonRuntime for FakeRuntime {
        fn startup(&mut self) -> Result<DaemonSnapshot, String> {
            Ok(standby())
        }
        fn observe(&mut self) -> Result<DaemonSnapshot, String> {
            self.probe
                .observe_results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Ok(standby()))
        }
        fn shutdown(
            &mut self,
            _control_lock_safe: &dyn Fn() -> bool,
        ) -> Result<ShutdownResult, String> {
            *self.probe.shutdown_calls.lock().unwrap() += 1;
            Ok(ShutdownResult::Clean)
        }
        fn peer_tick_at(
            &mut self,
            now: Instant,
            _peer_status: Option<crate::daemon::PeerStatusSnapshot>,
        ) -> Result<Option<crate::peer_observer::PeerObservationState>, String> {
            self.probe.peer_ticks.lock().unwrap().push(now);
            Ok(Some(
                crate::peer_observer::PeerObservationState::Unavailable,
            ))
        }
    }

    #[derive(Default)]
    struct Latch(Cell<bool>);

    impl PromotionIntentLatch for Latch {
        fn consume(&self) -> bool {
            self.0.replace(false)
        }
        fn discard(&self) {
            self.0.set(false);
        }
    }

    fn daemon(probe: &Probe) -> Daemon<FakeRuntime> {
        let mut daemon = Daemon::new(FakeRuntime {
            probe: Probe {
                observe_results: Arc::clone(&probe.observe_results),
                peer_ticks: Arc::clone(&probe.peer_ticks),
                shutdown_calls: Arc::clone(&probe.shutdown_calls),
            },
        });
        assert_eq!(daemon.start().unwrap(), StartResult::Running);
        daemon
    }

    fn exits_without_shutdown(exit: LoopExit) {
        match exit {
            LoopExit::ControlLockLost(message) => {
                assert!(!message.is_empty(), "the lock error must be retained");
            }
            other => panic!("expected ControlLockLost, got {other:?}"),
        }
    }

    #[test]
    fn a_lock_loss_at_the_first_check_does_not_request_shutdown_or_tick() {
        let probe = Probe::default();
        let mut daemon = daemon(&probe);
        let exit = run_observation_loop_checked(
            &mut daemon,
            Duration::from_secs(1),
            || Some("lock was replaced".to_string()),
            || false,
            |_| {},
            Instant::now,
            &Latch::default(),
            |_, _| {},
            |_| panic!("promotion must not run"),
        );
        exits_without_shutdown(exit);
        assert_eq!(daemon.state(), DaemonState::Running);
        assert_eq!(*probe.shutdown_calls.lock().unwrap(), 0);
        assert!(probe.peer_ticks.lock().unwrap().is_empty());
    }

    #[test]
    fn a_lock_loss_discards_a_pending_promotion_before_any_fencing_or_lease() {
        let probe = Probe::default();
        let mut daemon = daemon(&probe);
        let latch = Latch(Cell::new(false));
        let seeded = Cell::new(false);
        let checks = Cell::new(0u32);
        let exit = run_observation_loop_checked(
            &mut daemon,
            Duration::from_secs(1),
            || {
                checks.set(checks.get() + 1);
                (checks.get() >= 2).then(|| "lock was replaced".to_string())
            },
            || {
                // The loop clears intents on entry; seed one after entry so
                // this test reaches the pre-promotion lock check.
                if !seeded.replace(true) {
                    latch.0.set(true);
                }
                false
            },
            |_| {},
            Instant::now,
            &latch,
            |_, _| {},
            |_| panic!("promotion must not run"),
        );
        exits_without_shutdown(exit);
        assert!(!latch.consume(), "the intent must be discarded");
        assert_eq!(daemon.state(), DaemonState::Running);
        assert_eq!(*probe.shutdown_calls.lock().unwrap(), 0);
        assert!(
            probe.peer_ticks.lock().unwrap().is_empty(),
            "ticks={:?}",
            probe.peer_ticks.lock().unwrap()
        );
    }

    #[test]
    fn a_lock_loss_wins_over_a_simultaneous_shutdown_request() {
        let probe = Probe::default();
        let mut daemon = daemon(&probe);
        let exit = run_observation_loop_checked(
            &mut daemon,
            Duration::from_secs(1),
            || Some("lock was replaced".to_string()),
            || true,
            |_| {},
            Instant::now,
            &Latch::default(),
            |_, _| {},
            |_| panic!("promotion must not run"),
        );
        exits_without_shutdown(exit);
        assert_eq!(daemon.state(), DaemonState::Running);
        assert_eq!(*probe.shutdown_calls.lock().unwrap(), 0);
        assert!(probe.peer_ticks.lock().unwrap().is_empty());
    }

    #[test]
    fn a_lock_loss_after_one_tick_stops_before_the_next_tick() {
        let probe = Probe::default();
        let mut daemon = daemon(&probe);
        let lost = Cell::new(false);
        let mut waits = 0u32;
        let exit = run_observation_loop_checked(
            &mut daemon,
            Duration::from_secs(1),
            || lost.get().then(|| "lock was replaced".to_string()),
            || false,
            |_| {
                waits += 1;
                if waits == 1 {
                    lost.set(true);
                }
            },
            Instant::now,
            &Latch::default(),
            |_, _| {},
            |_| panic!("promotion must not run"),
        );
        exits_without_shutdown(exit);
        assert_eq!(daemon.state(), DaemonState::Running);
        assert_eq!(*probe.shutdown_calls.lock().unwrap(), 0);
        assert_eq!(probe.peer_ticks.lock().unwrap().len(), 1);
    }
}

/// cf31 M-1: the production start helper must hand `Daemon::start` the live
/// control lock. Before cf31 the guard was attached after `start`, so the
/// startup reconciliation read the default guard and could settle after the
/// lock file was replaced (F-3 b05 / k14).
#[cfg(all(test, target_os = "linux"))]
mod cf31_m1_startup_lock_tests {
    use super::*;
    use crate::control_lock::ControlLock;
    use crate::daemon::{
        DaemonError, DaemonHealth, DaemonService, DaemonSnapshot, DaemonVip, ShutdownResult,
    };
    use crate::state_machine::NodeState;
    use std::cell::RefCell;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::rc::Rc;

    fn temp_dir(label: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "mkg-cf31-m1-{label}-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn uid() -> u32 {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() }
    }

    /// Replace the lock file with a new inode, as the F-3 lockswap did.
    fn replace_lock_file(path: &Path) {
        let fresh = path.with_extension("fresh");
        std::fs::write(&fresh, b"").unwrap();
        std::fs::set_permissions(&fresh, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::rename(&fresh, path).unwrap();
    }

    fn snapshot(reconciled: bool) -> DaemonSnapshot {
        DaemonSnapshot {
            node_state: NodeState::Standby,
            health: DaemonHealth::Healthy,
            vip: DaemonVip::Absent,
            service: DaemonService::Stopped,
            resource_owning: false,
            recovery_reconciled: reconciled,
            unresolved_mutation: !reconciled,
        }
    }

    /// What the startup reconciliation model saw and did.
    #[derive(Default)]
    struct SorTrace {
        /// Predicate value at the trusted ZeroResource, then at the fresh
        /// ZeroResource right before the settle.
        samples: Vec<bool>,
        /// The obligation (M + O) was settled.
        settled: bool,
    }

    /// Models the SOR shape of `LinuxDaemonRuntime::startup_guarded`: the
    /// predicate gates the first ZeroResource and the fresh ZeroResource
    /// before the settle; a `false` keeps M and O and blocks the gate.
    /// `swap_at` replaces the lock file before that sample (0 or 1).
    struct SorRuntime {
        lock_path: PathBuf,
        swap_at: Option<usize>,
        trace: Rc<RefCell<SorTrace>>,
    }

    impl DaemonRuntime for SorRuntime {
        fn startup(&mut self) -> Result<DaemonSnapshot, String> {
            unreachable!("production start must use startup_guarded")
        }
        fn startup_guarded(
            &mut self,
            control_lock_safe: &dyn Fn() -> bool,
        ) -> Result<DaemonSnapshot, String> {
            for sample in 0..2 {
                if self.swap_at == Some(sample) {
                    replace_lock_file(&self.lock_path);
                }
                let safe = control_lock_safe();
                self.trace.borrow_mut().samples.push(safe);
                if !safe {
                    return Ok(snapshot(false));
                }
            }
            self.trace.borrow_mut().settled = true;
            Ok(snapshot(true))
        }
        fn recovery_block_cause(&self) -> Option<String> {
            (!self.trace.borrow().settled).then(|| "a release obligation is armed".to_string())
        }
        fn observe(&mut self) -> Result<DaemonSnapshot, String> {
            Ok(snapshot(true))
        }
        fn shutdown(
            &mut self,
            _control_lock_safe: &dyn Fn() -> bool,
        ) -> Result<ShutdownResult, String> {
            Ok(ShutdownResult::Clean)
        }
    }

    fn setup(
        label: &str,
        swap_at: Option<usize>,
    ) -> (
        PathBuf,
        PathBuf,
        super::linux::LiveControlLock,
        Daemon<SorRuntime>,
        Rc<RefCell<SorTrace>>,
    ) {
        let dir = temp_dir(label);
        let control = dir.join("control");
        let lock_path = control.join("control.lock");
        let live =
            super::linux::LiveControlLock::new(ControlLock::acquire(&lock_path, uid()).unwrap());
        let trace = Rc::new(RefCell::new(SorTrace::default()));
        let daemon = Daemon::new(SorRuntime {
            lock_path: lock_path.clone(),
            swap_at,
            trace: trace.clone(),
        });
        (dir, lock_path, live, daemon, trace)
    }

    #[test]
    fn cf31_m1_intact_lock_lets_the_startup_reconciliation_settle() {
        let (dir, _lock_path, live, mut daemon, trace) = setup("intact", None);
        super::linux::start_with_live_control_lock(&mut daemon, &live)
            .expect("an intact lock must not block startup");
        assert_eq!(daemon.state(), DaemonState::Running);
        assert_eq!(trace.borrow().samples, vec![true, true]);
        assert!(trace.borrow().settled, "M and O are resolved");
        assert!(live.error.lock().unwrap().is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn cf31_m1_lock_replaced_before_the_settle_keeps_the_obligation() {
        // F-3 b05 / k14: the lock is replaced while the exact Release is in
        // flight, i.e. after the first ZeroResource and before the settle.
        let (dir, _lock_path, live, mut daemon, trace) = setup("before-settle", Some(1));
        let error = super::linux::start_with_live_control_lock(&mut daemon, &live)
            .expect_err("a replaced lock must stop the settle and the startup");
        assert!(
            error.contains("the control lock became unsafe")
                && error.contains("replaced after it was acquired"),
            "{error}"
        );
        assert_eq!(trace.borrow().samples, vec![true, false]);
        assert!(!trace.borrow().settled, "M and O must be kept");
        assert_ne!(daemon.state(), DaemonState::Running);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn cf31_m1_lock_replaced_during_startup_blocks_before_any_effect() {
        let (dir, _lock_path, live, mut daemon, trace) = setup("startup", Some(0));
        let error = super::linux::start_with_live_control_lock(&mut daemon, &live)
            .expect_err("a lock replaced during startup must stop the startup");
        assert!(error.contains("the control lock became unsafe"), "{error}");
        assert_eq!(trace.borrow().samples, vec![false]);
        assert!(!trace.borrow().settled);
        assert_ne!(daemon.state(), DaemonState::Running);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn cf31_m1_the_start_guard_stays_attached_for_the_loop() {
        // run_daemon_inner no longer attaches a second guard: the one from
        // the start helper must still detect a later replacement.
        let (dir, lock_path, live, mut daemon, _trace) = setup("loop", None);
        super::linux::start_with_live_control_lock(&mut daemon, &live).unwrap();
        replace_lock_file(&lock_path);
        let error = daemon
            .tick_at(Instant::now())
            .expect_err("a replaced lock must stop the first tick");
        assert!(
            matches!(error, DaemonError::ControlLockLost(_)),
            "{error:?}"
        );
        assert!(live.error.lock().unwrap().is_some());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
