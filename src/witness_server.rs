//! Production Witness server: `mikagami witness init | run | rearm`
//! (Owner decisions A-5 / A-11, plan WU-3, contract ADD-6).
//!
//! The server is a thin transport around the existing Witness authority. It
//! decides nothing about leases: every GET_TERM / LEASE_* request goes through
//! `witness_authority::handle_*_authority`, which commits (journal, watermark
//! and authority state in one store commit) *before* the prepared response is
//! returned and sent. This module only
//! - owns the process: configuration, state readiness, the single-instance
//!   lock, the listener, the expiry scheduler and shutdown;
//! - checks the first message of each connection with the existing
//!   `PeerSession` HELLO contract;
//! - closes the connection (without a response) on any authority error.
//!
//! No test seam lives here: the boot id and clock providers are type
//! parameters whose production values are `ProcBootIdProvider` and
//! `SystemMonotonicClock`.

use crate::protocol::{CborSerializer, ClusterId, NodeId, ProtocolMessage};
use crate::security::{MessageAuthenticator, Psk};
use crate::session::{PeerSession, ProcessSession, SessionAction, build_hello_ack};
use crate::tcp::{PollFrameResult, TcpConnection};
use crate::witness_authority::{
    WitnessAuthorityError, handle_get_term_authority, handle_lease_release_authority,
    handle_lease_renew_authority, handle_lease_request_authority, send_prepared_lease_response,
    send_prepared_term_status,
};
use crate::witness_runtime::{WitnessConnection, WitnessPoll};
use crate::witness_scheduler::{SchedulerCancellation, WitnessExpiryScheduler};
use crate::witness_state::{
    BootIdProvider, ProcBootIdProvider, SystemMonotonicClock, WitnessNotReadyReason,
    WitnessReadiness, WitnessStateStore,
};
use serde::Deserialize;
use std::fs;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

/// HELLO must complete within this total time (slow-loris bound).
const HELLO_DEADLINE: Duration = Duration::from_secs(5);
/// Write bound for every response; a client that never reads is dropped.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// Poll cadence of the accept loop, the receive loops and the supervisor.
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const ACCEPT_INTERVAL: Duration = Duration::from_millis(20);
const SUPERVISE_INTERVAL: Duration = Duration::from_millis(100);
const SCHEDULER_RETRY: Duration = Duration::from_millis(100);
const DEFAULT_MAX_CONNECTIONS: usize = 16;
const MAX_CONNECTIONS_LIMIT: usize = 256;
const DEFAULT_REARM_MAX_DOWNTIME_SEC: u64 = 3600;
const STATE_FILE: &str = "witness-state.toml";
const LOCK_FILE: &str = "witness.lock";

// ---- configuration --------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum OnReboot {
    /// Re-base an Active lease automatically after a reboot (A-5 default).
    #[default]
    Rearm,
    /// Stay NotReady until the operator runs `mikagami witness rearm`.
    Refuse,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWitnessConfig {
    cluster: String,
    id: String,
    listen: String,
    nodes: Vec<String>,
    preferred: String,
    psk_file: String,
    state_dir: String,
    #[serde(default)]
    on_reboot: OnReboot,
    #[serde(default = "default_max_connections")]
    max_connections: usize,
    #[serde(default = "default_rearm_max_downtime_sec")]
    rearm_max_downtime_sec: u64,
}

fn default_max_connections() -> usize {
    DEFAULT_MAX_CONNECTIONS
}

fn default_rearm_max_downtime_sec() -> u64 {
    DEFAULT_REARM_MAX_DOWNTIME_SEC
}

/// A validated Witness server configuration.
#[derive(Debug, Clone)]
pub(crate) struct WitnessServerConfig {
    pub(crate) cluster: String,
    pub(crate) id: String,
    pub(crate) listen: SocketAddr,
    /// The two node ids and the HELLO priority each must present
    /// (preferred 100, the other 50 — the same derivation as `node.preferred`).
    pub(crate) nodes: Vec<(String, i32)>,
    pub(crate) psk_file: PathBuf,
    pub(crate) state_dir: PathBuf,
    pub(crate) on_reboot: OnReboot,
    pub(crate) max_connections: usize,
    pub(crate) rearm_max_downtime: Duration,
}

impl WitnessServerConfig {
    pub(crate) fn load(path: &Path) -> Result<Self, String> {
        let text = fs::read_to_string(path)
            .map_err(|error| format!("could not read witness configuration: {error}"))?;
        Self::parse_str(&text)
    }

    pub(crate) fn parse_str(text: &str) -> Result<Self, String> {
        let raw: RawWitnessConfig = toml::from_str(text).map_err(|error| {
            format!("could not parse witness configuration: {}", error.message())
        })?;
        let mut errors = Vec::new();
        for (field, value) in [("cluster", &raw.cluster), ("id", &raw.id)] {
            if value.is_empty() || value.chars().any(|c| c.is_whitespace() || c.is_control()) {
                errors.push(format!(
                    "{field} must be non-empty without whitespace or control characters"
                ));
            }
        }
        let listen = match raw.listen.parse::<SocketAddr>() {
            Ok(address) => Some(address),
            Err(_) => {
                errors.push("listen must be a valid socket address".to_string());
                None
            }
        };
        if raw.nodes.len() != 2 || raw.nodes[0] == raw.nodes[1] {
            errors.push("nodes must name exactly two different node ids".to_string());
        }
        if raw.nodes.iter().any(|node| {
            node.is_empty() || node.chars().any(|c| c.is_whitespace() || c.is_control())
        }) {
            errors.push("nodes must not contain empty or whitespace ids".to_string());
        }
        if !raw.nodes.contains(&raw.preferred) {
            errors.push("preferred must be one of nodes".to_string());
        }
        if raw.nodes.contains(&raw.id) {
            errors.push("id must differ from the node ids".to_string());
        }
        if !Path::new(&raw.psk_file).is_absolute() {
            errors.push("psk_file must be an absolute path".to_string());
        }
        if !Path::new(&raw.state_dir).is_absolute() {
            errors.push("state_dir must be an absolute path".to_string());
        }
        if !(1..=MAX_CONNECTIONS_LIMIT).contains(&raw.max_connections) {
            errors.push(format!(
                "max_connections must be between 1 and {MAX_CONNECTIONS_LIMIT}"
            ));
        }
        if raw.rearm_max_downtime_sec == 0 {
            errors.push("rearm_max_downtime_sec must be at least 1".to_string());
        }
        if !errors.is_empty() {
            return Err(format!(
                "witness configuration validation failed: {}",
                errors.join("; ")
            ));
        }
        let nodes = raw
            .nodes
            .iter()
            .map(|node| {
                let priority = if *node == raw.preferred {
                    crate::config::PRIORITY_PREFERRED
                } else {
                    crate::config::PRIORITY_STANDBY
                };
                (node.clone(), priority)
            })
            .collect();
        Ok(Self {
            cluster: raw.cluster,
            id: raw.id,
            listen: listen.expect("validated above"),
            nodes,
            psk_file: PathBuf::from(raw.psk_file),
            state_dir: PathBuf::from(raw.state_dir),
            on_reboot: raw.on_reboot,
            max_connections: raw.max_connections,
            rearm_max_downtime: Duration::from_secs(raw.rearm_max_downtime_sec),
        })
    }

    pub(crate) fn state_path(&self) -> PathBuf {
        self.state_dir.join(STATE_FILE)
    }

    fn lock_path(&self) -> PathBuf {
        self.state_dir.join(LOCK_FILE)
    }

    fn store<B: BootIdProvider>(&self, boot: B) -> WitnessStateStore<B, SystemMonotonicClock> {
        WitnessStateStore::with_providers(
            self.state_path(),
            ClusterId::new(self.cluster.clone()),
            boot,
            SystemMonotonicClock,
        )
    }
}

// ---- shutdown (no atomic flag: a mutex + condvar) -------------------------

#[derive(Default)]
struct ShutdownState {
    requested: bool,
    failure: Option<String>,
}

/// One-way shutdown request shared by the supervisor, the accept loop and the
/// connection workers. A fatal condition records its reason (the first wins).
#[derive(Clone, Default)]
pub(crate) struct Shutdown {
    inner: Arc<(Mutex<ShutdownState>, Condvar)>,
}

impl Shutdown {
    pub(crate) fn request(&self) {
        let (lock, wake) = &*self.inner;
        if let Ok(mut state) = lock.lock() {
            state.requested = true;
            wake.notify_all();
        }
    }

    fn fail(&self, reason: String) {
        let (lock, wake) = &*self.inner;
        if let Ok(mut state) = lock.lock() {
            state.requested = true;
            state.failure.get_or_insert(reason);
            wake.notify_all();
        }
    }

    fn is_requested(&self) -> bool {
        self.inner
            .0
            .lock()
            .map(|state| state.requested)
            .unwrap_or(true)
    }

    fn failure(&self) -> Option<String> {
        self.inner
            .0
            .lock()
            .ok()
            .and_then(|state| state.failure.clone())
    }

    /// Wait up to `duration` for a shutdown request; `true` once requested.
    fn wait(&self, duration: Duration) -> bool {
        let (lock, wake) = &*self.inner;
        let Ok(state) = lock.lock() else {
            return true;
        };
        if state.requested {
            return true;
        }
        let (state, _) = wake
            .wait_timeout_while(state, duration, |state| !state.requested)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.requested
    }
}

// ---- logging ---------------------------------------------------------------

fn log(level: &str, message: &str) {
    eprintln!("mikagami-witness: {level} {message}");
}

// ---- init / rearm / startup -------------------------------------------------

/// `witness init`: create the state directory (0700) and the initial state.
/// Refuses an existing state; never re-initializes (term would restart at 0).
pub(crate) fn initialize<B: BootIdProvider>(
    config: &WitnessServerConfig,
    boot: B,
) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    if config.state_path().exists() {
        return Err(format!(
            "witness state already exists at {}: refusing to re-initialize",
            config.state_path().display()
        ));
    }
    if config.state_dir.exists() {
        let mut entries = fs::read_dir(&config.state_dir)
            .map_err(|error| format!("could not read the state directory: {error}"))?;
        if entries.next().is_some() {
            return Err(
                "the state directory exists and is not empty: refusing to initialize".into(),
            );
        }
        fs::set_permissions(&config.state_dir, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("could not restrict the state directory: {error}"))?;
    } else {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&config.state_dir)
            .map_err(|error| format!("could not create the state directory: {error}"))?;
    }
    config
        .store(boot)
        .initialize_new()
        .map(|_| ())
        .map_err(|error| format!("could not initialize the witness state: {error}"))
}

/// What the startup readiness check decided.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Readiness {
    Ready,
    Rearmed { lease_was_active: bool },
}

/// Startup readiness (WS-1 / WS-2 / WS-3). `explicit` is the operator's
/// `witness rearm` command, which bypasses `on_reboot = "refuse"` and the
/// downtime guard (the operator vouches that the state was not restored).
pub(crate) fn ensure_ready<B: BootIdProvider>(
    config: &WitnessServerConfig,
    boot: B,
    explicit: bool,
    now: SystemTime,
) -> Result<Readiness, String> {
    let store = config.store(boot);
    let recovery = store.load();
    match recovery.readiness {
        WitnessReadiness::Ready => Ok(Readiness::Ready),
        WitnessReadiness::NotReady(WitnessNotReadyReason::StateMissing) => Err(
            "no witness state: run `mikagami witness init` once (the server never initializes \
             state itself)"
                .to_string(),
        ),
        WitnessReadiness::NotReady(WitnessNotReadyReason::BootIdChanged) => {
            if !explicit && config.on_reboot == OnReboot::Refuse {
                return Err(
                    "the host rebooted and on_reboot = \"refuse\": run `mikagami witness rearm` \
                     after confirming the state was not restored from a backup"
                        .to_string(),
                );
            }
            let lease_active = recovery
                .state
                .as_ref()
                .is_some_and(|state| state.lease_state == crate::witness_state::LeaseState::Active);
            if lease_active && !explicit {
                let age = fs::metadata(config.state_path())
                    .and_then(|metadata| metadata.modified())
                    .map(|modified| now.duration_since(modified).unwrap_or(Duration::ZERO))
                    .map_err(|error| {
                        format!("could not read the state modification time: {error}")
                    })?;
                if age > config.rearm_max_downtime {
                    return Err(format!(
                        "the state with an active lease is {}s old (limit {}s): automatic \
                         re-arm refused; run `mikagami witness rearm` after confirming the \
                         state was not restored from a backup",
                        age.as_secs(),
                        config.rearm_max_downtime.as_secs()
                    ));
                }
            }
            let outcome = store
                .rearm_after_reboot()
                .map_err(|error| format!("re-arm failed: {error}"))?;
            if store.load().readiness != WitnessReadiness::Ready {
                return Err("the state is not ready after the re-arm".to_string());
            }
            Ok(Readiness::Rearmed {
                lease_was_active: outcome.lease_was_active,
            })
        }
        WitnessReadiness::NotReady(reason) => Err(format!(
            "the witness state is not ready ({reason:?}): operator action required; the server \
             does not repair or re-initialize state"
        )),
    }
}

/// A started server: the bound listener plus the single-instance lock.
pub(crate) struct Prepared<B: BootIdProvider + Clone + Send + Sync + 'static> {
    config: WitnessServerConfig,
    psk: Psk,
    boot: B,
    listener: TcpListener,
    _lock: fs::File,
    rearm: Readiness,
}

impl<B: BootIdProvider + Clone + Send + Sync + 'static> Prepared<B> {
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.listener
            .local_addr()
            .unwrap_or_else(|_| self.config.listen)
    }
}

/// Everything `witness run` does before serving: lock, readiness (with the
/// automatic re-arm), bind.
pub(crate) fn prepare<B: BootIdProvider + Clone + Send + Sync + 'static>(
    config: WitnessServerConfig,
    psk: Psk,
    boot: B,
    now: SystemTime,
) -> Result<Prepared<B>, String> {
    // WS-10: one instance per state directory (the bind below is the second
    // layer). The lock is held for the life of this value.
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(config.lock_path())
        .map_err(|error| format!("could not open the instance lock: {error}"))?;
    lock.try_lock()
        .map_err(|_| "another witness instance holds this state directory".to_string())?;
    let rearm = ensure_ready(&config, boot.clone(), false, now)?;
    let listener = TcpListener::bind(config.listen)
        .map_err(|error| format!("could not listen on {}: {error}", config.listen))?;
    Ok(Prepared {
        config,
        psk,
        boot,
        listener,
        _lock: lock,
        rearm,
    })
}

// ---- serving ------------------------------------------------------------------

/// How a served instance ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ServeOutcome {
    /// Shutdown was requested and every worker finished.
    Clean,
    /// A fatal condition (scheduler stopped, authority lock poisoned, listener
    /// failure). The reason is logged; the process exits non-zero.
    Fatal(String),
}

struct ConnectionSlots {
    used: Mutex<usize>,
    limit: usize,
}

struct SlotGuard(Arc<ConnectionSlots>);

impl ConnectionSlots {
    fn acquire(self: &Arc<Self>) -> Option<SlotGuard> {
        let mut used = self.used.lock().ok()?;
        if *used >= self.limit {
            return None;
        }
        *used += 1;
        Some(SlotGuard(Arc::clone(self)))
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        if let Ok(mut used) = self.0.used.lock() {
            *used = used.saturating_sub(1);
        }
    }
}

/// Serve until `shutdown` is requested or a fatal condition occurs.
pub(crate) fn serve<B: BootIdProvider + Clone + Send + Sync + 'static>(
    prepared: Prepared<B>,
    shutdown: Shutdown,
) -> ServeOutcome {
    let Prepared {
        config,
        psk,
        boot,
        listener,
        _lock,
        rearm,
    } = prepared;
    if let Err(error) = listener.set_nonblocking(true) {
        return ServeOutcome::Fatal(format!("could not make the listener non-blocking: {error}"));
    }
    match rearm {
        Readiness::Ready => {}
        Readiness::Rearmed { lease_was_active } => log(
            "WARN",
            &format!(
                "re-armed after a host reboot (active lease re-based: {lease_was_active}); the \
                 state must never be restored from a backup"
            ),
        ),
    }
    log(
        "INFO",
        &format!(
            "serving cluster {} as {} on {}",
            config.cluster,
            config.id,
            listener
                .local_addr()
                .map(|address| address.to_string())
                .unwrap_or_default()
        ),
    );

    // WS-6: the expiry scheduler is supervised. Its thread ending for any
    // reason other than the shutdown below is fatal (expiry would stop and a
    // lease could outlive its TTL).
    let scheduler = WitnessExpiryScheduler::new(SCHEDULER_RETRY);
    let cancel: SchedulerCancellation = scheduler.cancellation();
    let scheduler_store = config.store(boot.clone());
    let scheduler_cancel = cancel.clone();
    let scheduler_handle: JoinHandle<Result<(), String>> = std::thread::spawn(move || {
        scheduler
            .run_until_cancelled(&scheduler_store, &scheduler_cancel)
            .map_err(|error| error.to_string())
    });

    let slots = Arc::new(ConnectionSlots {
        used: Mutex::new(0),
        limit: config.max_connections,
    });
    let policy = Arc::new(config.clone());
    let psk = Arc::new(psk);
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    let mut refused_logged = false;
    let mut scheduler_handle = Some(scheduler_handle);

    while !shutdown.is_requested() {
        if scheduler_handle
            .as_ref()
            .is_some_and(JoinHandle::is_finished)
        {
            let reason = match scheduler_handle.take().map(JoinHandle::join) {
                Some(Ok(Ok(()))) => "the expiry scheduler stopped".to_string(),
                Some(Ok(Err(error))) => format!("the expiry scheduler failed: {error}"),
                _ => "the expiry scheduler panicked".to_string(),
            };
            shutdown.fail(reason);
            break;
        }
        match listener.accept() {
            Ok((stream, peer)) => {
                let Some(guard) = slots.acquire() else {
                    if !refused_logged {
                        refused_logged = true;
                        log(
                            "WARN",
                            &format!(
                                "connection limit ({}) reached: refusing {peer}",
                                config.max_connections
                            ),
                        );
                    }
                    drop(stream);
                    continue;
                };
                refused_logged = false;
                workers.retain(|worker| !worker.is_finished());
                let (policy, psk, boot, shutdown) = (
                    Arc::clone(&policy),
                    Arc::clone(&psk),
                    boot.clone(),
                    shutdown.clone(),
                );
                workers.push(std::thread::spawn(move || {
                    let _guard = guard;
                    if let Err(ended) = serve_connection(stream, &policy, &psk, boot, &shutdown) {
                        match ended {
                            ConnectionEnd::Closed => {}
                            ConnectionEnd::Rejected(reason) => {
                                log(
                                    "WARN",
                                    &format!("connection from {peer} rejected: {reason}"),
                                );
                            }
                            ConnectionEnd::Authority(error) => {
                                log("ERROR", &format!("authority error from {peer}: {error}"));
                            }
                            ConnectionEnd::Fatal(reason) => shutdown.fail(reason),
                        }
                    }
                }));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if shutdown.wait(ACCEPT_INTERVAL) {
                    break;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                shutdown.fail(format!("accept failed: {error}"));
                break;
            }
        }
    }

    // New connections are no longer accepted; running requests finish (the
    // store commit precedes every response), then the scheduler stops.
    drop(listener);
    for worker in workers {
        let _ = worker.join();
    }
    cancel.cancel();
    if let Some(handle) = scheduler_handle {
        let _ = handle.join();
    }
    match shutdown.failure() {
        Some(reason) => ServeOutcome::Fatal(reason),
        None => ServeOutcome::Clean,
    }
}

enum ConnectionEnd {
    /// The peer closed or the server is shutting down.
    Closed,
    /// The first message was refused (no HELLO_ACK, no authority call).
    Rejected(String),
    /// An authority error: no response, connection closed (WS-5).
    Authority(String),
    /// The process cannot continue (e.g. a poisoned authority lock).
    Fatal(String),
}

/// The first message of a connection is validated by the existing inbound
/// handshake contract; the policy only names the expected values.
fn check_first_message(
    config: &WitnessServerConfig,
    hello: &crate::receive::AuthenticatedMessage,
) -> Result<(), String> {
    let common = &hello.unsigned().common;
    let sender = common.sender_node_id.as_str();
    let Some((_, priority)) = config.nodes.iter().find(|(node, _)| node == sender) else {
        return Err(format!("sender {sender:?} is not an expected node"));
    };
    let mut session = PeerSession::new(
        ClusterId::new(config.cluster.clone()),
        NodeId::new(config.id.clone()),
        common.sender_node_id.clone(),
        *priority,
    );
    match session.accept(hello) {
        Ok(SessionAction::SendHelloAck) => Ok(()),
        Ok(other) => Err(format!("unexpected session action {other:?}")),
        Err(error) => Err(error.to_string()),
    }
}

fn serve_connection<B: BootIdProvider>(
    stream: TcpStream,
    config: &WitnessServerConfig,
    psk: &Psk,
    boot: B,
    shutdown: &Shutdown,
) -> Result<(), ConnectionEnd> {
    stream
        .set_nonblocking(false)
        .map_err(|error| ConnectionEnd::Rejected(error.to_string()))?;
    let mut connection = TcpConnection::from_stream(stream, SUPERVISE_INTERVAL, WRITE_TIMEOUT)
        .map_err(|error| ConnectionEnd::Rejected(error.to_string()))?;
    let auth = MessageAuthenticator::new(psk.clone());

    // HELLO under one total deadline.
    let started = Instant::now();
    let hello = loop {
        if shutdown.is_requested() {
            return Err(ConnectionEnd::Closed);
        }
        if started.elapsed() >= HELLO_DEADLINE {
            return Err(ConnectionEnd::Rejected(
                "no HELLO within the deadline".into(),
            ));
        }
        match connection
            .poll_payload()
            .map_err(|error| ConnectionEnd::Rejected(error.to_string()))?
        {
            PollFrameResult::NoFrame => std::thread::sleep(POLL_INTERVAL),
            PollFrameResult::Eof => return Err(ConnectionEnd::Closed),
            PollFrameResult::Frame(bytes) => {
                break crate::receive::receive(&bytes, &CborSerializer, &auth)
                    .map_err(|error| ConnectionEnd::Rejected(error.to_string()))?;
            }
        }
    };
    check_first_message(config, &hello).map_err(ConnectionEnd::Rejected)?;
    let common = hello.unsigned().common.clone();
    let mut process =
        ProcessSession::generate().map_err(|error| ConnectionEnd::Rejected(error.to_string()))?;
    let ack = build_hello_ack(
        &mut process,
        common.cluster_id.clone(),
        NodeId::new(config.id.clone()),
        common.sender_node_id.clone(),
        common.term,
    )
    .map_err(|error| ConnectionEnd::Rejected(error.to_string()))?;
    connection
        .send_message(ack, &CborSerializer, &auth)
        .map_err(|_| ConnectionEnd::Closed)?;

    let mut witness = WitnessConnection::new(
        NodeId::new(config.id.clone()),
        common.sender_node_id.clone(),
        common.cluster_id.clone(),
        common.session_id.clone(),
        connection,
    );
    let store = config.store(boot);
    while !shutdown.is_requested() {
        let pending = match witness.poll_pending(&CborSerializer, &auth) {
            Ok(WitnessPoll::NoFrame) => {
                std::thread::sleep(POLL_INTERVAL);
                continue;
            }
            Ok(WitnessPoll::Eof) => return Err(ConnectionEnd::Closed),
            Ok(WitnessPoll::Pending(pending, _provenance)) => pending,
            // Authentication, framing, identity, replay: the connection ends.
            Err(error) => return Err(ConnectionEnd::Rejected(error.to_string())),
        };
        let result = match &pending.message().unsigned().message {
            ProtocolMessage::GetTerm => {
                match handle_get_term_authority(&mut witness, &pending, &store) {
                    Ok(prepared) => send_prepared_term_status(
                        &mut witness,
                        &mut process,
                        prepared,
                        &CborSerializer,
                        &auth,
                    )
                    .map_err(|_| ConnectionEnd::Closed),
                    Err(error) => Err(authority_failure(error)),
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
                    Ok(prepared) => send_prepared_lease_response(
                        &mut witness,
                        &mut process,
                        prepared,
                        &CborSerializer,
                        &auth,
                    )
                    .map_err(|_| ConnectionEnd::Closed),
                    Err(error) => Err(authority_failure(error)),
                }
            }
            other => Err(ConnectionEnd::Rejected(format!(
                "unsupported message {:?}",
                other.message_type()
            ))),
        };
        result?;
    }
    Err(ConnectionEnd::Closed)
}

/// WS-5: an authority error never produces a response and never `Ok(())`.
fn authority_failure(error: WitnessAuthorityError) -> ConnectionEnd {
    match error {
        WitnessAuthorityError::AuthorityLockPoisoned => ConnectionEnd::Fatal(
            "the authority mutation lock is poisoned; the witness cannot continue".to_string(),
        ),
        other => ConnectionEnd::Authority(format!("{other:?}")),
    }
}

// ---- entry points ---------------------------------------------------------------

fn load_config(path: &Path) -> Result<WitnessServerConfig, ExitCode> {
    WitnessServerConfig::load(path).map_err(|error| {
        log("ERROR", &error);
        ExitCode::FAILURE
    })
}

pub(crate) fn run_init(config_path: &Path) -> ExitCode {
    let config = match load_config(config_path) {
        Ok(config) => config,
        Err(code) => return code,
    };
    match initialize(&config, ProcBootIdProvider) {
        Ok(()) => {
            log(
                "INFO",
                &format!(
                    "initialized witness state at {}",
                    config.state_path().display()
                ),
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            log("ERROR", &error);
            ExitCode::FAILURE
        }
    }
}

pub(crate) fn run_rearm(config_path: &Path) -> ExitCode {
    let config = match load_config(config_path) {
        Ok(config) => config,
        Err(code) => return code,
    };
    // Same instance lock as `run`: re-arming a state a server is serving would
    // be a second writer.
    let lock = match fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(config.lock_path())
    {
        Ok(lock) => lock,
        Err(error) => {
            log(
                "ERROR",
                &format!("could not open the instance lock: {error}"),
            );
            return ExitCode::FAILURE;
        }
    };
    if lock.try_lock().is_err() {
        log(
            "ERROR",
            "a witness instance is running on this state directory",
        );
        return ExitCode::FAILURE;
    }
    match ensure_ready(&config, ProcBootIdProvider, true, SystemTime::now()) {
        Ok(Readiness::Ready) => {
            log("INFO", "the state is already ready; nothing to re-arm");
            ExitCode::SUCCESS
        }
        Ok(Readiness::Rearmed { lease_was_active }) => {
            log(
                "INFO",
                &format!("re-armed (active lease re-based: {lease_was_active})"),
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            log("ERROR", &error);
            ExitCode::FAILURE
        }
    }
}

pub(crate) fn run_witness(config_path: &Path) -> ExitCode {
    let config = match load_config(config_path) {
        Ok(config) => config,
        Err(code) => return code,
    };
    let psk = match Psk::load(&config.psk_file) {
        Ok(psk) => psk,
        Err(error) => {
            log("ERROR", &format!("could not load the PSK file: {error}"));
            return ExitCode::FAILURE;
        }
    };
    let shutdown = Shutdown::default();
    #[cfg(target_os = "linux")]
    signals::install(&shutdown);
    let prepared = match prepare(config, psk, ProcBootIdProvider, SystemTime::now()) {
        Ok(prepared) => prepared,
        Err(error) => {
            log("ERROR", &error);
            return ExitCode::FAILURE;
        }
    };
    match serve(prepared, shutdown) {
        ServeOutcome::Clean => {
            log("INFO", "stopped");
            ExitCode::SUCCESS
        }
        ServeOutcome::Fatal(reason) => {
            log("ERROR", &format!("stopped: {reason}"));
            ExitCode::FAILURE
        }
    }
}

/// SIGINT / SIGTERM request the shutdown. The signals are blocked in the
/// calling thread before any other thread exists, so every thread inherits the
/// mask and only the dedicated `sigwait` thread receives them: no handler, no
/// shared flag.
#[cfg(target_os = "linux")]
mod signals {
    use super::Shutdown;

    pub(super) fn install(shutdown: &Shutdown) {
        // SAFETY: `set` is a plain local the libc calls initialise and read;
        // all calls are used as documented (sigemptyset, sigaddset,
        // pthread_sigmask, sigwait).
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGINT);
            libc::sigaddset(&mut set, libc::SIGTERM);
            if libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) != 0 {
                return;
            }
        }
        let shutdown = shutdown.clone();
        std::thread::spawn(move || {
            // SAFETY: as above; `sigwait` only writes `signal`.
            unsafe {
                let mut set: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, libc::SIGINT);
                libc::sigaddset(&mut set, libc::SIGTERM);
                let mut signal: libc::c_int = 0;
                libc::sigwait(&set, &mut signal);
            }
            shutdown.request();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        DurationMs, LeaseId, LeaseReleasePayload, LeaseRenewPayload, LeaseRequestPayload,
        RequestId, Term,
    };

    /// The shipped example parses with the real parser and names the same
    /// cluster, Witness id, node pair and preferred node as the node examples.
    #[test]
    fn shipped_witness_example_matches_the_node_examples() {
        let config =
            WitnessServerConfig::parse_str(include_str!("../contrib/examples/witness.toml"))
                .expect("witness.toml");
        let node =
            crate::config::Config::parse_str(include_str!("../contrib/examples/node-a.toml"))
                .expect("node-a.toml");
        assert_eq!(config.cluster, node.cluster.id);
        assert_eq!(
            Some(&config.id),
            node.witness.as_ref().and_then(|w| w.id.as_ref())
        );
        assert_eq!(
            config.nodes,
            [("node-a".to_string(), 100), ("node-b".to_string(), 50)]
        );
        assert_eq!(config.on_reboot, OnReboot::Rearm);
        assert_eq!(config.psk_file, PathBuf::from(&node.security.psk_file));
    }
    use crate::session::OutboundHandshake;
    use crate::tcp::ReceiveMessageResult;
    use crate::witness_runtime::{WitnessResponseObservation, WitnessSession};
    use crate::witness_state::{BootId, LeaseState, WitnessStateError};
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    #[derive(Clone)]
    struct FixedBoot(Arc<Mutex<String>>);

    impl FixedBoot {
        fn new(value: &str) -> Self {
            Self(Arc::new(Mutex::new(value.to_string())))
        }
        fn set(&self, value: &str) {
            *self.0.lock().unwrap() = value.to_string();
        }
    }

    impl BootIdProvider for FixedBoot {
        fn current_boot_id(&self) -> Result<BootId, WitnessStateError> {
            Ok(BootId::new(self.0.lock().unwrap().clone()))
        }
    }

    fn test_psk() -> Psk {
        Psk::from_test_bytes([0x55; 32])
    }

    struct Fixture {
        dir: PathBuf,
        config: WitnessServerConfig,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            if !std::thread::panicking() {
                let _ = fs::remove_dir_all(&self.dir);
            }
        }
    }

    fn fixture(name: &str, extra: &str) -> Fixture {
        let dir = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "mikagami-witness-server-{name}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            ));
        fs::create_dir_all(&dir).unwrap();
        let config = WitnessServerConfig::parse_str(&format!(
            "cluster = \"ha1\"\nid = \"witness-1\"\nlisten = \"127.0.0.1:0\"\n\
             nodes = [\"node-a\", \"node-b\"]\npreferred = \"node-a\"\n\
             psk_file = \"/etc/mikagami/cluster.psk\"\nstate_dir = \"{}/state\"\n{extra}",
            dir.display()
        ))
        .unwrap();
        Fixture { dir, config }
    }

    fn running(
        fixture: &Fixture,
        boot: &FixedBoot,
    ) -> (SocketAddr, Shutdown, JoinHandle<ServeOutcome>) {
        let prepared = prepare(
            fixture.config.clone(),
            test_psk(),
            boot.clone(),
            SystemTime::now(),
        )
        .expect("prepare");
        let address = prepared.local_addr();
        let shutdown = Shutdown::default();
        let handle = {
            let shutdown = shutdown.clone();
            std::thread::spawn(move || serve(prepared, shutdown))
        };
        (address, shutdown, handle)
    }

    // ---- a minimal production-shaped client ------------------------------------

    struct Client {
        session: WitnessSession,
        generation: u64,
        next: u64,
    }

    impl Client {
        fn connect(address: SocketAddr, node: &str, priority: i32) -> Result<Self, String> {
            let auth = MessageAuthenticator::new(test_psk());
            let mut connection = TcpConnection::connect(
                address,
                Duration::from_secs(2),
                Duration::from_secs(5),
                Duration::from_secs(5),
            )
            .map_err(|e| e.to_string())?;
            let mut process = ProcessSession::generate().map_err(|e| e.to_string())?;
            let mut handshake = OutboundHandshake::new(
                ClusterId::new("ha1"),
                NodeId::new(node),
                NodeId::new("witness-1"),
                priority,
            );
            let hello = handshake
                .build_hello(&mut process, Term(0))
                .map_err(|e| e.to_string())?;
            connection
                .send_message(hello, &CborSerializer, &auth)
                .map_err(|e| e.to_string())?;
            let ReceiveMessageResult::Message(ack) = connection
                .receive_message(&CborSerializer, &auth)
                .map_err(|e| e.to_string())?
            else {
                return Err("closed before HELLO_ACK".into());
            };
            handshake
                .accept_hello_ack(&ack)
                .map_err(|e| e.to_string())?;
            let session_id = handshake
                .peer_session_id()
                .cloned()
                .ok_or("no session id")?;
            let connection = WitnessConnection::new(
                NodeId::new(node),
                NodeId::new("witness-1"),
                ClusterId::new("ha1"),
                session_id,
                connection,
            );
            Ok(Self {
                session: WitnessSession::new(connection, process, auth),
                generation: 0,
                next: 0,
            })
        }

        fn id(&mut self) -> RequestId {
            self.next += 1;
            static UNIQUE: AtomicU64 = AtomicU64::new(1);
            RequestId::new(format!(
                "{:08x}-0000-4000-8000-{:012x}",
                0xAB,
                UNIQUE.fetch_add(1, Ordering::SeqCst)
            ))
        }

        fn finish(&mut self) -> Result<WitnessResponseObservation, String> {
            let pending = self.session.receive_pending().map_err(|e| e.to_string())?;
            self.session
                .handle_pending_response(&pending)
                .map_err(|e| e.to_string())
        }

        fn get_term(&mut self) -> crate::protocol::TermStatusPayload {
            let id = self.id();
            self.session.send_get_term(id).unwrap();
            match self.finish().expect("GET_TERM response") {
                WitnessResponseObservation::TermStatus(payload) => payload,
                other => panic!("GET_TERM answered with {other:?}"),
            }
        }

        fn request(&mut self, observed_term: u64) -> WitnessResponseObservation {
            self.generation += 1;
            let (id, generation) = (self.id(), self.generation);
            self.session
                .send_lease_request(
                    id,
                    LeaseRequestPayload {
                        mutation_generation: generation,
                        observed_term: Term(observed_term),
                        priority: 100,
                        requested_ttl: DurationMs(10_000),
                    },
                )
                .unwrap();
            self.finish().expect("LeaseRequest response")
        }

        fn renew(&mut self, term: u64, lease_id: &str) -> WitnessResponseObservation {
            self.generation += 1;
            let (id, generation) = (self.id(), self.generation);
            self.session
                .send_lease_renew(
                    id,
                    LeaseRenewPayload {
                        mutation_generation: generation,
                        term: Term(term),
                        lease_id: LeaseId::new(lease_id),
                    },
                )
                .unwrap();
            self.finish().expect("LeaseRenew response")
        }

        fn release(&mut self, term: u64, lease_id: &str) -> WitnessResponseObservation {
            self.generation += 1;
            let (id, generation) = (self.id(), self.generation);
            self.session
                .send_lease_release(
                    id,
                    LeaseReleasePayload {
                        mutation_generation: generation,
                        term: Term(term),
                        lease_id: LeaseId::new(lease_id),
                        reason: "test".to_string(),
                    },
                )
                .unwrap();
            self.finish().expect("LeaseRelease response")
        }
    }

    fn grant_of(observation: WitnessResponseObservation) -> crate::protocol::LeaseGrantPayload {
        match observation {
            WitnessResponseObservation::LeaseGrant(grant) => grant,
            other => panic!("expected a grant, got {other:?}"),
        }
    }

    fn stop(shutdown: &Shutdown, handle: JoinHandle<ServeOutcome>) -> ServeOutcome {
        shutdown.request();
        handle.join().unwrap()
    }

    // ---- configuration ----------------------------------------------------------

    #[test]
    fn config_accepts_the_documented_shape_and_derives_priorities() {
        let fixture = fixture("config", "");
        let config = &fixture.config;
        assert_eq!(
            config.nodes,
            vec![("node-a".into(), 100), ("node-b".into(), 50)]
        );
        assert_eq!(config.on_reboot, OnReboot::Rearm);
        assert_eq!(config.max_connections, 16);
        assert_eq!(config.rearm_max_downtime, Duration::from_secs(3600));
        let refuse = WitnessServerConfig::parse_str(&format!(
            "cluster = \"c\"\nid = \"w\"\nlisten = \"127.0.0.1:7947\"\nnodes = [\"a\", \"b\"]\n\
             preferred = \"b\"\npsk_file = \"/p\"\nstate_dir = \"/s\"\non_reboot = \"refuse\"\n\
             max_connections = 4\n"
        ))
        .unwrap();
        assert_eq!(refuse.on_reboot, OnReboot::Refuse);
        assert_eq!(refuse.nodes, vec![("a".into(), 50), ("b".into(), 100)]);
    }

    #[test]
    fn config_rejects_bad_values_and_unknown_keys() {
        let base = "cluster = \"c\"\nid = \"w\"\nlisten = \"127.0.0.1:7947\"\n\
                    nodes = [\"a\", \"b\"]\npreferred = \"a\"\npsk_file = \"/p\"\nstate_dir = \"/s\"\n";
        assert!(WitnessServerConfig::parse_str(base).is_ok());
        for (from, to, expect) in [
            ("nodes = [\"a\", \"b\"]", "nodes = [\"a\"]", "exactly two"),
            (
                "nodes = [\"a\", \"b\"]",
                "nodes = [\"a\", \"a\"]",
                "exactly two",
            ),
            (
                "preferred = \"a\"",
                "preferred = \"z\"",
                "preferred must be one of nodes",
            ),
            ("listen = \"127.0.0.1:7947\"", "listen = \"nope\"", "listen"),
            (
                "psk_file = \"/p\"",
                "psk_file = \"p\"",
                "psk_file must be an absolute",
            ),
            (
                "state_dir = \"/s\"",
                "state_dir = \"s\"",
                "state_dir must be an absolute",
            ),
            ("id = \"w\"", "id = \"a\"", "id must differ"),
        ] {
            let error = WitnessServerConfig::parse_str(&base.replace(from, to)).unwrap_err();
            assert!(error.contains(expect), "{from}: {error}");
        }
        for extra in [
            "max_connections = 0\n",
            "max_connections = 1000\n",
            "rearm_max_downtime_sec = 0\n",
        ] {
            assert!(
                WitnessServerConfig::parse_str(&format!("{base}{extra}")).is_err(),
                "{extra}"
            );
        }
        let error = WitnessServerConfig::parse_str(&format!("{base}hello = 1\n")).unwrap_err();
        assert!(error.contains("unknown field"), "{error}");
    }

    // ---- init / readiness (CE-WS-1, CE-WS-2) -------------------------------------

    #[test]
    fn run_refuses_to_start_without_state_and_never_initializes_it() {
        let fixture = fixture("nostate", "");
        let boot = FixedBoot::new("boot-1");
        fs::create_dir_all(&fixture.config.state_dir).unwrap();
        let error = prepare(
            fixture.config.clone(),
            test_psk(),
            boot.clone(),
            SystemTime::now(),
        )
        .err()
        .expect("must refuse");
        assert!(error.contains("witness init"), "{error}");
        assert!(
            !fixture.config.state_path().exists(),
            "no implicit initialize_new"
        );
    }

    #[test]
    fn init_creates_a_private_directory_and_refuses_to_run_twice() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = fixture("init", "");
        let boot = FixedBoot::new("boot-1");
        initialize(&fixture.config, boot.clone()).unwrap();
        let mode = fs::metadata(&fixture.config.state_dir)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
        assert!(fixture.config.state_path().exists());
        let error = initialize(&fixture.config, boot.clone()).unwrap_err();
        assert!(error.contains("refusing to re-initialize"), "{error}");
        // a populated directory without state is refused too
        let other = fixture_named_dir(&fixture, "populated");
        fs::create_dir_all(&other).unwrap();
        fs::write(other.join("stray"), b"x").unwrap();
        let mut config = fixture.config.clone();
        config.state_dir = other;
        assert!(initialize(&config, boot).unwrap_err().contains("not empty"));
    }

    fn fixture_named_dir(fixture: &Fixture, name: &str) -> PathBuf {
        fixture.dir.join(name)
    }

    #[test]
    fn corrupt_state_refuses_startup_and_is_not_reinitialized() {
        let fixture = fixture("corrupt", "");
        let boot = FixedBoot::new("boot-1");
        initialize(&fixture.config, boot.clone()).unwrap();
        fs::write(fixture.config.state_path(), b"not = [valid").unwrap();
        let error = prepare(fixture.config.clone(), test_psk(), boot, SystemTime::now())
            .err()
            .expect("must refuse");
        assert!(error.contains("not ready"), "{error}");
        assert_eq!(
            fs::read(fixture.config.state_path()).unwrap(),
            b"not = [valid"
        );
    }

    // ---- end to end through the production authority ----------------------------

    #[test]
    fn grant_renew_release_and_expiry_through_the_product_server() {
        let fixture = fixture("e2e", "");
        let boot = FixedBoot::new("boot-1");
        initialize(&fixture.config, boot.clone()).unwrap();
        let (address, shutdown, handle) = running(&fixture, &boot);

        let mut a = Client::connect(address, "node-a", 100).unwrap();
        let view = a.get_term();
        assert_eq!(view.current_term, Term(0));
        assert!(view.current_holder.is_none());
        let grant = grant_of(a.request(0));
        assert_eq!(grant.term, Term(1));
        // node-b cannot preempt an active lease
        let mut b = Client::connect(address, "node-b", 50).unwrap();
        assert!(matches!(
            b.request(1),
            WitnessResponseObservation::LeaseReject(_)
        ));
        let renewed = a.renew(1, grant.lease_id.as_str());
        assert!(matches!(
            renewed,
            WitnessResponseObservation::LeaseRenewed(_)
        ));
        let released = a.release(1, grant.lease_id.as_str());
        assert!(matches!(
            released,
            WitnessResponseObservation::LeaseReleased(_)
        ));
        let second = grant_of(b.request(1));
        assert_eq!(second.term, Term(2), "a new grant raises the term");
        assert_eq!(stop(&shutdown, handle), ServeOutcome::Clean);
        // state survives a process restart on the same boot (W-2): same term.
        let (address, shutdown, handle) = running(&fixture, &boot);
        let mut b = Client::connect(address, "node-b", 50).unwrap();
        let view = b.get_term();
        assert_eq!(view.current_term, Term(2));
        assert_eq!(view.current_holder, Some(NodeId::new("node-b")));
        assert_eq!(stop(&shutdown, handle), ServeOutcome::Clean);
    }

    #[test]
    fn the_expiry_scheduler_runs_and_frees_the_term_for_a_new_grant() {
        use crate::witness_state::{WitnessPersistentState, WitnessStateStore as Store};
        let fixture = fixture("expiry", "");
        let boot = FixedBoot::new("boot-1");
        initialize(&fixture.config, boot.clone()).unwrap();
        // Plant a lease that is already past its deadline (what a crashed
        // holder leaves behind), then let the product scheduler expire it.
        let store: Store<FixedBoot, SystemMonotonicClock> = fixture.config.store(boot.clone());
        let mut state: WitnessPersistentState = store.load().state.unwrap();
        let expected = store.load().expected_old.unwrap();
        state.current_term = Term(4);
        state.lease_state = LeaseState::Active;
        state.active_lease_id = Some(LeaseId::new("lease-old"));
        state.holder_node_id = Some(NodeId::new("node-a"));
        state.lease_ttl_ms = Some(DurationMs(10_000));
        state.lease_deadline_monotonic_ms = Some(store.current_monotonic_ms().unwrap());
        store.commit_candidate(&state, &expected).unwrap();
        let (address, shutdown, handle) = running(&fixture, &boot);
        let mut b = Client::connect(address, "node-b", 50).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let view = b.get_term();
            if view.current_holder.is_none() {
                assert_eq!(view.current_term, Term(4), "expiry never changes the term");
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the scheduler never expired the lease"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(grant_of(b.request(4)).term, Term(5));
        assert_eq!(stop(&shutdown, handle), ServeOutcome::Clean);
    }

    // ---- connection hygiene (CE-WS-5) --------------------------------------------

    #[test]
    fn a_wrong_hello_gets_no_ack_and_does_not_disturb_other_connections() {
        let fixture = fixture("hello", "");
        let boot = FixedBoot::new("boot-1");
        initialize(&fixture.config, boot.clone()).unwrap();
        let (address, shutdown, handle) = running(&fixture, &boot);
        // unknown sender
        assert!(Client::connect(address, "node-z", 100).is_err());
        // right sender, wrong priority
        assert!(Client::connect(address, "node-a", 7).is_err());
        // garbage / partial frames are dropped
        let mut raw = TcpStream::connect(address).unwrap();
        raw.write_all(&[0, 0, 0, 9, 1, 2]).unwrap();
        // a good client still works
        let mut a = Client::connect(address, "node-a", 100).unwrap();
        assert_eq!(a.get_term().current_term, Term(0));
        drop(raw);
        assert_eq!(stop(&shutdown, handle), ServeOutcome::Clean);
    }

    #[test]
    fn a_connection_that_never_sends_hello_is_dropped_at_the_deadline() {
        let fixture = fixture("slowloris", "");
        let boot = FixedBoot::new("boot-1");
        initialize(&fixture.config, boot.clone()).unwrap();
        let (address, shutdown, handle) = running(&fixture, &boot);
        let mut idle = TcpStream::connect(address).unwrap();
        idle.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let started = Instant::now();
        let mut buffer = [0u8; 8];
        let read = std::io::Read::read(&mut idle, &mut buffer);
        assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
        assert!(started.elapsed() < Duration::from_secs(9));
        assert!(started.elapsed() >= HELLO_DEADLINE - Duration::from_millis(500));
        assert_eq!(stop(&shutdown, handle), ServeOutcome::Clean);
    }

    #[test]
    fn the_connection_limit_refuses_the_extra_connection_only() {
        let fixture = fixture("limit", "max_connections = 1\n");
        let boot = FixedBoot::new("boot-1");
        initialize(&fixture.config, boot.clone()).unwrap();
        let (address, shutdown, handle) = running(&fixture, &boot);
        let mut first = Client::connect(address, "node-a", 100).unwrap();
        assert_eq!(first.get_term().current_term, Term(0));
        assert!(
            Client::connect(address, "node-b", 50).is_err(),
            "over the limit"
        );
        assert_eq!(
            first.get_term().current_term,
            Term(0),
            "the first is unaffected"
        );
        drop(first);
        assert_eq!(stop(&shutdown, handle), ServeOutcome::Clean);
    }

    // ---- single instance (CE-WS-7) -----------------------------------------------

    #[test]
    fn a_second_instance_on_the_same_state_directory_is_refused() {
        let fixture = fixture("lock", "");
        let boot = FixedBoot::new("boot-1");
        initialize(&fixture.config, boot.clone()).unwrap();
        let first = prepare(
            fixture.config.clone(),
            test_psk(),
            boot.clone(),
            SystemTime::now(),
        )
        .expect("first instance");
        let second = prepare(fixture.config.clone(), test_psk(), boot, SystemTime::now())
            .err()
            .expect("second instance must be refused");
        assert!(second.contains("another witness instance"), "{second}");
        drop(first);
    }

    // ---- reboot re-arm (CE-WS-3, CE-WS-4) ----------------------------------------

    fn plant_active_lease(fixture: &Fixture, boot: &FixedBoot) -> u64 {
        let store = fixture.config.store(boot.clone());
        let recovery = store.load();
        let mut state = recovery.state.unwrap();
        state.current_term = Term(7);
        state.lease_state = LeaseState::Active;
        state.active_lease_id = Some(LeaseId::new("lease-7"));
        state.holder_node_id = Some(NodeId::new("node-a"));
        state.lease_ttl_ms = Some(DurationMs(10_000));
        // a deadline in the *old boot's* monotonic domain
        let old_deadline = 123_456_789;
        state.lease_deadline_monotonic_ms = Some(old_deadline);
        store
            .commit_candidate(&state, &recovery.expected_old.unwrap())
            .unwrap();
        old_deadline
    }

    #[test]
    fn reboot_rearm_rebases_the_deadline_and_keeps_everything_else() {
        let fixture = fixture("rearm", "");
        let boot = FixedBoot::new("boot-1");
        initialize(&fixture.config, boot.clone()).unwrap();
        plant_active_lease(&fixture, &boot);
        let before = fixture.config.store(boot.clone()).load().state.unwrap();
        boot.set("boot-2");
        let store = fixture.config.store(boot.clone());
        assert_eq!(
            store.load().readiness,
            WitnessReadiness::NotReady(WitnessNotReadyReason::BootIdChanged)
        );
        let now = store.current_monotonic_ms().unwrap();
        let outcome =
            ensure_ready(&fixture.config, boot.clone(), false, SystemTime::now()).unwrap();
        assert_eq!(
            outcome,
            Readiness::Rearmed {
                lease_was_active: true
            }
        );
        let after = store.load().state.unwrap();
        assert_eq!(store.load().readiness, WitnessReadiness::Ready);
        assert_eq!(after.boot_id, BootId::new("boot-2"));
        // term / holder / lease / journal / watermarks unchanged
        assert_eq!(after.current_term, before.current_term);
        assert_eq!(after.holder_node_id, before.holder_node_id);
        assert_eq!(after.active_lease_id, before.active_lease_id);
        assert_eq!(after.lease_ttl_ms, before.lease_ttl_ms);
        assert_eq!(after.journal, before.journal);
        assert_eq!(after.generation_watermarks, before.generation_watermarks);
        assert_eq!(after.lease_state, LeaseState::Active);
        // deadline = this boot's now + TTL (never earlier than now + 10 s)
        let deadline = after.lease_deadline_monotonic_ms.unwrap();
        assert!(deadline >= now + 10_000, "{deadline} < {now} + 10000");
        assert!(deadline <= store.current_monotonic_ms().unwrap() + 10_000);
        // a second readiness check is a no-op
        assert_eq!(
            ensure_ready(&fixture.config, boot, false, SystemTime::now()).unwrap(),
            Readiness::Ready
        );
    }

    #[test]
    fn a_rebooted_witness_serves_the_same_term_and_the_rebased_lease() {
        let fixture = fixture("rearm-serve", "");
        let boot = FixedBoot::new("boot-1");
        initialize(&fixture.config, boot.clone()).unwrap();
        plant_active_lease(&fixture, &boot);
        boot.set("boot-2");
        let (address, shutdown, handle) = running(&fixture, &boot);
        let mut b = Client::connect(address, "node-b", 50).unwrap();
        let view = b.get_term();
        assert_eq!(view.current_term, Term(7));
        assert_eq!(view.current_holder, Some(NodeId::new("node-a")));
        let remaining = view.lease_remaining_ms.expect("a live lease").0;
        assert!(remaining > 5_000 && remaining <= 10_000, "{remaining}");
        assert!(matches!(
            b.request(7),
            WitnessResponseObservation::LeaseReject(_)
        ));
        assert_eq!(stop(&shutdown, handle), ServeOutcome::Clean);
    }

    #[test]
    fn on_reboot_refuse_stays_not_ready_until_the_explicit_command() {
        let fixture = fixture("refuse", "on_reboot = \"refuse\"\n");
        let boot = FixedBoot::new("boot-1");
        initialize(&fixture.config, boot.clone()).unwrap();
        plant_active_lease(&fixture, &boot);
        boot.set("boot-2");
        let error = prepare(
            fixture.config.clone(),
            test_psk(),
            boot.clone(),
            SystemTime::now(),
        )
        .err()
        .expect("must refuse");
        assert!(error.contains("witness rearm"), "{error}");
        assert_eq!(
            fixture.config.store(boot.clone()).load().readiness,
            WitnessReadiness::NotReady(WitnessNotReadyReason::BootIdChanged)
        );
        // the explicit command bypasses `refuse`
        let outcome = ensure_ready(&fixture.config, boot, true, SystemTime::now()).unwrap();
        assert_eq!(
            outcome,
            Readiness::Rearmed {
                lease_was_active: true
            }
        );
    }

    #[test]
    fn a_stale_state_with_an_active_lease_needs_the_explicit_command() {
        let fixture = fixture("stale", "rearm_max_downtime_sec = 60\n");
        let boot = FixedBoot::new("boot-1");
        initialize(&fixture.config, boot.clone()).unwrap();
        plant_active_lease(&fixture, &boot);
        boot.set("boot-2");
        // Pretend the state was last written two hours ago.
        let later = SystemTime::now() + Duration::from_secs(7200);
        let error = ensure_ready(&fixture.config, boot.clone(), false, later)
            .err()
            .expect("must refuse");
        assert!(error.contains("automatic re-arm refused"), "{error}");
        assert!(error.contains("witness rearm"), "{error}");
        // within the limit it re-arms
        let outcome =
            ensure_ready(&fixture.config, boot.clone(), false, SystemTime::now()).unwrap();
        assert_eq!(
            outcome,
            Readiness::Rearmed {
                lease_was_active: true
            }
        );
    }

    #[test]
    fn rearm_without_an_active_lease_only_updates_the_boot_id() {
        let fixture = fixture("rearm-idle", "");
        let boot = FixedBoot::new("boot-1");
        initialize(&fixture.config, boot.clone()).unwrap();
        boot.set("boot-2");
        let outcome =
            ensure_ready(&fixture.config, boot.clone(), false, SystemTime::now()).unwrap();
        assert_eq!(
            outcome,
            Readiness::Rearmed {
                lease_was_active: false
            }
        );
        let state = fixture.config.store(boot).load().state.unwrap();
        assert_eq!(state.lease_state, LeaseState::None);
        assert_eq!(state.current_term, Term(0));
    }

    // ---- supervision (CE-WS-6) -----------------------------------------------------

    #[test]
    fn a_stopped_scheduler_ends_the_server_non_zero() {
        let fixture = fixture("supervise", "");
        let boot = FixedBoot::new("boot-1");
        initialize(&fixture.config, boot.clone()).unwrap();
        // Any fatal condition (a stopped scheduler, a poisoned authority lock,
        // an accept failure) takes the same path: `Shutdown::fail` records the
        // reason, the server drains and `serve` reports `Fatal`.
        let (_, shutdown, handle) = running(&fixture, &boot);
        shutdown.fail("injected fatal condition".to_string());
        assert_eq!(
            handle.join().unwrap(),
            ServeOutcome::Fatal("injected fatal condition".to_string())
        );
    }
}
