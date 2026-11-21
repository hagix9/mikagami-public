//! Durable Witness authority state and boot-scoped recovery.
//!
//! This module deliberately does not make term or lease decisions.  It only
//! loads, validates, and durably stores the state that a later authority
//! layer may use.

use crate::protocol::{ClusterId, DurationMs, LeaseId, NodeId, Term};
use crate::recovery::{self, CommitResult, ExpectedOldToken, Inspection, StoreKind};
use crate::witness_journal::{self, JournalRecord};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::{Arc, Barrier, Mutex, OnceLock};

#[cfg(test)]
struct MigrationTestHook {
    path: PathBuf,
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
}

#[cfg(test)]
static MIGRATION_TEST_HOOK: OnceLock<Mutex<Option<MigrationTestHook>>> = OnceLock::new();

#[cfg(test)]
fn pause_migration_after_read(path: &Path) {
    let hook = MIGRATION_TEST_HOOK
        .get_or_init(|| Mutex::new(None))
        .lock()
        .expect("migration hook")
        .as_ref()
        .filter(|hook| hook.path == path)
        .map(|hook| (Arc::clone(&hook.entered), Arc::clone(&hook.release)));
    if let Some((entered, release)) = hook {
        entered.wait();
        release.wait();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootId(String);

impl BootId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<(), WitnessStateError> {
        let parts: Vec<&str> = self.0.split('-').collect();
        let lengths = [8, 4, 4, 4, 12];
        if parts.len() != lengths.len()
            || parts.iter().zip(lengths).any(|(part, length)| {
                part.len() != length || !part.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        {
            return Err(WitnessStateError::Invariant("boot_id has invalid format"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseState {
    None,
    Active,
    Unknown,
}

/// OD-J32-4 (RR-32-4): the v2 document rejects unknown top-level fields. The
/// attribute must sit on this struct: on the `StrictState` newtype it had no
/// effect. Unknown fields inside a journal record's protocol payload are still
/// accepted (the protocol wire types are unchanged; residual RR-OR3-1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessPersistentState {
    pub state_format_version: u32,
    pub cluster_id: ClusterId,
    #[serde(with = "term_persistence")]
    pub current_term: Term,
    pub active_lease_id: Option<LeaseId>,
    pub holder_node_id: Option<NodeId>,
    pub lease_ttl_ms: Option<DurationMs>,
    pub lease_deadline_monotonic_ms: Option<u64>,
    pub lease_state: LeaseState,
    pub boot_id: BootId,
    pub journal: Vec<JournalRecord>,
    pub generation_watermarks: BTreeMap<String, u64>,
}

mod term_persistence {
    use super::Term;
    use serde::Serializer;
    use serde::de::{self, Deserializer, Visitor};
    use std::fmt;

    pub fn serialize<S>(term: &Term, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if term.0 <= i64::MAX as u64 {
            serializer.serialize_u64(term.0)
        } else {
            serializer.serialize_str(&term.0.to_string())
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Term, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TermVisitor;
        impl<'de> Visitor<'de> for TermVisitor {
            type Value = Term;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a non-negative Witness term")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Term(value))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                u64::try_from(value)
                    .map(Term)
                    .map_err(|_| E::custom("term must not be negative"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                value
                    .parse::<u64>()
                    .map(Term)
                    .map_err(|_| E::custom("term string is not a valid u64"))
            }
        }
        deserializer.deserialize_any(TermVisitor)
    }
}

impl WitnessPersistentState {
    pub fn new(cluster_id: ClusterId, boot_id: BootId) -> Self {
        Self {
            state_format_version: 2,
            cluster_id,
            current_term: Term(0),
            active_lease_id: None,
            holder_node_id: None,
            lease_ttl_ms: None,
            lease_deadline_monotonic_ms: None,
            lease_state: LeaseState::None,
            boot_id,
            journal: Vec::new(),
            generation_watermarks: BTreeMap::new(),
        }
    }

    fn validate_structure(&self) -> Result<(), WitnessStateError> {
        if self.state_format_version != 2 {
            return Err(WitnessStateError::Invariant(
                "unsupported state format version",
            ));
        }
        if self.cluster_id.as_str().trim().is_empty() {
            return Err(WitnessStateError::Invariant("required identifier is empty"));
        }
        if self.boot_id.as_str().trim().is_empty() {
            return Err(WitnessStateError::Invariant("boot_id is empty"));
        }
        match self.lease_state {
            LeaseState::None => {
                if self.active_lease_id.is_some()
                    || self.holder_node_id.is_some()
                    || self.lease_ttl_ms.is_some()
                    || self.lease_deadline_monotonic_ms.is_some()
                {
                    return Err(WitnessStateError::Invariant(
                        "None lease state contains active lease metadata",
                    ));
                }
            }
            LeaseState::Active => {
                if self.active_lease_id.is_none()
                    || self.holder_node_id.is_none()
                    || self.lease_ttl_ms.is_none_or(|v| v.0 == 0)
                    || self.lease_deadline_monotonic_ms.is_none()
                {
                    return Err(WitnessStateError::Invariant(
                        "Active lease state is incomplete",
                    ));
                }
            }
            LeaseState::Unknown => {
                let fields = [
                    self.active_lease_id.is_some(),
                    self.holder_node_id.is_some(),
                    self.lease_ttl_ms.is_some(),
                    self.lease_deadline_monotonic_ms.is_some(),
                ];
                if fields.iter().any(|present| *present != fields[0])
                    || (fields[0] && self.lease_ttl_ms.is_none_or(|value| value.0 == 0))
                {
                    return Err(WitnessStateError::Invariant(
                        "Unknown lease state contains partial or invalid metadata",
                    ));
                }
            }
        }
        witness_journal::validate_state(self)?;
        Ok(())
    }

    pub fn validate(&self, configured_cluster: &ClusterId) -> Result<(), WitnessStateError> {
        self.validate_structure()?;
        if self.cluster_id != *configured_cluster {
            return Err(WitnessStateError::Invariant("cluster_id mismatch"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessNotReadyReason {
    StateMissing,
    StateCorrupt,
    ClusterMismatch,
    BootIdUnavailable,
    BootIdChanged,
    StateInvariantViolation,
    PersistenceFailure,
    RecoveryRequired,
    MigrationRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessReadiness {
    Ready,
    NotReady(WitnessNotReadyReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessRecovery {
    pub state: Option<WitnessPersistentState>,
    pub expected_old: Option<ExpectedOldToken>,
    pub readiness: WitnessReadiness,
}

pub trait BootIdProvider {
    fn current_boot_id(&self) -> Result<BootId, WitnessStateError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ProcBootIdProvider;

impl BootIdProvider for ProcBootIdProvider {
    fn current_boot_id(&self) -> Result<BootId, WitnessStateError> {
        let value = fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|error| WitnessStateError::BootId(io::Error::new(error.kind(), error)))?;
        let value = value.trim();
        if value.is_empty() {
            return Err(WitnessStateError::BootId(io::Error::new(
                io::ErrorKind::InvalidData,
                "boot_id is empty",
            )));
        }
        let boot_id = BootId::new(value);
        boot_id.validate()?;
        Ok(boot_id)
    }
}

pub trait MonotonicClock {
    fn now_ms(&self) -> Result<u64, WitnessStateError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemMonotonicClock;

impl MonotonicClock for SystemMonotonicClock {
    fn now_ms(&self) -> Result<u64, WitnessStateError> {
        monotonic_now_ms()
    }
}

#[cfg(unix)]
fn monotonic_now_ms() -> Result<u64, WitnessStateError> {
    #[repr(C)]
    struct Timespec {
        seconds: i64,
        nanoseconds: i64,
    }
    unsafe extern "C" {
        fn clock_gettime(clock_id: i32, time: *mut Timespec) -> i32;
    }
    #[cfg(target_os = "linux")]
    const CLOCK_MONOTONIC: i32 = 1;
    #[cfg(target_os = "macos")]
    const CLOCK_MONOTONIC: i32 = 6;

    let mut time = Timespec {
        seconds: 0,
        nanoseconds: 0,
    };
    let result = unsafe { clock_gettime(CLOCK_MONOTONIC, &mut time) };
    if result != 0 || time.seconds < 0 || !(0..1_000_000_000).contains(&time.nanoseconds) {
        return Err(WitnessStateError::Clock(io::Error::last_os_error()));
    }
    let seconds = u64::try_from(time.seconds).map_err(|_| {
        WitnessStateError::Clock(io::Error::new(io::ErrorKind::InvalidData, "clock overflow"))
    })?;
    seconds
        .checked_mul(1_000)
        .and_then(|value| value.checked_add((time.nanoseconds as u64) / 1_000_000))
        .ok_or_else(|| {
            WitnessStateError::Clock(io::Error::new(io::ErrorKind::InvalidData, "clock overflow"))
        })
}

#[cfg(not(unix))]
fn monotonic_now_ms() -> Result<u64, WitnessStateError> {
    Err(WitnessStateError::Clock(io::Error::new(
        io::ErrorKind::Unsupported,
        "monotonic clock is unsupported on this platform",
    )))
}

#[derive(Debug)]
pub enum WitnessStateError {
    Io(io::Error),
    BootId(io::Error),
    Clock(io::Error),
    Parse(String),
    Invariant(&'static str),
    Path(&'static str),
    AlreadyExists,
    AlreadyCurrent,
    StateMissing,
    RecoveryRequired(String),
}

impl fmt::Display for WitnessStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "witness state I/O failed: {error}"),
            Self::BootId(error) => write!(f, "boot_id unavailable: {error}"),
            Self::Clock(error) => write!(f, "monotonic clock unavailable: {error}"),
            Self::Parse(error) => write!(f, "witness state parse failed: {error}"),
            Self::Invariant(error) => write!(f, "witness state invariant failed: {error}"),
            Self::Path(error) => write!(f, "witness state path rejected: {error}"),
            Self::AlreadyExists => write!(f, "witness state already exists"),
            Self::AlreadyCurrent => write!(f, "witness state is already current"),
            Self::StateMissing => write!(f, "witness state is missing"),
            Self::RecoveryRequired(reason) => write!(f, "witness recovery required: {reason}"),
        }
    }
}
impl std::error::Error for WitnessStateError {}

pub struct WitnessStateStore<B = ProcBootIdProvider, C = SystemMonotonicClock> {
    path: PathBuf,
    configured_cluster: ClusterId,
    boot_id_provider: B,
    #[allow(dead_code)]
    clock: C,
}

impl WitnessStateStore<ProcBootIdProvider, SystemMonotonicClock> {
    pub fn new(path: impl Into<PathBuf>, configured_cluster: ClusterId) -> Self {
        Self::with_providers(
            path,
            configured_cluster,
            ProcBootIdProvider,
            SystemMonotonicClock,
        )
    }
}

impl<B, C> WitnessStateStore<B, C>
where
    B: BootIdProvider,
    C: MonotonicClock,
{
    pub fn with_providers(
        path: impl Into<PathBuf>,
        configured_cluster: ClusterId,
        boot_id_provider: B,
        clock: C,
    ) -> Self {
        let input = path.into();
        let resolved = recovery::resolve_store_path(&input)
            .map(|value| value.canonical_io_path().to_path_buf())
            .unwrap_or(input);
        Self {
            path: resolved,
            configured_cluster,
            boot_id_provider,
            clock,
        }
    }

    pub fn load(&self) -> WitnessRecovery {
        if let Some(reason) = self.recovery_block_reason() {
            return WitnessRecovery {
                state: None,
                expected_old: None,
                readiness: WitnessReadiness::NotReady(reason),
            };
        }
        let (persisted, migrated, expected_old) =
            match read_state(&self.path, self.configured_cluster.as_str()) {
                Ok(state) => state,
                Err(ReadStateError::Missing) => {
                    return WitnessRecovery {
                        state: None,
                        expected_old: None,
                        readiness: WitnessReadiness::NotReady(WitnessNotReadyReason::StateMissing),
                    };
                }
                Err(ReadStateError::Invalid(error)) => {
                    let reason = match error {
                        WitnessStateError::Invariant("cluster_id mismatch") => {
                            WitnessNotReadyReason::ClusterMismatch
                        }
                        WitnessStateError::Invariant(_) => {
                            WitnessNotReadyReason::StateInvariantViolation
                        }
                        _ => WitnessNotReadyReason::StateCorrupt,
                    };
                    return WitnessRecovery {
                        state: None,
                        expected_old: None,
                        readiness: WitnessReadiness::NotReady(reason),
                    };
                }
            };

        if let Err(error) = persisted.validate(&self.configured_cluster) {
            let reason = if matches!(error, WitnessStateError::Invariant("cluster_id mismatch")) {
                WitnessNotReadyReason::ClusterMismatch
            } else {
                WitnessNotReadyReason::StateInvariantViolation
            };
            return WitnessRecovery {
                state: Some(persisted),
                expected_old: Some(expected_old.clone()),
                readiness: WitnessReadiness::NotReady(reason),
            };
        }

        if migrated {
            return WitnessRecovery {
                state: Some(persisted),
                expected_old: Some(expected_old.clone()),
                readiness: WitnessReadiness::NotReady(WitnessNotReadyReason::MigrationRequired),
            };
        }

        let current_boot = match self.boot_id_provider.current_boot_id() {
            Ok(value) => value,
            Err(_) => {
                return WitnessRecovery {
                    state: Some(persisted),
                    expected_old: Some(expected_old.clone()),
                    readiness: WitnessReadiness::NotReady(WitnessNotReadyReason::BootIdUnavailable),
                };
            }
        };
        if current_boot != persisted.boot_id {
            return WitnessRecovery {
                state: Some(persisted),
                expected_old: Some(expected_old.clone()),
                readiness: WitnessReadiness::NotReady(WitnessNotReadyReason::BootIdChanged),
            };
        }
        WitnessRecovery {
            state: Some(persisted),
            expected_old: Some(expected_old),
            readiness: WitnessReadiness::Ready,
        }
    }

    pub fn current_monotonic_ms(&self) -> Result<u64, WitnessStateError> {
        self.clock.now_ms()
    }

    pub fn migrate_legacy_explicitly(&self) -> Result<WitnessPersistentState, WitnessStateError> {
        if let Some(reason) = self.recovery_block_reason() {
            return Err(WitnessStateError::RecoveryRequired(format!("{reason:?}")));
        }
        let (state, migrated, expected_old) =
            match read_state(&self.path, self.configured_cluster.as_str()) {
                Ok(value) => value,
                Err(ReadStateError::Missing) => return Err(WitnessStateError::StateMissing),
                Err(ReadStateError::Invalid(error)) => return Err(error),
            };
        if !migrated {
            return Err(WitnessStateError::AlreadyCurrent);
        }
        state.validate(&self.configured_cluster)?;
        let current_boot = self.boot_id_provider.current_boot_id()?;
        if current_boot != state.boot_id {
            return Err(WitnessStateError::BootId(io::Error::new(
                io::ErrorKind::InvalidData,
                "legacy state boot_id does not match current boot",
            )));
        }
        #[cfg(test)]
        pause_migration_after_read(&self.path);
        self.commit_candidate(&state, &expected_old)?;
        Ok(state)
    }

    fn recovery_block_reason(&self) -> Option<WitnessNotReadyReason> {
        if recovery::is_uncertain(&self.path) {
            return Some(WitnessNotReadyReason::RecoveryRequired);
        }
        match recovery::inspect(
            &self.path,
            StoreKind::Witness,
            self.configured_cluster.as_str(),
            "witness",
        ) {
            Inspection::Absent => None,
            Inspection::Active(_) | Inspection::Invalid(_) => {
                Some(WitnessNotReadyReason::RecoveryRequired)
            }
        }
    }

    pub fn initialize_new(&self) -> Result<WitnessPersistentState, WitnessStateError> {
        reject_unsafe_final(&self.path)?;
        if self.path.exists() {
            return Err(WitnessStateError::AlreadyExists);
        }
        let boot_id = self.boot_id_provider.current_boot_id()?;
        let state = WitnessPersistentState::new(self.configured_cluster.clone(), boot_id);
        state.validate(&self.configured_cluster)?;
        let content = serialize_state(&state)?;
        match recovery::persist(
            &self.path,
            StoreKind::Witness,
            self.configured_cluster.as_str(),
            "witness",
            "initialization",
            &[],
            content.as_bytes(),
            true,
        )
        .map_err(|e| WitnessStateError::Io(io::Error::other(e.0)))?
        {
            CommitResult::ConfirmedCommitted => Ok(state),
            CommitResult::PreCommitFailure(reason) => {
                Err(WitnessStateError::Io(io::Error::other(reason)))
            }
            CommitResult::CommitOutcomeUnknown(reason)
            | CommitResult::CleanupOutcomeUnknown(reason) => Err(WitnessStateError::Io(
                io::Error::other(format!("recovery required: {reason}")),
            )),
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn save(&self, state: &WitnessPersistentState) -> Result<(), WitnessStateError> {
        state.validate(&self.configured_cluster)?;
        reject_unsafe_final(&self.path)?;
        let create_only = !self.path.exists();
        let content = serialize_state(state)?;
        let expected_old = recovery::read_snapshot_with_token(
            &self.path,
            StoreKind::Witness,
            state.cluster_id.as_str(),
            "witness",
        )
        .map_err(|e| WitnessStateError::RecoveryRequired(e.0))?
        .map(|snapshot| snapshot.expected_old)
        .unwrap_or(ExpectedOldToken::Absent);
        match recovery::persist_with_expected_old(
            &self.path,
            StoreKind::Witness,
            state.cluster_id.as_str(),
            "witness",
            "mutation",
            &expected_old,
            content.as_bytes(),
            create_only || matches!(expected_old, ExpectedOldToken::Absent),
        )
        .map_err(|e| WitnessStateError::Io(io::Error::other(e.0)))?
        {
            CommitResult::ConfirmedCommitted => Ok(()),
            CommitResult::PreCommitFailure(reason) => {
                Err(WitnessStateError::Io(io::Error::other(reason)))
            }
            CommitResult::CommitOutcomeUnknown(reason)
            | CommitResult::CleanupOutcomeUnknown(reason) => Err(WitnessStateError::Io(
                io::Error::other(format!("recovery required: {reason}")),
            )),
        }
    }

    pub fn commit_candidate(
        &self,
        state: &WitnessPersistentState,
        expected_old: &ExpectedOldToken,
    ) -> Result<(), WitnessStateError> {
        state.validate(&self.configured_cluster)?;
        reject_unsafe_final(&self.path)?;
        let content = serialize_state(state)?;
        match recovery::persist_with_expected_old(
            &self.path,
            StoreKind::Witness,
            state.cluster_id.as_str(),
            "witness",
            "mutation",
            expected_old,
            content.as_bytes(),
            matches!(expected_old, ExpectedOldToken::Absent),
        )
        .map_err(|e| WitnessStateError::Io(io::Error::other(e.0)))?
        {
            CommitResult::ConfirmedCommitted => Ok(()),
            CommitResult::PreCommitFailure(reason) => {
                Err(WitnessStateError::Io(io::Error::other(reason)))
            }
            CommitResult::CommitOutcomeUnknown(reason)
            | CommitResult::CleanupOutcomeUnknown(reason) => Err(WitnessStateError::Io(
                io::Error::other(format!("recovery required: {reason}")),
            )),
        }
    }

    /// Re-arm after a host reboot (Owner decision A-5, plan WU-3).
    ///
    /// Only for a state that is otherwise `Ready` except that its recorded
    /// `boot_id` is not the current one (`NotReady(BootIdChanged)`): the state
    /// validated, there is no recovery marker, and it is not a legacy image.
    /// One atomic `commit_candidate` (CAS against the state just read) then
    /// - records the current `boot_id`, and
    /// - if a lease is `Active`, sets its deadline to *this boot's* monotonic
    ///   now plus the lease's own TTL.
    ///
    /// `current_term`, holder, lease identity, journal and generation
    /// watermarks are not touched. Because the re-arm happens after the last
    /// commit that could have renewed the lease, the new deadline is never
    /// earlier than the old one, so the Witness grants to another node no
    /// sooner than before (availability, never safety, is what it costs); the
    /// holder's own safe deadline is earlier than the original deadline.
    ///
    /// This cannot detect a state file that was restored from an older copy
    /// (Owner decision A-11: out of scope for v1.0).
    pub fn rearm_after_reboot(&self) -> Result<RearmOutcome, WitnessStateError> {
        let recovery = self.load();
        if recovery.readiness != WitnessReadiness::NotReady(WitnessNotReadyReason::BootIdChanged) {
            return Err(WitnessStateError::Invariant(
                "re-arm requires a consistent state whose boot_id changed",
            ));
        }
        let (Some(state), Some(expected_old)) = (recovery.state, recovery.expected_old) else {
            return Err(WitnessStateError::Invariant("re-arm found no state image"));
        };
        let current_boot = self.boot_id_provider.current_boot_id()?;
        let mut candidate = state.clone();
        candidate.boot_id = current_boot;
        let lease_was_active = match candidate.lease_state {
            LeaseState::Active => {
                let ttl = candidate.lease_ttl_ms.filter(|ttl| ttl.0 > 0).ok_or(
                    WitnessStateError::Invariant("active lease has no TTL to re-arm with"),
                )?;
                let now = self.clock.now_ms()?;
                candidate.lease_deadline_monotonic_ms = Some(
                    now.checked_add(ttl.0)
                        .ok_or(WitnessStateError::Invariant("re-armed deadline overflows"))?,
                );
                true
            }
            LeaseState::None => false,
            LeaseState::Unknown => {
                return Err(WitnessStateError::Invariant(
                    "an unknown lease state is never re-armed automatically",
                ));
            }
        };
        self.commit_candidate(&candidate, &expected_old)?;
        Ok(RearmOutcome { lease_was_active })
    }
}

/// What a successful [`WitnessStateStore::rearm_after_reboot`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RearmOutcome {
    /// An `Active` lease existed and its deadline was re-based.
    pub lease_was_active: bool,
}

fn serialize_state(state: &WitnessPersistentState) -> Result<String, WitnessStateError> {
    toml::to_string(state).map_err(|error| WitnessStateError::Parse(error.to_string()))
}

/// The v2 parse. A newtype forwards to its inner type, so the strictness
/// comes from `WitnessPersistentState` itself (OD-J32-4).
#[derive(Deserialize)]
struct StrictState(WitnessPersistentState);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyState {
    cluster_id: ClusterId,
    current_term: Term,
    active_lease_id: Option<LeaseId>,
    holder_node_id: Option<NodeId>,
    lease_ttl_ms: Option<DurationMs>,
    lease_deadline_monotonic_ms: Option<u64>,
    lease_state: LeaseState,
    boot_id: BootId,
}

impl LegacyState {
    fn migrate(self) -> WitnessPersistentState {
        WitnessPersistentState {
            state_format_version: 2,
            cluster_id: self.cluster_id,
            current_term: self.current_term,
            active_lease_id: self.active_lease_id,
            holder_node_id: self.holder_node_id,
            lease_ttl_ms: self.lease_ttl_ms,
            lease_deadline_monotonic_ms: self.lease_deadline_monotonic_ms,
            lease_state: self.lease_state,
            boot_id: self.boot_id,
            journal: Vec::new(),
            generation_watermarks: BTreeMap::new(),
        }
    }
}

enum ReadStateError {
    Missing,
    Invalid(WitnessStateError),
}

fn read_state(
    path: &Path,
    cluster: &str,
) -> Result<(WitnessPersistentState, bool, ExpectedOldToken), ReadStateError> {
    let loaded =
        crate::recovery::read_snapshot_with_token(path, StoreKind::Witness, cluster, "witness")
            .map_err(|error| ReadStateError::Invalid(WitnessStateError::RecoveryRequired(error.0)))?
            .ok_or(ReadStateError::Missing)?;
    let content = String::from_utf8(loaded.parsed_state)
        .map_err(|error| ReadStateError::Invalid(WitnessStateError::Parse(error.to_string())))?;
    let value: toml::Value = toml::from_str(&content)
        .map_err(|error| ReadStateError::Invalid(WitnessStateError::Parse(error.to_string())))?;
    let has_version = value.get("state_format_version").is_some();
    let state = if has_version {
        toml::from_str::<StrictState>(&content)
            .map_err(|error| ReadStateError::Invalid(WitnessStateError::Parse(error.to_string())))?
            .0
    } else {
        toml::from_str::<LegacyState>(&content)
            .map_err(|error| ReadStateError::Invalid(WitnessStateError::Parse(error.to_string())))?
            .migrate()
    };
    state
        .validate_structure()
        .map_err(ReadStateError::Invalid)?;
    Ok((state, !has_version, loaded.expected_old))
}

fn reject_unsafe_final(path: &Path) -> Result<(), WitnessStateError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(WitnessStateError::Path("final state must not be a symlink"))
        }
        Ok(metadata) if !metadata.file_type().is_file() => Err(WitnessStateError::Path(
            "final state must be a regular file",
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(WitnessStateError::Io(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Clone)]
    struct FixedBootIdProvider(BootId);
    impl BootIdProvider for FixedBootIdProvider {
        fn current_boot_id(&self) -> Result<BootId, WitnessStateError> {
            Ok(self.0.clone())
        }
    }

    #[derive(Clone, Copy)]
    struct FixedClock(u64);
    impl MonotonicClock for FixedClock {
        fn now_ms(&self) -> Result<u64, WitnessStateError> {
            Ok(self.0)
        }
    }

    static MIGRATION_TEST_SERIAL: OnceLock<Mutex<()>> = OnceLock::new();

    fn migration_test_serial() -> &'static Mutex<()> {
        MIGRATION_TEST_SERIAL.get_or_init(|| Mutex::new(()))
    }

    fn install_migration_hook(path: &Path) -> (Arc<Barrier>, Arc<Barrier>) {
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let resolved = crate::recovery::resolve_store_path(path)
            .expect("migration path resolution")
            .canonical_io_path()
            .to_path_buf();
        *MIGRATION_TEST_HOOK
            .get_or_init(|| Mutex::new(None))
            .lock()
            .expect("migration hook") = Some(MigrationTestHook {
            path: resolved,
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        (entered, release)
    }

    fn clear_migration_hook() {
        *MIGRATION_TEST_HOOK
            .get_or_init(|| Mutex::new(None))
            .lock()
            .expect("migration hook") = None;
    }

    fn path(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("mikagami-witness-{name}-{suffix}"))
    }

    fn store(path: &Path, boot: &str) -> WitnessStateStore<FixedBootIdProvider, FixedClock> {
        store_for(path, "cluster", boot)
    }

    fn store_for(
        path: &Path,
        cluster: &str,
        boot: &str,
    ) -> WitnessStateStore<FixedBootIdProvider, FixedClock> {
        WitnessStateStore::with_providers(
            path,
            ClusterId::new(cluster),
            FixedBootIdProvider(BootId::new(boot)),
            FixedClock(123),
        )
    }

    fn active_state(boot: &str) -> WitnessPersistentState {
        WitnessPersistentState {
            state_format_version: 2,
            cluster_id: ClusterId::new("cluster"),
            current_term: Term(7),
            active_lease_id: Some(LeaseId::new("lease-1")),
            holder_node_id: Some(NodeId::new("node-a")),
            lease_ttl_ms: Some(DurationMs(10_000)),
            lease_deadline_monotonic_ms: Some(10_123),
            lease_state: LeaseState::Active,
            boot_id: BootId::new(boot),
            journal: Vec::new(),
            generation_watermarks: BTreeMap::new(),
        }
    }

    #[test]
    fn initialize_and_same_boot_load_are_ready() {
        let file = path("init");
        let store = store(&file, "boot-a");
        assert!(matches!(
            store.load().readiness,
            WitnessReadiness::NotReady(WitnessNotReadyReason::StateMissing)
        ));
        let initialized = store.initialize_new().unwrap();
        assert_eq!(initialized.current_term, Term(0));
        assert!(matches!(store.load().readiness, WitnessReadiness::Ready));
        assert!(matches!(
            store.initialize_new(),
            Err(WitnessStateError::AlreadyExists)
        ));
        let _ = fs::remove_file(&file);
    }

    #[test]
    fn same_boot_preserves_active_metadata_and_boot_change_is_fail_closed() {
        let file = path("boot");
        let first = store(&file, "boot-a");
        first.save(&active_state("boot-a")).unwrap();
        let loaded = store(&file, "boot-a").load();
        assert!(matches!(loaded.readiness, WitnessReadiness::Ready));
        assert_eq!(loaded.state, Some(active_state("boot-a")));
        let changed = store(&file, "boot-b").load();
        assert!(matches!(
            changed.readiness,
            WitnessReadiness::NotReady(WitnessNotReadyReason::BootIdChanged)
        ));
        assert_eq!(changed.state, Some(active_state("boot-a")));
        let _ = fs::remove_file(&file);
    }

    #[test]
    fn cluster_mismatch_preserves_state_and_file() {
        let file = path("cluster-mismatch");
        let persisted = WitnessPersistentState {
            cluster_id: ClusterId::new("cluster-a"),
            ..active_state("boot-a")
        };
        store_for(&file, "cluster-a", "boot-a")
            .save(&persisted)
            .unwrap();
        let before = fs::read(&file).unwrap();
        let recovery = store_for(&file, "cluster-b", "boot-a").load();
        assert!(matches!(
            recovery.readiness,
            WitnessReadiness::NotReady(WitnessNotReadyReason::ClusterMismatch)
        ));
        assert_eq!(recovery.state, Some(persisted));
        assert_eq!(fs::read(&file).unwrap(), before);
        let _ = fs::remove_file(file);
    }

    #[test]
    fn every_lease_state_is_not_ready_after_boot_change_without_mutation() {
        let states = [
            WitnessPersistentState::new(ClusterId::new("cluster"), BootId::new("boot-a")),
            active_state("boot-a"),
            WitnessPersistentState {
                lease_state: LeaseState::Unknown,
                ..WitnessPersistentState::new(ClusterId::new("cluster"), BootId::new("boot-a"))
            },
        ];
        for state in states {
            let file = path("boot-state");
            store(&file, "boot-a").save(&state).unwrap();
            let before = fs::read(&file).unwrap();
            let recovery = store(&file, "boot-b").load();
            assert!(matches!(
                recovery.readiness,
                WitnessReadiness::NotReady(WitnessNotReadyReason::BootIdChanged)
            ));
            assert_eq!(recovery.state, Some(state));
            assert_eq!(fs::read(&file).unwrap(), before);
            let _ = fs::remove_file(file);
        }
    }

    #[test]
    fn missing_corrupt_unknown_and_inconsistent_state_fail_closed() {
        for content in [
            "not = [valid",
            "cluster_id = 'cluster'",
            "cluster_id = 'cluster'\ncurrent_term = 1\nactive_lease_id = 'x'\nholder_node_id = 'n'\nlease_ttl_ms = 1\nlease_deadline_monotonic_ms = 2\nlease_state = 'Future'\nboot_id = 'boot-a'",
        ] {
            let file = path("invalid");
            fs::write(&file, content).unwrap();
            let result = store(&file, "boot-a").load();
            assert!(matches!(result.readiness, WitnessReadiness::NotReady(_)));
            let _ = fs::remove_file(file);
        }
        let file = path("invariant");
        let mut state = active_state("boot-a");
        state.active_lease_id = None;
        store(&file, "boot-a").save(&state).unwrap_err();
        let _ = fs::remove_file(file);
    }

    #[test]
    fn legacy_state_requires_explicit_migration_and_preserves_bytes() {
        let file = path("legacy-migration");
        fs::write(
            &file,
            "cluster_id = 'cluster'\ncurrent_term = 7\nactive_lease_id = 'lease-1'\nholder_node_id = 'node-a'\nlease_ttl_ms = 10000\nlease_deadline_monotonic_ms = 10123\nlease_state = 'Active'\nboot_id = 'boot-a'\n",
        )
        .unwrap();
        let store = store(&file, "boot-a");
        let before = fs::read(&file).unwrap();
        let recovery = store.load();
        assert!(matches!(
            recovery.readiness,
            WitnessReadiness::NotReady(WitnessNotReadyReason::MigrationRequired)
        ));
        let state = recovery.state.unwrap();
        assert_eq!(state.state_format_version, 2);
        assert!(state.journal.is_empty());
        assert!(state.generation_watermarks.is_empty());
        assert_eq!(fs::read(&file).unwrap(), before);
        assert!(!crate::recovery::marker_path(&file).exists());

        let migrated = store.migrate_legacy_explicitly().unwrap();
        assert_eq!(migrated, state);
        assert!(
            fs::read_to_string(&file)
                .unwrap()
                .contains("state_format_version = 2")
        );
        assert!(matches!(store.load().readiness, WitnessReadiness::Ready));
        let current = fs::read(&file).unwrap();
        assert!(matches!(
            store.migrate_legacy_explicitly(),
            Err(WitnessStateError::AlreadyCurrent)
        ));
        assert_eq!(fs::read(&file).unwrap(), current);
        let _ = fs::remove_file(file);
    }

    #[test]
    fn explicit_legacy_migration_precommit_failures_clean_marker_and_keep_legacy() {
        for (name, fault) in [
            (
                "candidate-fsync",
                crate::recovery::FaultPoint::CandidateTempFsync,
            ),
            (
                "canonical-install",
                crate::recovery::FaultPoint::CanonicalInstallBeforeMutation,
            ),
        ] {
            let file = path(name);
            let legacy = "cluster_id = 'cluster'\ncurrent_term = 7\nactive_lease_id = 'lease-1'\nholder_node_id = 'node-a'\nlease_ttl_ms = 10000\nlease_deadline_monotonic_ms = 10123\nlease_state = 'Active'\nboot_id = 'boot-a'\n";
            fs::write(&file, legacy).unwrap();
            let before = fs::read(&file).unwrap();
            crate::recovery::inject_fault_once(fault);
            assert!(matches!(
                store(&file, "boot-a").migrate_legacy_explicitly(),
                Err(WitnessStateError::Io(_))
            ));
            assert_eq!(fs::read(&file).unwrap(), before);
            assert!(!crate::recovery::marker_path(&file).exists());
            assert!(matches!(
                store(&file, "boot-a").load().readiness,
                WitnessReadiness::NotReady(WitnessNotReadyReason::MigrationRequired)
            ));
            let _ = fs::remove_file(file);
        }
    }

    #[test]
    fn explicit_legacy_migration_rejects_state_changed_after_snapshot() {
        let _serial = migration_test_serial().lock().expect("migration serial");
        let file = path("migration-stale-candidate");
        fs::write(
            &file,
            "cluster_id = 'cluster'\ncurrent_term = 7\nactive_lease_id = 'lease-1'\nholder_node_id = 'node-a'\nlease_ttl_ms = 10000\nlease_deadline_monotonic_ms = 10123\nlease_state = 'Active'\nboot_id = 'boot-a'\n",
        )
        .unwrap();
        let migration_store = store(&file, "boot-a");
        let (entered, release) = install_migration_hook(&file);
        let migration = std::thread::spawn(move || migration_store.migrate_legacy_explicitly());
        entered.wait();

        let concurrent_store = store(&file, "boot-a");
        let loaded = concurrent_store.load();
        let mut newer = loaded.state.clone().unwrap();
        newer.current_term = Term(8);
        concurrent_store
            .commit_candidate(&newer, &loaded.expected_old.clone().unwrap())
            .unwrap();

        release.wait();
        assert!(matches!(
            migration.join().unwrap(),
            Err(WitnessStateError::Io(_))
        ));
        assert!(!crate::recovery::marker_path(&file).exists());
        assert_eq!(store(&file, "boot-a").load().state, Some(newer));
        clear_migration_hook();
        let _ = fs::remove_file(file);
    }

    #[test]
    fn explicit_migration_cleanup_failure_requires_recovery() {
        let file = path("migration-cleanup-failure");
        fs::write(
            &file,
            "cluster_id = 'cluster'\ncurrent_term = 7\nactive_lease_id = 'lease-1'\nholder_node_id = 'node-a'\nlease_ttl_ms = 10000\nlease_deadline_monotonic_ms = 10123\nlease_state = 'Active'\nboot_id = 'boot-a'\n",
        )
        .unwrap();
        crate::recovery::inject_fault_sequence_once(&[
            crate::recovery::FaultPoint::CandidateTempFsync,
            crate::recovery::FaultPoint::RecoveryUnlink,
        ]);
        assert!(matches!(
            store(&file, "boot-a").migrate_legacy_explicitly(),
            Err(WitnessStateError::Io(_))
        ));
        assert!(crate::recovery::marker_path(&file).exists());
        assert!(matches!(
            store(&file, "boot-a").load().readiness,
            WitnessReadiness::NotReady(WitnessNotReadyReason::RecoveryRequired)
        ));
        assert!(matches!(
            store(&file, "boot-a").migrate_legacy_explicitly(),
            Err(WitnessStateError::RecoveryRequired(_))
        ));
        let _ = fs::remove_file(&file);
        let _ = fs::remove_file(crate::recovery::marker_path(&file));
    }

    #[test]
    fn explicit_migration_distinguishes_missing_corrupt_and_recovery_marker() {
        let missing = path("migration-missing");
        assert!(matches!(
            store(&missing, "boot-a").migrate_legacy_explicitly(),
            Err(WitnessStateError::StateMissing)
        ));

        let corrupt = path("migration-corrupt");
        fs::write(&corrupt, "not = [valid").unwrap();
        assert!(matches!(
            store(&corrupt, "boot-a").load().readiness,
            WitnessReadiness::NotReady(WitnessNotReadyReason::StateCorrupt)
        ));
        assert!(matches!(
            store(&corrupt, "boot-a").migrate_legacy_explicitly(),
            Err(WitnessStateError::Parse(_))
        ));

        let legacy = path("migration-marker");
        fs::write(
            &legacy,
            "cluster_id = 'cluster'\ncurrent_term = 7\nactive_lease_id = 'lease-1'\nholder_node_id = 'node-a'\nlease_ttl_ms = 10000\nlease_deadline_monotonic_ms = 10123\nlease_state = 'Active'\nboot_id = 'boot-a'\n",
        )
        .unwrap();
        fs::write(crate::recovery::marker_path(&legacy), "invalid").unwrap();
        assert!(matches!(
            store(&legacy, "boot-a").load().readiness,
            WitnessReadiness::NotReady(WitnessNotReadyReason::RecoveryRequired)
        ));
        assert!(matches!(
            store(&legacy, "boot-a").migrate_legacy_explicitly(),
            Err(WitnessStateError::RecoveryRequired(_))
        ));
        let _ = fs::remove_file(missing);
        let _ = fs::remove_file(corrupt);
        let _ = fs::remove_file(&legacy);
        let _ = fs::remove_file(crate::recovery::marker_path(&legacy));
    }

    #[test]
    fn v2_missing_required_metadata_and_unknown_version_fail_closed() {
        let missing = path("v2-missing");
        fs::write(
            &missing,
            "state_format_version = 2\ncluster_id = 'cluster'\n",
        )
        .unwrap();
        assert!(matches!(
            store(&missing, "boot-a").load().readiness,
            WitnessReadiness::NotReady(_)
        ));

        let future = path("future-version");
        let mut state =
            WitnessPersistentState::new(ClusterId::new("cluster"), BootId::new("boot-a"));
        state.state_format_version = 99;
        fs::write(&future, serialize_state(&state).unwrap()).unwrap();
        assert!(matches!(
            store(&future, "boot-a").load().readiness,
            WitnessReadiness::NotReady(_)
        ));
        let _ = fs::remove_file(missing);
        let _ = fs::remove_file(future);
    }

    #[test]
    fn v2_round_trip_preserves_journal_watermark_and_result() {
        let file = path("journal-round-trip");
        let mut state =
            WitnessPersistentState::new(ClusterId::new("cluster"), BootId::new("boot-a"));
        state.generation_watermarks.insert("node-a".to_string(), 1);
        state.journal.push(JournalRecord {
            request_id: crate::protocol::RequestId::new("00000000-0000-4000-8000-000000000001"),
            requester_node_id: "node-a".to_string(),
            request_kind: crate::protocol::MessageType::LeaseRequest,
            mutation_generation: 1,
            semantic_fingerprint: [7; 32],
            result: crate::witness_journal::CommittedSemanticResult::LeaseReject(
                crate::protocol::LeaseRejectPayload {
                    code: crate::protocol::WitnessMutationOutcomeCode::PolicyReject,
                    reason: "not ready".to_string(),
                },
            ),
        });
        let store = store(&file, "boot-a");
        store
            .commit_candidate(&state, &ExpectedOldToken::Absent)
            .unwrap();
        assert_eq!(store.load().state, Some(state));
        let _ = fs::remove_file(file);
    }

    #[test]
    fn stale_witness_candidate_is_rejected_without_marker_or_state_rollback() {
        let file = path("stale-candidate");
        let first = store(&file, "boot-a");
        first.initialize_new().unwrap();
        let loaded_first = first.load();
        let state_zero = loaded_first.state.clone().unwrap();
        let token_zero = loaded_first.expected_old.clone().unwrap();

        let second = store(&file, "boot-a");
        let loaded_second = second.load();
        let mut state_one = loaded_second.state.clone().unwrap();
        state_one.current_term = Term(8);
        state_one.active_lease_id = Some(LeaseId::new("lease-1"));
        state_one.holder_node_id = Some(NodeId::new("node-a"));
        state_one.lease_ttl_ms = Some(DurationMs(10_000));
        state_one.lease_deadline_monotonic_ms = Some(10_123);
        state_one.lease_state = LeaseState::Active;
        state_one.journal.push(JournalRecord {
            request_id: crate::protocol::RequestId::new("00000000-0000-4000-8000-000000000001"),
            requester_node_id: "node-a".to_string(),
            request_kind: crate::protocol::MessageType::LeaseRequest,
            mutation_generation: 1,
            semantic_fingerprint: [9; 32],
            result: crate::witness_journal::CommittedSemanticResult::LeaseReject(
                crate::protocol::LeaseRejectPayload {
                    code: crate::protocol::WitnessMutationOutcomeCode::PolicyReject,
                    reason: "test result".to_string(),
                },
            ),
        });
        state_one.generation_watermarks.insert("node-a".into(), 1);
        second
            .commit_candidate(&state_one, &loaded_second.expected_old.clone().unwrap())
            .unwrap();

        let mut stale_candidate = state_zero;
        stale_candidate.current_term = Term(99);
        let error = first
            .commit_candidate(&stale_candidate, &token_zero)
            .unwrap_err();
        assert!(matches!(error, WitnessStateError::Io(_)));
        assert!(!crate::recovery::marker_path(&file).exists());

        assert_eq!(first.load().state, Some(state_one.clone()));
        assert_eq!(second.load().state, Some(state_one));
        let _ = fs::remove_file(file);
    }

    #[test]
    fn unknown_lease_rejects_partial_metadata() {
        let mut state = active_state("boot-a");
        state.lease_state = LeaseState::Unknown;
        state.holder_node_id = None;
        let file = path("unknown-partial");
        fs::write(&file, serialize_state(&state).unwrap()).unwrap();
        assert!(matches!(
            store(&file, "boot-a").load().readiness,
            WitnessReadiness::NotReady(WitnessNotReadyReason::StateInvariantViolation)
        ));
        let _ = fs::remove_file(file);
    }

    #[test]
    fn atomic_save_is_reloadable_and_rejects_symlink() {
        let file = path("atomic");
        let store = store(&file, "boot-a");
        store.save(&active_state("boot-a")).unwrap();
        assert_eq!(store.load().state, Some(active_state("boot-a")));
        let link = path("link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&file, &link).unwrap();
        #[cfg(unix)]
        assert!(matches!(
            store_with_path(&link).save(&active_state("boot-a")),
            Err(WitnessStateError::Path(_))
        ));
        #[cfg(unix)]
        {
            let directory = path("directory");
            fs::create_dir(&directory).unwrap();
            assert!(matches!(
                store_with_path(&directory).save(&active_state("boot-a")),
                Err(WitnessStateError::Path(_))
            ));
            let _ = fs::remove_dir(directory);
        }
        let _ = fs::remove_file(file);
        let _ = fs::remove_file(link);
    }

    #[test]
    fn ambiguous_witness_commit_poisoning_blocks_second_handle() {
        let file = path("ambiguous-commit");
        let initialized_store = store(&file, "boot-a");
        initialized_store.initialize_new().unwrap();
        let state = initialized_store.load().state.unwrap();
        crate::recovery::inject_fault_once(crate::recovery::FaultPoint::CanonicalParentFsync);
        assert!(matches!(
            initialized_store.save(&state),
            Err(WitnessStateError::Io(_))
        ));
        assert!(matches!(
            initialized_store.load().readiness,
            WitnessReadiness::NotReady(WitnessNotReadyReason::RecoveryRequired)
        ));
        assert!(matches!(
            store(&file, "boot-a").load().readiness,
            WitnessReadiness::NotReady(WitnessNotReadyReason::RecoveryRequired)
        ));
        let _ = fs::remove_file(&file);
        let _ = fs::remove_file(crate::recovery::marker_path(&file));
    }

    #[test]
    fn precanonical_witness_failure_keeps_second_handle_retryable() {
        let file = path("precanonical-second-handle");
        let first = store(&file, "boot-a");
        first.initialize_new().unwrap();
        let state = first.load().state.unwrap();
        crate::recovery::inject_fault_once(crate::recovery::FaultPoint::CandidateTempFsync);
        assert!(matches!(first.save(&state), Err(WitnessStateError::Io(_))));
        assert!(!crate::recovery::marker_path(&file).exists());
        assert!(matches!(
            store(&file, "boot-a").load().readiness,
            WitnessReadiness::Ready
        ));
        store(&file, "boot-a").save(&state).unwrap();
        let _ = fs::remove_file(file);
    }

    #[cfg(unix)]
    #[test]
    fn state_files_use_private_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let file = path("permissions");
        let store = store(&file, "boot-a");
        store.initialize_new().unwrap();
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        store.save(&active_state("boot-a")).unwrap();
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = fs::remove_file(file);
    }

    #[cfg(unix)]
    fn store_with_path(path: &Path) -> WitnessStateStore<FixedBootIdProvider, FixedClock> {
        store(path, "boot-a")
    }

    // ---- J35 (cf30, OD-J32-4 scope (ii)): StrictState ----

    fn j35_state_with_journal() -> WitnessPersistentState {
        use crate::protocol::{
            LeaseGrantPayload, LeaseRejectPayload, MessageType, RequestId,
            WitnessMutationOutcomeCode,
        };
        use crate::witness_journal::CommittedSemanticResult;
        let mut state = active_state("boot-a");
        state.journal.push(JournalRecord {
            request_id: RequestId::new("00000000-0000-4000-8000-000000000001"),
            requester_node_id: "node-a".to_string(),
            request_kind: MessageType::LeaseRequest,
            mutation_generation: 1,
            semantic_fingerprint: [0u8; 32],
            result: CommittedSemanticResult::LeaseGrant(LeaseGrantPayload {
                term: Term(7),
                lease_id: LeaseId::new("lease-1"),
                holder_node_id: NodeId::new("node-a"),
                lease_ttl_ms: DurationMs(10_000),
                renew_after_ms: DurationMs(3_000),
                lease_remaining_ms: DurationMs(10_000),
            }),
        });
        state.journal.push(JournalRecord {
            request_id: RequestId::new("00000000-0000-4000-8000-000000000002"),
            requester_node_id: "node-b".to_string(),
            request_kind: MessageType::LeaseRequest,
            mutation_generation: 1,
            semantic_fingerprint: [1u8; 32],
            result: CommittedSemanticResult::LeaseReject(LeaseRejectPayload {
                code: WitnessMutationOutcomeCode::PolicyReject,
                reason: "policy".to_string(),
            }),
        });
        state
    }

    fn j35_inject(content: &str, edit: impl Fn(&mut toml::Value)) -> String {
        let mut value: toml::Value = toml::from_str(content).unwrap();
        edit(&mut value);
        toml::to_string(&value).unwrap()
    }

    /// OD-J32-4 (ii): an unknown top-level field or an unknown field of a
    /// persisted reject fails the v2 parse; the state this code writes still
    /// round-trips. Unknown fields inside a protocol payload of a journal
    /// record are still accepted: that is the recorded residual RR-OR3-1.
    #[test]
    fn j35_strict_state_rejects_unknown_fields_in_scope_ii() {
        let base = serialize_state(&j35_state_with_journal()).unwrap();
        assert!(toml::from_str::<StrictState>(&base).is_ok());
        let top = j35_inject(&base, |value| {
            value
                .as_table_mut()
                .unwrap()
                .insert("j35_unknown".into(), toml::Value::Integer(1));
        });
        assert!(toml::from_str::<StrictState>(&top).is_err());
        let reject = j35_inject(&base, |value| {
            let result = value["journal"].as_array_mut().unwrap()[1]["result"]
                .as_table_mut()
                .unwrap();
            let (_, inner) = result.iter_mut().next().unwrap();
            inner
                .as_table_mut()
                .unwrap()
                .insert("j35_unknown".into(), toml::Value::Integer(1));
        });
        assert!(toml::from_str::<StrictState>(&reject).is_err());
        let record = j35_inject(&base, |value| {
            value["journal"].as_array_mut().unwrap()[0]
                .as_table_mut()
                .unwrap()
                .insert("j35_unknown".into(), toml::Value::Integer(1));
        });
        assert!(toml::from_str::<StrictState>(&record).is_err());
        // RR-OR3-1 (accepted residual, protocol wire types unchanged).
        let payload = j35_inject(&base, |value| {
            let result = value["journal"].as_array_mut().unwrap()[0]["result"]
                .as_table_mut()
                .unwrap();
            let (_, inner) = result.iter_mut().next().unwrap();
            inner
                .as_table_mut()
                .unwrap()
                .insert("j35_unknown".into(), toml::Value::Integer(1));
        });
        assert!(toml::from_str::<StrictState>(&payload).is_ok());
    }

    /// OD-J32-4 through the store: a saved v2 state with an unknown
    /// top-level field is not Ready; the unchanged state is.
    #[test]
    fn j35_store_load_refuses_an_unknown_top_level_field() {
        let file = path("j35-strict");
        store(&file, "boot-a")
            .save(&active_state("boot-a"))
            .unwrap();
        assert!(matches!(
            store(&file, "boot-a").load().readiness,
            WitnessReadiness::Ready
        ));
        let content = fs::read_to_string(&file).unwrap();
        fs::write(&file, format!("j35_unknown = 1\n{content}")).unwrap();
        assert!(!matches!(
            store(&file, "boot-a").load().readiness,
            WitnessReadiness::Ready
        ));
        let _ = fs::remove_file(file);
    }
}
