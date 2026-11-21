//! Phase 1-J25 candidate: the GCE fencing backend of the Stage 14 command backend.
//!
//! The Stage 14 command backend (`fencing_backend`) runs one fence action process and then verify
//! poll processes, and only a verify poll that prints exactly `isolated` lets the Node store write
//! `CONFIRMED(backend k)` (`fencing::FencingIncident::confirm_by_verification`). This module is the
//! decision core of a helper that plays both roles for a GCE target (`src/bin/mikagami-gce-fence.rs`):
//!
//! - F-2 (external fencing): `instances.stop` of the identified target. Proof is the recorded stop
//!   operation of **this attempt** observed `DONE` without error for the target's numeric id, and a
//!   fresh describe of the same numeric id reading `TERMINATED`.
//! - F-4 (resource-level fencing): removal of the protected alias IP ranges from the target's NIC.
//!   Proof is a fresh describe of the same numeric id whose NIC no longer carries any protected
//!   range, for at least the propagation hold, and (when configured) a data-plane probe that finds
//!   no host answering on the protected path. It proves the revocation of those ranges only.
//! - F-5 (combination): `combine` decides from the per-method verdicts which ones are sufficient.
//!
//! Safety rules (J25 I-1..I-10, `FENCING_STATE_MACHINE.md`):
//!
//! 1. A sent, accepted or timed-out request is never proof (I-2). Only a fresh observation of the
//!    identified target after this attempt's action can be.
//! 2. Every record is bound to the attempt (`AttemptBinding`: cluster, target node, incident id,
//!    attempt token) and to the target's numeric instance id (I-3). The Node store binds the incident
//!    id to the observer session, the loss episode and the anchor term, so a record of another
//!    incident or token is never read as evidence of this one (I-4).
//! 3. `Unknown` never isolates (I-5). The verify process exits non-zero for it, which the command
//!    backend classifies as an inconclusive poll.
//! 4. A mutating request is sent at most once per attempt and method (I-6). A retry needs a new
//!    attempt token (a new operator action, Stage 14 T3) and therefore a new request id.
//! 5. The intent record is durable before a request is sent, and the evidence is durable before
//!    `isolated` is reported (I-9).
//! 6. The core performs no I/O itself: the transport, the record store, the probe, the fault hooks
//!    and the clock are supplied by the caller, so every branch is deterministic in tests.
//!
//! The module is self-contained (std, serde, serde_json, sha2) so the helper binary includes it with
//! `#[path]`; the `mikagami` daemon compiles it only in test builds and does not call it.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fmt;

/// The record format version. A record of any other version is not evidence.
pub const RECORD_VERSION: u32 = 1;

// ---------------------------------------------------------------------------------------------
// Identity and binding
// ---------------------------------------------------------------------------------------------

/// The configured target. `instance_id` is the numeric GCE id recorded when the cluster was set
/// up; a VM recreated under the same name has another id and is never the target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceIdentity {
    pub project: String,
    pub zone: String,
    pub name: String,
    pub instance_id: String,
}

/// A name that goes into a URL path or query (J25 SA-2): only the characters GCE allows in
/// resource names, so no value can add a path segment or a query parameter.
pub fn check_name(value: &str, name: &str) -> Result<(), String> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Err(format!("{name} must be a non-empty name of [A-Za-z0-9._-]"))
    } else {
        Ok(())
    }
}

impl InstanceIdentity {
    /// Every part of the identity, including the numeric id (J25 audit N-3: `assign` uses it too).
    pub fn validate(&self) -> Result<(), String> {
        check_name(&self.project, "project")?;
        check_name(&self.zone, "zone")?;
        check_name(&self.name, "instance")?;
        if self.instance_id.is_empty()
            || !self.instance_id.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err("instance_id must be the numeric GCE id".to_string());
        }
        Ok(())
    }

    fn path(&self) -> String {
        format!(
            "projects/{}/zones/{}/instances/{}",
            self.project, self.zone, self.name
        )
    }
}

/// The Stage 14 attempt a record belongs to, from the four `MIKAGAMI_*` values the command backend
/// passes to every step (`fencing_backend::SpawnPlan`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptBinding {
    pub cluster: String,
    pub target_node: String,
    pub incident_id: String,
    pub attempt_token: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingError {
    Missing(&'static str),
    ClusterMismatch,
    TargetMismatch,
    MalformedIncident,
    MalformedAttempt,
}

impl fmt::Display for BindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(name) => write!(formatter, "{name} is not set"),
            Self::ClusterMismatch => write!(formatter, "the cluster is not the configured one"),
            Self::TargetMismatch => write!(formatter, "the target node is not the configured one"),
            Self::MalformedIncident => {
                write!(formatter, "the incident id is not a canonical UUIDv4")
            }
            Self::MalformedAttempt => {
                write!(formatter, "the attempt token is not a positive integer")
            }
        }
    }
}

impl AttemptBinding {
    /// Validates the step identity against the plan before anything is read or sent.
    pub fn from_step(
        plan: &FencePlan,
        cluster: Option<&str>,
        target_node: Option<&str>,
        incident_id: Option<&str>,
        attempt_token: Option<&str>,
    ) -> Result<Self, BindingError> {
        let cluster = cluster.ok_or(BindingError::Missing("MIKAGAMI_CLUSTER"))?;
        let target_node = target_node.ok_or(BindingError::Missing("MIKAGAMI_FENCE_TARGET"))?;
        let incident_id = incident_id.ok_or(BindingError::Missing("MIKAGAMI_FENCE_INCIDENT"))?;
        let attempt_token = attempt_token.ok_or(BindingError::Missing("MIKAGAMI_FENCE_ATTEMPT"))?;
        if cluster != plan.cluster {
            return Err(BindingError::ClusterMismatch);
        }
        if target_node != plan.target_node {
            return Err(BindingError::TargetMismatch);
        }
        if !is_canonical_uuid_v4(incident_id) {
            return Err(BindingError::MalformedIncident);
        }
        let attempt_token = parse_positive(attempt_token).ok_or(BindingError::MalformedAttempt)?;
        Ok(Self {
            cluster: cluster.to_string(),
            target_node: target_node.to_string(),
            incident_id: incident_id.to_string(),
            attempt_token,
        })
    }
}

fn parse_positive(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) || text.starts_with('0') {
        return None;
    }
    text.parse::<u64>().ok().filter(|value| *value > 0)
}

pub fn is_canonical_uuid_v4(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (index, byte) in bytes.iter().enumerate() {
        let ok = match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            14 => *byte == b'4',
            19 => matches!(byte, b'8' | b'9' | b'a' | b'b'),
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(byte),
        };
        if !ok {
            return false;
        }
    }
    true
}

/// The request id of one attempt's mutation of one method: a UUID derived from the binding, so the
/// same attempt can only ever name one request (GCE de-duplicates a repeated `requestId`; whether a
/// resend returns the original operation is a G25-1 check, so this module never resends).
pub fn request_id(binding: &AttemptBinding, method: FenceMethod) -> String {
    let mut hash = Sha256::new();
    hash.update(b"mikagami-j25-gce-fence-request-id\0");
    for part in [
        binding.cluster.as_str(),
        binding.target_node.as_str(),
        binding.incident_id.as_str(),
        &binding.attempt_token.to_string(),
        method.as_str(),
    ] {
        hash.update(part.as_bytes());
        hash.update(b"\0");
    }
    let digest = hash.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

// ---------------------------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FenceMethod {
    Stop,
    AliasIp,
}

impl FenceMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::AliasIp => "alias-ip",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Combine {
    /// Isolated when one sufficient method is isolated (F-2 always; F-4 only with a complete
    /// alias-only inventory).
    AnySufficient,
    /// Isolated only when every configured method is isolated.
    All,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasPolicy {
    pub nic: String,
    pub ranges: Vec<String>,
    /// The operator's declaration that the protected ranges are the only way the old node can
    /// affect clients. Without it F-4 alone never isolates the node (J25 §7).
    pub inventory_complete: bool,
    /// How long the removal must be observed before it is relied on ("it might take up to a minute
    /// for the transfer to complete", GCE alias IP documentation). Measured on the caller's clock,
    /// which is `CLOCK_BOOTTIME` in the helper.
    pub propagation_hold_ms: u64,
    /// J26 audit N-1: the longest interval between two absent observations that still counts as
    /// one continuous absence. A longer gap (a range could have come back unseen) restarts the hold.
    pub max_observation_gap_ms: u64,
    pub probe_required: bool,
    /// J26 audit N-2: a hold below `MIN_PROPAGATION_HOLD_MS` is accepted only for a test build.
    pub short_hold_for_test: bool,
}

/// J26 audit N-2: the shortest production propagation hold. GCE documents that an alias transfer
/// "might take up to a minute"; the value actually needed is a G25-2 measurement (OD-J26-3).
pub const MIN_PROPAGATION_HOLD_MS: u64 = 30_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FencePlan {
    pub cluster: String,
    pub target_node: String,
    pub target: InstanceIdentity,
    pub methods: Vec<FenceMethod>,
    pub combine: Combine,
    pub alias: Option<AliasPolicy>,
}

impl FencePlan {
    pub fn validate(&self) -> Result<(), String> {
        let nonempty = check_name;
        nonempty(&self.cluster, "cluster")?;
        nonempty(&self.target_node, "target_node")?;
        self.target.validate()?;
        if self.methods.is_empty() {
            return Err("at least one method is required".to_string());
        }
        for (index, method) in self.methods.iter().enumerate() {
            if self.methods[..index].contains(method) {
                return Err(format!("method {} is listed twice", method.as_str()));
            }
        }
        let wants_alias = self.methods.contains(&FenceMethod::AliasIp);
        match (&self.alias, wants_alias) {
            (None, true) => return Err("the alias-ip method needs [alias]".to_string()),
            (Some(_), false) => {
                return Err("[alias] is set but alias-ip is not a method".to_string());
            }
            (Some(alias), true) => {
                nonempty(&alias.nic, "alias.nic")?;
                if alias.ranges.is_empty() {
                    return Err("alias.ranges must not be empty".to_string());
                }
                for range in &alias.ranges {
                    // J25 audit B-1c: canonical (no host bits), so containment can be compared.
                    if parse_cidr(range).is_none_or(|cidr| cidr.to_string() != *range) {
                        return Err(format!("alias range {range} is not a canonical IPv4 CIDR"));
                    }
                }
                // J25 audit B-1/N-6: the control plane alone never proves the data path, so every
                // alias plan needs the data-plane probe.
                if !alias.probe_required {
                    return Err("the alias-ip method needs alias.probe".to_string());
                }
                if alias.propagation_hold_ms < MIN_PROPAGATION_HOLD_MS && !alias.short_hold_for_test
                {
                    return Err(format!(
                        "alias.propagation_hold_sec must be at least {}",
                        MIN_PROPAGATION_HOLD_MS / 1_000
                    ));
                }
                if alias.max_observation_gap_ms == 0
                    || alias.max_observation_gap_ms > alias.propagation_hold_ms.max(1)
                {
                    return Err(
                        "alias.max_observation_gap_sec must be positive and at most the hold"
                            .to_string(),
                    );
                }
            }
            (None, false) => {}
        }
        // F-4 alone isolates only a complete alias-only inventory; a plan that can never isolate is
        // a configuration error, not a run-time UNKNOWN.
        if self.methods == [FenceMethod::AliasIp]
            && !self
                .alias
                .as_ref()
                .is_some_and(|alias| alias.inventory_complete)
        {
            return Err("alias-ip alone needs alias.inventory_complete = true".to_string());
        }
        Ok(())
    }

    fn alias(&self) -> Option<&AliasPolicy> {
        self.alias.as_ref()
    }
}

/// An IPv4 CIDR as (network, prefix), with the host bits cleared. A bare address is a /32.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    network: u32,
    prefix: u8,
}

impl Cidr {
    fn mask(prefix: u8) -> u32 {
        if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(prefix))
        }
    }

    /// Whether the two ranges share at least one address (one contains the other).
    pub fn overlaps(&self, other: &Cidr) -> bool {
        let mask = Self::mask(self.prefix.min(other.prefix));
        self.network & mask == other.network & mask
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d] = self.network.to_be_bytes();
        write!(formatter, "{a}.{b}.{c}.{d}/{}", self.prefix)
    }
}

pub fn parse_cidr(text: &str) -> Option<Cidr> {
    let (address, prefix) = match text.split_once('/') {
        Some((address, prefix)) => (address, prefix),
        None => (text, "32"),
    };
    if prefix.is_empty() || (prefix.len() > 1 && prefix.starts_with('0')) {
        return None;
    }
    let prefix = prefix.parse::<u8>().ok().filter(|bits| *bits <= 32)?;
    let address = u32::from(address.parse::<std::net::Ipv4Addr>().ok()?);
    Some(Cidr {
        network: address & Cidr::mask(prefix),
        prefix,
    })
}

/// Whether a range observed on a NIC may share an address with a protected range. An observed
/// range that cannot be parsed is treated as overlapping (fail-closed).
fn may_overlap(observed: &str, protected: &[Cidr]) -> bool {
    match parse_cidr(observed) {
        Some(cidr) => protected.iter().any(|range| range.overlaps(&cidr)),
        None => true,
    }
}

fn protected_cidrs(alias: &AliasPolicy) -> Vec<Cidr> {
    alias
        .ranges
        .iter()
        .filter_map(|range| parse_cidr(range))
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Transport and result classification
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Patch,
}

impl HttpMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Patch => "PATCH",
        }
    }

    fn mutates(self) -> bool {
        !matches!(self, Self::Get)
    }
}

/// What one HTTP exchange gave. `NotSent` is only for failures that prove the request never left
/// (name resolution, connection refused); every other transport failure may have reached GCE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpOutcome {
    Response { status: u16, body: String },
    NotSent(String),
    Timeout,
    Transport(String),
}

/// The Compute API transport. `path` is relative to the API base (`projects/...`), with the query.
pub trait ComputeTransport {
    fn call(&mut self, method: HttpMethod, path: &str, body: Option<&str>) -> HttpOutcome;
}

/// A classified API failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "detail", rename_all = "kebab-case")]
pub enum ApiFailure {
    Unauthenticated,
    PermissionDenied,
    NotFound,
    Conflict,
    PreconditionFailed,
    RateLimited,
    ServerError(u16),
    OtherStatus(u16),
    Timeout,
    Transport(String),
    NotSent(String),
    Malformed(String),
}

impl ApiFailure {
    /// Whether a mutating request with this result may have been applied. Only the listed 4xx
    /// refusals (GCE validates and authorizes before it creates an operation: 400, 401, 403, 404,
    /// 409, 412, 429) and a connection that never opened count as "not applied"; every other
    /// answer, including any other status (J25 audit N-4), may have been applied.
    pub fn may_have_been_applied(&self) -> bool {
        !matches!(
            self,
            Self::Unauthenticated
                | Self::PermissionDenied
                | Self::NotFound
                | Self::Conflict
                | Self::PreconditionFailed
                | Self::RateLimited
                | Self::NotSent(_)
                | Self::OtherStatus(400)
        )
    }
}

impl fmt::Display for ApiFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthenticated => write!(formatter, "HTTP 401 (authentication failed)"),
            Self::PermissionDenied => write!(formatter, "HTTP 403 (permission denied)"),
            Self::NotFound => write!(formatter, "HTTP 404 (not found)"),
            Self::Conflict => write!(formatter, "HTTP 409 (conflict)"),
            Self::PreconditionFailed => write!(formatter, "HTTP 412 (fingerprint mismatch)"),
            Self::RateLimited => write!(formatter, "HTTP 429 (rate limited)"),
            Self::ServerError(status) => write!(formatter, "HTTP {status} (server error)"),
            Self::OtherStatus(status) => write!(formatter, "HTTP {status}"),
            Self::Timeout => write!(formatter, "timeout (outcome unknown)"),
            Self::Transport(detail) => write!(formatter, "transport failure: {detail}"),
            Self::NotSent(detail) => write!(formatter, "not sent: {detail}"),
            Self::Malformed(detail) => write!(formatter, "malformed answer: {detail}"),
        }
    }
}

pub fn classify(outcome: HttpOutcome) -> Result<Value, ApiFailure> {
    match outcome {
        HttpOutcome::Response { status: 200, body } => serde_json::from_str::<Value>(&body)
            .map_err(|error| ApiFailure::Malformed(format!("not JSON: {error}"))),
        HttpOutcome::Response { status, .. } => Err(match status {
            401 => ApiFailure::Unauthenticated,
            403 => ApiFailure::PermissionDenied,
            404 => ApiFailure::NotFound,
            409 => ApiFailure::Conflict,
            412 => ApiFailure::PreconditionFailed,
            429 => ApiFailure::RateLimited,
            500..=599 => ApiFailure::ServerError(status),
            _ => ApiFailure::OtherStatus(status),
        }),
        HttpOutcome::NotSent(detail) => Err(ApiFailure::NotSent(detail)),
        HttpOutcome::Timeout => Err(ApiFailure::Timeout),
        HttpOutcome::Transport(detail) => Err(ApiFailure::Transport(detail)),
    }
}

// ---------------------------------------------------------------------------------------------
// Resources
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationStatus {
    Pending,
    Running,
    Done,
}

/// The fields of a zone operation this module decides on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operation {
    pub name: String,
    pub operation_type: String,
    pub target_id: String,
    pub status: OperationStatus,
    /// `error.errors[].code`, joined; `Some` means the operation failed.
    pub error: Option<String>,
    pub http_error_status_code: Option<u64>,
}

impl Operation {
    pub fn parse(value: &Value) -> Result<Self, String> {
        let text = |key: &str| {
            value
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| format!("operation field {key} is missing"))
        };
        let status = match text("status")?.as_str() {
            "PENDING" => OperationStatus::Pending,
            "RUNNING" => OperationStatus::Running,
            "DONE" => OperationStatus::Done,
            other => return Err(format!("unknown operation status {other}")),
        };
        let error = match value.get("error") {
            None | Some(Value::Null) => None,
            Some(error) => {
                let codes: Vec<String> = error
                    .get("errors")
                    .and_then(Value::as_array)
                    .map(|errors| {
                        errors
                            .iter()
                            .map(|entry| {
                                entry
                                    .get("code")
                                    .and_then(Value::as_str)
                                    .unwrap_or("UNSPECIFIED")
                                    .to_string()
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                // An error object without readable codes is still an error.
                Some(if codes.is_empty() {
                    "UNSPECIFIED".to_string()
                } else {
                    codes.join(",")
                })
            }
        };
        let name = text("name")?;
        // J25 audit N-2: the name is used in a later URL; only operation-name characters.
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err("the operation name is not a resource name".to_string());
        }
        Ok(Self {
            name,
            operation_type: text("operationType")?,
            target_id: text("targetId")?,
            status,
            error,
            http_error_status_code: value.get("httpErrorStatusCode").and_then(Value::as_u64),
        })
    }

    /// Done and without any error indication.
    pub fn succeeded(&self) -> bool {
        self.status == OperationStatus::Done
            && self.error.is_none()
            && self
                .http_error_status_code
                .is_none_or(|status| (200..300).contains(&status))
    }

    pub fn failed(&self) -> bool {
        self.status == OperationStatus::Done && !self.succeeded()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInterface {
    pub name: String,
    pub fingerprint: String,
    pub alias_ranges: Vec<String>,
    /// The `aliasIpRanges` entries as GCE returned them (J25 audit N-5: an update keeps the other
    /// ranges' `subnetworkRangeName` and any other field unchanged).
    pub alias_entries: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    pub id: String,
    pub name: String,
    pub status: String,
    pub nics: Vec<NetworkInterface>,
}

impl Instance {
    pub fn parse(value: &Value) -> Result<Self, String> {
        let text = |key: &str| {
            value
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| format!("instance field {key} is missing"))
        };
        let mut nics = Vec::new();
        if let Some(list) = value.get("networkInterfaces") {
            let list = list
                .as_array()
                .ok_or("networkInterfaces is not a list".to_string())?;
            for nic in list {
                let name = nic
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or("a network interface has no name".to_string())?;
                let fingerprint = nic
                    .get("fingerprint")
                    .and_then(Value::as_str)
                    .ok_or("a network interface has no fingerprint".to_string())?;
                let mut alias_ranges = Vec::new();
                let mut alias_entries = Vec::new();
                if let Some(ranges) = nic.get("aliasIpRanges") {
                    for range in ranges
                        .as_array()
                        .ok_or("aliasIpRanges is not a list".to_string())?
                    {
                        alias_ranges.push(
                            range
                                .get("ipCidrRange")
                                .and_then(Value::as_str)
                                .ok_or("an alias range has no ipCidrRange".to_string())?
                                .to_string(),
                        );
                        alias_entries.push(range.clone());
                    }
                }
                nics.push(NetworkInterface {
                    name: name.to_string(),
                    fingerprint: fingerprint.to_string(),
                    alias_ranges,
                    alias_entries,
                });
            }
        }
        Ok(Self {
            id: text("id")?,
            name: text("name")?,
            status: text("status")?,
            nics,
        })
    }

    pub fn nic(&self, name: &str) -> Option<&NetworkInterface> {
        self.nics.iter().find(|nic| nic.name == name)
    }
}

/// What a fresh describe of the target showed, with the identity already checked.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Observed {
    Target(Instance),
    IdentityMismatch(String),
    Failed(ApiFailure),
}

/// `observe`, also keeping every target describe of the current verify poll (J26 re-audit NB-1:
/// a protected range seen by any describe of the poll counts for the alias method).
fn observe_in_poll(
    api: &mut dyn ComputeTransport,
    target: &InstanceIdentity,
    seen: &mut Vec<Instance>,
) -> Observed {
    let observed = observe(api, target);
    if let Observed::Target(instance) = &observed {
        seen.push(instance.clone());
    }
    observed
}

fn observe(api: &mut dyn ComputeTransport, target: &InstanceIdentity) -> Observed {
    match classify(api.call(HttpMethod::Get, &target.path(), None)) {
        Err(failure) => Observed::Failed(failure),
        Ok(value) => match Instance::parse(&value) {
            Err(detail) => Observed::Failed(ApiFailure::Malformed(detail)),
            Ok(instance) if instance.id != target.instance_id || instance.name != target.name => {
                Observed::IdentityMismatch(instance.id)
            }
            Ok(instance) => Observed::Target(instance),
        },
    }
}

fn operation(
    api: &mut dyn ComputeTransport,
    target: &InstanceIdentity,
    name: &str,
) -> Result<Operation, ApiFailure> {
    let path = format!(
        "projects/{}/zones/{}/operations/{}",
        target.project, target.zone, name
    );
    let value = classify(api.call(HttpMethod::Get, &path, None))?;
    Operation::parse(&value).map_err(ApiFailure::Malformed)
}

// ---------------------------------------------------------------------------------------------
// Durable records
// ---------------------------------------------------------------------------------------------

/// Where one attempt's action stands. Only `Accepted` names an operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ActionPhase {
    /// Persisted before the request; the request may not have been sent.
    Intent,
    Accepted {
        operation: String,
    },
    /// The request was refused and was not applied.
    Refused {
        failure: ApiFailure,
    },
    /// The request may have been applied; no operation is known.
    OutcomeUnknown {
        failure: ApiFailure,
    },
    /// Alias only: no protected range was on the NIC when the action ran; nothing was sent.
    NotNeeded,
}

impl ActionPhase {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::Accepted { .. } => "accepted",
            Self::Refused { .. } => "refused",
            Self::OutcomeUnknown { .. } => "outcome-unknown",
            Self::NotNeeded => "not-needed",
        }
    }
}

/// The evidence a verify poll relied on, persisted before `isolated` is printed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmedEvidence {
    pub observed_at_ms: u64,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRecord {
    pub version: u32,
    pub binding: AttemptBinding,
    pub method: FenceMethod,
    pub target: InstanceIdentity,
    pub request_id: String,
    pub phase: ActionPhase,
    /// Alias only: when the removal was first observed (caller's clock).
    pub removal_first_seen_ms: Option<u64>,
    /// Alias only (J26 audit N-1): the last absent observation of the current hold.
    #[serde(default)]
    pub removal_last_seen_ms: Option<u64>,
    /// Alias only (J26 re-audit NB-2): set durably before a poll's API calls and cleared in the
    /// same save that records the poll's outcome. A poll whose outcome was not recorded leaves
    /// it set, and the next poll restarts the hold.
    #[serde(default)]
    pub alias_poll_open: bool,
    pub confirmed: Option<ConfirmedEvidence>,
    /// v0.7 G-2 (audit M-3): the digest of the plan the action ran under (`plan_digest`), so a
    /// later route handoff can refuse a configuration changed after the fence. Absent in records
    /// written before G-2, which route-check therefore never accepts.
    #[serde(default)]
    pub plan_digest: Option<String>,
}

/// v0.7 G-2 (audit M-3): a digest of the parts of the plan the fence proof and the route handoff
/// depend on: the target identity, the methods and their combination, the NIC and the protected
/// ranges (canonical, order-independent).
pub fn plan_digest(plan: &FencePlan) -> String {
    let mut methods: Vec<&str> = plan.methods.iter().map(|method| method.as_str()).collect();
    methods.sort_unstable();
    let combine = match plan.combine {
        Combine::All => "all",
        Combine::AnySufficient => "any-sufficient",
    };
    let (nic, mut ranges, inventory) = match plan.alias() {
        Some(alias) => (
            alias.nic.as_str(),
            alias
                .ranges
                .iter()
                .map(|range| parse_cidr(range).map_or(range.clone(), |cidr| cidr.to_string()))
                .collect::<Vec<_>>(),
            if alias.inventory_complete {
                "complete"
            } else {
                "partial"
            },
        ),
        None => ("", Vec::new(), "none"),
    };
    ranges.sort_unstable();
    let methods = methods.join(",");
    let ranges = ranges.join(",");
    stable_hex(&[
        "mikagami-g2-plan-digest",
        &plan.cluster,
        &plan.target_node,
        &plan.target.project,
        &plan.target.zone,
        &plan.target.name,
        &plan.target.instance_id,
        &methods,
        combine,
        nic,
        &ranges,
        inventory,
    ])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    Io(String),
    /// A record exists but is not this attempt's, method's and target's (or not this version).
    Foreign(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(detail) => write!(formatter, "record store I/O failure: {detail}"),
            Self::Foreign(detail) => write!(formatter, "foreign record: {detail}"),
        }
    }
}

/// The durable store of action records, keyed by (incident id, attempt token, method). `save` must
/// be durable (written, synced, renamed, directory synced) before it returns `Ok`.
pub trait RecordStore {
    fn load(
        &mut self,
        binding: &AttemptBinding,
        method: FenceMethod,
    ) -> Result<Option<ActionRecord>, StoreError>;
    fn save(&mut self, record: &ActionRecord) -> Result<(), StoreError>;
}

/// The checks every loaded record must pass before it is read as this attempt's record.
pub fn check_record(
    record: &ActionRecord,
    binding: &AttemptBinding,
    method: FenceMethod,
    target: &InstanceIdentity,
) -> Result<(), StoreError> {
    if record.version != RECORD_VERSION {
        return Err(StoreError::Foreign(format!("version {}", record.version)));
    }
    if &record.binding != binding {
        return Err(StoreError::Foreign("another attempt".to_string()));
    }
    if record.method != method {
        return Err(StoreError::Foreign("another method".to_string()));
    }
    if &record.target != target {
        return Err(StoreError::Foreign("another target".to_string()));
    }
    if record.request_id != request_id(binding, method) {
        return Err(StoreError::Foreign("another request id".to_string()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Test-only crash points
// ---------------------------------------------------------------------------------------------

/// The helper-side crash points of J25 §10 (1, 3, 4, 5). Production passes `NoFaults`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FencePoint {
    BeforeRequest,
    AfterAccept,
    AfterOperationDone,
    AfterInstanceObserved,
}

impl FencePoint {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BeforeRequest => "before-request",
            Self::AfterAccept => "after-accept",
            Self::AfterOperationDone => "after-operation-done",
            Self::AfterInstanceObserved => "after-instance-observed",
        }
    }
}

pub trait FaultHook {
    fn at(&mut self, point: FencePoint);
}

pub struct NoFaults;

impl FaultHook for NoFaults {
    fn at(&mut self, _point: FencePoint) {}
}

// ---------------------------------------------------------------------------------------------
// Fence action
// ---------------------------------------------------------------------------------------------

/// What one method's fence action did. This is provenance only: no variant is evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionReport {
    Sent {
        operation: String,
    },
    NotNeeded,
    /// A record for this attempt and method already exists: nothing was sent again.
    AlreadyRecorded(&'static str),
    Refused(ApiFailure),
    Unknown(ApiFailure),
    /// Nothing was sent.
    Blocked(String),
}

impl ActionReport {
    pub fn is_success(&self) -> bool {
        matches!(
            self,
            Self::Sent { .. } | Self::NotNeeded | Self::AlreadyRecorded("accepted" | "not-needed")
        )
    }
}

impl fmt::Display for ActionReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sent { .. } => write!(formatter, "request accepted (not proof)"),
            Self::NotNeeded => write!(formatter, "no protected range present; nothing sent"),
            Self::AlreadyRecorded(phase) => {
                write!(formatter, "already recorded ({phase}); nothing sent again")
            }
            Self::Refused(failure) => write!(formatter, "refused: {failure}"),
            Self::Unknown(failure) => write!(formatter, "outcome unknown: {failure}"),
            Self::Blocked(reason) => write!(formatter, "blocked, nothing sent: {reason}"),
        }
    }
}

pub struct ActionContext<'a> {
    pub plan: &'a FencePlan,
    pub binding: &'a AttemptBinding,
    pub api: &'a mut dyn ComputeTransport,
    pub store: &'a mut dyn RecordStore,
    pub hooks: &'a mut dyn FaultHook,
}

/// The fence action: the alias removal first (it revokes the resource at once), then the stop.
pub fn fence(context: &mut ActionContext<'_>) -> Vec<(FenceMethod, ActionReport)> {
    let mut order = context.plan.methods.clone();
    order.sort_by_key(|method| match method {
        FenceMethod::AliasIp => 0,
        FenceMethod::Stop => 1,
    });
    order
        .into_iter()
        .map(|method| (method, fence_one(context, method)))
        .collect()
}

fn fence_one(context: &mut ActionContext<'_>, method: FenceMethod) -> ActionReport {
    let plan = context.plan;
    match context.store.load(context.binding, method) {
        Ok(Some(record)) => {
            if let Err(error) = check_record(&record, context.binding, method, &plan.target) {
                return ActionReport::Blocked(error.to_string());
            }
            return ActionReport::AlreadyRecorded(record.phase.name());
        }
        Ok(None) => {}
        Err(error) => return ActionReport::Blocked(error.to_string()),
    }
    // The target is described before any mutation, so a recreated VM (another numeric id) is
    // never stopped or changed.
    let instance = match observe(context.api, &plan.target) {
        Observed::Target(instance) => instance,
        Observed::IdentityMismatch(actual) => {
            return ActionReport::Blocked(format!(
                "the instance {} has id {actual}, not the configured id",
                plan.target.name
            ));
        }
        Observed::Failed(failure) => {
            return ActionReport::Blocked(format!("the target could not be described: {failure}"));
        }
    };
    let mut record = ActionRecord {
        version: RECORD_VERSION,
        binding: context.binding.clone(),
        method,
        target: plan.target.clone(),
        request_id: request_id(context.binding, method),
        phase: ActionPhase::Intent,
        removal_first_seen_ms: None,
        removal_last_seen_ms: None,
        alias_poll_open: false,
        confirmed: None,
        plan_digest: Some(plan_digest(plan)),
    };
    let (http_method, path, body, operation_type) = match method {
        FenceMethod::Stop => (
            HttpMethod::Post,
            format!(
                "{}/stop?requestId={}",
                plan.target.path(),
                record.request_id
            ),
            None,
            "stop",
        ),
        FenceMethod::AliasIp => {
            let Some(alias) = plan.alias() else {
                return ActionReport::Blocked("the alias-ip method has no [alias]".to_string());
            };
            let Some(nic) = instance.nic(&alias.nic) else {
                return ActionReport::Blocked(format!("the target has no NIC {}", alias.nic));
            };
            // J25 audit B-1c: by address, not by text, on every NIC. Only an exact protected
            // range on the configured NIC is removed; any other overlap (a wider range, another
            // NIC) is not something this action may change, so nothing is sent.
            let protected = protected_cidrs(alias);
            for other in instance.nics.iter().filter(|other| other.name != alias.nic) {
                if other
                    .alias_ranges
                    .iter()
                    .any(|range| may_overlap(range, &protected))
                {
                    return ActionReport::Blocked(format!(
                        "NIC {} also holds a range overlapping a protected range",
                        other.name
                    ));
                }
            }
            let mut remaining = Vec::new();
            let mut removed = 0;
            for (range, entry) in nic.alias_ranges.iter().zip(&nic.alias_entries) {
                let exact = parse_cidr(range).is_some_and(|cidr| protected.contains(&cidr));
                if exact {
                    removed += 1;
                } else if may_overlap(range, &protected) {
                    return ActionReport::Blocked(format!(
                        "{} holds {range}, which overlaps a protected range but is not one",
                        alias.nic
                    ));
                } else {
                    remaining.push(entry.clone());
                }
            }
            if removed == 0 {
                record.phase = ActionPhase::NotNeeded;
                return match context.store.save(&record) {
                    Ok(()) => ActionReport::NotNeeded,
                    Err(error) => ActionReport::Blocked(error.to_string()),
                };
            }
            let body = json!({
                "aliasIpRanges": remaining,
                "fingerprint": nic.fingerprint,
            })
            .to_string();
            (
                HttpMethod::Patch,
                format!(
                    "{}/updateNetworkInterface?networkInterface={}&requestId={}",
                    plan.target.path(),
                    alias.nic,
                    record.request_id
                ),
                Some(body),
                "updateNetworkInterface",
            )
        }
    };
    if let Err(error) = context.store.save(&record) {
        return ActionReport::Blocked(format!("the intent was not persisted: {error}"));
    }
    context.hooks.at(FencePoint::BeforeRequest);
    debug_assert!(http_method.mutates());
    let answer = classify(context.api.call(http_method, &path, body.as_deref()));
    let report = match answer {
        Ok(value) => match Operation::parse(&value) {
            Ok(op)
                if op.target_id == plan.target.instance_id
                    && op.operation_type == operation_type =>
            {
                context.hooks.at(FencePoint::AfterAccept);
                record.phase = ActionPhase::Accepted {
                    operation: op.name.clone(),
                };
                ActionReport::Sent { operation: op.name }
            }
            Ok(op) => {
                let failure = ApiFailure::Malformed(format!(
                    "the answer names a {} operation of target {}",
                    op.operation_type, op.target_id
                ));
                record.phase = ActionPhase::OutcomeUnknown {
                    failure: failure.clone(),
                };
                ActionReport::Unknown(failure)
            }
            Err(detail) => {
                let failure = ApiFailure::Malformed(detail);
                record.phase = ActionPhase::OutcomeUnknown {
                    failure: failure.clone(),
                };
                ActionReport::Unknown(failure)
            }
        },
        Err(failure) if failure.may_have_been_applied() => {
            record.phase = ActionPhase::OutcomeUnknown {
                failure: failure.clone(),
            };
            ActionReport::Unknown(failure)
        }
        Err(failure) => {
            record.phase = ActionPhase::Refused {
                failure: failure.clone(),
            };
            ActionReport::Refused(failure)
        }
    };
    match context.store.save(&record) {
        Ok(()) => report,
        // The intent stays durable, which every verify reads as "outcome unknown".
        Err(error) => ActionReport::Unknown(ApiFailure::Malformed(format!(
            "the action result was not persisted: {error}"
        ))),
    }
}

// ---------------------------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodVerdict {
    Isolated(String),
    /// A definitive observation that the method did not isolate the target.
    NotIsolated(String),
    Unknown(String),
}

impl MethodVerdict {
    fn is_isolated(&self) -> bool {
        matches!(self, Self::Isolated(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResult {
    /// No host answers on the protected path.
    Absent,
    Present,
    Unknown,
}

/// J26 audit N-4: probes one protected range; the caller probes every range.
pub trait DataPlaneProbe {
    fn probe(&mut self, range: &str) -> ProbeResult;
}

pub struct NoProbe;

impl DataPlaneProbe for NoProbe {
    fn probe(&mut self, _range: &str) -> ProbeResult {
        ProbeResult::Unknown
    }
}

pub struct VerifyContext<'a> {
    pub plan: &'a FencePlan,
    pub binding: &'a AttemptBinding,
    pub api: &'a mut dyn ComputeTransport,
    pub store: &'a mut dyn RecordStore,
    pub hooks: &'a mut dyn FaultHook,
    pub probe: &'a mut dyn DataPlaneProbe,
    /// The caller's clock in milliseconds (`CLOCK_BOOTTIME` in the helper), read at the moment it
    /// is needed (J25 audit B-1b). `None` is a clock failure: Unknown.
    pub clock: &'a mut dyn FnMut() -> Option<u64>,
}

/// The final verify classification, mapped by the helper onto the §17.1 verify grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalVerdict {
    Isolated(String),
    NotIsolated(String),
    Unknown(String),
}

/// One verify poll: per-method verdicts, the F-5 combination, and, for `Isolated`, the evidence
/// persisted on the contributing records before the verdict is returned (I-9).
pub fn verify(
    context: &mut VerifyContext<'_>,
) -> (Vec<(FenceMethod, MethodVerdict)>, FinalVerdict) {
    // J26 re-audit NB-1: the alias method is evaluated last, against every describe of the poll.
    let mut order = context.plan.methods.clone();
    order.sort_by_key(|method| matches!(method, FenceMethod::AliasIp));
    let mut seen = Vec::new();
    let mut evaluated: Vec<(FenceMethod, MethodVerdict)> = order
        .iter()
        .map(|method| (*method, verify_one(context, *method, &mut seen)))
        .collect();
    let verdicts: Vec<(FenceMethod, MethodVerdict)> = context
        .plan
        .methods
        .iter()
        .map(|method| {
            let at = evaluated
                .iter()
                .position(|(m, _)| m == method)
                .expect("evaluated");
            evaluated.remove(at)
        })
        .collect();
    let mut verdict = combine(context.plan, &verdicts);
    if let FinalVerdict::Isolated(summary) = &verdict {
        for (method, method_verdict) in &verdicts {
            if !method_verdict.is_isolated() {
                continue;
            }
            let persisted = context
                .store
                .load(context.binding, *method)
                .and_then(|record| {
                    let mut record = record
                        .ok_or_else(|| StoreError::Io("the record disappeared".to_string()))?;
                    check_record(&record, context.binding, *method, &context.plan.target)?;
                    let observed_at_ms = (context.clock)()
                        .ok_or_else(|| StoreError::Io("the clock is unreadable".to_string()))?;
                    record.confirmed = Some(ConfirmedEvidence {
                        observed_at_ms,
                        summary: summary.clone(),
                    });
                    context.store.save(&record)
                });
            if let Err(error) = persisted {
                verdict = FinalVerdict::Unknown(format!("the evidence was not persisted: {error}"));
                break;
            }
        }
    }
    (verdicts, verdict)
}

fn load_checked(
    context: &mut VerifyContext<'_>,
    method: FenceMethod,
) -> Result<ActionRecord, MethodVerdict> {
    match context.store.load(context.binding, method) {
        Ok(Some(record)) => {
            check_record(&record, context.binding, method, &context.plan.target)
                .map_err(|error| MethodVerdict::Unknown(error.to_string()))?;
            Ok(record)
        }
        Ok(None) => Err(MethodVerdict::Unknown(
            "no fence action is recorded for this attempt".to_string(),
        )),
        Err(error) => Err(MethodVerdict::Unknown(error.to_string())),
    }
}

fn verify_one(
    context: &mut VerifyContext<'_>,
    method: FenceMethod,
    seen: &mut Vec<Instance>,
) -> MethodVerdict {
    let record = match load_checked(context, method) {
        Ok(record) => record,
        Err(verdict) => return verdict,
    };
    match method {
        FenceMethod::Stop => verify_stop(context, &record, seen),
        FenceMethod::AliasIp => verify_alias(context, record, seen),
    }
}

fn runs(status: &str) -> bool {
    matches!(
        status,
        "RUNNING" | "PROVISIONING" | "STAGING" | "REPAIRING" | "PENDING"
    )
}

fn verify_stop(
    context: &mut VerifyContext<'_>,
    record: &ActionRecord,
    seen: &mut Vec<Instance>,
) -> MethodVerdict {
    let target = &context.plan.target;
    let name = match &record.phase {
        ActionPhase::Accepted { operation } => operation.clone(),
        ActionPhase::Refused { failure } => {
            // A refused stop is definitive only if the target is seen running.
            return match observe_in_poll(context.api, target, seen) {
                Observed::Target(instance) if runs(&instance.status) => {
                    MethodVerdict::NotIsolated(format!(
                        "the stop was refused ({failure}) and the instance is {}",
                        instance.status
                    ))
                }
                _ => MethodVerdict::Unknown(format!("the stop was refused ({failure})")),
            };
        }
        phase => {
            return MethodVerdict::Unknown(format!(
                "the stop request's outcome is unknown ({})",
                phase.name()
            ));
        }
    };
    let op = match operation(context.api, target, &name) {
        Ok(op) => op,
        Err(failure) => {
            return MethodVerdict::Unknown(format!(
                "the stop operation is unobservable: {failure}"
            ));
        }
    };
    if op.name != name || op.target_id != target.instance_id || op.operation_type != "stop" {
        return MethodVerdict::Unknown("the operation is not this attempt's stop".to_string());
    }
    if op.status != OperationStatus::Done {
        return MethodVerdict::Unknown("the stop operation is in progress".to_string());
    }
    let failed = op.failed();
    if !failed {
        context.hooks.at(FencePoint::AfterOperationDone);
    }
    let instance = match observe_in_poll(context.api, target, seen) {
        Observed::Target(instance) => instance,
        Observed::IdentityMismatch(actual) => {
            return MethodVerdict::Unknown(format!(
                "the instance name now has id {actual} (deleted and recreated?)"
            ));
        }
        Observed::Failed(failure) => {
            return MethodVerdict::Unknown(format!("the instance is unobservable: {failure}"));
        }
    };
    match (failed, instance.status.as_str()) {
        (false, "TERMINATED") => {
            context.hooks.at(FencePoint::AfterInstanceObserved);
            MethodVerdict::Isolated(format!(
                "stop operation DONE without error and instance id {} TERMINATED",
                target.instance_id
            ))
        }
        (_, status) if runs(status) => MethodVerdict::NotIsolated(if failed {
            format!(
                "the stop operation failed ({}) and the instance is {status}",
                op.error.as_deref().unwrap_or("HTTP error")
            )
        } else {
            format!("the stop operation is DONE but the instance is {status}")
        }),
        (true, status) => MethodVerdict::Unknown(format!(
            "the stop operation failed and the instance is {status}"
        )),
        (false, status) => {
            MethodVerdict::Unknown(format!("the instance is {status}, not TERMINATED"))
        }
    }
}

/// J26 audit N-1: a poll that could not observe a continuous absence ends the current hold. The
/// stamps are cleared durably before the Unknown verdict is returned.
fn restart_hold(
    context: &mut VerifyContext<'_>,
    record: &mut ActionRecord,
    reason: String,
) -> MethodVerdict {
    // The stamps and the poll marker are cleared in one save; if it fails, the marker stays set
    // in the store (written at the poll's start) and the next poll restarts the hold.
    record.removal_first_seen_ms = None;
    record.removal_last_seen_ms = None;
    record.alias_poll_open = false;
    if let Err(error) = context.store.save(record) {
        return MethodVerdict::Unknown(format!(
            "{reason}; the restart of the hold was not persisted: {error}"
        ));
    }
    MethodVerdict::Unknown(reason)
}

fn verify_alias(
    context: &mut VerifyContext<'_>,
    mut record: ActionRecord,
    seen: &mut Vec<Instance>,
) -> MethodVerdict {
    let Some(alias) = context.plan.alias().cloned() else {
        return MethodVerdict::Unknown("the alias-ip method has no [alias]".to_string());
    };
    let target = context.plan.target.clone();
    // J26 re-audit NB-2: a previous poll that did not record its outcome restarts the hold; this
    // poll's marker is durable before any API call.
    if record.alias_poll_open {
        record.removal_first_seen_ms = None;
        record.removal_last_seen_ms = None;
    }
    record.alias_poll_open = true;
    if let Err(error) = context.store.save(&record) {
        return MethodVerdict::Unknown(format!("the poll marker was not persisted: {error}"));
    }
    // The operation, if any, decides only whether a still-present range is definitive.
    let op_state = match &record.phase {
        ActionPhase::Accepted { operation: name } => match operation(context.api, &target, name) {
            Ok(op)
                if &op.name == name
                    && op.target_id == target.instance_id
                    && op.operation_type == "updateNetworkInterface" =>
            {
                Some(op)
            }
            Ok(_) => {
                return restart_hold(
                    context,
                    &mut record,
                    "the operation is not this attempt's alias update".to_string(),
                );
            }
            Err(failure) => {
                return restart_hold(
                    context,
                    &mut record,
                    format!("the alias operation is unobservable: {failure}"),
                );
            }
        },
        _ => None,
    };
    let instance = match observe_in_poll(context.api, &target, seen) {
        Observed::Target(instance) => instance,
        Observed::IdentityMismatch(actual) => {
            return restart_hold(
                context,
                &mut record,
                format!("the instance name now has id {actual} (deleted and recreated?)"),
            );
        }
        Observed::Failed(failure) => {
            return restart_hold(
                context,
                &mut record,
                format!("the instance is unobservable: {failure}"),
            );
        }
    };
    if instance.nic(&alias.nic).is_none() {
        return restart_hold(
            context,
            &mut record,
            format!("the target has no NIC {}", alias.nic),
        );
    }
    // J25 audit B-1c: by address on every NIC of the old instance; an unparseable range counts.
    let protected = protected_cidrs(&alias);
    // J26 re-audit NB-1: every describe of this poll (the stop method's too), not only this one.
    let present = seen
        .iter()
        .chain(std::iter::once(&instance))
        .flat_map(|instance| instance.nics.iter())
        .flat_map(|nic| nic.alias_ranges.iter())
        .filter(|range| may_overlap(range, &protected))
        .count();
    if present > 0 {
        let definitive = match (&record.phase, &op_state) {
            (_, Some(op)) => op.status == OperationStatus::Done,
            (ActionPhase::Refused { .. }, None) => true,
            _ => false,
        };
        let detail =
            format!("{present} range(s) overlapping a protected range still on the old node");
        // J25 audit B-1a: the hold is a continuous absence; a range seen again restarts it.
        return match restart_hold(context, &mut record, detail.clone()) {
            MethodVerdict::Unknown(_) if definitive => MethodVerdict::NotIsolated(detail),
            other => other,
        };
    }
    // Removed although this attempt's update failed means somebody else changed the NIC: the
    // observed state is what counts, and the summary says so.
    let foreign_removal = op_state.as_ref().is_some_and(Operation::failed);
    // J25 audit B-1b: the clock is read after the describe that showed the absence.
    let Some(now_ms) = (context.clock)() else {
        return restart_hold(context, &mut record, "the clock is unreadable".to_string());
    };
    // J26 audit N-1: two absent observations further apart than the gap are not one absence.
    // J26 re-audit NB-3: a clock behind the last observation, or a hold without a last
    // observation (an older record), is not one continuous absence either.
    let gap_exceeded = match (record.removal_first_seen_ms, record.removal_last_seen_ms) {
        (_, Some(last)) => now_ms < last || now_ms - last > alias.max_observation_gap_ms,
        (Some(_), None) => true,
        (None, None) => false,
    };
    let first_seen = match record.removal_first_seen_ms {
        Some(first_seen) if !gap_exceeded => first_seen,
        _ => now_ms,
    };
    record.removal_first_seen_ms = Some(first_seen);
    record.removal_last_seen_ms = Some(now_ms);
    let held = now_ms.saturating_sub(first_seen);
    // The marker stays open until the probe has run (NB-2): a probe that sees the path must be
    // able to restart the hold, and a failure to record that leaves the marker set.
    if held < alias.propagation_hold_ms {
        record.alias_poll_open = false;
    }
    if let Err(error) = context.store.save(&record) {
        return MethodVerdict::Unknown(format!(
            "the removal observation was not persisted: {error}"
        ));
    }
    if held < alias.propagation_hold_ms {
        return MethodVerdict::Unknown(format!(
            "removed from the control plane {held} ms ago{}; the propagation hold is {} ms",
            if gap_exceeded {
                " (hold restarted: observation gap exceeded)"
            } else {
                ""
            },
            alias.propagation_hold_ms
        ));
    }
    if alias.probe_required {
        // J26 audit N-4: every protected range must be probed absent.
        for range in &alias.ranges {
            match context.probe.probe(range) {
                ProbeResult::Absent => {}
                ProbeResult::Present => {
                    return restart_hold(
                        context,
                        &mut record,
                        format!("the data-plane probe still finds a host on {range}"),
                    );
                }
                ProbeResult::Unknown => {
                    return restart_hold(
                        context,
                        &mut record,
                        format!("the data-plane probe is inconclusive for {range}"),
                    );
                }
            }
        }
    }
    record.alias_poll_open = false;
    if let Err(error) = context.store.save(&record) {
        return MethodVerdict::Unknown(format!("the poll outcome was not persisted: {error}"));
    }
    MethodVerdict::Isolated(format!(
        "{} protected range(s) absent from {} of instance id {} for {held} ms{}{}",
        alias.ranges.len(),
        alias.nic,
        target.instance_id,
        if alias.probe_required {
            ", data-plane probe absent for every range"
        } else {
            ""
        },
        if foreign_removal {
            " (removed although this attempt's update failed)"
        } else {
            ""
        }
    ))
}

/// F-5: the explicit combination of the per-method verdicts (`FENCING_STATE_MACHINE.md` §3).
pub fn combine(plan: &FencePlan, verdicts: &[(FenceMethod, MethodVerdict)]) -> FinalVerdict {
    let get = |method: FenceMethod| {
        verdicts
            .iter()
            .find(|(candidate, _)| *candidate == method)
            .map(|(_, verdict)| verdict)
    };
    // A configured method without a verdict is Unknown.
    for method in &plan.methods {
        if get(*method).is_none() {
            return FinalVerdict::Unknown(format!("no verdict for {}", method.as_str()));
        }
    }
    let describe = |method: FenceMethod| match get(method) {
        Some(MethodVerdict::Isolated(detail))
        | Some(MethodVerdict::NotIsolated(detail))
        | Some(MethodVerdict::Unknown(detail)) => format!("{}: {detail}", method.as_str()),
        None => format!("{}: not configured", method.as_str()),
    };
    let all_summary = plan
        .methods
        .iter()
        .map(|method| describe(*method))
        .collect::<Vec<_>>()
        .join("; ");
    let isolated = |method: FenceMethod| get(method).is_some_and(MethodVerdict::is_isolated);
    let alias_sufficient = plan.alias().is_some_and(|alias| alias.inventory_complete);
    let pass = match plan.combine {
        Combine::All => plan.methods.iter().all(|method| isolated(*method)),
        Combine::AnySufficient => {
            isolated(FenceMethod::Stop) || (alias_sufficient && isolated(FenceMethod::AliasIp))
        }
    };
    if pass {
        return FinalVerdict::Isolated(all_summary);
    }
    // NotIsolated only when no configured method can still turn out isolated.
    let all_definitive_not = plan.methods.iter().all(|method| {
        matches!(get(*method), Some(MethodVerdict::NotIsolated(_)))
            || (plan.combine == Combine::AnySufficient
                && *method == FenceMethod::AliasIp
                && !alias_sufficient)
    });
    let any_not = plan
        .methods
        .iter()
        .any(|method| matches!(get(*method), Some(MethodVerdict::NotIsolated(_))));
    match plan.combine {
        Combine::All if any_not => FinalVerdict::NotIsolated(all_summary),
        Combine::AnySufficient if any_not && all_definitive_not => {
            FinalVerdict::NotIsolated(all_summary)
        }
        _ => FinalVerdict::Unknown(all_summary),
    }
}

// ---------------------------------------------------------------------------------------------
// New-node alias assignment (after promotion; not part of the fencing proof)
// ---------------------------------------------------------------------------------------------

/// Adds `ranges` to `nic` of `instance`. GCE refuses a range still assigned to another NIC, so a
/// success also shows (control plane only) that the old NIC no longer holds it. The daemon does not
/// call this; the J25 harness calls the helper's `assign` after a promotion.
pub fn assign_alias(
    api: &mut dyn ComputeTransport,
    instance: &InstanceIdentity,
    nic_name: &str,
    ranges: &[String],
    request: &str,
) -> ActionReport {
    let current = match observe(api, instance) {
        Observed::Target(current) => current,
        Observed::IdentityMismatch(actual) => {
            return ActionReport::Blocked(format!("the instance has id {actual}"));
        }
        Observed::Failed(failure) => return ActionReport::Blocked(failure.to_string()),
    };
    let Some(nic) = current.nic(nic_name) else {
        return ActionReport::Blocked(format!("no NIC {nic_name}"));
    };
    let held: Vec<Option<Cidr>> = nic
        .alias_ranges
        .iter()
        .map(|range| parse_cidr(range))
        .collect();
    let missing: Vec<&String> = ranges
        .iter()
        .filter(|range| !held.contains(&parse_cidr(range)))
        .collect();
    if missing.is_empty() {
        return ActionReport::NotNeeded;
    }
    let mut wanted = nic.alias_entries.clone();
    for range in missing {
        wanted.push(json!({ "ipCidrRange": range }));
    }
    let body = json!({
        "aliasIpRanges": wanted,
        "fingerprint": nic.fingerprint,
    })
    .to_string();
    let path = format!(
        "{}/updateNetworkInterface?networkInterface={nic_name}&requestId={request}",
        instance.path()
    );
    match classify(api.call(HttpMethod::Patch, &path, Some(&body))) {
        Ok(value) => match Operation::parse(&value) {
            Ok(op) => ActionReport::Sent { operation: op.name },
            Err(detail) => ActionReport::Unknown(ApiFailure::Malformed(detail)),
        },
        Err(failure) if failure.may_have_been_applied() => ActionReport::Unknown(failure),
        Err(failure) => ActionReport::Refused(failure),
    }
}

// ---------------------------------------------------------------------------------------------
// v0.7 G-2 route handoff (G2_SAFETY_CONTRACT.md R4.1 §3.1): route-check, route-observe,
// route-assign and operator-assign. The daemon runs the first three as RH steps (one Compute API
// call at most per step); operator-assign is an operator command only.
// ---------------------------------------------------------------------------------------------

/// The route record format version. Any other version is not read as a record.
pub const ROUTE_RECORD_VERSION: u32 = 1;

/// The provenance carried by the daemon's intent (mirror of `route_handoff::RhOrigin`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RouteOrigin {
    Fencing {
        incident_seq: u64,
        incident_id: String,
        attempt_token: u64,
        confirmed_by: String,
    },
    Bootstrap,
    Unknown,
}

/// The daemon's intent file (mirror of `route_handoff::RhIntent`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteIntent {
    pub version: u32,
    pub cluster: String,
    pub node: String,
    pub peer_node: String,
    pub term: u64,
    pub origin: RouteOrigin,
}

/// One term's route binding as the helper uses it: the intent checked against the helper's own
/// configuration, which stays authoritative for every instance identity (contract §3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteBinding {
    pub cluster: String,
    pub peer_node: String,
    pub term: u64,
    pub own: InstanceIdentity,
    pub peer: InstanceIdentity,
    pub nic: String,
    pub ranges: Vec<String>,
    /// `Some` only for a fencing origin confirmed by the backend (the only automated one).
    pub fence: Option<AttemptBinding>,
    /// The incident label of the key (`none` without a fencing origin).
    incident_label: String,
    attempt_label: u64,
}

impl RouteBinding {
    /// Checks the intent against the plan and the configured own instance. `env` is the step
    /// identity the command backend passes (`MIKAGAMI_*`): for a fencing origin it must name the
    /// same incident and attempt as the intent.
    pub fn from_intent(
        plan: &FencePlan,
        own: &InstanceIdentity,
        intent: &RouteIntent,
        env_incident: Option<&str>,
        env_attempt: Option<&str>,
    ) -> Result<Self, String> {
        own.validate()?;
        if intent.version != ROUTE_RECORD_VERSION {
            return Err("the intent has another version".to_string());
        }
        if intent.cluster != plan.cluster {
            return Err("the intent names another cluster".to_string());
        }
        if intent.peer_node != plan.target_node {
            return Err("the intent names another peer node".to_string());
        }
        if intent.term == 0 {
            return Err("the intent has no term".to_string());
        }
        if own.instance_id == plan.target.instance_id {
            return Err("the own instance is the fencing target".to_string());
        }
        let Some(alias) = plan.alias() else {
            return Err("route handoff needs [alias]".to_string());
        };
        let (fence, incident_label, attempt_label) = match &intent.origin {
            RouteOrigin::Fencing {
                incident_id,
                attempt_token,
                confirmed_by,
                ..
            } if confirmed_by == "backend" => {
                if !is_canonical_uuid_v4(incident_id) || *attempt_token == 0 {
                    return Err("the intent's incident is malformed".to_string());
                }
                if env_incident != Some(incident_id.as_str())
                    || env_attempt.and_then(parse_positive) != Some(*attempt_token)
                {
                    return Err("the step identity differs from the intent".to_string());
                }
                let fence = AttemptBinding {
                    cluster: plan.cluster.clone(),
                    target_node: plan.target_node.clone(),
                    incident_id: incident_id.clone(),
                    attempt_token: *attempt_token,
                };
                (Some(fence), incident_id.clone(), *attempt_token)
            }
            // T8 (operator-attested), BA and no provenance: observation only, never a send.
            RouteOrigin::Fencing { .. } | RouteOrigin::Bootstrap | RouteOrigin::Unknown => {
                (None, "none".to_string(), 0)
            }
        };
        Ok(Self {
            cluster: plan.cluster.clone(),
            peer_node: plan.target_node.clone(),
            term: intent.term,
            own: own.clone(),
            peer: plan.target.clone(),
            nic: alias.nic.clone(),
            ranges: alias.ranges.clone(),
            fence,
            incident_label,
            attempt_label,
        })
    }

    /// The record key: stable identity only (cluster, term, own numeric id, incident, attempt),
    /// never an observed value (contract L-R4-3), so a second send of the term finds the record.
    pub fn key(&self) -> String {
        stable_hex(&[
            "mikagami-g2-route-key",
            &self.cluster,
            &self.term.to_string(),
            &self.own.instance_id,
            &self.incident_label,
            &self.attempt_label.to_string(),
        ])
    }

    /// The `requestId` of the term's one `route-assign` (a UUIDv4 derived from the key parts).
    pub fn request_id(&self) -> String {
        stable_uuid(&[
            "mikagami-g2-route-assign",
            &self.cluster,
            &self.term.to_string(),
            &self.own.instance_id,
            &self.incident_label,
            &self.attempt_label.to_string(),
        ])
    }
}

fn stable_digest(parts: &[&str]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part.as_bytes());
        hash.update(b"\0");
    }
    hash.finalize().into()
}

fn stable_hex(parts: &[&str]) -> String {
    stable_digest(parts)[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A canonical UUIDv4 shaped from a SHA-256 of `parts`.
pub fn stable_uuid(parts: &[&str]) -> String {
    let digest = stable_digest(parts);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// The `own` observation `route-assign` builds its body from (the same describe as the
/// fingerprint, contract M-R3-2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteObservation {
    pub version: u32,
    pub key: String,
    pub own: InstanceIdentity,
    pub nic: String,
    pub fingerprint: String,
    pub alias_entries: Vec<Value>,
    pub coverage: String,
}

/// The term's one `route-assign` (or one `operator-assign` request), and (r17, a separate record
/// of the same key) the term's one `route-reissue`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteAssignRecord {
    pub version: u32,
    pub key: String,
    pub request_id: String,
    pub own: InstanceIdentity,
    pub nic: String,
    pub phase: ActionPhase,
    /// r17 (contract R5 R-6): the `own` observation the body was built from, persisted with the
    /// intent before the request. A record without it (written before r17, or by
    /// `operator-assign`) is never re-issued.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<RouteBase>,
}

/// r17: what the one alias update was built from, so a re-issue sends exactly the same body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteBase {
    pub fingerprint: String,
    pub alias_entries: Vec<Value>,
    /// SHA-256 (hex) of the exact body text that was (or was about to be) sent.
    pub body_sha256: String,
}

/// The durable store of route records, keyed by the binding key. `save_*` is durable before `Ok`.
pub trait RouteStore {
    fn load_observation(&mut self, key: &str) -> Result<Option<RouteObservation>, StoreError>;
    fn save_observation(&mut self, record: &RouteObservation) -> Result<(), StoreError>;
    fn load_assign(&mut self, key: &str) -> Result<Option<RouteAssignRecord>, StoreError>;
    fn save_assign(&mut self, record: &RouteAssignRecord) -> Result<(), StoreError>;
    /// r17: the term's one re-issue record (a separate file of the same key).
    fn load_reissue(&mut self, key: &str) -> Result<Option<RouteAssignRecord>, StoreError>;
    fn save_reissue(&mut self, record: &RouteAssignRecord) -> Result<(), StoreError>;
    /// r17 (R-9): whether any other route assign or re-issue record (another term's, or an
    /// operator's) was written after this key's assign record. Unknown is `Err` (no re-issue).
    fn newer_route_records(&mut self, key: &str) -> Result<bool, StoreError>;
}

/// G-A3 (contract §2): the plan stops and removes the alias with `combine = all`, and the helper's
/// own records of the same incident and attempt show both methods `confirmed` (the evidence a
/// verify poll persists before `isolated` is printed, I-9). Read-only; no API call.
pub fn route_check(
    plan: &FencePlan,
    binding: &RouteBinding,
    store: &mut dyn RecordStore,
) -> Result<(), String> {
    let Some(fence) = &binding.fence else {
        return Err("the promotion was not confirmed by the backend".to_string());
    };
    if plan.combine != Combine::All
        || !plan.methods.contains(&FenceMethod::Stop)
        || !plan.methods.contains(&FenceMethod::AliasIp)
    {
        return Err("the fencing plan is not stop + alias-ip with combine = all".to_string());
    }
    for method in [FenceMethod::Stop, FenceMethod::AliasIp] {
        let record = match store.load(fence, method) {
            Ok(Some(record)) => record,
            Ok(None) => return Err(format!("no {} record for this attempt", method.as_str())),
            Err(error) => return Err(error.to_string()),
        };
        check_record(&record, fence, method, &plan.target).map_err(|error| error.to_string())?;
        if record.plan_digest.as_deref() != Some(plan_digest(plan).as_str()) {
            return Err(format!(
                "the {} record was written under another fencing plan (configuration changed)",
                method.as_str()
            ));
        }
        if record.confirmed.is_none() {
            return Err(format!("the {} record is not confirmed", method.as_str()));
        }
        let accepted = match (&record.phase, method) {
            (ActionPhase::Accepted { .. }, _) => true,
            (ActionPhase::NotNeeded, FenceMethod::AliasIp) => true,
            _ => false,
        };
        if !accepted {
            return Err(format!(
                "the {} record is {}, not a completed action",
                method.as_str(),
                record.phase.name()
            ));
        }
    }
    Ok(())
}

/// How many protected ranges the NIC holds exactly (by address).
fn coverage(nic: &NetworkInterface, ranges: &[String]) -> &'static str {
    let held: Vec<Option<Cidr>> = nic.alias_ranges.iter().map(|r| parse_cidr(r)).collect();
    let present = ranges
        .iter()
        .filter(|range| parse_cidr(range).is_some_and(|cidr| held.contains(&Some(cidr))))
        .count();
    if present == ranges.len() {
        "all"
    } else if present == 0 {
        "none"
    } else {
        "some"
    }
}

/// `route-observe --part own` (one API call): C-2 for this node, recorded for `route-assign`.
pub fn observe_own(
    api: &mut dyn ComputeTransport,
    binding: &RouteBinding,
    store: &mut dyn RouteStore,
) -> Result<&'static str, String> {
    let instance = match observe(api, &binding.own) {
        Observed::Target(instance) => instance,
        Observed::IdentityMismatch(_) => return Ok("own mismatch"),
        Observed::Failed(failure) => return Err(failure.to_string()),
    };
    let Some(nic) = instance.nic(&binding.nic) else {
        return Ok("own missing-nic");
    };
    let coverage = coverage(nic, &binding.ranges);
    store
        .save_observation(&RouteObservation {
            version: ROUTE_RECORD_VERSION,
            key: binding.key(),
            own: binding.own.clone(),
            nic: binding.nic.clone(),
            fingerprint: nic.fingerprint.clone(),
            alias_entries: nic.alias_entries.clone(),
            coverage: coverage.to_string(),
        })
        .map_err(|error| error.to_string())?;
    Ok(match coverage {
        "all" => "own all",
        "none" => "own none",
        _ => "own some",
    })
}

/// `route-observe --part peer` (one API call): C-3, any NIC of the peer, by address
/// (an unparseable range counts as present).
pub fn observe_peer(
    api: &mut dyn ComputeTransport,
    binding: &RouteBinding,
) -> Result<&'static str, String> {
    let protected: Vec<Cidr> = binding
        .ranges
        .iter()
        .filter_map(|r| parse_cidr(r))
        .collect();
    match observe(api, &binding.peer) {
        Observed::Target(instance) => Ok(
            if instance
                .nics
                .iter()
                .flat_map(|nic| nic.alias_ranges.iter())
                .any(|range| may_overlap(range, &protected))
            {
                "peer present"
            } else {
                "peer absent"
            },
        ),
        Observed::IdentityMismatch(_) => Ok("peer mismatch"),
        Observed::Failed(ApiFailure::NotFound) => Ok("peer missing"),
        // Contract C-3 (audit M-1): a describe failure means C-3 does not hold.
        Observed::Failed(_) => Ok("peer unknown"),
    }
}

/// `route-observe --part op` (at most one API call): C-5, the term's own request only.
pub fn observe_op(
    api: &mut dyn ComputeTransport,
    binding: &RouteBinding,
    store: &mut dyn RouteStore,
) -> Result<&'static str, String> {
    let key = binding.key();
    let record = match store.load_assign(&key) {
        Ok(Some(record)) => record,
        Ok(None) => return Ok("op none"),
        Err(error) => return Err(error.to_string()),
    };
    if record.version != ROUTE_RECORD_VERSION
        || record.key != key
        || record.own != binding.own
        || record.request_id != binding.request_id()
    {
        return Ok("op mismatch");
    }
    let name = match &record.phase {
        ActionPhase::Refused { .. } => return Ok("op refused"),
        ActionPhase::NotNeeded => return Ok("op not-needed"),
        ActionPhase::Accepted { operation } => operation.clone(),
        // r17 (contract R5 C-5'): no operation name is known (the answer was lost, or the record
        // of the answer was not persisted). The re-issue, if any, may name one; otherwise the
        // term's operation is looked up by its requestId (`clientOperationId`). Read-only.
        ActionPhase::Intent | ActionPhase::OutcomeUnknown { .. } => {
            match store.load_reissue(&key) {
                Ok(Some(reissue))
                    if reissue.key == key
                        && reissue.own == binding.own
                        && reissue.request_id == record.request_id =>
                {
                    match &reissue.phase {
                        ActionPhase::Accepted { operation } => operation.clone(),
                        _ => return Ok(lookup_term_operation(api, binding)),
                    }
                }
                Ok(Some(_)) => return Ok("op mismatch"),
                Ok(None) => return Ok(lookup_term_operation(api, binding)),
                Err(error) => return Err(error.to_string()),
            }
        }
    };
    let op = operation(api, &binding.own, &name).map_err(|failure| failure.to_string())?;
    if op.name != name
        || op.target_id != binding.own.instance_id
        || op.operation_type != "updateNetworkInterface"
    {
        return Ok("op mismatch");
    }
    Ok(op_word(&op))
}

fn op_word(op: &Operation) -> &'static str {
    match op.status {
        OperationStatus::Pending | OperationStatus::Running => "op pending",
        OperationStatus::Done if op.succeeded() => "op done-ok",
        OperationStatus::Done => "op done-error",
    }
}

/// The zone operation list query of `own`'s operations (one page of at most 500). r18: no sort
/// order. GCE refuses a list filter together with `orderBy` (HTTP 400 "Specifying both a list
/// filter and sort order is not currently supported", run t RR-R17-3 A). The order is not needed:
/// only a provably complete list is accepted and every item of it is matched.
pub fn term_operation_list_path(own: &InstanceIdentity) -> String {
    format!(
        "projects/{}/zones/{}/operations?filter=targetId%20%3D%20{}&maxResults=500",
        own.project, own.zone, own.instance_id
    )
}

/// One operation of a list, with the `requestId` it was created with (if any).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedOperation {
    pub operation: Operation,
    pub client_operation_id: Option<String>,
}

/// r17: a zone operation list accepted only when it is provably complete (the stage16 P8 strict
/// rules, stricter on warnings): the list envelope of this project and zone, no further page, no
/// warning, every item of this zone and of the filtered target. `Err` is "not complete": it is
/// never read as an empty list.
pub fn parse_complete_operation_list(
    value: &Value,
    own: &InstanceIdentity,
) -> Result<Vec<ListedOperation>, String> {
    if value.get("kind").and_then(Value::as_str) != Some("compute#operationList") {
        return Err("not an operation list".to_string());
    }
    let id = format!("projects/{}/zones/{}/operations", own.project, own.zone);
    if value.get("id").and_then(Value::as_str) != Some(id.as_str()) {
        return Err("the list is not of this project and zone".to_string());
    }
    match value.get("nextPageToken") {
        None | Some(Value::Null) => {}
        Some(Value::String(token)) if token.is_empty() => {}
        Some(_) => return Err("the list has a further page".to_string()),
    }
    if value
        .get("warning")
        .is_some_and(|warning| !warning.is_null())
    {
        return Err("the list carries a warning".to_string());
    }
    let items = match value.get("items") {
        None => return Ok(Vec::new()),
        Some(Value::Array(items)) => items,
        Some(_) => return Err("the list items are not an array".to_string()),
    };
    let zone_suffix = format!("/zones/{}", own.zone);
    let mut listed = Vec::with_capacity(items.len());
    let mut names = Vec::with_capacity(items.len());
    for item in items {
        let operation = Operation::parse(item)?;
        if operation.target_id != own.instance_id {
            return Err("the list holds an operation of another target".to_string());
        }
        if !item
            .get("zone")
            .and_then(Value::as_str)
            .is_some_and(|zone| zone.ends_with(&zone_suffix))
        {
            return Err("the list holds an operation of another zone".to_string());
        }
        if names.contains(&operation.name) {
            return Err("the list holds a duplicated operation".to_string());
        }
        names.push(operation.name.clone());
        let client_operation_id = match item.get("clientOperationId") {
            None | Some(Value::Null) => None,
            Some(Value::String(id)) => Some(id.clone()),
            Some(_) => return Err("a clientOperationId is not a string".to_string()),
        };
        listed.push(ListedOperation {
            operation,
            client_operation_id,
        });
    }
    Ok(listed)
}

/// r17 (contract R5 C-5'): the term's own operation by its requestId. One API call. A complete
/// list without it is `op absent` (never proof that nothing was sent); a list that is not provably
/// complete, or a failed read, is `op unknown`; more than one match is `op mismatch`.
fn lookup_term_operation(api: &mut dyn ComputeTransport, binding: &RouteBinding) -> &'static str {
    let path = term_operation_list_path(&binding.own);
    let Ok(value) = classify(api.call(HttpMethod::Get, &path, None)) else {
        return "op unknown";
    };
    let Ok(listed) = parse_complete_operation_list(&value, &binding.own) else {
        return "op unknown";
    };
    let request_id = binding.request_id();
    let matches: Vec<&ListedOperation> = listed
        .iter()
        .filter(|item| item.client_operation_id.as_deref() == Some(request_id.as_str()))
        .collect();
    match matches.as_slice() {
        [] => "op absent",
        [one] if one.operation.operation_type == "updateNetworkInterface" => {
            op_word(&one.operation)
        }
        _ => "op mismatch",
    }
}

/// The body of the one alias update: every entry GCE returned (other ranges and their
/// `subnetworkRangeName` unchanged, J25 audit N-5) plus the missing protected ranges. `None` when
/// an existing entry overlaps a protected range without being one (nothing may be sent).
fn assign_body(observation: &RouteObservation, ranges: &[String]) -> Option<(Value, usize)> {
    let protected: Vec<Cidr> = ranges.iter().filter_map(|r| parse_cidr(r)).collect();
    let mut held = Vec::new();
    for entry in &observation.alias_entries {
        let range = entry.get("ipCidrRange").and_then(Value::as_str)?;
        let cidr = parse_cidr(range);
        let exact = cidr.is_some_and(|cidr| protected.contains(&cidr));
        if !exact && may_overlap(range, &protected) {
            return None;
        }
        held.push(cidr);
    }
    let mut wanted = observation.alias_entries.clone();
    let mut added = 0;
    for range in ranges {
        if !held.contains(&parse_cidr(range)) {
            wanted.push(json!({ "ipCidrRange": range }));
            added += 1;
        }
    }
    Some((
        json!({
            "aliasIpRanges": wanted,
            "fingerprint": observation.fingerprint,
        }),
        added,
    ))
}

/// Sends the one alias update of `key` (intent durable first; at most once per key).
fn send_assign(
    api: &mut dyn ComputeTransport,
    store: &mut dyn RouteStore,
    own: &InstanceIdentity,
    nic: &str,
    key: &str,
    request_id: &str,
    observation: &RouteObservation,
    ranges: &[String],
) -> String {
    match store.load_assign(key) {
        Ok(Some(record)) => return format!("already {}", record.phase.name()),
        Ok(None) => {}
        Err(_) => return "blocked".to_string(),
    }
    if observation.version != ROUTE_RECORD_VERSION
        || observation.key != key
        || &observation.own != own
        || observation.nic != nic
    {
        return "blocked".to_string();
    }
    let Some((body, added)) = assign_body(observation, ranges) else {
        return "blocked".to_string();
    };
    let body_text = body.to_string();
    let mut record = RouteAssignRecord {
        version: ROUTE_RECORD_VERSION,
        key: key.to_string(),
        request_id: request_id.to_string(),
        own: own.clone(),
        nic: nic.to_string(),
        phase: ActionPhase::Intent,
        base: Some(RouteBase {
            fingerprint: observation.fingerprint.clone(),
            alias_entries: observation.alias_entries.clone(),
            body_sha256: sha256_hex(&body_text),
        }),
    };
    if added == 0 {
        record.phase = ActionPhase::NotNeeded;
        return match store.save_assign(&record) {
            Ok(()) => "not-needed".to_string(),
            Err(_) => "blocked".to_string(),
        };
    }
    if store.save_assign(&record).is_err() {
        return "blocked".to_string();
    }
    let (phase, word) = patch_alias_update(api, own, nic, request_id, &body_text);
    record.phase = phase;
    match store.save_assign(&record) {
        Ok(()) => word.to_string(),
        // The intent stays durable, which `route-observe --part op` looks up by the requestId.
        Err(_) => "unknown".to_string(),
    }
}

fn sha256_hex(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The one PATCH of an alias update (bound to `request_id`) and its classification. The caller
/// has made its intent durable before this is called.
fn patch_alias_update(
    api: &mut dyn ComputeTransport,
    own: &InstanceIdentity,
    nic: &str,
    request_id: &str,
    body_text: &str,
) -> (ActionPhase, &'static str) {
    let path = format!(
        "{}/updateNetworkInterface?networkInterface={nic}&requestId={request_id}",
        own.path()
    );
    match classify(api.call(HttpMethod::Patch, &path, Some(body_text))) {
        Ok(value) => match Operation::parse(&value) {
            Ok(op)
                if op.target_id == own.instance_id
                    && op.operation_type == "updateNetworkInterface" =>
            {
                (ActionPhase::Accepted { operation: op.name }, "accepted")
            }
            Ok(op) => (
                ActionPhase::OutcomeUnknown {
                    failure: ApiFailure::Malformed(format!(
                        "the answer names a {} operation of target {}",
                        op.operation_type, op.target_id
                    )),
                },
                "unknown",
            ),
            Err(detail) => (
                ActionPhase::OutcomeUnknown {
                    failure: ApiFailure::Malformed(detail),
                },
                "unknown",
            ),
        },
        Err(failure) if failure.may_have_been_applied() => {
            (ActionPhase::OutcomeUnknown { failure }, "unknown")
        }
        Err(failure) => (ActionPhase::Refused { failure }, "refused"),
    }
}

/// r17 `route-reissue` (one API call; contract R5 §R): the term's one re-issue of the identical
/// alias update — the same `requestId` and the same body text — after the original request's
/// outcome stayed unknown. The daemon decides R-3, R-4, R-5 (operation never seen, two complete
/// absent lists a hold apart, the time window); the helper re-checks here, before anything is
/// sent: G-A3 (R-8), the original record (R-1, R-2), no newer route record (R-9), and that the
/// latest `own` observation is exactly the observation the body was built from, with none of the
/// protected ranges (R-6). The re-issue intent is durable before the request.
pub fn route_reissue(
    api: &mut dyn ComputeTransport,
    plan: &FencePlan,
    binding: &RouteBinding,
    fence_store: &mut dyn RecordStore,
    store: &mut dyn RouteStore,
) -> String {
    if route_check(plan, binding, fence_store).is_err() {
        return "refused".to_string();
    }
    let key = binding.key();
    let request_id = binding.request_id();
    // R-2 (helper side): at most one re-issue per key.
    match store.load_reissue(&key) {
        Ok(Some(record)) => return format!("already {}", record.phase.name()),
        Ok(None) => {}
        Err(_) => return "blocked".to_string(),
    }
    // R-1: the original request of this term, sent, with a "may have been applied" transport
    // outcome (not a malformed or mismatched answer), and its base persisted.
    let original = match store.load_assign(&key) {
        Ok(Some(record)) => record,
        _ => return "blocked".to_string(),
    };
    let eligible = matches!(
        &original.phase,
        ActionPhase::OutcomeUnknown {
            failure: ApiFailure::Timeout | ApiFailure::Transport(_) | ApiFailure::ServerError(_)
        }
    );
    let Some(base) = original.base.clone() else {
        return "blocked".to_string();
    };
    if !eligible
        || original.version != ROUTE_RECORD_VERSION
        || original.key != key
        || original.request_id != request_id
        || original.own != binding.own
        || original.nic != binding.nic
    {
        return "blocked".to_string();
    }
    // R-9: nothing else wrote a route record after this term's request.
    match store.newer_route_records(&key) {
        Ok(false) => {}
        _ => return "blocked".to_string(),
    }
    // R-6: the latest own observation is the base, with none of the protected ranges.
    let observation = match store.load_observation(&key) {
        Ok(Some(observation)) => observation,
        _ => return "blocked".to_string(),
    };
    if observation.version != ROUTE_RECORD_VERSION
        || observation.key != key
        || observation.own != binding.own
        || observation.nic != binding.nic
        || observation.coverage != "none"
        || observation.fingerprint != base.fingerprint
        || observation.alias_entries != base.alias_entries
    {
        return "blocked".to_string();
    }
    // The same body text as the original request (rebuilt from the base; checked by digest).
    let Some((body, added)) = assign_body(&observation, &binding.ranges) else {
        return "blocked".to_string();
    };
    let body_text = body.to_string();
    if added == 0 || sha256_hex(&body_text) != base.body_sha256 {
        return "blocked".to_string();
    }
    let mut record = RouteAssignRecord {
        version: ROUTE_RECORD_VERSION,
        key: key.clone(),
        request_id: request_id.clone(),
        own: binding.own.clone(),
        nic: binding.nic.clone(),
        phase: ActionPhase::Intent,
        base: Some(base),
    };
    if store.save_reissue(&record).is_err() {
        return "blocked".to_string();
    }
    let (phase, word) =
        patch_alias_update(api, &binding.own, &binding.nic, &request_id, &body_text);
    record.phase = phase;
    match store.save_reissue(&record) {
        Ok(()) => word.to_string(),
        Err(_) => "unknown".to_string(),
    }
}

/// `route-assign` (one API call): G-A3 again, then the term's one update, built from the recorded
/// `own` observation of the same key (its fingerprint and its whole entry list).
pub fn route_assign(
    api: &mut dyn ComputeTransport,
    plan: &FencePlan,
    binding: &RouteBinding,
    fence_store: &mut dyn RecordStore,
    store: &mut dyn RouteStore,
) -> String {
    if route_check(plan, binding, fence_store).is_err() {
        return "refused".to_string();
    }
    let key = binding.key();
    let observation = match store.load_observation(&key) {
        Ok(Some(observation)) => observation,
        _ => return "blocked".to_string(),
    };
    send_assign(
        api,
        store,
        &binding.own,
        &binding.nic,
        &key,
        &binding.request_id(),
        &observation,
        &binding.ranges,
    )
}

/// `operator-assign` (an operator command, never run by the daemon): one update bound to the
/// operator's request id, only after a fresh describe shows the peer TERMINATED and holding no
/// protected range on any NIC (contract §5.2).
pub fn operator_assign(
    api: &mut dyn ComputeTransport,
    plan: &FencePlan,
    own: &InstanceIdentity,
    operator_request: &str,
    store: &mut dyn RouteStore,
) -> String {
    let Some(alias) = plan.alias() else {
        return "blocked: no [alias]".to_string();
    };
    if !is_canonical_uuid_v4(operator_request) || own.validate().is_err() {
        return "blocked: bad request id or own instance".to_string();
    }
    let protected = protected_cidrs(alias);
    match observe(api, &plan.target) {
        Observed::Target(peer) => {
            if peer.status != "TERMINATED" {
                return format!("refused: the peer is {}, not TERMINATED", peer.status);
            }
            if peer
                .nics
                .iter()
                .flat_map(|nic| nic.alias_ranges.iter())
                .any(|range| may_overlap(range, &protected))
            {
                return "refused: the peer still holds a protected range".to_string();
            }
        }
        Observed::IdentityMismatch(_) => return "refused: the peer's identity differs".to_string(),
        Observed::Failed(failure) => return format!("blocked: {failure}"),
    }
    let instance = match observe(api, own) {
        Observed::Target(instance) => instance,
        Observed::IdentityMismatch(_) => return "refused: the own identity differs".to_string(),
        Observed::Failed(failure) => return format!("blocked: {failure}"),
    };
    let Some(nic) = instance.nic(&alias.nic) else {
        return "blocked: no such NIC".to_string();
    };
    let key = stable_hex(&[
        "mikagami-g2-operator-assign",
        &plan.cluster,
        operator_request,
    ]);
    let observation = RouteObservation {
        version: ROUTE_RECORD_VERSION,
        key: key.clone(),
        own: own.clone(),
        nic: alias.nic.clone(),
        fingerprint: nic.fingerprint.clone(),
        alias_entries: nic.alias_entries.clone(),
        coverage: coverage(nic, &alias.ranges).to_string(),
    };
    send_assign(
        api,
        store,
        own,
        &alias.nic,
        &key,
        operator_request,
        &observation,
        &alias.ranges,
    )
}

/// The §17.1 verify grammar the command backend parses (`fencing_backend::classify_verify`): only
/// exit 0 with exactly `isolated` lets the Node store write `CONFIRMED`; `not-isolated` gives
/// `FAILED`; a non-zero exit is an inconclusive poll.
pub const VERIFY_INCONCLUSIVE_EXIT: i32 = 3;

pub fn verify_output(verdict: &FinalVerdict) -> (i32, &'static str) {
    match verdict {
        FinalVerdict::Isolated(_) => (0, "isolated\n"),
        FinalVerdict::NotIsolated(_) => (0, "not-isolated\n"),
        FinalVerdict::Unknown(_) => (VERIFY_INCONCLUSIVE_EXIT, ""),
    }
}
