//! Google Compute Engine access through the `gcloud` command line tool.
//!
//! Only three things are needed: read one instance, replace the alias IP
//! ranges of its first network interface (the VIP is a /32 alias range), and
//! list the recent zonal operations that target one instance.
//!
//! Because a command can fail after the cloud already applied the change (or
//! time out before we learn the result), `set_aliases` reports what the tool
//! said and callers always re-observe through `describe`. A request that the
//! caller gave up on may still land later: `list_operations` is how callers
//! learn whether such a request is still pending (round-1 audit, C-01).

use super::config::ControlConfig;
use super::exec::{self, ExecCommand, ExecOutcome};
use serde_json::Value;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Alias {
    pub(crate) cidr: String,
    pub(crate) range_name: Option<String>,
}

impl Alias {
    pub(crate) fn plain(cidr: &str) -> Self {
        Self {
            cidr: cidr.to_string(),
            range_name: None,
        }
    }

    fn flag_value(&self) -> String {
        match &self.range_name {
            Some(name) => format!("{name}:{}", self.cidr),
            None => self.cidr.clone(),
        }
    }
}

/// The value of `--aliases=`. `gcloud ... network-interfaces update --help`
/// states that multiple ranges are separated by semicolons (round-1 audit,
/// C-05); a comma would be read as part of one range.
pub(crate) fn aliases_flag_value(aliases: &[Alias]) -> String {
    aliases
        .iter()
        .map(Alias::flag_value)
        .collect::<Vec<_>>()
        .join(";")
}

/// Parse the JSON array printed by `gcloud compute operations list`.
/// A row that cannot be understood makes the whole listing unusable
/// (fail closed): skipping it could hide a pending change.
pub(crate) fn parse_operations(text: &[u8], limit: usize) -> Result<OpList, Unavailable> {
    let value: Value = serde_json::from_slice(text)
        .map_err(|e| Unavailable(format!("operations output is not JSON: {e}")))?;
    let rows = value
        .as_array()
        .ok_or_else(|| Unavailable("operations output is not a list".into()))?;
    let mut ops = Vec::new();
    for row in rows {
        let name = str_field(row, "name")
            .filter(|n| !n.is_empty())
            .ok_or_else(|| Unavailable("an operation has no name".into()))?;
        let status = str_field(row, "status")
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Unavailable(format!("operation {name} has no status")))?;
        ops.push(CloudOp {
            op_type: str_field(row, "operationType").unwrap_or_default(),
            failed: row.get("error").is_some_and(|e| !e.is_null()),
            name,
            status,
        });
    }
    order_newest_first(&mut ops)?;
    let complete = ops.len() < limit;
    Ok(OpList { ops, complete })
}

/// The creation time of an operation in milliseconds since the epoch, taken
/// from its name (`operation-<ms>-<hex>-<hex>-<hex>`, observed on a real
/// project). `None` when the name does not have that shape.
pub(crate) fn op_name_epoch_ms(name: &str) -> Option<u64> {
    let rest = name.strip_prefix("operation-")?;
    let digits = rest.split('-').next()?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Put the rows newest first by the time in their names, not by the order the
/// tool printed them (audit RA-C-04). The tool sorts by `insertTime`, a
/// string that always carries the Pacific offset; across the end of daylight
/// saving time (an hour that exists twice) a string order can put a newer
/// operation behind an older one, and the "operations newer than the anchor"
/// rule reads positions. A listing whose rows cannot be ordered this way is
/// unusable (fail closed): a wrongly ordered list could hide a pending change.
/// The sort is stable, so rows of the same millisecond keep the tool's order.
fn order_newest_first(ops: &mut [CloudOp]) -> Result<(), Unavailable> {
    if ops.len() < 2 {
        return Ok(());
    }
    let mut keyed = Vec::with_capacity(ops.len());
    for op in ops.iter() {
        let Some(at) = op_name_epoch_ms(&op.name) else {
            return Err(Unavailable(format!(
                "operation {} has no creation time in its name; the listing cannot be ordered",
                op.name.chars().take(60).collect::<String>()
            )));
        };
        keyed.push(at);
    }
    let mut order: Vec<usize> = (0..ops.len()).collect();
    order.sort_by(|a, b| keyed[*b].cmp(&keyed[*a]));
    let sorted: Vec<CloudOp> = order.iter().map(|i| ops[*i].clone()).collect();
    ops.clone_from_slice(&sorted);
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InstanceInfo {
    pub(crate) name: String,
    pub(crate) id: String,
    pub(crate) status: String,
    pub(crate) aliases: Vec<Alias>,
    pub(crate) internal_ip: Option<String>,
    pub(crate) nat_ip: Option<String>,
    pub(crate) last_stop: Option<String>,
}

impl InstanceInfo {
    pub(crate) fn has_alias(&self, cidr: &str) -> bool {
        self.aliases.iter().any(|a| a.cidr == cidr)
    }
}

/// No usable observation could be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Unavailable(pub(crate) String);

impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// What the tool reported for a change request. `Done` is not proof: callers
/// verify by observation. `Error` and `TimedOut` are not proof of "unchanged".
///
/// `Rejected` is the one report that points to "not applied": the tool ended
/// with its error exit code and its message shows an explicit client error
/// (HTTP 4xx) of the update request itself ([`classify_update_failure`]). It
/// is still only a *claim*: the caller must see that no new operation of the
/// instance appears and that the alias list is unchanged before it treats the
/// request as refused. Anything the classifier is not sure about is `Error`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChangeReport {
    Done,
    Error(String),
    /// An explicit HTTP 4xx answer to the update request (see above).
    Rejected {
        status: u16,
        detail: String,
    },
    TimedOut,
}

/// The only client errors that count as "the request was refused before an
/// operation could be created": bad request, not authenticated, permission
/// denied, resource not found. Everything else (408 and 429 included, 409
/// and 412 as well) stays an unclassified error and ends UNKNOWN.
const REJECTION_STATUSES: [u16; 4] = [400, 401, 403, 404];

/// The prefix of the error line that gcloud prints for a failed
/// `network-interfaces update` when the API answered with an HTTP error.
/// NOT VERIFIED on a real project (R4 live check): if the real text differs,
/// nothing is classified and every failure stays UNKNOWN (safe).
const REJECTION_PREFIX: &str =
    "ERROR: (gcloud.compute.instances.network-interfaces.update) HTTPError ";

/// Words that show that the failure may belong to a later stage of the
/// command (it creates an operation first and then waits for it) or is not an
/// answer to the request at all. One of them anywhere in the text means "not
/// classified".
const LATER_STAGE_MARKERS: [&str; 9] = [
    "operation",
    "updated [",
    "timed out",
    "timeout",
    "deadline",
    "retry",
    "unavailable",
    "internal error",
    "backend",
];

/// Classify the end of a failed `gcloud ... network-interfaces update`.
///
/// `Rejected` only when **all** of these hold: the exit code is exactly 1;
/// nothing was printed on standard output; standard error is complete, valid
/// UTF-8 and short; its first line is the update command's own `HTTPError`
/// line with a status of [`REJECTION_STATUSES`]; there is exactly one
/// `HTTPError`; and no word of [`LATER_STAGE_MARKERS`] appears. Everything
/// else — other exit codes, a signal, truncated or non-UTF-8 output, a 5xx,
/// 408/429, a message that mentions an operation, a text we do not know — is
/// `Error`. Doubt always means `Error` (UNKNOWN downstream).
pub(crate) fn classify_update_failure(
    code: Option<i32>,
    stdout: &exec::Captured,
    stderr: &exec::Captured,
) -> ChangeReport {
    let generic = || {
        ChangeReport::Error(format!(
            "gcloud update exited {code:?}: {}",
            stderr.text().trim().chars().take(300).collect::<String>()
        ))
    };
    if code != Some(1) || stdout.truncated || stderr.truncated {
        return generic();
    }
    if !stdout.bytes.iter().all(u8::is_ascii_whitespace) {
        return generic();
    }
    let Ok(text) = String::from_utf8(stderr.bytes.clone()) else {
        return generic();
    };
    if text.len() > 4096 || text.lines().count() > 20 {
        return generic();
    }
    let lowered = text.to_ascii_lowercase();
    if LATER_STAGE_MARKERS.iter().any(|m| lowered.contains(m)) {
        return generic();
    }
    if text.matches("HTTPError").count() != 1 {
        return generic();
    }
    let Some(first) = text.lines().map(str::trim).find(|l| !l.is_empty()) else {
        return generic();
    };
    let Some(rest) = first.strip_prefix(REJECTION_PREFIX) else {
        return generic();
    };
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    let after = &rest[digits.len()..];
    let status = digits.parse::<u16>().ok();
    match status {
        Some(status)
            if digits.len() == 3
                && REJECTION_STATUSES.contains(&status)
                && (after.is_empty() || after.starts_with(':')) =>
        {
            ChangeReport::Rejected {
                status,
                detail: first.chars().take(300).collect(),
            }
        }
        _ => generic(),
    }
}

/// One zonal operation that targets an instance (a row of
/// `gcloud compute operations list`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CloudOp {
    pub(crate) name: String,
    /// For example `compute.instances.updateNetworkInterface`.
    pub(crate) op_type: String,
    /// `PENDING`, `RUNNING` or `DONE`.
    pub(crate) status: String,
    /// `DONE` with an error object: the request was not applied.
    pub(crate) failed: bool,
}

impl CloudOp {
    pub(crate) fn is_done(&self) -> bool {
        self.status == "DONE"
    }

    /// An alias change. The exact type string was not observed on a real
    /// project in this round (NOT VERIFIED, see LIMITATIONS).
    pub(crate) fn is_nic_update(&self) -> bool {
        self.op_type.contains("updateNetworkInterface")
    }
}

/// Newest-first listing of the operations that target one instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OpList {
    pub(crate) ops: Vec<CloudOp>,
    /// `false` when the cloud (or the page limit) may have hidden older rows.
    pub(crate) complete: bool,
}

/// How many operations one listing asks for.
pub(crate) const OPS_LIMIT: usize = 100;

pub(crate) trait Gce {
    fn describe(&self, instance: &str) -> Result<InstanceInfo, Unavailable>;
    /// `tag` identifies the issuing operation for audit purposes only; it is
    /// never sent to the cloud.
    fn set_aliases(&self, instance: &str, aliases: &[Alias], tag: &str) -> ChangeReport;
    fn list_operations(&self, instance: &str) -> Result<OpList, Unavailable>;
}

pub(crate) struct GcloudGce {
    gcloud: String,
    project: String,
    zone: String,
}

const PASS_ENV: &[&str] = &[
    "HOME",
    "PATH",
    "USER",
    "LANG",
    "TMPDIR",
    "CLOUDSDK_CONFIG",
    "CLOUDSDK_PYTHON",
    "CLOUDSDK_ACTIVE_CONFIG_NAME",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "SSL_CERT_FILE",
    "HTTPS_PROXY",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
];

impl GcloudGce {
    pub(crate) fn new(cfg: &ControlConfig) -> Self {
        Self {
            gcloud: cfg.gcloud_tool.clone(),
            project: cfg.project.clone(),
            zone: cfg.zone.clone(),
        }
    }

    fn command(&self, args: Vec<String>, timeout: Duration) -> ExecCommand {
        let mut command = ExecCommand::new(self.gcloud.clone(), args, timeout);
        for key in PASS_ENV {
            if let Ok(value) = std::env::var(key) {
                command = command.with_env(key, &value);
            }
        }
        command.with_env("CLOUDSDK_CORE_DISABLE_PROMPTS", "1")
    }
}

fn str_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

pub(crate) fn parse_instance(
    text: &[u8],
    expected_name: &str,
) -> Result<InstanceInfo, Unavailable> {
    let value: Value = serde_json::from_slice(text)
        .map_err(|e| Unavailable(format!("describe output is not JSON: {e}")))?;
    let name = str_field(&value, "name").ok_or_else(|| Unavailable("no instance name".into()))?;
    if name != expected_name {
        return Err(Unavailable(format!(
            "describe returned instance {name:?}, expected {expected_name:?}"
        )));
    }
    let id = str_field(&value, "id").ok_or_else(|| Unavailable("no instance id".into()))?;
    let status = str_field(&value, "status").ok_or_else(|| Unavailable("no status".into()))?;
    let nic = value
        .get("networkInterfaces")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .ok_or_else(|| Unavailable("instance has no network interface".into()))?;
    let aliases = nic
        .get("aliasIpRanges")
        .and_then(Value::as_array)
        .map(|ranges| {
            ranges
                .iter()
                .filter_map(|r| {
                    str_field(r, "ipCidrRange").map(|cidr| Alias {
                        cidr,
                        range_name: str_field(r, "subnetworkRangeName"),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let nat_ip = nic
        .get("accessConfigs")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(|a| str_field(a, "natIP"));
    Ok(InstanceInfo {
        name,
        id,
        status,
        aliases,
        internal_ip: str_field(nic, "networkIP"),
        nat_ip,
        last_stop: str_field(&value, "lastStopTimestamp"),
    })
}

impl Gce for GcloudGce {
    fn describe(&self, instance: &str) -> Result<InstanceInfo, Unavailable> {
        let command = self.command(
            vec![
                "compute".into(),
                "instances".into(),
                "describe".into(),
                instance.into(),
                "--zone".into(),
                self.zone.clone(),
                "--project".into(),
                self.project.clone(),
                "--format=json".into(),
                "--quiet".into(),
            ],
            Duration::from_secs(60),
        );
        match exec::run(&command) {
            ExecOutcome::Exited {
                code: Some(0),
                stdout,
                ..
            } if !stdout.truncated => parse_instance(&stdout.bytes, instance),
            ExecOutcome::Exited { code, stderr, .. } => Err(Unavailable(format!(
                "gcloud describe exited {code:?}: {}",
                stderr.text().trim().chars().take(200).collect::<String>()
            ))),
            ExecOutcome::TimedOut { .. } => Err(Unavailable("gcloud describe timed out".into())),
            ExecOutcome::SpawnFailed(e) => Err(Unavailable(format!("gcloud: {e}"))),
        }
    }

    fn list_operations(&self, instance: &str) -> Result<OpList, Unavailable> {
        let command = self.command(
            vec![
                "compute".into(),
                "operations".into(),
                "list".into(),
                "--zones".into(),
                self.zone.clone(),
                "--project".into(),
                self.project.clone(),
                format!("--filter=targetLink~'/instances/{instance}$'"),
                "--sort-by=~insertTime".into(),
                format!("--limit={OPS_LIMIT}"),
                "--format=json".into(),
                "--quiet".into(),
            ],
            Duration::from_secs(60),
        );
        match exec::run(&command) {
            ExecOutcome::Exited {
                code: Some(0),
                stdout,
                ..
            } if !stdout.truncated => parse_operations(&stdout.bytes, OPS_LIMIT),
            ExecOutcome::Exited { code, stderr, .. } => Err(Unavailable(format!(
                "gcloud operations list exited {code:?}: {}",
                stderr.text().trim().chars().take(200).collect::<String>()
            ))),
            ExecOutcome::TimedOut { .. } => {
                Err(Unavailable("gcloud operations list timed out".into()))
            }
            ExecOutcome::SpawnFailed(e) => Err(Unavailable(format!("gcloud: {e}"))),
        }
    }

    fn set_aliases(&self, instance: &str, aliases: &[Alias], _tag: &str) -> ChangeReport {
        let value = aliases_flag_value(aliases);
        let command = self.command(
            vec![
                "compute".into(),
                "instances".into(),
                "network-interfaces".into(),
                "update".into(),
                instance.into(),
                "--zone".into(),
                self.zone.clone(),
                "--project".into(),
                self.project.clone(),
                "--network-interface=nic0".into(),
                format!("--aliases={value}"),
                "--quiet".into(),
            ],
            Duration::from_secs(180),
        );
        match exec::run(&command) {
            ExecOutcome::Exited { code: Some(0), .. } => ChangeReport::Done,
            ExecOutcome::Exited {
                code,
                stdout,
                stderr,
            } => classify_update_failure(code, &stdout, &stderr),
            ExecOutcome::TimedOut { .. } => ChangeReport::TimedOut,
            ExecOutcome::SpawnFailed(e) => ChangeReport::Error(format!("gcloud: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "id": "1234567890", "name": "inst-a", "status": "RUNNING",
      "lastStopTimestamp": "2026-10-24T00:00:00.000-07:00",
      "networkInterfaces": [{
        "networkIP": "10.0.0.10",
        "accessConfigs": [{"natIP": "203.0.113.5"}],
        "aliasIpRanges": [
          {"ipCidrRange": "10.0.0.130/32"},
          {"ipCidrRange": "10.9.0.0/24", "subnetworkRangeName": "pods"}
        ]
      }]
    }"#;

    #[test]
    fn parses_a_describe_document() {
        let info = parse_instance(SAMPLE.as_bytes(), "inst-a").unwrap();
        assert_eq!(info.id, "1234567890");
        assert_eq!(info.status, "RUNNING");
        assert!(info.has_alias("10.0.0.130/32"));
        assert_eq!(info.aliases[1].range_name.as_deref(), Some("pods"));
        assert_eq!(info.nat_ip.as_deref(), Some("203.0.113.5"));
        assert_eq!(info.aliases[1].flag_value(), "pods:10.9.0.0/24");
    }

    #[test]
    fn rejects_wrong_instance_garbage_and_missing_fields() {
        assert!(parse_instance(SAMPLE.as_bytes(), "inst-b").is_err());
        assert!(parse_instance(b"not json", "inst-a").is_err());
        assert!(parse_instance(b"{}", "inst-a").is_err());
        let no_nic = SAMPLE.replace("networkInterfaces", "other");
        assert!(parse_instance(no_nic.as_bytes(), "inst-a").is_err());
    }

    #[test]
    fn multiple_alias_ranges_are_joined_with_semicolons() {
        let two = [Alias::plain("10.0.0.130/32"), Alias::plain("10.9.0.0/24")];
        assert_eq!(aliases_flag_value(&two), "10.0.0.130/32;10.9.0.0/24");
        let named = [
            Alias::plain("10.0.0.130/32"),
            Alias {
                cidr: "10.9.0.0/24".into(),
                range_name: Some("pods".into()),
            },
        ];
        assert_eq!(aliases_flag_value(&named), "10.0.0.130/32;pods:10.9.0.0/24");
        assert_eq!(aliases_flag_value(&[]), "");
    }

    #[test]
    fn operations_listing_is_parsed_strictly() {
        let text = br#"[
          {"name":"operation-2","operationType":"compute.instances.updateNetworkInterface","status":"RUNNING"},
          {"name":"operation-1","operationType":"compute.instances.updateNetworkInterface","status":"DONE",
           "error":{"errors":[{"code":"X"}]}},
          {"name":"operation-0","status":"DONE"}
        ]"#;
        let list = parse_operations(text, OPS_LIMIT).unwrap();
        assert!(list.complete);
        assert_eq!(list.ops.len(), 3);
        assert!(!list.ops[0].is_done() && list.ops[0].is_nic_update());
        assert!(list.ops[1].is_done() && list.ops[1].failed);
        assert!(!list.ops[2].failed && !list.ops[2].is_nic_update());
        // A full page may hide older rows.
        assert!(!parse_operations(text, 3).unwrap().complete);
        // Anything not understood makes the listing unusable.
        for bad in [
            &b"not json"[..],
            br#"{"name":"x"}"#,
            br#"[{"status":"DONE"}]"#,
            br#"[{"name":"x"}]"#,
            br#"[{"name":"","status":"DONE"}]"#,
        ] {
            assert!(parse_operations(bad, OPS_LIMIT).is_err());
        }
        assert!(parse_operations(b"[]", OPS_LIMIT).unwrap().ops.is_empty());
    }

    #[test]
    fn ra_c04_the_listing_is_ordered_by_the_time_in_the_names_not_by_the_tools_order() {
        // Across the end of daylight saving time the tool's string order of
        // `insertTime` can put the newer operation second. Both rows below
        // carry the Pacific offsets of the repeated hour: the older one was
        // inserted at 01:30 -07:00, the newer one at 01:10 -08:00 (which sorts
        // BELOW the older one as a string).
        let text = br#"[
          {"name":"operation-1793000000000-aaaa-bbbb-cccc","operationType":"updateNetworkInterface",
           "status":"DONE","insertTime":"2026-11-01T01:30:00.000-07:00"},
          {"name":"operation-1793003000000-dddd-eeee-ffff","operationType":"updateNetworkInterface",
           "status":"DONE","insertTime":"2026-11-01T01:10:00.000-08:00"}
        ]"#;
        let list = parse_operations(text, OPS_LIMIT).unwrap();
        let names: Vec<&str> = list.ops.iter().map(|o| o.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "operation-1793003000000-dddd-eeee-ffff",
                "operation-1793000000000-aaaa-bbbb-cccc"
            ],
            "the newer operation comes first"
        );
        // Already ordered input stays as it is; equal times keep the tool's
        // order (stable sort).
        let same = br#"[
          {"name":"operation-1793000000000-x-1","status":"DONE"},
          {"name":"operation-1793000000000-x-2","status":"DONE"},
          {"name":"operation-1792999999999-x-3","status":"DONE"}
        ]"#;
        let kept = parse_operations(same, OPS_LIMIT).unwrap();
        assert_eq!(kept.ops[0].name, "operation-1793000000000-x-1");
        assert_eq!(kept.ops[1].name, "operation-1793000000000-x-2");
        // Fail closed: a listing of several rows with a name that carries no
        // time cannot be ordered, and must not be used.
        for bad in [
            br#"[{"name":"operation-1-a","status":"DONE"},{"name":"other","status":"DONE"}]"#
                .as_slice(),
            br#"[{"name":"operation-1-a","status":"DONE"},{"name":"operation-x-a","status":"DONE"}]"#,
            br#"[{"name":"operation-1-a","status":"DONE"},{"name":"operation--a","status":"DONE"}]"#,
            br#"[{"name":"operation-99999999999999999999999-a","status":"DONE"},{"name":"operation-1-a","status":"DONE"}]"#,
        ] {
            assert!(parse_operations(bad, OPS_LIMIT).is_err());
        }
        // One row has nothing to be ordered against.
        assert!(parse_operations(br#"[{"name":"odd","status":"DONE"}]"#, OPS_LIMIT).is_ok());
        assert_eq!(op_name_epoch_ms("operation-12-ab-cd"), Some(12));
        assert_eq!(op_name_epoch_ms("operation-12"), Some(12));
        assert_eq!(op_name_epoch_ms("op-12"), None);
        assert_eq!(op_name_epoch_ms("operation-"), None);
    }

    fn cap(text: &str) -> exec::Captured {
        exec::Captured {
            bytes: text.as_bytes().to_vec(),
            truncated: false,
        }
    }

    const UPDATE_ERR: &str =
        "ERROR: (gcloud.compute.instances.network-interfaces.update) HTTPError";

    fn classify(code: Option<i32>, out: &str, err: &str) -> ChangeReport {
        classify_update_failure(code, &cap(out), &cap(err))
    }

    fn is_rejected(report: &ChangeReport, expected: u16) -> bool {
        matches!(report, ChangeReport::Rejected { status, .. } if *status == expected)
    }

    #[test]
    fn r4_an_explicit_client_error_of_the_update_request_is_rejected() {
        // The four statuses of the list, with and without a message.
        for (status, message) in [
            (
                403,
                "Required 'compute.instances.updateNetworkInterface' permission for 'projects/p/zones/z/instances/i'",
            ),
            (
                404,
                "The resource 'projects/p/zones/z/instances/i' was not found",
            ),
            (
                400,
                "Invalid value for field 'aliasIpRanges[0].ipCidrRange'",
            ),
            (401, "Login Required"),
        ] {
            let err = format!("{UPDATE_ERR} {status}: {message}\n");
            assert!(
                is_rejected(&classify(Some(1), "", &err), status),
                "{status}"
            );
        }
        // Surrounding blank lines and a status without a message are fine.
        let err = format!("\n{UPDATE_ERR} 403\n\n");
        assert!(is_rejected(&classify(Some(1), "\n", &err), 403));
        // The detail is bounded and carries the line, not the whole text.
        let long = format!("{UPDATE_ERR} 403: {}\n", "x".repeat(1000));
        match classify(Some(1), "", &long) {
            ChangeReport::Rejected { detail, .. } => assert!(detail.chars().count() <= 300),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn r4_everything_that_is_not_certainly_a_client_error_stays_an_error() {
        let ok403 = format!("{UPDATE_ERR} 403: denied\n");
        let is_error = |r: ChangeReport| matches!(r, ChangeReport::Error(_));
        // Not exit code 1 (a signal gives None; other codes are not gcloud's
        // error exit).
        for code in [None, Some(2), Some(-1), Some(137), Some(255)] {
            assert!(is_error(classify(code, "", &ok403)), "{code:?}");
        }
        // Server errors and the statuses that are not on the list.
        for status in [
            408, 409, 412, 429, 500, 502, 503, 504, 302, 200, 4030, 40, 0, 999,
        ] {
            let err = format!("{UPDATE_ERR} {status}: x\n");
            assert!(is_error(classify(Some(1), "", &err)), "{status}");
        }
        // A status glued to other characters is not a status.
        for tail in ["x: y", "403: ok", "-403", "+403"] {
            let err = format!("{UPDATE_ERR} {tail}\n");
            if tail == "403: ok" {
                assert!(is_rejected(&classify(Some(1), "", &err), 403));
            } else {
                assert!(is_error(classify(Some(1), "", &err)), "{tail}");
            }
        }
        // Output we do not know: other command name, no marker, free text,
        // the "Could not fetch resource" form (no status in it), empty.
        for err in [
            "ERROR: (gcloud.compute.instances.describe) HTTPError 403: denied\n",
            "ERROR: (gcloud.compute.instances.network-interfaces.update) Could not fetch resource:\n - denied\n",
            "ERROR: (gcloud.compute.instances.network-interfaces.update) Some requests did not succeed:\n - denied\n",
            "permission denied\n",
            "HTTPError 403: denied\n",
            "",
            "   \n",
            "ERROR: (gcloud.compute.instances.network-interfaces.update) HTTPError 403\nERROR: (gcloud.compute.instances.network-interfaces.update) HTTPError 403\n",
        ] {
            assert!(is_error(classify(Some(1), "", err)), "{err:?}");
        }
        // The error line is not the first line: not ours to interpret.
        let later = format!("Updating network interface...\n{UPDATE_ERR} 403: denied\n");
        assert!(is_error(classify(Some(1), "", &later)));
        // Anything on standard output (a success-like or unknown answer).
        assert!(is_error(classify(Some(1), "{\"x\":1}", &ok403)));
        // Truncated or non-UTF-8 output, or too much of it.
        assert!(is_error(classify_update_failure(
            Some(1),
            &cap(""),
            &exec::Captured {
                bytes: ok403.as_bytes().to_vec(),
                truncated: true
            }
        )));
        assert!(is_error(classify_update_failure(
            Some(1),
            &exec::Captured {
                bytes: Vec::new(),
                truncated: true
            },
            &cap(&ok403)
        )));
        let mut bad = ok403.as_bytes().to_vec();
        bad.push(0xff);
        assert!(is_error(classify_update_failure(
            Some(1),
            &cap(""),
            &exec::Captured {
                bytes: bad,
                truncated: false
            }
        )));
        let big = format!("{UPDATE_ERR} 403: {}\n", "x".repeat(5000));
        assert!(is_error(classify(Some(1), "", &big)));
        let many = format!("{UPDATE_ERR} 403: denied\n{}", "more\n".repeat(30));
        assert!(is_error(classify(Some(1), "", &many)));
    }

    #[test]
    fn r4_a_failure_that_may_belong_to_a_later_stage_is_never_rejected() {
        // The command creates an operation first and then waits for it: a
        // 4xx while waiting (for example no permission to read the operation)
        // comes after the change was accepted.
        for message in [
            "Required 'compute.zoneOperations.get' permission for 'projects/p/zones/z/operations/operation-1'",
            "operation-1234 not found",
            "Operation timed out",
            "request timeout",
            "deadline exceeded while waiting",
            "will retry",
            "Updated [https://example.invalid/instances/i].",
            "backend unavailable",
            "internal error encountered",
        ] {
            let err = format!("{UPDATE_ERR} 404: {message}\n");
            assert!(
                matches!(classify(Some(1), "", &err), ChangeReport::Error(_)),
                "{message}"
            );
        }
        // The same words anywhere in the text, not only in the HTTPError line.
        let err = format!("{UPDATE_ERR} 403: denied\nwaiting for operation\n");
        assert!(matches!(
            classify(Some(1), "", &err),
            ChangeReport::Error(_)
        ));
    }

    #[test]
    fn an_instance_without_aliases_has_an_empty_list() {
        let text = r#"{"id":"1","name":"i","status":"TERMINATED",
            "networkInterfaces":[{"networkIP":"10.0.0.1"}]}"#;
        let info = parse_instance(text.as_bytes(), "i").unwrap();
        assert!(info.aliases.is_empty());
        assert_eq!(info.nat_ip, None);
    }
}
