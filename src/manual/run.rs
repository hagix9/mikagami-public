//! Command execution glue: configuration, real adapters, rendering and exit
//! codes of the manual control plane.

use super::cli_def::{
    ChronydCommands, MovableResource, ResourceCommands, ResourceName, ServiceResource,
};
use super::clock::SystemClock;
use super::config::{ConfigError, ControlConfig};
use super::gce::GcloudGce;
use super::remote::SshRemote;
use super::{
    Ctx, EXIT_FAILED, EXIT_UNKNOWN, Failure, Res, StderrReporter, chrony_ctl, clean_for_terminal,
    clean_json_for_terminal, resource, result_word, say_err, say_out, short_digest, signals, vip,
};
use serde::Serialize;
use serde_json::{Value, json};
use std::fmt::Write as _;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// What a command produced: a human rendering, a JSON document and the exit
/// code that reflects the observed state.
pub(crate) struct Output {
    pub(crate) text: String,
    pub(crate) json: Value,
    pub(crate) exit: u8,
}

fn to_value<T: Serialize>(report: &T) -> Value {
    serde_json::to_value(report).unwrap_or(Value::Null)
}

fn clean(text: &str) -> String {
    clean_for_terminal(text)
}

/// The `--json` document of a failed command. `exit` is the process exit
/// code and `result` its word (R4), so the document alone says what the
/// shell sees.
pub(crate) fn failure_document(failure: &Failure) -> Value {
    json!({
        "ok": false,
        "result": failure.label().to_lowercase(),
        "exit": failure.exit_code(),
        "error": clean(failure.message()),
    })
}

/// The `--json` document of a command that produced an [`Output`]: its own
/// document plus `ok` (true exactly when the exit code is 0), `exit` and
/// `result`. Keys the command already set are overwritten: these three always
/// agree with the exit code.
pub(crate) fn success_document(output: &Output) -> Value {
    let mut document = output.json.clone();
    clean_json_for_terminal(&mut document);
    if let Value::Object(map) = &mut document {
        map.insert("ok".to_string(), Value::Bool(output.exit == 0));
        map.insert("exit".to_string(), Value::from(output.exit));
        map.insert("result".to_string(), Value::from(result_word(output.exit)));
    }
    document
}

fn render_failure(failure: &Failure, as_json: bool) -> ExitCode {
    say_err(&clean(&failure.to_string()));
    if as_json {
        say_out(&format!(
            "{}\n",
            serde_json::to_string_pretty(&failure_document(failure)).unwrap_or_default()
        ));
    }
    ExitCode::from(failure.exit_code())
}

fn emit(output: Output, as_json: bool) -> ExitCode {
    if as_json {
        say_out(&format!(
            "{}\n",
            serde_json::to_string_pretty(&success_document(&output)).unwrap_or_default()
        ));
    } else {
        let mut text = clean(&output.text);
        if !text.ends_with('\n') {
            text.push('\n');
        }
        say_out(&text);
    }
    ExitCode::from(output.exit)
}

fn load_config(path: Option<&Path>) -> Result<ControlConfig, Failure> {
    let path = ControlConfig::resolve_path(path);
    ControlConfig::load(&path).map_err(|e| match e {
        ConfigError::Io(m) => Failure::Refused(format!(
            "cannot read the control configuration {}: {m}",
            path.display()
        )),
        other => Failure::Refused(other.to_string()),
    })
}

fn prepare_state_dir(cfg: &ControlConfig) -> Res<()> {
    let dir: &Path = &cfg.state_dir;
    match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => Err(Failure::Refused(format!(
            "state directory {} is not a directory",
            dir.display()
        ))),
        Err(_) => std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| {
                Failure::Refused(format!(
                    "cannot create state directory {}: {e}",
                    dir.display()
                ))
            }),
    }
}

/// Build the production context and run `body` with it.
fn with_context<F>(config: Option<&Path>, body: F) -> Res<Output>
where
    F: FnOnce(&Ctx<'_>) -> Res<Output>,
{
    let cfg = load_config(config)?;
    prepare_state_dir(&cfg)?;
    let gce = GcloudGce::new(&cfg);
    let remote = SshRemote::new(&cfg);
    let clock = SystemClock::new();
    let log = StderrReporter;
    let ctx = Ctx::new(&cfg, &gce, &remote, &clock, &log);
    body(&ctx)
}

fn finish_json(result: Res<Output>, as_json: bool) -> ExitCode {
    match result {
        Ok(output) => emit(output, as_json),
        Err(failure) => render_failure(&failure, as_json),
    }
}

fn default_node(ctx: &Ctx<'_>, node: Option<&String>) -> String {
    node.cloned()
        .unwrap_or_else(|| ctx.cfg.nodes[0].name.clone())
}

// ---------------------------------------------------------------------------
// resource
// ---------------------------------------------------------------------------

/// Run a command to its end whatever happens around it (audit E-01):
///
/// * a command that changes something holds SIGINT/SIGTERM/SIGHUP until it is
///   done (a second signal ends it at once as UNKNOWN);
/// * a panic never escapes as exit code 101: the command's result is
///   UNKNOWN (4), because something may have been changed before it;
/// * output problems are ignored (`say_out`/`say_err`), so they cannot
///   interrupt a rollback.
fn guarded(changes_something: bool, body: impl FnOnce() -> ExitCode) -> ExitCode {
    if changes_something {
        signals::hold();
    }
    let code = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)).unwrap_or_else(|_| {
        say_err(
            "UNKNOWN: the command failed unexpectedly (internal error). Something may have been \
             changed before it stopped: run `resource status vip` and `chronyd show` before \
             anything else.",
        );
        ExitCode::from(EXIT_UNKNOWN)
    });
    if changes_something && let Some(signal) = signals::received() {
        say_err(&format!(
            "note: signal {signal} arrived while the command was running; it was held until the \
             command finished so that no change was interrupted"
        ));
    }
    code
}

pub(crate) fn resource(command: ResourceCommands) -> ExitCode {
    let changes = !matches!(
        command,
        ResourceCommands::List { .. } | ResourceCommands::Status { .. }
    );
    guarded(changes, || resource_command(command))
}

fn resource_command(command: ResourceCommands) -> ExitCode {
    let (config, json) = resource_common(&command);
    finish_json(
        with_context(config.as_deref(), |ctx| execute_resource(ctx, command)),
        json,
    )
}

/// Where a resource command reads its configuration and whether it prints JSON.
fn resource_common(command: &ResourceCommands) -> (Option<PathBuf>, bool) {
    let common = match command {
        ResourceCommands::List { common }
        | ResourceCommands::Status { common, .. }
        | ResourceCommands::Move { common, .. }
        | ResourceCommands::Init { common, .. }
        | ResourceCommands::Reconcile { common, .. }
        | ResourceCommands::Start { common, .. }
        | ResourceCommands::Stop { common, .. }
        | ResourceCommands::Restart { common, .. } => common,
    };
    (common.config.clone(), common.json)
}

/// Run one `resource` command against a context. Everything a command
/// prints and every exit code comes out of here, so the tests of the
/// exit-code / JSON contract (R4) drive exactly this function.
pub(crate) fn execute_resource(ctx: &Ctx<'_>, command: ResourceCommands) -> Res<Output> {
    match command {
        ResourceCommands::List { .. } => {
            let rows = resource::list(ctx)?;
            let mut text = String::new();
            for row in &rows {
                let _ = writeln!(
                    text,
                    "{:<8} {:<16} configured: {}",
                    row.name, row.kind, row.configured
                );
                let _ = writeln!(text, "{:<8} {:<16} observed:   {}", "", "", row.runtime);
            }
            Ok(Output {
                json: json!({"ok": true, "resources": rows}),
                text,
                exit: 0,
            })
        }
        ResourceCommands::Status {
            resource: name,
            node,
            ..
        } => match name {
            ResourceName::Vip => {
                let status = vip::vip_status(ctx);
                Ok(render_vip_status(&status))
            }
            ResourceName::Chronyd => {
                let value = resource::chronyd_status(ctx, node.as_deref())?;
                let healthy = value["healthy"].as_bool() == Some(true);
                // (without the VIP picture the exclusion from the HA daemon is not known here;
                // the advice names the apply's own refusal for that case)
                let guidance = super::guidance::for_chronyd(&value, &[]);
                let mut value = value;
                if let Value::Object(map) = &mut value {
                    map.insert("guidance".to_string(), to_value(&guidance));
                }
                let mut text = render_chronyd_status(&value);
                text.push_str(&guidance.text());
                Ok(Output {
                    text,
                    json: value,
                    exit: if healthy { 0 } else { super::EXIT_UNKNOWN },
                })
            }
            ResourceName::Demo => {
                let value = resource::demo_status(ctx)?;
                let observed = value["nodes"].as_object().is_some_and(|nodes| {
                    nodes.values().all(|n| {
                        n["reachable"] == true
                            && n.get("error").is_none()
                            && n["active"].is_boolean()
                    })
                });
                Ok(Output {
                    text: serde_json::to_string_pretty(&value).unwrap_or_default(),
                    json: value,
                    exit: if observed { 0 } else { super::EXIT_UNKNOWN },
                })
            }
        },
        ResourceCommands::Move {
            resource: MovableResource::Vip,
            to,
            confirm_fenced,
            ..
        } => {
            let report = vip::move_vip(
                ctx,
                &vip::MoveRequest {
                    target: to,
                    confirm_fenced,
                },
            )?;
            let mut text = String::new();
            let _ = writeln!(
                text,
                "move: ok {} -> {} (op={})",
                report.source, report.target, report.op_id
            );
            let _ = writeln!(
                text,
                "vip: {} owner={} served_by={} epoch {} -> {}{}",
                ctx.cfg.vip,
                report.target,
                report.served_by,
                report.epoch_before,
                report.epoch_after,
                if report.fenced_source {
                    " (source was fenced)"
                } else {
                    ""
                }
            );
            let _ = writeln!(text, "note: {}", report.advice);
            Ok(Output {
                json: to_value(&report),
                text,
                exit: 0,
            })
        }
        ResourceCommands::Init {
            resource: MovableResource::Vip,
            owner,
            reinit,
            ..
        } => {
            let report = vip::init_vip(ctx, &owner, reinit)?;
            Ok(Output {
                text: format!(
                    "init: vip owner recorded as {} (epoch {}, fencing seq {}); ha_daemon: {}\n",
                    report.owner,
                    report.epoch,
                    report.seq,
                    ha_summary(&report.evidence)
                ),
                json: to_value(&report),
                exit: 0,
            })
        }
        ResourceCommands::Reconcile {
            resource: MovableResource::Vip,
            abandon_op,
            accept_unconfirmed_cloud_change,
            ..
        } => {
            let report =
                vip::reconcile_vip(ctx, abandon_op.as_deref(), accept_unconfirmed_cloud_change)?;
            Ok(Output {
                text: if report.changed {
                    format!(
                        "reconcile: recorded owner is now {} (epoch {}), operation record \
                             cleared; ha_daemon: {}\n",
                        report.owner,
                        report.epoch,
                        ha_summary(&report.evidence)
                    )
                } else {
                    format!(
                        "reconcile: already consistent, owner {} (epoch {}); nothing changed; \
                             ha_daemon: {}\n",
                        report.owner,
                        report.epoch,
                        ha_summary(&report.evidence)
                    )
                },
                json: to_value(&report),
                exit: 0,
            })
        }
        ResourceCommands::Start {
            resource: ServiceResource::Chronyd,
            node,
            ..
        } => service_output(ctx, "start", &node),
        ResourceCommands::Stop {
            resource: ServiceResource::Chronyd,
            node,
            ..
        } => service_output(ctx, "stop", &node),
        ResourceCommands::Restart {
            resource: ServiceResource::Chronyd,
            node,
            ..
        } => service_output(ctx, "restart", &node),
    }
}

/// `node-a=masked, node-b=masked, witness=masked` from the evidence of an
/// `init` / `reconcile` (a TERMINATED peer is not asked and not listed).
fn ha_summary(evidence: &Value) -> String {
    evidence
        .get("ha")
        .and_then(Value::as_object)
        .map(|hosts| {
            hosts
                .iter()
                .map(|(host, state)| format!("{host}={}", state.as_str().unwrap_or("?")))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "not recorded".to_string())
}

fn service_output(ctx: &Ctx<'_>, action: &str, node: &str) -> Res<Output> {
    let report = chrony_ctl::service_action(ctx, node, action)?;
    Ok(Output {
        text: format!(
            "{action}: ok {} on {} ({})\n",
            report.unit, report.node, report.active_state
        ),
        json: to_value(&report),
        exit: 0,
    })
}

/// One readable line for the recorded operation (v0.3). The full record stays in
/// the `--json` document; only facts that are in the record are printed.
pub(crate) fn operation_summary(op: &Value) -> String {
    let field = |name: &str| op[name].as_str().filter(|v| !v.is_empty()).unwrap_or("?");
    let mut line = format!(
        "{} {} -> {}, phase {}, controller {}",
        field("op_id"),
        field("source"),
        field("target"),
        field("phase"),
        field("controller")
    );
    if let Some(changes) = op["evidence"]["cloud_changes"].as_array()
        && !changes.is_empty()
    {
        let sent: Vec<String> = changes
            .iter()
            .map(|c| {
                format!(
                    "{} on {}",
                    c["action"].as_str().unwrap_or("?"),
                    c["node"].as_str().unwrap_or("?")
                )
            })
            .collect();
        line.push_str(&format!("; cloud change(s) sent: {}", sent.join(", ")));
    }
    line
}

fn render_vip_status(status: &vip::VipStatus) -> Output {
    let mut text = String::new();
    let _ = writeln!(text, "resource: vip {}", status.vip);
    let _ = writeln!(
        text,
        "recorded owner: {} (epoch {})",
        status.recorded_owner.as_deref().unwrap_or("unknown"),
        status.epoch.map_or("?".to_string(), |e| e.to_string())
    );
    let _ = writeln!(
        text,
        "cloud holders:  {}",
        status
            .cloud_holders
            .as_ref()
            .map_or("unknown".to_string(), |h| if h.is_empty() {
                "none".into()
            } else {
                h.join(", ")
            })
    );
    let _ = writeln!(
        text,
        "served by:      {}",
        status.served_by.as_deref().unwrap_or("nobody/unknown")
    );
    if let Some(op) = &status.operation {
        let _ = writeln!(text, "operation:      {}", operation_summary(op));
    }
    for (name, n) in &status.nodes {
        let _ = writeln!(
            text,
            "node {name}: cloud={} holds_vip={} reachable={} ha_daemon={} service_active={} \
             local_id={}",
            n.cloud_status.as_deref().unwrap_or("?"),
            n.holds_vip.map_or("?".to_string(), |b| b.to_string()),
            n.reachable.map_or("?".to_string(), |b| b.to_string()),
            n.ha_daemon.as_deref().unwrap_or("?"),
            n.service_active.map_or("?".to_string(), |b| b.to_string()),
            n.local_id.as_deref().unwrap_or("-"),
        );
    }
    let _ = writeln!(
        text,
        "witness: ha_daemon={}",
        status.witness_ha.as_deref().unwrap_or("?")
    );
    let _ = writeln!(text, "verdict: {}", status.verdict);
    for problem in &status.problems {
        let _ = writeln!(text, "  problem: {problem}");
    }
    text.push_str(&status.guidance.text());
    let consistent = status.verdict == "consistent";
    Output {
        json: to_value(status),
        text,
        exit: if consistent { 0 } else { super::EXIT_UNKNOWN },
    }
}

fn render_chronyd_status(value: &Value) -> String {
    let mut text = String::new();
    let _ = writeln!(text, "resource: chronyd healthy={}", value["healthy"]);
    if let Some(nodes) = value["nodes"].as_object() {
        for (name, n) in nodes {
            if let Some(error) = n["error"].as_str() {
                let _ = writeln!(text, "node {name}: ERROR {error}");
            } else {
                let _ = writeln!(
                    text,
                    "node {name}: unit={} tracking_ok={} conf_sha256={}",
                    n["unit_state"].as_str().unwrap_or("?"),
                    n["tracking_ok"],
                    n["conf_sha256"]
                        .as_str()
                        .map_or_else(|| "?".to_string(), |s| short_digest(s, 16))
                );
            }
        }
    }
    text
}

// ---------------------------------------------------------------------------
// chronyd
// ---------------------------------------------------------------------------

pub(crate) fn chronyd(command: ChronydCommands) -> ExitCode {
    let changes = matches!(command, ChronydCommands::Apply { dry_run: false, .. });
    guarded(changes, || chronyd_command(command))
}

fn chronyd_command(command: ChronydCommands) -> ExitCode {
    let common = match &command {
        ChronydCommands::Show { common, .. }
        | ChronydCommands::Validate { common, .. }
        | ChronydCommands::Diff { common, .. }
        | ChronydCommands::Apply { common, .. } => common,
    };
    let (config, json) = (common.config.clone(), common.json);
    finish_json(
        with_context(config.as_deref(), |ctx| execute_chronyd(ctx, command)),
        json,
    )
}

/// Run one `chronyd` command against a context (see [`execute_resource`]).
pub(crate) fn execute_chronyd(ctx: &Ctx<'_>, command: ChronydCommands) -> Res<Output> {
    match command {
        ChronydCommands::Show { node, .. } => {
            let node = default_node(ctx, node.as_ref());
            let report = chrony_ctl::show(ctx, &node)?;
            let mut text = String::new();
            let _ = writeln!(text, "node: {}", report.node);
            let _ = writeln!(
                text,
                "config: {} sha256={}",
                report.conf_path,
                report.conf_sha256.as_deref().unwrap_or("unknown")
            );
            let _ = writeln!(text, "config trusted: {}", report.conf_trusted);
            let _ = writeln!(
                text,
                "unit: {}",
                report.unit_state.as_deref().unwrap_or("unknown")
            );
            let _ = writeln!(
                text,
                "tracking: {}",
                if report.tracking_ok {
                    "ok"
                } else {
                    "NOT ANSWERING"
                }
            );
            if let Some(t) = &report.tracking {
                let _ = writeln!(text, "{t}");
            }
            for p in &report.problems {
                let _ = writeln!(text, "problem: {p}");
            }
            let healthy = report.conf_trusted
                && report.unit_matches
                && report.unit_active == Some(true)
                && report.tracking_ok;
            Ok(Output {
                json: to_value(&report),
                text,
                exit: if healthy { 0 } else { super::EXIT_UNKNOWN },
            })
        }
        ChronydCommands::Validate { file, node, .. } => {
            let content = chrony_ctl::read_candidate(&file)?;
            let node = default_node(ctx, node.as_ref());
            let report = chrony_ctl::validate(ctx, &node, &content)?;
            if !report.valid {
                return Err(Failure::Refused(format!(
                    "chronyd on {} rejected {}: {}",
                    report.node,
                    file.display(),
                    report.message.clone().unwrap_or_default()
                )));
            }
            Ok(Output {
                text: format!(
                    "validate: ok ({}) by chronyd on {} sha256={}\n",
                    file.display(),
                    report.node,
                    report.sha256
                ),
                json: to_value(&report),
                exit: 0,
            })
        }
        ChronydCommands::Diff { file, node, .. } => {
            let content = chrony_ctl::read_candidate(&file)?;
            let report = chrony_ctl::diff(ctx, &node, &content)?;
            let text = if report.identical {
                "no difference\n".to_string()
            } else {
                report.unified.clone()
            };
            Ok(Output {
                json: to_value(&report),
                text,
                exit: 0,
            })
        }
        ChronydCommands::Apply {
            file,
            node,
            dry_run,
            ..
        } => {
            let content = chrony_ctl::read_candidate(&file)?;
            let report = chrony_ctl::apply(ctx, &node, &content, dry_run)?;
            let mut text = String::new();
            if !report.diff.is_empty() {
                text.push_str(&report.diff);
            }
            if report.dry_run {
                let _ = writeln!(text, "apply: dry run, nothing changed on {}", report.node);
            } else if !report.changed {
                let _ = writeln!(
                    text,
                    "apply: {} already runs this configuration; nothing changed",
                    report.node
                );
            } else {
                let _ = writeln!(
                    text,
                    "apply: ok node={} backup={} new_sha256={}",
                    report.node,
                    report.backup_id.as_deref().unwrap_or("-"),
                    report.new_sha256
                );
            }
            Ok(Output {
                json: to_value(&report),
                text,
                exit: 0,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// agent
// ---------------------------------------------------------------------------

pub(crate) fn agent(config: Option<PathBuf>) -> ExitCode {
    let path = config.unwrap_or_else(|| PathBuf::from(super::agent::DEFAULT_AGENT_CONFIG));
    super::agent::run_stdio(&path)
}

// ---------------------------------------------------------------------------
// status section
// ---------------------------------------------------------------------------

/// Whether `status` should add the control-plane overview: only when the
/// operator asks with `--control-config` (audit E-05). Neither `MKG_CONFIG`
/// nor a configuration file at the default location changes what `mikagami
/// status` does or whether it contacts anything; `ha_config_present` is kept
/// for the caller's signature and ignored.
pub(crate) fn status_wanted(explicit: Option<&Path>, _ha_config_present: bool) -> Option<PathBuf> {
    explicit.map(Path::to_path_buf)
}

/// The read-only cluster overview used by `status`.
pub(crate) fn status_overview(config: &Path) -> Res<Output> {
    // Remote text can reach the overview; the caller prints it as it is, so it
    // is made safe here (audit RA-E-07), failure messages included.
    with_context(Some(config), status_overview_in).map_err(Failure::cleaned)
}

/// [`status_overview`] against a context (the tests drive this one).
pub(crate) fn status_overview_in(ctx: &Ctx<'_>) -> Res<Output> {
    let vip_status = vip::vip_status(ctx);
    let mut chrony = resource::chronyd_status(ctx, None)?;
    // the nodes whose exclusion from the HA daemon is not proven (nothing observed is not proven)
    let ha_unproven: Vec<String> = vip_status
        .nodes
        .iter()
        .filter(|(_, n)| !matches!(n.ha_daemon.as_deref(), Some("masked" | "absent")))
        .map(|(name, _)| name.clone())
        .collect();
    let chrony_guidance = super::guidance::for_chronyd(&chrony, &ha_unproven);
    if let Value::Object(map) = &mut chrony {
        map.insert("guidance".to_string(), to_value(&chrony_guidance));
    }
    let healthy = vip_status.verdict == "consistent" && chrony["healthy"].as_bool() == Some(true);
    let mut text = String::new();
    let _ = writeln!(text, "control-plane: cluster {}", ctx.cfg.cluster);
    let vip_out = render_vip_status(&vip_status);
    text.push_str(&vip_out.text);
    text.push_str(&render_chronyd_status(&chrony));
    text.push_str(&chrony_guidance.text());
    let _ = writeln!(
        text,
        "control-plane.verdict: {}",
        if healthy {
            "consistent"
        } else {
            "NOT CONSISTENT / UNKNOWN"
        }
    );
    let mut json = json!({
        "ok": healthy,
        "cluster": ctx.cfg.cluster,
        "vip": to_value(&vip_status),
        "chronyd": chrony,
    });
    clean_json_for_terminal(&mut json);
    Ok(Output {
        json,
        text: clean(&text),
        exit: if healthy { 0 } else { super::EXIT_UNKNOWN },
    })
}

pub(crate) fn status_failure_exit(failure: &Failure) -> ExitCode {
    say_err(&clean(&failure.to_string()));
    ExitCode::from(failure.exit_code().max(EXIT_FAILED))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manual::fakes::World;

    #[test]
    fn the_overview_is_asked_for_only_by_the_explicit_flag() {
        // E-05: the environment variable and a file at the default location
        // no longer change `status` (it used to contact ssh/gcloud and could
        // exit 4 where it always exited 0).
        let explicit = Path::new("/explicit.toml");
        for ha_config_present in [true, false] {
            assert_eq!(
                status_wanted(Some(explicit), ha_config_present),
                Some(PathBuf::from("/explicit.toml"))
            );
            assert_eq!(status_wanted(None, ha_config_present), None);
        }
        // SAFETY: tests that read this variable run in this process only; the
        // value is restored at once.
        let before = std::env::var_os(super::super::config::CONFIG_ENV);
        unsafe { std::env::set_var(super::super::config::CONFIG_ENV, "/from-env.toml") };
        let wanted = status_wanted(None, false);
        match before {
            Some(v) => unsafe { std::env::set_var(super::super::config::CONFIG_ENV, v) },
            None => unsafe { std::env::remove_var(super::super::config::CONFIG_ENV) },
        }
        assert_eq!(wanted, None, "MKG_CONFIG must not enable the overview");
    }

    #[test]
    fn output_json_marks_success_and_carries_the_report() {
        let value = to_value(&vip::InitReport {
            owner: "node-a".to_string(),
            epoch: 1,
            seq: 2,
            evidence: json!({"ha": {"node-a": "masked"}}),
        });
        assert_eq!(
            ha_summary(&json!({"ha": {"node-a": "masked", "witness": "absent"}})),
            "node-a=masked, witness=absent"
        );
        assert_eq!(ha_summary(&json!({})), "not recorded");
        assert_eq!(value["owner"], "node-a");
        let status = render_vip_status(&vip::vip_status(&World::new("run-status").ctx()));
        assert_eq!(status.exit, 0);
        assert_eq!(status.json["verdict"], "consistent");
        assert!(status.text.contains("verdict: consistent"));
    }

    #[test]
    fn remote_text_cannot_drive_the_terminal() {
        assert_eq!(
            clean("a\u{1b}[31mred\u{7}\nline\ttab"),
            "a?[31mred?\nline\ttab"
        );
        // Bidirectional controls and zero-width characters (audit E-04).
        assert_eq!(
            clean("ok\u{202e}gnp.exe\u{2066}x\u{200b}y\u{feff}\u{2028}"),
            "ok?gnp.exe?x?y??"
        );
        // The whole ranges: LRM/RLM/ZWJ/ZWNJ, Arabic letter mark, word joiner,
        // bidi isolates and overrides, line/paragraph separators.
        for c in [
            '\u{061c}', '\u{200b}', '\u{200c}', '\u{200d}', '\u{200e}', '\u{200f}', '\u{2028}',
            '\u{2029}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', '\u{2060}',
            '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', '\u{206f}', '\u{feff}',
        ] {
            assert_eq!(clean(&format!("a{c}b")), "a?b", "U+{:04X}", c as u32);
        }
        assert_eq!(
            clean("\u{e9}\u{3042}"),
            "\u{e9}\u{3042}",
            "ordinary text is kept"
        );
    }

    #[test]
    fn a_hostile_hash_in_a_node_report_is_shown_not_sliced() {
        // E-03: the old code cut at byte 16 and panicked inside a character.
        let hostile = format!("a{}", "\u{e9}".repeat(20));
        let value = json!({"healthy": false, "nodes": {"node-a": {
            "unit_state": "active", "tracking_ok": true, "conf_sha256": hostile}}});
        let text = render_chronyd_status(&value);
        assert!(text.contains("conf_sha256=(malformed)"), "{text}");
        let good = json!({"nodes": {"node-a": {"conf_sha256": "a".repeat(64)}}});
        assert!(render_chronyd_status(&good).contains(&format!("conf_sha256={}", "a".repeat(16))));
    }

    #[test]
    fn a_panic_is_unknown_not_101_and_a_closed_output_does_not_matter() {
        let code = guarded(false, || panic!("test panic"));
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::from(EXIT_UNKNOWN))
        );
        let code = guarded(false, || ExitCode::from(3));
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(3)));
        // The output helpers never panic, whatever the other end does.
        say_out("");
        say_err("");
    }

    #[test]
    fn demo_status_is_not_ok_when_a_node_cannot_be_observed() {
        let w = World::new("run-demo");
        let ok = resource::demo_status(&w.ctx()).unwrap();
        assert!(
            ok["nodes"]
                .as_object()
                .unwrap()
                .values()
                .all(|n| n["reachable"] == true)
        );
        w.remote.host("node-b").reachable.set(false);
        let bad = resource::demo_status(&w.ctx()).unwrap();
        assert_eq!(bad["nodes"]["node-b"]["reachable"], false);
    }

    #[test]
    fn a_status_that_is_not_consistent_exits_with_unknown() {
        let w = World::new("run-status-bad");
        w.remote.host("witness").reachable.set(false);
        let out = render_vip_status(&vip::vip_status(&w.ctx()));
        assert_eq!(out.exit, super::super::EXIT_UNKNOWN);
        assert_eq!(out.json["verdict"], "unknown");
    }
}
