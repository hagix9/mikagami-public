//! Stage 14 Design Revision 5 §28 / §28.1 operator-facing log lines.
//!
//! Diagnostic output only. Every emitter here returns `()`: a log line is
//! never evidence, authorization, a clearance, a state-transition input, a
//! Witness input, or a fencing-result input, and nothing in this module can
//! hand a value back to a caller (guard `017_diagnostics_not_evidence`).
//! Lines carry the operator-visible facts of §13.1 / §28 only: the target
//! node, the incident sequence number, the fencing state name, and a bounded
//! reason. They never carry UUIDs, session ids, attempt tokens, PSK paths, or
//! any secret.
//!
//! Format: `mikagami: INFO|WARN <message>`, one line, to stderr (the
//! daemon's existing log channel). Verify polls are not logged here (they log
//! at DEBUG in the backend, §28), and there is no per-iteration line.

// The emitters are called from the Linux runtime and the peer runtime; on a
// non-Linux development host the Linux callers are not compiled.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::fmt::Write as _;

#[derive(Clone, Copy)]
enum Level {
    Info,
    Warn,
    Error,
}

impl Level {
    const fn name(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }
}

// Test-only capture so a test can assert the exact lines a code path wrote.
#[cfg(test)]
thread_local! {
    static CAPTURE: std::cell::RefCell<Option<Vec<String>>> =
        const { std::cell::RefCell::new(None) };
}

/// Test-only: start recording this thread's lines instead of printing them.
#[cfg(test)]
pub(crate) fn capture_start() {
    CAPTURE.with(|capture| *capture.borrow_mut() = Some(Vec::new()));
}

/// Test-only: stop recording and return the lines written since `capture_start`.
#[cfg(test)]
pub(crate) fn capture_take() -> Vec<String> {
    CAPTURE.with(|capture| capture.borrow_mut().take().unwrap_or_default())
}

/// The canonical maximum length, in UTF-8 bytes, of any free-text reason an
/// operator line carries (L2). Every reason that reaches a line passes through
/// [`bounded_reason`]; the emitters below apply it themselves, so a caller
/// cannot bypass the bound by passing a raw error string.
pub(crate) const MAX_REASON_BYTES: usize = 240;

const TRUNCATION_MARK: &str = "...";
const EMPTY_REASON: &str = "unspecified";

/// The one bounded-reason policy (Rev5 §28 "bounded reason"): deterministic,
/// always valid UTF-8, at most [`MAX_REASON_BYTES`] bytes.
///
/// * control characters (including newlines) become spaces, so a reason can
///   never break the one-line format, and surrounding whitespace is dropped;
/// * an empty reason is rendered as `unspecified`;
/// * a reason over the bound is cut at a character boundary so that the
///   result, `...` included, is exactly within the bound.
///
/// Diagnostic only: the result is text for a log line and nothing else.
pub(crate) fn bounded_reason(reason: &str) -> String {
    let flat: String = reason
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let flat = flat.trim();
    if flat.is_empty() {
        return EMPTY_REASON.to_string();
    }
    if flat.len() <= MAX_REASON_BYTES {
        return flat.to_string();
    }
    let mut end = MAX_REASON_BYTES - TRUNCATION_MARK.len();
    while !flat.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{TRUNCATION_MARK}", flat[..end].trim_end())
}

fn emit(level: Level, message: &str) {
    let line = format!("mikagami: {} {message}", level.name());
    #[cfg(test)]
    {
        let captured = CAPTURE.with(|capture| {
            capture.borrow_mut().as_mut().map(|lines| {
                lines.push(line.clone());
            })
        });
        if captured.is_some() {
            return;
        }
    }
    eprintln!("{line}");
}

/// `INFO` for one committed durable fencing transition (§13.2 T1-T8).
pub(crate) fn info_fencing_transition(seq: u64, target: &str, from: &str, to: &str) {
    emit(
        Level::Info,
        &format!("fencing incident {seq} (target {target}): {from} -> {to}"),
    );
}

/// `INFO` for the incident opened at gate G (T1 / T2).
pub(crate) fn info_fencing_incident_opened(seq: u64, target: &str, state: &str) {
    emit(
        Level::Info,
        &format!("fencing incident {seq} (target {target}) opened: {state}"),
    );
}

/// `INFO` for an incident retired (T9). `reason` is a bounded name.
pub(crate) fn info_fencing_incident_retired(seq: u64, target: &str, reason: &str) {
    emit(
        Level::Info,
        &format!(
            "fencing incident {seq} (target {target}) retired: {}",
            bounded_reason(reason)
        ),
    );
}

/// `INFO` for an incident consumed atomically with a release obligation
/// (T10 success ARM, or the §25.1 abort cleanup). `how` is a bounded name.
pub(crate) fn info_fencing_incident_consumed(seq: u64, target: &str, how: &str) {
    emit(
        Level::Info,
        &format!(
            "fencing incident {seq} (target {target}) consumed: {}",
            bounded_reason(how)
        ),
    );
}

/// v0.7 G-2: one route-handoff state line (`INFO` progress, `WARN` operator-required).
pub(crate) fn route_handoff_state(description: &str, reason: &str, warn: bool) {
    emit(
        if warn { Level::Warn } else { Level::Info },
        &format!(
            "service route handoff {description}: {}",
            bounded_reason(reason)
        ),
    );
}

/// v0.7 G-2: the diagnostic timing of one route-handoff step (contract §5.1 budget).
pub(crate) fn info_route_step_measured(line: &str) {
    emit(Level::Info, &bounded_reason(line));
}

/// v0.7 G-2: a route-handoff diagnostic (startup sweep, begin failure).
pub(crate) fn warn_route_handoff(reason: &str) {
    emit(Level::Warn, &bounded_reason(reason));
}

/// v0.7 G-2 (contract §1.1): the internal promotion succeeded, which is not the switchover.
pub(crate) fn info_promotion_internal_only(route: bool) {
    emit(
        Level::Info,
        if route {
            "promotion committed internally; the HA switchover is NOT complete until the route \
             handoff confirms the route and an external check confirms the service"
        } else {
            "promotion committed internally; no route handoff is configured, so this node does \
             not move the VIP route; the HA switchover is NOT verified by this node"
        },
    );
}

/// The incident an attempt was blocked on, when there is one.
pub(crate) struct BlockedIncident<'a> {
    pub(crate) seq: u64,
    pub(crate) target: &'a str,
    pub(crate) state: &'a str,
}

/// `WARN` for one blocked activation attempt. `reason` is bounded by
/// [`bounded_reason`]; the incident context (target, sequence, state) is
/// appended when present.
pub(crate) fn warn_attempt_blocked(reason: &str, incident: Option<BlockedIncident<'_>>) {
    let mut message = format!("activation attempt blocked: {}", bounded_reason(reason));
    if let Some(incident) = incident {
        let _ = write!(
            message,
            " (target {}, incident {}, state {})",
            incident.target, incident.seq, incident.state
        );
    }
    emit(Level::Warn, &message);
}

/// `ERROR` for a post-grant abort whose lease cleanup failed closed
/// (§25.1): the cleanup could not be proven, so the daemon is
/// `RecoveryBlocked`. `how` is a bounded name (`blocked` for an uncertain or
/// mismatched cleanup, `failed` for a cleanup that returned an error);
/// `reason` is bounded by [`bounded_reason`], so the underlying cause is
/// reported, never swallowed, and never unbounded.
pub(crate) fn error_abort_cleanup(how: &str, reason: &str) {
    emit(
        Level::Error,
        &format!(
            "post-grant abort cleanup {how}; recovery blocked: {}",
            bounded_reason(reason)
        ),
    );
}

/// `WARN` for one rejected attestation intent (§18.5). `reason` is bounded by
/// [`bounded_reason`].
pub(crate) fn warn_attestation_rejected(reason: &str) {
    emit(
        Level::Warn,
        &format!("attestation intent rejected: {}", bounded_reason(reason)),
    );
}

/// The §28.1 operator guidance printed with the first `ListenerInterference`
/// WARN of a process.
pub(crate) const LISTENER_INTERFERENCE_GUIDANCE: &str = "an accepted connection proves listener activity, not peer identity, so it cannot count as peer absence; loss evidence resumes only after the interfering arrivals stop and fresh verified-listen windows complete (two to form loss, one to refresh a live episode); investigate unexpected connection sources and restrict the heartbeat port to the configured peer address";

/// `WARN ListenerInterference` (§28.1): the counts since the previous WARN.
/// The guidance rides along on the first WARN of the process only.
pub(crate) fn warn_listener_interference(arrivals: u64, voided_windows: u64, first: bool) {
    let mut message = format!(
        "ListenerInterference: {arrivals} unauthenticated arrivals, {voided_windows} voided windows since the previous WARN"
    );
    if first {
        let _ = write!(message, "; {LISTENER_INTERFERENCE_GUIDANCE}");
    }
    emit(Level::Warn, &message);
}

/// `WARN` for a §27.3 fencing step that reached its pre-commit store and was
/// not committed. The store's I/O error is free text (and `NodeMutationError::
/// Io` carries it whole), so it goes through [`bounded_reason`] here rather
/// than being interpolated raw at the call site.
pub(crate) fn warn_fencing_step_not_committed(reason: &str) {
    emit(
        Level::Warn,
        &format!("fencing step not committed: {}", bounded_reason(reason)),
    );
}

/// `WARN` for a bounded foreground step that was refused before it committed
/// (§9 shutdown join). Same free-text discipline as
/// [`warn_fencing_step_not_committed`].
pub(crate) fn warn_shutdown_step_rejected(reason: &str) {
    emit(
        Level::Warn,
        &format!("bounded shutdown step rejected: {}", bounded_reason(reason)),
    );
}

/// `WARN` for a §24 fencing gate that failed closed. Free text, so bounded by
/// [`bounded_reason`].
pub(crate) fn warn_fencing_gate_failed_closed(reason: &str) {
    emit(
        Level::Warn,
        &format!("fencing gate failed closed: {}", bounded_reason(reason)),
    );
}

/// `INFO` for the Bootstrap Admission anchor (attempt 1): the Witness term the
/// cold start is anchored on. Silent in steady state.
pub(crate) fn info_bootstrap_anchored(term: u64) {
    emit(
        Level::Info,
        &format!("bootstrap admission: anchored at Witness term {term}; probing the peer"),
    );
}

/// `INFO` for the peer's matching `ACK` to the probe (the session is
/// attested; the next promotion request decides).
pub(crate) fn info_bootstrap_attested() {
    emit(
        Level::Info,
        "bootstrap admission: the peer confirmed it is a safe standby; the next request decides",
    );
}

/// `WARN` for a Bootstrap Admission session that was dropped. `reason` is
/// bounded by [`bounded_reason`].
pub(crate) fn warn_bootstrap_dropped(reason: &str) {
    emit(
        Level::Warn,
        &format!("bootstrap admission dropped: {}", bounded_reason(reason)),
    );
}

/// `INFO` for a node that became Active through Bootstrap Admission.
pub(crate) fn info_bootstrap_activated(term: u64) {
    emit(
        Level::Info,
        &format!("bootstrap admission: became Active at Witness term {term}"),
    );
}

/// `INFO` for a startup obligation reconciliation that resolved the node's
/// release obligation (`how` is a bounded name: exact release, superseded).
pub(crate) fn info_sor_resolved(term: u64, how: &str) {
    emit(
        Level::Info,
        &format!(
            "startup reconciliation resolved the release obligation of term {term}: {}",
            bounded_reason(how)
        ),
    );
}

/// `INFO` when a running node settled its release obligation without a
/// restart (Amendment C, C-a(1)): the Witness rejected the exact release as
/// not releasable. It is not a release; the node becomes an ordinary Standby.
pub(crate) fn info_release_settled_not_releasable(term: u64, how: &str) {
    emit(
        Level::Info,
        &format!(
            "the release obligation of term {term} was settled as not releasable (not released): {}",
            bounded_reason(how)
        ),
    );
}

/// `INFO` when a retained lease renewal from before the restart was resolved
/// against the Witness by replaying the exact durable request (idempotent).
pub(crate) fn info_startup_renew_resolved(how: &str) {
    emit(
        Level::Info,
        &format!(
            "startup reconciliation resolved the retained lease renewal (exact replay: {})",
            bounded_reason(how)
        ),
    );
}

/// `INFO` when a retained lease request from before the restart was resolved against the
/// Witness by replaying the exact durable request (J21).
pub(crate) fn info_startup_request_resolved(how: &str) {
    emit(
        Level::Info,
        &format!(
            "startup reconciliation resolved the retained lease request ({})",
            bounded_reason(how)
        ),
    );
}

/// `WARN` (J23, OD-J22-5) when a retained lease request was resolved but the Release of its unused
/// grant is not confirmed: the request is settled, the lease is not proven released, and the
/// release obligation stays for the startup reconciliation.
pub(crate) fn warn_retained_request_release_unconfirmed(how: &str) {
    emit(
        Level::Warn,
        &format!(
            "startup reconciliation resolved the retained lease request, but the release of its unused grant is NOT confirmed ({})",
            bounded_reason(how)
        ),
    );
}

/// `ERROR` for the recovery gate: the daemon refuses to run and says why and
/// what the operator can do.
pub(crate) fn error_recovery_blocked(cause: &str) {
    emit(
        Level::Error,
        &format!(
            "recovery gate blocked startup: {}; resolve it (see `mikagami recover`) or restart once the cause is gone",
            bounded_reason(cause)
        ),
    );
}

/// `INFO` for an automatic failover cycle starting (`origin` is a bounded name).
pub(crate) fn info_auto_failover_started(origin: &str) {
    emit(
        Level::Info,
        &format!("automatic failover started: {}", bounded_reason(origin)),
    );
}

/// `WARN` for an automatic failover that stopped trying (budget or state).
pub(crate) fn warn_auto_failover_stopped(reason: &str) {
    emit(
        Level::Warn,
        &format!(
            "automatic failover stopped: {}; an operator decision is needed",
            bounded_reason(reason)
        ),
    );
}

/// `WARN` once when the peer is lost (transition only).
pub(crate) fn warn_peer_lost() {
    emit(Level::Warn, "peer lost: no authenticated heartbeat");
}

/// `INFO` once when the peer is healthy again (transition only).
pub(crate) fn info_peer_recovered() {
    emit(
        Level::Info,
        "peer recovered: authenticated heartbeat resumed",
    );
}

/// `ERROR` when the Witness session is lost for good (this daemon exits).
pub(crate) fn error_witness_session_lost(reason: &str) {
    emit(
        Level::Error,
        &format!(
            "Witness session lost: {}; stopping so the service manager can restart this daemon",
            bounded_reason(reason)
        ),
    );
}

/// `WARN` when the health command crosses its failure threshold.
pub(crate) fn warn_health_unhealthy(consecutive_failures: u32) {
    emit(
        Level::Warn,
        &format!("service health check failing ({consecutive_failures} consecutive failures)"),
    );
}

/// `INFO` when the health check is healthy again (transition only).
pub(crate) fn info_health_recovered() {
    emit(Level::Info, "service health check recovered");
}

/// `WARN` for a startup configuration warning.
pub(crate) fn warn_startup(message: &str) {
    emit(Level::Warn, &bounded_reason(message));
}

/// `WARN` for a demotion and its reason (never printed when nothing happens).
pub(crate) fn warn_demoting(reason: &str) {
    emit(
        Level::Warn,
        &format!("demoting to Standby: {}", bounded_reason(reason)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(run: impl FnOnce()) -> Vec<String> {
        capture_start();
        run();
        capture_take()
    }

    #[test]
    fn stage14_11_lines_have_the_documented_shape() {
        assert_eq!(
            lines(|| info_fencing_transition(7, "node-b", "UNKNOWN", "REQUESTED")),
            ["mikagami: INFO fencing incident 7 (target node-b): UNKNOWN -> REQUESTED"]
        );
        assert_eq!(
            lines(|| info_fencing_incident_opened(7, "node-b", "REQUESTED")),
            ["mikagami: INFO fencing incident 7 (target node-b) opened: REQUESTED"]
        );
        assert_eq!(
            lines(|| info_fencing_incident_retired(7, "node-b", "observer session changed")),
            ["mikagami: INFO fencing incident 7 (target node-b) retired: observer session changed"]
        );
        assert_eq!(
            lines(|| info_fencing_incident_consumed(7, "node-b", "success ARM")),
            ["mikagami: INFO fencing incident 7 (target node-b) consumed: success ARM"]
        );
        assert_eq!(
            lines(|| warn_attestation_rejected("wrong incident")),
            ["mikagami: WARN attestation intent rejected: wrong incident"]
        );
    }

    #[test]
    fn stage14_11_blocked_line_carries_target_incident_state_and_reason() {
        assert_eq!(
            lines(|| warn_attempt_blocked(
                "fencing required",
                Some(BlockedIncident {
                    seq: 7,
                    target: "node-b",
                    state: "UNKNOWN"
                })
            )),
            [
                "mikagami: WARN activation attempt blocked: fencing required (target node-b, incident 7, state UNKNOWN)"
            ]
        );
        assert_eq!(
            lines(|| warn_attempt_blocked("local safety not ready", None)),
            ["mikagami: WARN activation attempt blocked: local safety not ready"]
        );
    }

    #[test]
    fn stage14_11_guidance_rides_only_on_the_first_interference_warn() {
        let first = lines(|| warn_listener_interference(3, 1, true));
        assert_eq!(first.len(), 1);
        assert!(first[0].starts_with(
            "mikagami: WARN ListenerInterference: 3 unauthenticated arrivals, 1 voided windows since the previous WARN; "
        ));
        assert!(first[0].contains(LISTENER_INTERFERENCE_GUIDANCE));
        assert_eq!(
            lines(|| warn_listener_interference(2, 0, false)),
            [
                "mikagami: WARN ListenerInterference: 2 unauthenticated arrivals, 0 voided windows since the previous WARN"
            ]
        );
    }

    // ---- Phase 14.11 remediation L2: the canonical bounded reason ----

    const PREFIX_BLOCKED: &str = "mikagami: WARN activation attempt blocked: ";

    #[test]
    fn stage14_11_bounded_reason_short_boundary_and_overflow() {
        // The canonical value itself is part of the contract (Rev5 §28), so it
        // is pinned here and not merely used symbolically: every other bound
        // assertion below is written against `MAX_REASON_BYTES` and would
        // otherwise follow a change of the bound.
        assert_eq!(
            MAX_REASON_BYTES, 240,
            "the canonical bounded-reason limit is 240 UTF-8 bytes"
        );
        assert_eq!(bounded_reason("fencing required"), "fencing required");
        let exact = "a".repeat(MAX_REASON_BYTES);
        assert_eq!(bounded_reason(&exact), exact, "exactly at the bound");
        let over = "a".repeat(MAX_REASON_BYTES + 1);
        let cut = bounded_reason(&over);
        assert_eq!(
            cut.len(),
            MAX_REASON_BYTES,
            "boundary + 1 is cut to the bound"
        );
        assert_eq!(
            cut,
            format!("{}...", "a".repeat(MAX_REASON_BYTES - 3)),
            "a recognisable truncation mark, then nothing"
        );
        let huge = "e".repeat(8192);
        let cut = bounded_reason(&huge);
        assert_eq!(cut.len(), MAX_REASON_BYTES);
        assert!(cut.starts_with(&"e".repeat(MAX_REASON_BYTES - 3)));
        assert!(cut.ends_with("..."));
    }

    #[test]
    fn stage14_11_bounded_reason_empty_and_control_characters() {
        assert_eq!(bounded_reason(""), "unspecified");
        assert_eq!(bounded_reason("  \t\n "), "unspecified");
        // A reason can never break the one-line format.
        assert_eq!(
            bounded_reason("io error:\nsecond line\r\nthird\u{0}"),
            "io error: second line  third"
        );
        assert!(!bounded_reason("a\nb").contains('\n'));
    }

    /// Multibyte text is cut on a character boundary, never inside one, never
    /// panics, stays within the byte bound, and keeps as much as fits.
    #[test]
    fn stage14_11_bounded_reason_cuts_multibyte_text_on_a_character_boundary() {
        for unit in ["é", "日", "🦀", "e\u{301}"] {
            for pad in 0..5usize {
                for count in 55..120usize {
                    let input = format!("{}{}", "x".repeat(pad), unit.repeat(count));
                    let out = bounded_reason(&input);
                    assert!(out.len() <= MAX_REASON_BYTES, "{unit} {pad} {count}");
                    if input.len() <= MAX_REASON_BYTES {
                        assert_eq!(out, input, "{unit} {pad} {count}: no change when it fits");
                        continue;
                    }
                    assert!(out.ends_with("..."), "{unit} {pad} {count}");
                    let kept = out.strip_suffix("...").unwrap();
                    assert!(
                        input.starts_with(kept),
                        "{unit} {pad} {count}: the kept text is a prefix"
                    );
                    // Maximal: one more character would not have fit.
                    let next = input[kept.len()..].chars().next().unwrap();
                    assert!(
                        kept.len() + next.len_utf8() + 3 > MAX_REASON_BYTES,
                        "{unit} {pad} {count}: cut too early ({} kept)",
                        kept.len()
                    );
                }
            }
        }
    }

    #[test]
    fn stage14_11_bounded_reason_is_idempotent() {
        for input in ["", "short", &"é".repeat(400), &"z".repeat(9000), "a\nb"] {
            let once = bounded_reason(input);
            assert_eq!(bounded_reason(&once), once);
        }
    }

    /// Every emitter that takes free text applies the one bound, so a caller
    /// cannot bypass it with a raw error string.
    #[test]
    fn stage14_11_every_free_text_emitter_applies_the_bound() {
        let huge = "K".repeat(8192);
        let blocked = lines(|| warn_attempt_blocked(&huge, None));
        assert_eq!(
            blocked,
            [format!("{PREFIX_BLOCKED}{}", bounded_reason(&huge))]
        );
        assert_eq!(blocked[0].len(), PREFIX_BLOCKED.len() + MAX_REASON_BYTES);
        let with_incident = lines(|| {
            warn_attempt_blocked(
                &huge,
                Some(BlockedIncident {
                    seq: 7,
                    target: "node-b",
                    state: "UNKNOWN",
                }),
            )
        });
        assert_eq!(
            with_incident,
            [format!(
                "{PREFIX_BLOCKED}{} (target node-b, incident 7, state UNKNOWN)",
                bounded_reason(&huge)
            )],
            "the incident context survives a truncated reason"
        );
        let rejected = lines(|| warn_attestation_rejected(&huge));
        assert_eq!(
            rejected,
            [format!(
                "mikagami: WARN attestation intent rejected: {}",
                bounded_reason(&huge)
            )]
        );
        let abort = lines(|| error_abort_cleanup("failed", &huge));
        assert_eq!(
            abort,
            [format!(
                "mikagami: ERROR post-grant abort cleanup failed; recovery blocked: {}",
                bounded_reason(&huge)
            )]
        );
        let retired = lines(|| info_fencing_incident_retired(7, "node-b", &huge));
        assert_eq!(
            retired,
            [format!(
                "mikagami: INFO fencing incident 7 (target node-b) retired: {}",
                bounded_reason(&huge)
            )]
        );
        let consumed = lines(|| info_fencing_incident_consumed(7, "node-b", &huge));
        assert!(consumed[0].ends_with("..."), "{consumed:?}");
        assert!(consumed[0].len() < 120 + MAX_REASON_BYTES);
        // Multibyte, empty, and ordinary reasons through the same emitters.
        let multibyte = "日本語のエラー".repeat(200);
        let line = lines(|| warn_attestation_rejected(&multibyte));
        assert!(
            line[0].len()
                <= "mikagami: WARN attestation intent rejected: ".len() + MAX_REASON_BYTES
        );
        assert_eq!(
            lines(|| warn_attempt_blocked("", None)),
            [format!("{PREFIX_BLOCKED}unspecified")]
        );
        assert_eq!(
            lines(|| warn_attempt_blocked("local safety not ready", None)),
            [format!("{PREFIX_BLOCKED}local safety not ready")]
        );
    }

    #[test]
    fn stage14_11_capture_is_per_thread_and_off_by_default() {
        // Without `capture_start` nothing is recorded (the line goes to stderr).
        info_fencing_transition(1, "node-b", "UNKNOWN", "REQUESTED");
        assert!(capture_take().is_empty());
    }

    // ---- Phase 14.11 second remediation L2: the fencing-step WARN path ----

    const PREFIX_STEP: &str = "mikagami: WARN fencing step not committed: ";

    /// The fencing-step WARN — the path the independent re-audit found still
    /// printing a raw `NodeMutationError::Io(String)` — carries a canonically
    /// bounded reason: at most 240 UTF-8 bytes including the truncation mark,
    /// valid UTF-8, one line, deterministic, and unchanged for ordinary text.
    #[test]
    fn stage14_11_fencing_step_warn_reason_is_canonically_bounded() {
        // The contract is 240 UTF-8 bytes including the truncation mark. The
        // literal is used on purpose, so changing the constant is caught here
        // rather than silently followed by the assertions below.
        const LIMIT: usize = 240;
        assert_eq!(MAX_REASON_BYTES, LIMIT);
        // Short reason: exact, no truncation mark.
        assert_eq!(
            lines(|| warn_fencing_step_not_committed("No such file or directory (os error 2)")),
            [format!(
                "{PREFIX_STEP}No such file or directory (os error 2)"
            )]
        );
        // Exact boundary: 240 bytes pass through whole.
        let exact = "a".repeat(LIMIT);
        assert_eq!(
            lines(|| warn_fencing_step_not_committed(&exact)),
            [format!("{PREFIX_STEP}{exact}")]
        );
        // 241+ bytes: cut to exactly the bound, mark included.
        for over in [LIMIT + 1, 300, 8_192usize, 200_000] {
            let reason = "e".repeat(over);
            let line = lines(|| warn_fencing_step_not_committed(&reason));
            assert_eq!(line.len(), 1);
            assert_eq!(line[0].len(), PREFIX_STEP.len() + LIMIT, "{over} bytes");
            assert!(line[0].ends_with("..."), "{over} bytes: {line:?}");
        }
        // 8192 ASCII characters, the exact case the re-audit named.
        let huge = "K".repeat(8192);
        assert_eq!(
            lines(|| warn_fencing_step_not_committed(&huge)),
            [format!("{PREFIX_STEP}{}", bounded_reason(&huge))]
        );
        // Large Japanese UTF-8 and mixed multibyte: cut on a character
        // boundary, never inside one, always valid UTF-8.
        for reason in [
            "日本語のエラー".repeat(200),
            format!("{}mixed 日本語 🦀 é e\u{301} text", "x".repeat(400)),
            "🦀".repeat(400),
        ] {
            let line = lines(|| warn_fencing_step_not_committed(&reason));
            assert_eq!(line.len(), 1);
            assert!(
                line[0].len() <= PREFIX_STEP.len() + LIMIT,
                "{} bytes",
                line[0].len()
            );
            assert!(line[0].ends_with("..."), "{line:?}");
            let kept = line[0][PREFIX_STEP.len()..].strip_suffix("...").unwrap();
            assert!(reason.starts_with(kept), "the kept text is a prefix");
        }
        // Newline, CR, NUL and other control characters can never break the
        // one-line format.
        let control =
            lines(|| warn_fencing_step_not_committed("io error:\nsecond\r\nthird\u{0}\u{7}end"));
        assert_eq!(control.len(), 1);
        assert!(!control[0].contains('\n') && !control[0].contains('\r'));
        assert!(!control[0].contains('\u{0}') && !control[0].contains('\u{7}'));
        assert_eq!(
            control,
            [format!(
                "{PREFIX_STEP}{}",
                bounded_reason("io error:\nsecond\r\nthird\u{0}\u{7}end")
            )]
        );
        // Empty and whitespace-only reasons.
        assert_eq!(
            lines(|| warn_fencing_step_not_committed("")),
            [format!("{PREFIX_STEP}unspecified")]
        );
        assert_eq!(
            lines(|| warn_fencing_step_not_committed("  \t\n \r")),
            [format!("{PREFIX_STEP}unspecified")]
        );
        // Deterministic: the same input yields the same line every time.
        let repeated = lines(|| warn_fencing_step_not_committed(&huge));
        for _ in 0..8 {
            assert_eq!(lines(|| warn_fencing_step_not_committed(&huge)), repeated);
        }
        // One line out, whatever the input size.
        for over in [0usize, 1, LIMIT, LIMIT + 1, 8_192, 100_000] {
            assert_eq!(
                lines(|| warn_fencing_step_not_committed(&"z".repeat(over))).len(),
                1,
                "{over}"
            );
        }
    }

    /// The other two Phase 14.11 operator lines that carried raw error text
    /// take the same canonical bound, with their own prefixes.
    #[test]
    fn stage14_11_remaining_raw_error_lines_are_bounded() {
        let huge = "R".repeat(8192);
        let shutdown = lines(|| warn_shutdown_step_rejected(&huge));
        assert_eq!(
            shutdown,
            [format!(
                "mikagami: WARN bounded shutdown step rejected: {}",
                bounded_reason(&huge)
            )]
        );
        assert!(
            shutdown[0].len()
                <= "mikagami: WARN bounded shutdown step rejected: ".len() + MAX_REASON_BYTES
        );
        let gate = lines(|| warn_fencing_gate_failed_closed(&huge));
        assert_eq!(
            gate,
            [format!(
                "mikagami: WARN fencing gate failed closed: {}",
                bounded_reason(&huge)
            )]
        );
        assert!(
            gate[0].len() <= "mikagami: WARN fencing gate failed closed: ".len() + MAX_REASON_BYTES
        );
        assert_eq!(
            lines(|| warn_fencing_gate_failed_closed("clearance refused")),
            ["mikagami: WARN fencing gate failed closed: clearance refused"]
        );
        assert_eq!(
            lines(|| warn_shutdown_step_rejected("")),
            ["mikagami: WARN bounded shutdown step rejected: unspecified"]
        );
    }
}
