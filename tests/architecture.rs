//! Architecture Guard v1: dependency-direction checks.
//!
//! These guards are intentionally small. They enforce the direction of module
//! dependencies, not naming or vocabulary.

use std::fs;
use std::path::{Path, PathBuf};

// Source analysis for the guards of the manual control plane (audit G-01).
mod manual_scan;

/// Observation and policy layers must not depend on mutation-capable layers.
///
/// Safety invariant: an observation (`Ready`/`Unavailable`/eligibility) must
/// never be able to reach the code that mutates authority or resources. If
/// these modules could import `resource_executor`, `resource_workflow`,
/// `linux_node_runtime`, or `node_lease_authority`, an observation could
/// silently acquire authority or mutate VIP/service/lease, bypassing the
/// fail-closed policy gates and risking split-brain.
const PROTECTED_MODULES: &[&str] = &[
    "evidence_fusion",
    "witness_evidence_adapter",
    "failover_policy",
    "promotion_authorization",
    // Stage 13.1: the promotion-attempt lifecycle is inert plumbing; it must
    // never gain a path to mutation-capable layers.
    "promotion_attempt",
    // v1.0: the pure decision modules (Bootstrap Admission, the automatic
    // trigger, the health filter) must never gain a path to mutation layers.
    "bootstrap_admission",
    "auto_failover",
    "health_hysteresis",
];

const FORBIDDEN_MUTATION_MODULES: &[&str] = &[
    "resource_executor",
    "resource_workflow",
    "linux_node_runtime",
    "node_lease_authority",
];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Extract exactly one function body, starting at the declaration containing
/// `signature` and ending at its matching closing brace.
///
/// Brace matching is lexical but sufficient for this crate's hand-written
/// production code, which contains no raw strings and no brace-in-string
/// literals inside the functions these guards inspect. Comments must already
/// be stripped by the caller so a commented-out brace cannot skew matching.
fn function_body(source: &str, signature: &str) -> String {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("function signature not found: {signature}"));
    let open = source[start..]
        .find('{')
        .map(|offset| start + offset)
        .unwrap_or_else(|| panic!("function body has no opening brace: {signature}"));
    let mut depth = 0usize;
    for (index, byte) in source.as_bytes()[open..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return source[open..=open + index].to_string();
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced braces in function body: {signature}");
}

/// Assert that `first` appears before `second` inside a single function body.
/// A presence-only check is not enough here: the gate must precede the
/// mutation, not merely exist somewhere in the function.
fn assert_before(body: &str, first: &str, second: &str, message: &str) {
    let first_at = body
        .find(first)
        .unwrap_or_else(|| panic!("{message}: missing {first:?}"));
    let second_at = body
        .find(second)
        .unwrap_or_else(|| panic!("{message}: missing {second:?}"));
    assert!(
        first_at < second_at,
        "{message} (found {first:?} at {first_at}, {second:?} at {second_at})"
    );
}

/// Remove `//` line comments and `/* */` block comments so that a module path
/// mentioned only in prose is not treated as a dependency. This is a small,
/// best-effort lexer sufficient for source files that contain no raw strings
/// with comment markers.
fn strip_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = String::with_capacity(bytes.len());
    let mut index = 0;
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    while index < bytes.len() {
        let current = bytes[index];
        let next = bytes.get(index + 1).copied();
        if in_line_comment {
            if current == b'\n' {
                in_line_comment = false;
                output.push('\n');
            }
            index += 1;
            continue;
        }
        if in_block_comment {
            if current == b'*' && next == Some(b'/') {
                in_block_comment = false;
                index += 2;
            } else {
                if current == b'\n' {
                    output.push('\n');
                }
                index += 1;
            }
            continue;
        }
        if current == b'/' && next == Some(b'/') {
            in_line_comment = true;
            index += 2;
            continue;
        }
        if current == b'/' && next == Some(b'*') {
            in_block_comment = true;
            index += 2;
            continue;
        }
        output.push(current as char);
        index += 1;
    }
    output
}

/// Return the forbidden dependency markers referenced by `source`.
///
/// A dependency exists only when the forbidden module is referenced as a crate
/// path, e.g. `use crate::resource_executor::...` or a fully-qualified
/// `crate::resource_executor::...` call.
fn forbidden_dependencies(source: &str) -> Vec<&'static str> {
    let code = strip_comments(source);
    FORBIDDEN_MUTATION_MODULES
        .iter()
        .copied()
        .filter(|forbidden| code.contains(&format!("crate::{forbidden}")))
        .collect()
}

fn source_path(module: &str) -> PathBuf {
    manifest_dir().join("src").join(format!("{module}.rs"))
}

/// MKM-ARCH-001
#[test]
fn mkm_arch_001_observation_and_policy_do_not_depend_on_mutation_layers() {
    let mut violations = Vec::new();
    for module in PROTECTED_MODULES {
        let path: &Path = &source_path(module);
        let source = fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("MKM-ARCH-001: cannot read {path:?}: {error}"));
        for forbidden in forbidden_dependencies(&source) {
            violations.push(format!("{module} -> crate::{forbidden}"));
        }
    }
    assert!(
        violations.is_empty(),
        "MKM-ARCH-001 violated: observation/policy layer must not depend on \
         mutation-capable layers (an observation could then mutate authority, \
         lease, VIP, or service, bypassing fail-closed policy): {violations:?}"
    );
}

/// MKM-ARCH-001 self-check: the detector must both catch a real dependency and
/// ignore a module path that appears only in a comment, so the guard cannot
/// pass trivially.
#[test]
fn mkm_arch_001_detector_catches_code_and_ignores_comments() {
    assert_eq!(
        forbidden_dependencies("use crate::resource_executor::ResourceExecutor;"),
        vec!["resource_executor"]
    );
    assert_eq!(
        forbidden_dependencies("// see crate::node_lease_authority for details"),
        Vec::<&str>::new()
    );
    assert_eq!(
        forbidden_dependencies("/* crate::resource_workflow */ fn f() {}"),
        Vec::<&str>::new()
    );
    assert_eq!(
        forbidden_dependencies("let _ = crate::linux_node_runtime::new();"),
        vec!["linux_node_runtime"]
    );
}

/// MKM-ARCH-012 remediation F-01: `RuntimeLeaseAuthority` is the single
/// usable authority value and must stay non-clonable. A `Clone` impl would
/// let Stage 13.2 mint an attempt-bound copy while the installed original
/// also remains usable — two simultaneously usable authority values, which
/// the move-ownership contract forbids. The compiler enforces this once the
/// derive is gone; this guard makes an accidental reintroduction visible.
#[test]
fn mkm_arch_012_remediation_f01_lease_authority_is_not_clonable() {
    let source = fs::read_to_string(source_path("node_lease_authority"))
        .expect("MKM-ARCH-012-F01: cannot read node_lease_authority.rs");
    let code = strip_comments(&source);
    let declaration = code
        .find("pub struct RuntimeLeaseAuthority")
        .expect("MKM-ARCH-012-F01: RuntimeLeaseAuthority declaration not found");
    let derive_start = code[..declaration]
        .rfind("#[derive(")
        .expect("MKM-ARCH-012-F01: RuntimeLeaseAuthority has no derive");
    let derive = &code[derive_start..declaration];
    assert!(
        !derive.contains("Clone") && !derive.contains("Copy"),
        "MKM-ARCH-012-F01 violated: RuntimeLeaseAuthority must stay \
         non-Clone/non-Copy so no second usable authority value can exist"
    );

    // The attempt-bound wrapper must be minted by moving the installed
    // authority, never by cloning a reference to it.
    let daemon =
        fs::read_to_string(source_path("daemon")).expect("MKM-ARCH-012-F01: cannot read daemon.rs");
    let squashed: String = strip_comments(&daemon).split_whitespace().collect();
    assert!(
        !squashed.contains("installed_lease_authority().clone"),
        "MKM-ARCH-012-F01 violated: Stage 13.2 must not clone the installed \
         authority to mint the attempt-bound wrapper"
    );
}

/// MKM-ARCH-013: the retired Stage 12.x authorization semantics must not
/// exist anywhere in production code. `WitnessStatus::Reachable` was the
/// ambiguous transport-level name and `CorroboratedLoss` the ambiguous
/// fusion state; Stage 13.3 replaces them with
/// `AuthorityViewCompatible` / `FailoverEvidenceReady`. No compatibility
/// alias may reintroduce the unsafe meaning.
#[test]
fn mkm_arch_013_retired_authorization_semantics_are_absent() {
    let src = manifest_dir().join("src");
    let mut violations = Vec::new();
    for entry in fs::read_dir(&src).expect("MKM-ARCH-013: cannot read src/") {
        let path = entry.expect("MKM-ARCH-013: bad dir entry").path();
        // Skip dotfiles (e.g. macOS AppleDouble `._*.rs` metadata): they are
        // never Rust source and may not be valid UTF-8.
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_none_or(|n| n.starts_with('.'))
        {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("MKM-ARCH-013: cannot read {path:?}: {error}"));
        let code = strip_comments(&source);
        for retired in ["WitnessStatus::Reachable", "CorroboratedLoss"] {
            if code.contains(retired) {
                violations.push(format!("{} contains {retired}", path.display()));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "MKM-ARCH-013 violated: retired authorization semantics must not \
         exist in code (no compatibility aliases): {violations:?}"
    );
}

/// MKM-ARCH-013: evidence must never mint executable authority or reach
/// the mutation boundary. The observation/evidence layers must contain
/// no path to `RuntimeLeaseAuthority` / `AttemptBoundLeaseAuthority`,
/// lease acquisition, or Stage 11 promotion — `Authorized` is only
/// permission to enter the mandatory fresh Stage 13.2 lease phase.
#[test]
fn mkm_arch_013_evidence_cannot_construct_lease_authority() {
    const EVIDENCE_MODULES: &[&str] = &[
        "evidence_fusion",
        "witness_evidence_adapter",
        "failure_assessment",
        "failover_policy",
        "promotion_authorization",
    ];
    const FORBIDDEN_MARKERS: &[&str] = &[
        "RuntimeLeaseAuthority",
        "AttemptBoundLeaseAuthority",
        "acquire_lease",
        "begin_lease_request",
        "execute_lease_request",
        "ResourceWorkflow",
        "take_installed_lease_authority",
    ];
    let mut violations = Vec::new();
    for module in EVIDENCE_MODULES {
        let path = source_path(module);
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("MKM-ARCH-013: cannot read {path:?}: {error}"));
        let code = strip_comments(&source);
        for marker in FORBIDDEN_MARKERS {
            if code.contains(marker) {
                violations.push(format!("{module} contains {marker}"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "MKM-ARCH-013 violated: evidence/policy layers must not construct \
         lease authority or reach the mutation boundary: {violations:?}"
    );
}

/// MKM-ARCH-013: evidence values are ephemeral. `LocalLossEvidence` and
/// `WitnessAuthorityViewEvidence` must not be serializable, persistable,
/// or clonable — restart destroys them and no snapshot can restore them.
#[test]
fn mkm_arch_013_evidence_is_ephemeral_not_persistable() {
    let checks = [
        ("failure_assessment", "pub struct LocalLossEvidence"),
        (
            "witness_evidence_adapter",
            "pub(crate) struct WitnessAuthorityViewEvidence",
        ),
    ];
    for (module, declaration_marker) in checks {
        let path = source_path(module);
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("MKM-ARCH-013: cannot read {path:?}: {error}"));
        let code = strip_comments(&source);
        let declaration = code
            .find(declaration_marker)
            .unwrap_or_else(|| panic!("MKM-ARCH-013: {declaration_marker} not found in {module}"));
        let derive_start = code[..declaration]
            .rfind("#[derive(")
            .unwrap_or_else(|| panic!("MKM-ARCH-013: {declaration_marker} has no derive"));
        let derive = &code[derive_start..declaration];
        for forbidden in ["Clone", "Copy", "Serialize", "Deserialize"] {
            assert!(
                !derive.contains(forbidden),
                "MKM-ARCH-013 violated: {declaration_marker} must not derive \
                 {forbidden} (ephemeral evidence must not be cloned, copied, \
                 or persisted)"
            );
        }
    }
    // Neither evidence module may name a serde/persistence boundary in
    // real code for its evidence types.
    for module in ["failure_assessment", "witness_evidence_adapter"] {
        let path = source_path(module);
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("MKM-ARCH-013: cannot read {path:?}: {error}"));
        let code = strip_comments(&source);
        for marker in ["serde::", "to_writer", "from_reader", "persist"] {
            assert!(
                !code.contains(marker),
                "MKM-ARCH-013 violated: {module} references persistence \
                 boundary {marker:?} — evidence must never be persisted"
            );
        }
    }
}

/// MKM-ARCH-013: no CLI promotion path and no automatic failover caller.
/// `main` must stay inert: no `mikagami promote`, no daemon start, no
/// background loop constructing a promotion request.
#[test]
fn mkm_arch_013_no_cli_promotion_or_automatic_failover() {
    let main = fs::read_to_string(source_path("main")).expect("MKM-ARCH-013: cannot read main.rs");
    let code = strip_comments(&main);
    for forbidden in [
        "promote",
        "PromotionExecutionRequest",
        "execute_promotion_attempt",
        "PromotionAttemptLifecycle",
        "Daemon::new",
        "loop {",
        "loop{",
    ] {
        assert!(
            !code.contains(forbidden),
            "MKM-ARCH-013 violated: main.rs contains {forbidden:?} — no CLI \
             promotion surface or automatic failover trigger may exist"
        );
    }
}

/// MKM-ARCH-013: Protocol v1 wire is unchanged. The version constant must
/// remain 1; Stage 13.3 is a semantic adapter/policy implementation over
/// the existing TermStatus message only.
#[test]
fn mkm_arch_013_protocol_v1_unchanged() {
    let protocol =
        fs::read_to_string(source_path("protocol")).expect("MKM-ARCH-013: cannot read protocol.rs");
    let code = strip_comments(&protocol);
    assert!(
        code.contains("pub const PROTOCOL_VERSION: u32 = 1;"),
        "MKM-ARCH-013 violated: PROTOCOL_VERSION must remain 1 (wire unchanged)"
    );
}

/// MKM-13.4-06: the Stage 13.4 CLI wiring (main/cli/daemon_run/status) must
/// never gain a call path to promotion execution, lease acquisition, or
/// resource mutation. The library keeps those methods for later stages —
/// this guard constrains only what the binary's command surface can reach.
#[test]
fn mkm_arch_014_cli_wiring_cannot_reach_promotion_or_mutation() {
    // Stage 14 §33.2 (Phase 14.8): the `recover` CLI and the intent-file
    // module it shares with the daemon are CLI modules too.
    const CLI_WIRING_MODULES: &[&str] = &["main", "cli", "status", "recover", "attestation"];
    // Stage 14 §33.2: no Node store write API, confirmation, Witness
    // session, or fencing backend from any CLI module.
    const STAGE14_CLI_MARKERS: &[&str] = &[
        ".initialize_new(",
        ".begin_",
        ".complete(",
        ".arm_",
        "persist(",
        ".retire",
        "confirm_by_",
        "open_fencing_incident",
        "apply_fencing_transition",
        "mint_fencing_clearance",
        "WitnessSession",
        "crate::fencing_backend",
    ];
    const FORBIDDEN_MARKERS: &[&str] = &[
        "execute_promotion_attempt",
        "request_promotion_attempt",
        "PromotionExecutionRequest",
        "acquire_attempt_lease",
        "acquire_lease",
        "begin_lease_request",
        "execute_lease_request",
        "take_installed_lease_authority",
        "ResourceWorkflow",
        "ResourceExecutor",
        "crate::node_witness_runtime",
        "crate::promotion_runtime",
        "crate::promotion_authorization",
        "crate::failover_policy",
    ];
    let mut violations = Vec::new();
    for module in CLI_WIRING_MODULES {
        let path = source_path(module);
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("MKM-13.4-06: cannot read {path:?}: {error}"));
        let code = strip_comments(&source);
        // `#[cfg(test)]` fixture code may legitimately name these APIs; the
        // production path is what must stay unreachable.
        let production = code
            .find(&"mod tests")
            .map_or(code.as_str(), |i| &code[..i]);
        for marker in FORBIDDEN_MARKERS.iter().chain(STAGE14_CLI_MARKERS) {
            if production.contains(marker) {
                violations.push(format!("{module} contains {marker}"));
            }
        }
    }
    // Stage 13.5: daemon_run is the one module that may reach promotion —
    // exactly once, through the consumed-intent path into
    // `Daemon::execute_promotion_attempt`. The sanctioned markers are
    // count-checked; every other marker stays forbidden there.
    const SANCTIONED_INTENT_MARKERS: &[&str] = &[
        "execute_promotion_attempt",
        "PromotionExecutionRequest",
        "PromotionRequestId",
    ];
    let daemon_run =
        fs::read_to_string(source_path("daemon_run")).expect("MKM-13.5: cannot read daemon_run.rs");
    let daemon_run_code = strip_comments(&daemon_run);
    let daemon_run_production = daemon_run_code
        .find("mod tests")
        .map_or(daemon_run_code.as_str(), |i| &daemon_run_code[..i]);
    for marker in FORBIDDEN_MARKERS {
        if SANCTIONED_INTENT_MARKERS.contains(marker) {
            continue;
        }
        if daemon_run_production.contains(marker) {
            violations.push(format!("daemon_run contains {marker}"));
        }
    }
    assert!(
        violations.is_empty(),
        "MKM-13.4-06/13.5 violated: CLI wiring must not reach promotion, lease \
         acquisition, or resource mutation outside the one sanctioned \
         intent->attempt call site: {violations:?}"
    );
}

/// MKM-13.4-04: the one-shot status report must stay read-only — no daemon
/// machinery, no Witness/peer contact, no ticking, no PSK load, no
/// persistence writes.
#[test]
fn mkm_arch_014_status_is_one_shot_read_only() {
    const FORBIDDEN_MARKERS: &[&str] = &[
        "crate::daemon",
        "crate::daemon_run",
        "crate::daemon_peer_runtime",
        "crate::linux_node_runtime",
        "crate::witness_runtime",
        "crate::node_witness_runtime",
        "crate::evidence_fusion",
        "crate::failover_policy",
        "crate::promotion",
        "WitnessSession",
        "TcpConnection",
        "Psk::load",
        "MessageAuthenticator",
        ".tick(",
        ".tick_at(",
        "send_get_term",
        "Instant::now",
        "UnixListener",
        "TcpListener",
        // Phase 14.11 (§28): the Stage 14 lines are presentation only. Status
        // never writes, creates, renames, or removes anything, never logs, and
        // never touches a fencing or authority writer.
        "std::fs",
        "fs::write",
        "File::create",
        "OpenOptions",
        "remove_file",
        "remove_dir",
        "rename(",
        "create_dir",
        "operator_log",
        "eprintln!",
        "open_fencing_incident",
        "apply_fencing_transition",
        "retire_fencing_incident",
        "arm_consuming_fencing",
        "mint_fencing_clearance",
        "crate::fencing_backend",
        "crate::attestation::install_intent",
        "remove_intent",
    ];
    let path = source_path("status");
    let source = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("MKM-13.4-04: cannot read {path:?}: {error}"));
    let code = strip_comments(&source);
    let production = code.find("mod tests").map_or(code.as_str(), |i| &code[..i]);
    let mut violations = Vec::new();
    for marker in FORBIDDEN_MARKERS {
        if production.contains(marker) {
            violations.push(format!("status contains {marker}"));
        }
    }
    assert!(
        violations.is_empty(),
        "MKM-13.4-04 violated: status must be a one-shot read-only report \
         with no daemon/witness/promotion surface: {violations:?}"
    );
}

/// MKM-13.4-11 + test-constructor boundary: the production wiring must not
/// use test-only constructors or accept secret material through the CLI.
/// `cli.rs` must never name a `psk` argument at all — the PSK reaches the
/// process only via `Psk::load` on the configured file.
#[test]
fn mkm_arch_014_no_test_constructors_or_cli_psk_in_production_wiring() {
    const WIRING_MODULES: &[&str] = &["main", "cli", "daemon_run", "status", "recover"];
    const TEST_ONLY_MARKERS: &[&str] = &[
        "new_for_test",
        "from_test_bytes",
        "TestClock",
        "ScriptedWitness",
        "new_for_test_with",
    ];
    let mut violations = Vec::new();
    for module in WIRING_MODULES {
        let path = source_path(module);
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("MKM-13.4-11: cannot read {path:?}: {error}"));
        let code = strip_comments(&source);
        // Test-only constructors may legitimately appear inside the
        // `#[cfg(test)]` module; scan only the production portion.
        let production = code.find("mod tests").map_or(code.as_str(), |i| &code[..i]);
        for marker in TEST_ONLY_MARKERS {
            if production.contains(marker) {
                violations.push(format!("{module} production code contains {marker}"));
            }
        }
    }
    let cli = fs::read_to_string(source_path("cli")).expect("MKM-13.4-11: cannot read cli.rs");
    let cli_code = strip_comments(&cli);
    let cli_production = cli_code
        .find("mod tests")
        .map_or(cli_code.as_str(), |i| &cli_code[..i]);
    assert!(
        !cli_production.contains("psk"),
        "MKM-13.4-11 violated: cli.rs must not define any argument that could \
         carry raw PSK material"
    );
    assert!(
        violations.is_empty(),
        "MKM-13.4 violated: production wiring must not use test-only \
         constructors: {violations:?}"
    );
}

/// MKM-13.4-09: the production path establishes exactly one WitnessSession
/// construction site. More than one `WitnessSession::new`/`WitnessConnection::
/// new` in the wiring would risk parallel sessions or extra outstanding
/// request slots.
#[test]
fn mkm_arch_014_single_witness_session_construction() {
    let path = source_path("daemon_run");
    let source = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("MKM-13.4-09: cannot read {path:?}: {error}"));
    let code = strip_comments(&source);
    let production = code.find("mod tests").map_or(code.as_str(), |i| &code[..i]);
    for marker in ["WitnessSession::new", "WitnessConnection::new"] {
        let count = production.matches(marker).count();
        assert_eq!(
            count, 1,
            "MKM-13.4-09 violated: expected exactly one {marker} call site in \
             the production wiring, found {count}"
        );
    }
}

/// MKM-13.5-01/02: the SIGUSR1 handler must be signal-safe — set the atomic
/// latch and return, nothing else. The handler body must not contain any
/// allocation, logging, I/O, locking, witness/authority/lease/promotion
/// call, or non-atomic operation.
#[test]
fn mkm_arch_015_sigusr1_handler_is_signal_safe() {
    let source = fs::read_to_string(source_path("daemon_run"))
        .expect("MKM-13.5-01: cannot read daemon_run.rs");
    let code = strip_comments(&source);
    let start = code
        .find("fn on_promotion_intent")
        .expect("MKM-13.5-01: on_promotion_intent handler must exist");
    // The handler body ends at the first closing brace at function level.
    let body_start = code[start..]
        .find('{')
        .map(|i| start + i)
        .expect("MKM-13.5-01: handler body not found");
    let body_end = code[body_start..]
        .find('}')
        .map(|i| body_start + i)
        .expect("MKM-13.5-01: handler body not terminated");
    let body = &code[body_start..body_end];
    for marker in [
        "println",
        "eprintln",
        "log::",
        "format!",
        "Vec",
        "String::",
        "lock()",
        "Mutex",
        "send_",
        "receive",
        "tick",
        "evaluate",
        "lease",
        "promot",
        "TcpStream",
        "File::",
        "read(",
        "write(",
    ] {
        assert!(
            !body.contains(marker),
            "MKM-13.5-01 violated: signal handler body contains forbidden \
             operation {marker:?}: {body}"
        );
    }
    assert!(
        body.contains("PROMOTION_INTENT.store(true"),
        "MKM-13.5-01 violated: handler must only set the atomic intent latch: \
         {body}"
    );
}

/// MKM-13.5-03/04: exactly one production call path may reach promotion —
/// the consumed-intent closure inside the daemon loop. `main`, `cli`, and
/// `status` must carry no promotion surface at all, and `daemon_run` may
/// contain the sanctioned markers exactly once each.
#[test]
fn mkm_arch_015_single_production_promotion_entry() {
    for (module, marker, expected) in [
        ("daemon_run", "execute_promotion_attempt", 1usize),
        ("daemon_run", "PromotionExecutionRequest::new", 1),
        ("daemon_run", "PromotionRequestId::new", 1),
        ("daemon_run", "SIGUSR1", 1),
        ("main", "execute_promotion_attempt", 0),
        ("cli", "execute_promotion_attempt", 0),
        ("status", "execute_promotion_attempt", 0),
    ] {
        let source = fs::read_to_string(source_path(module))
            .unwrap_or_else(|error| panic!("MKM-13.5-03: cannot read {module}.rs: {error}"));
        let code = strip_comments(&source);
        let production = code.find("mod tests").map_or(code.as_str(), |i| &code[..i]);
        let count = production.matches(marker).count();
        assert_eq!(
            count, expected,
            "MKM-13.5-03 violated: expected {expected} occurrence(s) of \
             {marker:?} in {module} production code, found {count}"
        );
    }
}

/// MKM-13.5-07: no PID discovery, pidfile, process scanning, daemon
/// registry, general IPC, control socket, or remote operator surface may be
/// introduced — the signal is the only operator channel.
#[test]
fn mkm_arch_015_no_pid_ipc_or_control_plane() {
    // Stage 14 §33.2 (Phase 14.8): `recover` and its intent-file module join
    // the wiring set; every forbidden marker is kept.
    const WIRING_MODULES: &[&str] = &[
        "main",
        "cli",
        "daemon_run",
        "status",
        "recover",
        "attestation",
    ];
    const FORBIDDEN_MARKERS: &[&str] = &[
        "pidfile",
        "getpid",
        "pgrep",
        "UnixListener",
        "UnixStream",
        "UnixDatagram",
        "signal_hook",
        "daemonize",
        "SIGUSR2",
        "libc::kill",
        "kill(",
        "/proc/",
        "Process::",
        "fork(",
        "mqueue",
        "shm_open",
        "bind(",       // no new listening socket
        "TcpListener", // wiring must not open server sockets
    ];
    let mut violations = Vec::new();
    for module in WIRING_MODULES {
        let source = fs::read_to_string(source_path(module))
            .unwrap_or_else(|error| panic!("MKM-13.5-07: cannot read {module}.rs: {error}"));
        let code = strip_comments(&source);
        let production = code.find("mod tests").map_or(code.as_str(), |i| &code[..i]);
        for marker in FORBIDDEN_MARKERS {
            if production.contains(marker) {
                violations.push(format!("{module} contains {marker}"));
            }
        }
    }
    // The CLI must not grow a `promote` helper — SIGUSR1 is the only
    // operator channel (the daemon_run loop's `promote` closure parameter is
    // the sanctioned intent->attempt plumbing, not a command surface).
    let cli = fs::read_to_string(source_path("cli")).expect("cannot read cli.rs");
    let cli_production = strip_comments(&cli);
    let cli_production = cli_production
        .find("mod tests")
        .map_or(cli_production.as_str(), |i| &cli_production[..i]);
    assert!(
        !cli_production.contains("promote"),
        "MKM-13.5-07 violated: no `mikagami promote` helper may be added"
    );
    // Stage 14 §33.2: the same token ban applies to `recover.rs` (and the
    // intent-file module it uses).
    for module in ["recover", "attestation"] {
        assert!(
            !production_source(module).contains("promote"),
            "{module}: the activation-command token"
        );
    }
    // Stage 14 §33.2: `ATTESTATION_INTENT_FILE` is defined exactly once and
    // reached by exactly one CLI writer and one daemon reader.
    let mut definitions = 0;
    let mut writers = Vec::new();
    let mut readers = Vec::new();
    for (module, code) in production_modules() {
        definitions += code.matches("const ATTESTATION_INTENT_FILE").count();
        assert!(
            module == "attestation" || !code.contains("fence-attestation"),
            "{module} spells the intent file name"
        );
        if module != "attestation" {
            for _ in code.matches("install_intent(") {
                writers.push(module.clone());
            }
            for _ in code.matches("read_intent(") {
                readers.push(module.clone());
            }
        }
    }
    assert_eq!(definitions, 1);
    assert_eq!(writers, ["recover"]);
    assert_eq!(readers, ["linux_node_runtime"]);
    assert!(
        violations.is_empty(),
        "MKM-13.5-07 violated: no PID discovery, IPC, or control-plane \
         surface may be introduced: {violations:?}"
    );
}

/// MKM-13.5-08: the intent latch must be a single atomic boolean — no
/// counter, queue, channel, or Mutex may carry promotion intent. The latch
/// is the only state the signal handler is allowed to touch.
#[test]
fn mkm_arch_015_intent_latch_is_a_single_atomic() {
    let source = fs::read_to_string(source_path("daemon_run"))
        .expect("MKM-13.5-08: cannot read daemon_run.rs");
    let code = strip_comments(&source);
    let production = code.find("mod tests").map_or(code.as_str(), |i| &code[..i]);
    assert_eq!(
        production.matches("PROMOTION_INTENT").count() >= 2,
        true,
        "MKM-13.5-08: PROMOTION_INTENT static must exist and be referenced \
         by the handler"
    );
    assert!(
        production.contains("static PROMOTION_INTENT: AtomicBool = AtomicBool::new(false)"),
        "MKM-13.5-08 violated: intent latch must be a plain AtomicBool"
    );
    for marker in [
        "VecDeque<Promotion",
        "Vec<Promotion",
        "mpsc",
        "channel::<Promotion",
        "Mutex<Promotion",
        "Mutex<Option<Promotion",
        "AtomicU64",
        "AtomicUsize",
    ] {
        assert!(
            !production.contains(marker),
            "MKM-13.5-08 violated: intent must not be carried by a counter, \
             queue, or mutex ({marker})"
        );
    }
}

/// MKM-13.6-01: the persistent Node document has one executable slot plus
/// independent O. Intentionally amended by Stage 14 Design Revision 4 §33.2:
/// the document is now v3 and additionally carries exactly one incident slot.
#[test]
fn mkm_arch_016_persistent_v2_one_slot_and_obligation() {
    let source = fs::read_to_string(source_path("node_mutation")).unwrap();
    let code = strip_comments(&source);
    let production = code.find("mod tests").map_or(code.as_str(), |i| &code[..i]);
    assert!(production.contains("NODE_MUTATION_STATE_FORMAT_VERSION: u32 = 3"));
    assert_eq!(
        production.matches("outstanding_mutation: Option<").count(),
        1
    );
    assert_eq!(production.matches("release_obligation: Option<").count(), 1);
    assert_eq!(production.matches("fencing_incident: Option<").count(), 1);
    assert!(production.contains("complete_owned_release"));
}

/// Names declared directly inside one `struct`/`enum` body: field names for
/// a struct, variant names for an enum (nested variant fields are skipped).
fn item_members(production: &str, item: &str, enum_variants: bool) -> Vec<String> {
    let body = function_body(production, item);
    let inner = &body[1..body.len() - 1];
    let mut depth = 0usize;
    let mut members = Vec::new();
    for line in inner.lines() {
        let trimmed = line.trim();
        if depth == 0 {
            let name: String = trimmed
                .trim_start_matches("pub ")
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            let wanted = if enum_variants {
                name.starts_with(|c: char| c.is_ascii_uppercase())
            } else {
                trimmed.starts_with("pub ") && trimmed.contains(':')
            };
            if wanted && !name.is_empty() {
                members.push(name);
            }
        }
        depth += trimmed.matches(['{', '(']).count();
        depth -= trimmed.matches(['}', ')']).count();
    }
    members
}

/// The `#[...]` attribute lines directly above one item declaration.
fn item_attributes(production: &str, item: &str) -> String {
    let start = production
        .find(item)
        .unwrap_or_else(|| panic!("item not found: {item}"));
    production[..start]
        .lines()
        .rev()
        .skip_while(|line| line.trim().is_empty())
        .take_while(|line| line.trim().starts_with("#["))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Stage 14 Design Revision 4 §33.3 `017_node_v3_shape` (Phase 14.1).
///
/// Source shape only: the Node v3 fields are exactly §19.1, the incident
/// fields exactly §12.2, `FencingState` has exactly the five §13.1 variants
/// and no stored `NotRequired`, and every new struct rejects unknown fields.
/// Validation, v2 read-compatibility, and fail-closed parsing are behavioral
/// and are proven by the `node_mutation` Stage 14 tests, not by this guard.
#[test]
fn mkm_arch_017_node_v3_shape() {
    let production = |module: &str| {
        let code = strip_comments(&fs::read_to_string(source_path(module)).unwrap());
        code.find("mod tests")
            .map_or(code.clone(), |i| code[..i].to_string())
    };
    let node = production("node_mutation");
    let fencing = production("fencing");

    assert_eq!(
        item_members(&node, "pub struct NodeMutationPersistentState", false),
        [
            "state_format_version",
            "cluster_id",
            "node_id",
            "initialization_id",
            "highest_started_mutation_generation",
            "outstanding_mutation",
            "release_obligation",
            "highest_fencing_incident_seq",
            "fencing_incident",
        ],
        "Node v3 document fields must be exactly Design §19.1"
    );
    assert_eq!(
        item_members(&fencing, "pub struct FencingIncident", false),
        [
            "incident_seq",
            "incident_id",
            "target_node_id",
            "anchor_term",
            "observer_session_id",
            "observer_loss_generation",
            "attempt_token_high_water",
            "state",
        ],
        "fencing incident fields must be exactly Design §12.2"
    );
    assert_eq!(
        item_members(&fencing, "pub enum FencingState", true),
        ["Unknown", "Requested", "Verifying", "Confirmed", "Failed"],
        "FencingState must have exactly the five Design §13.1 states"
    );
    for code in [&node, &fencing] {
        let folded = code.to_ascii_lowercase().replace(['_', '-'], "");
        assert!(
            !folded.contains("notrequired"),
            "no stored NotRequired fencing state may exist"
        );
    }

    assert!(
        item_attributes(&node, "pub struct NodeMutationPersistentState")
            .contains("deny_unknown_fields")
    );
    for item in [
        "pub struct FencingIncident",
        "pub enum FencingState",
        "pub enum UnknownReason",
        "pub enum ConfirmedBy",
    ] {
        assert!(
            item_attributes(&fencing, item).contains("deny_unknown_fields"),
            "{item} must reject unknown fields"
        );
    }
}

/// MKM-13.6-02: ARM is structurally before the sole Stage 11 promotion call,
/// and Active renewal/reconciliation has no promotion edge.
#[test]
fn mkm_arch_016_arm_precedes_resources_and_renew_cannot_promote() {
    let source = fs::read_to_string(source_path("linux_node_runtime")).unwrap();
    let code = strip_comments(&source);
    let production = code.find("mod tests").map_or(code.as_str(), |i| &code[..i]);
    assert!(production.contains("fn promote(&mut self)"));

    // Stage 13.6 focused remediation: every LeaseRelease transmission path must
    // independently re-verify trusted ZeroResource, and ARM must observe it
    // before the durable obligation is written. Each relationship is asserted
    // *inside the correct function body* and as an ordering, so a neighbouring
    // function cannot satisfy the guard by accident.
    // Stage 14 §33.1/§33.3 (Phase 14.10): the durable ARM in this body is
    // now the atomic `arm_consuming_fencing`; the ordering is unchanged and
    // the plain ARM is gone from the fencing-backed success path.
    let arm_body = function_body(&production, "pub(crate) fn arm_and_promote");
    assert_before(
        &arm_body,
        "observe_trusted_zero_resource",
        "arm_consuming_fencing",
        "arm_and_promote must observe trusted ZeroResource before durable ARM",
    );
    assert_before(
        &arm_body,
        "arm_consuming_fencing",
        "self.promote()",
        "durable ARM must precede the Stage 11 resource mutation",
    );
    assert!(!arm_body.contains("arm_release_obligation"));

    // All three known LeaseRelease send/execute paths. The pending-mutation
    // wrapper delegates to its guarded form, which owns the ZeroResource gate.
    for (path, exec) in [
        (
            "pub(crate) fn release_attempt_lease_once",
            "begin_and_execute_lease_release_once",
        ),
        (
            "pub(crate) fn execute_durable_witness_mutation_once",
            "execute_outstanding_once",
        ),
    ] {
        let body = function_body(&production, path);
        assert!(
            body.contains("ensure_trusted_zero_resource"),
            "{path} must gate on trusted ZeroResource"
        );
        assert_before(
            &body,
            "ensure_trusted_zero_resource",
            exec,
            "{path} must verify trusted ZeroResource before transmitting a Release",
        );
    }
    let pending_wrapper = function_body(
        &production,
        "pub(crate) fn execute_pending_witness_mutation_once",
    );
    assert!(
        pending_wrapper.contains("execute_pending_witness_mutation_once_guarded"),
        "the pending-mutation wrapper must delegate to the guarded form"
    );
    let pending_guarded = function_body(
        &production,
        "fn execute_pending_witness_mutation_once_guarded",
    );
    assert!(
        pending_guarded.contains("ensure_trusted_zero_resource_guarded"),
        "the guarded pending-mutation path must gate on trusted ZeroResource"
    );
    assert_before(
        &pending_guarded,
        "ensure_trusted_zero_resource_guarded",
        "execute_outstanding_once",
        "the guarded pending-mutation path must verify ZeroResource before transmitting a Release",
    );

    // Post-accept completion must reconcile the controller before Standby.
    let pending_body = function_body(
        &production,
        "fn execute_pending_witness_mutation_once_guarded",
    );
    assert!(
        pending_body.contains("reconcile_zero_resource"),
        "Release/CLEAR completion must reconcile the controller"
    );
    assert_before(
        &pending_body,
        "reconcile_zero_resource",
        "complete_demotion",
        "controller reconciliation must precede Standby commit",
    );
    // Stage 13.6 H6: a shutdown verdict must never be taken before durable
    // O/M and recovery state are checked.
    let shutdown_body = function_body(&production, "pub(crate) fn shutdown_for_daemon");
    for required in [
        "load_existing",
        "release_obligation",
        "outstanding_mutation",
        "recovery_reconciled",
        "Failed",
        "RecoveryPending",
    ] {
        assert!(
            shutdown_body.contains(required),
            "shutdown_for_daemon must consider {required}"
        );
    }
    // Stage 13.6 H5: post-demotion scheduling must not consult an expired
    // authority deadline, and the ordinary cadence must remain the fallback.
    let schedule_body = function_body(&production, "pub(crate) fn active_schedule_delay");
    assert!(
        schedule_body.contains("return Ok(ordinary)"),
        "active_schedule_delay must fall back to the ordinary cadence"
    );
    let controller =
        strip_comments(&fs::read_to_string(source_path("node_lease_authority")).unwrap());
    let controller_production = controller
        .find("mod tests")
        .map_or(controller.as_str(), |i| &controller[..i]);
    let delays_body = function_body(
        controller_production,
        "pub(crate) fn active_schedule_delays",
    );
    // Assert the *guard clause*, not merely the field name: `safe_deadline` is
    // also read when building the returned delays, so a presence-only check
    // would pass even if the at/after-deadline early return were deleted.
    assert!(
        delays_body.contains("now >= authority.safe_deadline()"),
        "active_schedule_delays must return no schedule at or after the safe deadline"
    );
    assert_before(
        &delays_body,
        "now >= authority.safe_deadline()",
        "Ok(Some(ActiveScheduleDelays",
        "the expired-deadline guard must precede constructing any Active schedule",
    );
    assert!(
        delays_body.contains("if self.authority.demotion_latched() {"),
        "active_schedule_delays must not schedule while demotion is latched"
    );
    assert_before(
        &delays_body,
        "if self.authority.demotion_latched() {",
        "Ok(Some(ActiveScheduleDelays",
        "the demotion-latch guard must precede constructing any Active schedule",
    );

    // Stage 13.6 A-2: shutdown must join the existing owner with at most one
    // bounded eligible reconciliation step, and that step must be gated by a
    // structural latch so it cannot become a retry loop.
    let daemon_source = strip_comments(&fs::read_to_string(source_path("daemon")).unwrap());
    let daemon_production = daemon_source
        .find("mod tests")
        .map_or(daemon_source.as_str(), |i| &daemon_source[..i]);
    let tick_body = function_body(daemon_production, "pub(crate) fn tick_at");
    assert_before(
        &tick_body,
        "shutdown_bounded_step",
        ".shutdown(&|| self.control_lock_guard.lost().is_none())",
        "the bounded shutdown step must run before the final shutdown verdict",
    );
    assert_before(
        &tick_body,
        "if self.shutdown_requested",
        "shutdown_bounded_step",
        "the bounded step must only run once shutdown is observed",
    );
    let runtime_step_body = function_body(&production, "pub(crate) fn shutdown_bounded_step");
    assert!(
        runtime_step_body.contains("if self.shutdown_step_performed {"),
        "the bounded shutdown step must be guarded by the at-most-once latch"
    );
    assert_before(
        &runtime_step_body,
        "if self.shutdown_step_performed {",
        "drive_post_cleanup_reconciliation",
        "the at-most-once latch must be checked before any reconciliation runs",
    );
    // The latch must also be *set* inside the step, otherwise a guard that
    // only reads the flag would permit repeated steps.
    assert!(
        runtime_step_body.contains("self.shutdown_step_performed = true;"),
        "the bounded shutdown step must set the at-most-once latch before acting"
    );
    assert_before(
        &runtime_step_body,
        "self.shutdown_step_performed = true;",
        "drive_post_cleanup_reconciliation",
        "the latch must be set before the reconciliation step runs",
    );
    assert!(
        runtime_step_body.contains("drive_post_cleanup_reconciliation"),
        "the bounded shutdown step must reuse the single post-cleanup owner"
    );
    // The bounded step must never demote from Active, begin fresh work, or
    // touch the promotion path.
    for forbidden in ["self.demote()", "self.promote()", "begin_lease_release"] {
        assert!(
            !runtime_step_body.contains(forbidden),
            "the bounded shutdown step must not contain {forbidden}"
        );
    }
    let runtime_struct = &production[..production.find("impl LinuxNodeRuntime").unwrap_or(0)];
    assert!(
        runtime_struct.contains("shutdown_step_performed: bool"),
        "the runtime must own the at-most-once shutdown latch"
    );

    let renew = production
        .find("pub(crate) fn drive_foreground_lifecycle")
        .unwrap();
    let renew_body = &production[renew..production[renew..].find("fn promote").unwrap() + renew];
    assert!(!renew_body.contains("promote("));
}

/// Stage 14 Design Revision 4 §33.3 `017_suspect_provenance_timer`
/// (Phase 14.2).
///
/// Source shape only: `failure_assessment::tick`'s elapsed-time
/// `Suspect → CommunicationLost` path is guarded by
/// `suspect_origin == Some(SuspectOrigin::Healthy)`, and `SuspectOrigin` has
/// exactly three variants and is not serializable. The timer restriction and
/// the reset rows are proven behaviorally by the `failure_assessment` Stage 14
/// tests (§34.15), not by this guard.
#[test]
fn mkm_arch_017_suspect_provenance_timer() {
    let source = fs::read_to_string(source_path("failure_assessment")).unwrap();
    let code = strip_comments(&source);
    let production = code.find("mod tests").map_or(code.as_str(), |i| &code[..i]);

    let tick = function_body(production, "pub fn tick(");
    assert_before(
        &tick,
        "self.suspect_origin == Some(SuspectOrigin::Healthy)",
        "self.assessment = PeerFailureAssessment::CommunicationLost",
        "the elapsed-time Suspect -> CommunicationLost path must be gated on Healthy origin",
    );

    assert_eq!(
        item_members(production, "pub enum SuspectOrigin", true),
        ["Healthy", "RestartFormation", "UncertaintyFormation"],
        "SuspectOrigin must have exactly the three Design §10.8 origins"
    );
    let attributes = item_attributes(production, "pub enum SuspectOrigin");
    assert!(
        !attributes.contains("Serialize") && !attributes.contains("Deserialize"),
        "SuspectOrigin must not be serializable"
    );
    assert!(
        !production.contains("serde"),
        "the failure detector must stay runtime-only (no serde)"
    );
}

/// Production region (comments stripped, test module removed) of one module.
fn production_source(module: &str) -> String {
    let code = strip_comments(&fs::read_to_string(source_path(module)).unwrap());
    code.find("mod tests")
        .map_or(code.clone(), |i| code[..i].to_string())
}

/// Every production module under `src/`, by module name.
fn production_modules() -> Vec<(String, String)> {
    let mut modules = Vec::new();
    for entry in fs::read_dir(manifest_dir().join("src")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|extension| extension == "rs") {
            let name = path.file_stem().unwrap().to_string_lossy().into_owned();
            let code = production_source(&name);
            modules.push((name, code));
        }
    }
    modules
}

/// Every production module below `src/`, sub-directories included, named by
/// its `src`-relative path without `.rs` (for example `manual/agent`). The
/// R-2 "A" guard used to scan only `src/*.rs`; a module under `src/manual/`
/// could therefore have introduced a process-wide child reaper unseen
/// (v0.4 audit F-05). This walk is the fix: the guard is about the whole
/// binary, not about the top-level directory.
fn all_production_modules() -> Vec<(String, String)> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(base, &path, out);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let relative = path.strip_prefix(base).unwrap();
                let name = relative
                    .with_extension("")
                    .to_string_lossy()
                    .replace('\\', "/");
                let code = strip_comments(&fs::read_to_string(&path).unwrap());
                let code = code
                    .find("mod tests")
                    .map_or(code.clone(), |i| code[..i].to_string());
                out.push((name, code));
            }
        }
    }
    let base = manifest_dir().join("src");
    let mut modules = Vec::new();
    walk(&base, &base, &mut modules);
    modules.sort_by(|a, b| a.0.cmp(&b.0));
    modules
}

/// Stage 14 Design Revision 4 §33.3 `017_permitted_freshness_sources`
/// (Phase 14.3). Source shape only; the behavior is proven by the
/// `failure_assessment` / `daemon_peer_runtime` Stage 14 tests.
#[test]
fn mkm_arch_017_permitted_freshness_sources() {
    let detector = production_source("failure_assessment");
    let writer = function_body(&detector, "fn record_permitted_observation(");
    let assignments = detector.matches("last_failed_contact_at = Some(").count();
    assert!(assignments >= 1);
    assert_eq!(
        writer.matches("last_failed_contact_at = Some(").count(),
        assignments,
        "last_failed_contact_at may be set only by the permitted-observation writer"
    );
    assert_eq!(
        detector.matches("record_permitted_observation(").count(),
        3,
        "one definition plus exactly the two §10.3 writers"
    );
    for writer in [
        "pub fn observe_initiated_contact_failure(",
        "pub fn observe_verified_listen_window(",
    ] {
        assert!(function_body(&detector, writer).contains("self.record_permitted_observation("));
    }

    let runtime = production_source("daemon_peer_runtime");
    assert_eq!(
        runtime
            .matches(".observe_initiated_contact_failure(")
            .count(),
        3,
        "the detector writer is called once, from the Outbound wrapper, which has exactly the two §10.3.1 callers"
    );
    assert!(
        function_body(&runtime, "fn observe_initiated_contact_failure(")
            .contains(".observe_initiated_contact_failure(t_start, now)")
    );
    assert!(
        function_body(&runtime, "fn observe_initiated_contact_failure(")
            .contains("PeerRuntimeRole::Outbound")
    );
    assert!(
        function_body(&runtime, "fn attempt_reconnect(")
            .contains("self.observe_initiated_contact_failure(")
    );
    assert!(
        function_body(&runtime, "fn expire_handshake_if_due(")
            .contains("self.observe_initiated_contact_failure(")
    );
    assert_eq!(
        runtime.matches(".observe_verified_listen_window(").count(),
        1
    );
    assert!(
        function_body(&runtime, "fn record_accept_sample(")
            .contains(".observe_verified_listen_window(")
    );
    assert_eq!(runtime.matches("self.record_accept_sample(").count(), 1);
    assert!(
        function_body(&runtime, "pub(crate) fn tick_at_with(")
            .contains("self.record_accept_sample(")
    );

    for (module, code) in production_modules() {
        if module == "failure_assessment" || module == "daemon_peer_runtime" {
            continue;
        }
        for marker in [
            "observe_initiated_contact_failure",
            "observe_verified_listen_window",
            "last_failed_contact_at",
            "VerifiedListenWindow",
        ] {
            assert!(
                !code.contains(marker),
                "{module} must not reach the freshness writers ({marker})"
            );
        }
    }
}

/// Stage 14 Design Revision 4 §33.3 `017_verified_listen_contract`
/// (Phase 14.3). Source shape only; GAP-01..12 prove the behavior.
#[test]
fn mkm_arch_017_verified_listen_contract() {
    let runtime = production_source("daemon_peer_runtime");
    assert!(runtime.contains(
        "const VERIFIED_LISTEN_MIN_DURATION: Duration = MAX_RETRY_DELAY.saturating_add(HANDSHAKE_TIMEOUT);"
    ));
    let constructor = function_body(&runtime, "pub(crate) fn new(");
    assert!(constructor.contains(".max(Duration::from_secs(1))"));
    assert!(constructor.contains(".saturating_add(HANDSHAKE_TIMEOUT)"));

    let sample = function_body(&runtime, "fn record_accept_sample(");
    for required in [
        "window.listener_generation != listener_generation",
        "iteration <= window.last_iteration",
        "window.loss_generation != loss_generation",
        "now.checked_duration_since(window.last_sample)",
        "gap > self.listen_max_gap",
        "VERIFIED_LISTEN_MIN_DURATION",
        "ListenWindowVoid::ClockRegression",
    ] {
        assert!(
            sample.contains(required),
            "record_accept_sample: {required}"
        );
    }
    assert!(
        !sample.contains("Instant::now"),
        "the sample timestamp is the iteration now; no clock read"
    );

    // Contract K-3: `tick_at` wraps `tick_at_with` (the probe responder's
    // verdict closure); the body, and so the window logic, lives there.
    let tick = function_body(&runtime, "pub(crate) fn tick_at_with(");
    assert_before(
        &tick,
        "ListenWindowVoid::AcceptedConnection",
        "self.current_token = Some(token)",
        "an accepted connection voids the window before it is installed",
    );
    assert!(tick.contains("ListenWindowVoid::AcceptError"));
    assert!(tick.contains("Ok(TcpRuntimeStep::NoEvent) => self.record_accept_sample(now)"));

    let bind = function_body(&runtime, "pub(crate) fn bind(");
    assert!(bind.contains("self.listener_generation.checked_add(1)"));
    assert!(bind.contains("observe_listener_generation_change"));
    // Revision 5 R.2 `bound_since`: set only by a successful bind from the
    // supplied lifecycle instant, cleared by every listener close.
    assert!(bind.contains("self.bound_since = Some(now)"));
    assert_eq!(runtime.matches("self.bound_since = Some(").count(), 1);
    assert!(function_body(&runtime, "fn close_listener(").contains("self.bound_since = None"));
    assert_eq!(
        runtime.matches("self.transport.close_listener()").count(),
        1,
        "every listener close goes through close_listener"
    );

    let detector = production_source("failure_assessment");
    let attributes = item_attributes(&detector, "pub struct VerifiedListenWindow");
    for forbidden in ["Clone", "Copy", "Serialize", "Deserialize"] {
        assert!(
            !attributes.contains(forbidden),
            "VerifiedListenWindow must not derive {forbidden}"
        );
    }
    assert!(
        function_body(&detector, "pub fn observe_verified_listen_window(")
            .contains("window.w_start")
    );
    assert_eq!(runtime.matches("VerifiedListenWindow::new(").count(), 1);
    for (module, code) in production_modules() {
        if module != "daemon_peer_runtime" {
            assert!(
                !code.contains("VerifiedListenWindow::new("),
                "{module} must not mint verified-listen windows"
            );
        }
    }
}

/// Stage 14 Design Revision 4 §33.3 `017_restart_formation_conservative_only`
/// (Phase 14.3). Source shape only; the formation tests prove the behavior.
#[test]
fn mkm_arch_017_restart_formation_conservative_only() {
    let detector = production_source("failure_assessment");
    let permitted = function_body(&detector, "fn formation_permitted(");
    assert!(permitted.contains("self.restart_formation_enabled"));
    // Revision 5 §10.5 / §11.1: the formation floor is strict.
    assert!(permitted.contains("start > floor"));
    assert!(!permitted.contains(">="));
    let writer = function_body(&detector, "fn record_permitted_observation(");
    assert_eq!(writer.matches("self.formation_permitted(start)").count(), 2);
    assert!(writer.contains("self.confirmation_window"));
    assert!(writer.contains("!self.authenticated_contact_seen"));
    assert_eq!(
        detector.matches("restart_formation_enabled =").count(),
        1,
        "set only by with_restart_formation"
    );
    assert!(
        function_body(&detector, "pub fn with_restart_formation(")
            .contains("self.restart_formation_enabled = conservative_mode")
    );
    let tick = function_body(&detector, "pub fn tick(");
    for forbidden in [
        "RestartFormation",
        "UncertaintyFormation",
        "formation_count",
    ] {
        assert!(
            !tick.contains(forbidden),
            "elapsed time never forms: {forbidden}"
        );
    }
    assert!(
        function_body(&detector, "fn invalidate_for_uncertainty(")
            .contains("self.formation_count = 0")
    );

    let mut callers = Vec::new();
    for (module, code) in production_modules() {
        if code.contains("with_restart_formation(") && module != "failure_assessment" {
            callers.push(module);
        }
    }
    assert_eq!(callers, ["daemon_peer_runtime"]);
    let from_config = function_body(
        &production_source("daemon_peer_runtime"),
        "pub(crate) fn from_config(",
    );
    assert_before(
        &from_config,
        "with_restart_formation(",
        "Mode::Conservative",
        "formation is enabled only from the conservative-mode flag",
    );
}

/// Stage 14 Design Revision 4 §33.3
/// `017_no_listener_worker_or_topology_change` (Phase 14.3).
#[test]
fn mkm_arch_017_no_listener_worker_or_topology_change() {
    for module in ["daemon_peer_runtime", "failure_assessment"] {
        let code = production_source(module);
        for forbidden in [
            "TcpListener",
            "TcpStream",
            "PeerListener::bind",
            "thread::spawn",
            "async fn",
            "mpsc",
            "tokio",
        ] {
            assert!(!code.contains(forbidden), "{module}: {forbidden}");
        }
    }
    let transport = production_source("tcp_runtime");
    assert_eq!(transport.matches("PeerListener::bind(").count(), 1);
    assert!(
        function_body(&transport, "pub(crate) fn connect(").contains("NonCanonicalDirection"),
        "the Inbound role still never dials"
    );
    let mut constructors = Vec::new();
    for (module, code) in production_modules() {
        let count = code.matches("DaemonPeerRuntime::from_config(").count();
        if count > 0 {
            constructors.push((module, count));
        }
    }
    assert_eq!(constructors, [("daemon".to_string(), 1)]);
}

/// Stage 14 Design Revision 5 §15 / §33.3 `017_counted_confirmed_mint_sites`
/// (Phase 14.4 subset). `CONFIRMED` is constructed only in the two mint
/// functions. Their single production call sites (verify-poll step,
/// ingestion step) belong to later dependency units, so at most one each may
/// exist now.
#[test]
fn mkm_arch_017_counted_confirmed_mint_sites() {
    let fencing = production_source("fencing");
    // v0.7 G-2 (G-A2): `FencingClearance::backend_attempt_token` reads the provenance copied at
    // mint time with exactly one `if let` pattern; it constructs nothing. Every other occurrence
    // is still the one construction in `confirm_by_verification`.
    let provenance_read = function_body(&fencing, "pub fn backend_attempt_token(");
    assert_eq!(provenance_read.matches("ConfirmedBy::Backend {").count(), 1);
    assert!(
        provenance_read
            .contains("if let ConfirmedBy::Backend { attempt_token } = &self.confirmed_by")
    );
    assert!(!provenance_read.contains("Self {") && !provenance_read.contains("FencingState::"));
    assert_eq!(fencing.matches("ConfirmedBy::Backend {").count(), 2);
    assert_eq!(fencing.matches("ConfirmedBy::Operator {").count(), 1);
    assert!(
        function_body(&fencing, "pub fn confirm_by_verification(")
            .contains("ConfirmedBy::Backend {")
    );
    assert!(
        function_body(&fencing, "pub fn confirm_by_attestation(")
            .contains("ConfirmedBy::Operator {")
    );
    let node_mutation = production_source("node_mutation");
    let validator = function_body(&node_mutation, "fn validate_fencing_incident(");
    for (module, code) in production_modules() {
        if module == "fencing" {
            continue;
        }
        let allowed = if module == "node_mutation" {
            // Structural validation patterns only (§19.2), not construction.
            validator.matches("ConfirmedBy::").count()
        } else {
            0
        };
        assert_eq!(
            code.matches("ConfirmedBy::").count(),
            allowed,
            "{module} must not construct CONFIRMED"
        );
        for mint in [".confirm_by_verification(", ".confirm_by_attestation("] {
            assert!(
                code.matches(mint).count() <= 1,
                "{module}: {mint} has more than one production call site"
            );
        }
    }
}

/// Stage 14 Design Revision 5 §15 E3 / §33.3 `017_no_exit_zero_confirm`
/// (Phase 14.4 subset): no action outcome flows into `CONFIRMED`, and the
/// action-result transition never produces it.
#[test]
fn mkm_arch_017_no_exit_zero_confirm() {
    let fencing = production_source("fencing");
    let verification = function_body(&fencing, "pub fn confirm_by_verification(");
    let attestation = function_body(&fencing, "pub fn confirm_by_attestation(");
    for body in [&verification, &attestation] {
        assert!(!body.contains("ActionOutcome"));
        assert!(!body.contains("action_outcome"));
    }
    assert!(!function_body(&fencing, "pub fn action_returned(").contains("Confirmed"));
}

/// Stage 14 Design Revision 5 §33.3
/// `017_no_fencing_authority_or_promotion_edge` (Phase 14.4 subset): the
/// incident model has no path to authority, lease mutation, promotion,
/// resources, the Witness session, processes, or threads.
#[test]
fn mkm_arch_017_no_fencing_authority_or_promotion_edge() {
    let fencing = production_source("fencing");
    for forbidden in [
        "RuntimeLeaseAuthority",
        "acquire_",
        "begin_lease_",
        "execute_promotion_attempt",
        "promote(",
        "ResourceWorkflow",
        "ResourceExecutor",
        "WitnessSession",
        "NodeMutationStore",
        "std::process",
        "Command::new",
        "thread::spawn",
        "async fn",
        "mpsc",
    ] {
        assert!(!fencing.contains(forbidden), "fencing.rs: {forbidden}");
    }
}

/// Stage 14 Design Revision 5 §33.3 `017_clearance_not_clonable`, plus the
/// same discipline for `FencingTransition`: neither is copyable or
/// serializable, and each is constructed only inside `fencing.rs` (the
/// clearance only in `FencingClearance::mint`).
#[test]
fn mkm_arch_017_clearance_not_clonable() {
    let fencing = production_source("fencing");
    for item in [
        "pub struct FencingClearance",
        "pub struct FencingTransition",
    ] {
        let attributes = item_attributes(&fencing, item);
        for forbidden in ["Clone", "Copy", "Serialize", "Deserialize"] {
            assert!(
                !attributes.contains(forbidden),
                "{item} must not derive {forbidden}"
            );
        }
    }
    let mint = function_body(&fencing, "pub(crate) fn mint(");
    assert!(mint.contains("Ok(Self {"));
    assert_eq!(
        fencing
            .matches("Self {\n            incident: incident.incident_ref()")
            .count(),
        1
    );
    assert_eq!(
        fencing
            .matches("FencingTransition {\n            from:")
            .count(),
        1,
        "one transition constructor"
    );
    assert!(function_body(&fencing, "fn transition(").contains("FencingTransition {"));
    for (module, code) in production_modules() {
        if module != "fencing" {
            assert!(
                !code.contains("FencingClearance {"),
                "{module} constructs a clearance"
            );
            assert!(
                !code.contains("FencingTransition {"),
                "{module} constructs a transition"
            );
        }
    }
}

/// Stage 14 Phase 14.4 F-01 (Design Revision 5 §24 G, §26): a
/// `FencingIncident` value — deserialized, copied, or built from its public
/// fields — is durable schema, not proof, and cannot mint a
/// `FencingClearance`. The mint accepts only a `DurableIncident`, which only
/// `NodeMutationStore::mint_fencing_clearance` constructs, from its own
/// validated load, and which no production code can construct, convert, or
/// receive.
#[test]
fn mkm_arch_017_clearance_requires_durable_store_proof() {
    let fencing = production_source("fencing");
    let start = fencing.find("pub(crate) fn mint(").expect("clearance mint");
    let signature = &fencing[start..start + fencing[start..].find('{').unwrap()];
    assert!(
        signature.contains("durable: &DurableIncident<'_>"),
        "{signature}"
    );
    assert!(!signature.contains("FencingIncident"), "{signature}");
    assert!(
        !fencing.contains("pub fn mint("),
        "the clearance mint is crate-internal"
    );

    let node_mutation = production_source("node_mutation");
    let attributes = item_attributes(&node_mutation, "pub struct DurableIncident");
    assert!(
        attributes.is_empty(),
        "DurableIncident has no derives: {attributes}"
    );
    let declaration = function_body(&node_mutation, "pub struct DurableIncident");
    assert!(
        declaration.contains("incident: &'a FencingIncident") && !declaration.contains("pub "),
        "the proof's field is private"
    );
    let store_mint = function_body(&node_mutation, "pub fn mint_fencing_clearance(");
    assert_eq!(node_mutation.matches("DurableIncident {").count(), 1);
    assert!(store_mint.contains("DurableIncident {\n            incident: current,"));
    assert!(store_mint.contains("load_existing_snapshot()"));
    assert!(store_mint.contains("FencingClearance::mint("));

    let mut mint_call_sites = 0;
    for (module, code) in production_modules() {
        mint_call_sites += code.matches("FencingClearance::mint(").count();
        for forbidden in [
            "-> DurableIncident",
            "DurableIncident<'_>>",
            "DurableIncident<'a>>",
            "for DurableIncident",
        ] {
            assert!(
                !code.contains(forbidden),
                "{module}: DurableIncident escapes or converts via {forbidden:?}"
            );
        }
        if module != "node_mutation" {
            assert!(
                !code.contains("DurableIncident {"),
                "{module} constructs the store proof"
            );
            if code.contains("mint_fencing_clearance(") {
                assert_eq!(module, "linux_node_runtime", "{module} mints a clearance");
            }
        }
    }
    assert_eq!(mint_call_sites, 1, "only the store mints a clearance");
}

/// Stage 14 Design Revision 5 §19.3 / §33.3 `017_daemon_only_v3_writer`
/// (Phase 14.4 subset): the incident is written only by the three
/// `NodeMutationStore` operations, which production code may call only from
/// `linux_node_runtime.rs` (none yet) and never from the CLI, recovery,
/// status, or `main`.
#[test]
fn mkm_arch_017_daemon_only_v3_writer() {
    let node_mutation = production_source("node_mutation");
    let writers: Vec<&str> = node_mutation
        .match_indices("state.fencing_incident = ")
        .map(|(index, _)| &node_mutation[index..])
        .collect();
    assert_eq!(
        writers.len(),
        5,
        "open, transition, retire, success ARM, abort cleanup"
    );
    for (body, expected) in [
        (
            "pub fn arm_consuming_fencing(",
            "state.fencing_incident = None",
        ),
        (
            "pub fn retire_incident_and_arm_cleanup_obligation(",
            "state.fencing_incident = None",
        ),
        (
            "pub fn open_fencing_incident(",
            "state.fencing_incident = Some(incident.clone())",
        ),
        (
            "pub fn apply_fencing_transition(",
            "state.fencing_incident = Some(transition.to().clone())",
        ),
        (
            "pub fn retire_fencing_incident(",
            "state.fencing_incident = None",
        ),
    ] {
        assert!(
            function_body(&node_mutation, body).contains(expected),
            "{body}"
        );
    }
    assert!(
        function_body(&node_mutation, "pub fn open_fencing_incident(")
            .contains("state.highest_fencing_incident_seq = incident_seq")
    );
    for (module, code) in production_modules() {
        if module == "node_mutation" {
            continue;
        }
        for writer in [
            "open_fencing_incident(",
            "apply_fencing_transition(",
            "retire_fencing_incident(",
            "arm_consuming_fencing(",
            "retire_incident_and_arm_cleanup_obligation(",
        ] {
            if code.contains(writer) {
                assert_eq!(module, "linux_node_runtime", "{module} calls {writer}");
            }
        }
    }
}

/// Stage 14 Phase 14.4 L-01 (Design Revision 5 §24 G; F-01 TOCTOU): the Node
/// mutation guard that protects the validated durable load stays held until
/// `FencingClearance::mint` has completed, so no incident writer can
/// interleave between validation and mint. The primary enforcement is
/// structural: `DurableIncident` borrows the held guard, so releasing (moving)
/// the guard while the proof is alive does not compile. This guard pins the
/// parts the borrow checker cannot see: the proof keeps its guard field, the
/// guard is acquired once and before the load, and it is never released or
/// re-acquired inside the mint.
#[test]
fn mkm_arch_017_clearance_mint_holds_mutation_guard() {
    let node_mutation = production_source("node_mutation");
    let declaration = function_body(&node_mutation, "pub struct DurableIncident");
    assert!(
        declaration.contains("_guard: &'a MutexGuard<'static, ()>"),
        "the store proof borrows the held mutation guard"
    );
    let store_mint = function_body(&node_mutation, "pub fn mint_fencing_clearance(");
    assert_eq!(store_mint.matches("mutation_guard()").count(), 1);
    assert!(store_mint.contains("let guard = mutation_guard()?;"));
    assert_before(
        &store_mint,
        "let guard = mutation_guard()?;",
        "load_existing_snapshot()",
        "the guard is held before the durable load",
    );
    assert_before(
        &store_mint,
        "load_existing_snapshot()",
        "FencingClearance::mint(",
        "the durable load precedes the mint",
    );
    assert!(
        store_mint.contains("_guard: &guard"),
        "the proof borrows this guard"
    );
    for forbidden in ["drop(", "forget(", "let _ = mutation_guard", "MutexGuard::"] {
        assert!(
            !store_mint.contains(forbidden),
            "mint_fencing_clearance must not release the guard early: {forbidden:?}"
        );
    }
}

/// Stage 14 Design Revision 5 §33.3 `017_argv_no_shell` (Phase 14.5): the
/// bounded-process backend never adds a shell, clears the environment, and
/// starts every leader in a new process group with stdin `/dev/null`.
#[test]
fn mkm_arch_017_argv_no_shell() {
    let backend = production_source("fencing_backend");
    for module in ["fencing", "fencing_backend"] {
        let code = production_source(module);
        for forbidden in ["\"sh\"", "\"-c\"", "/bin/sh", "bash"] {
            assert!(!code.contains(forbidden), "{module}: {forbidden}");
        }
    }
    assert_eq!(backend.matches("Command::new(").count(), 1);
    let spawn = function_body(
        &backend,
        "fn spawn(&mut self, plan: &SpawnPlan<'_>) -> Result<Child, i32>",
    );
    assert!(spawn.contains("Command::new(program)"));
    assert!(spawn.contains(".args(arguments)"));
    assert!(spawn.contains(".env_clear()"));
    assert!(spawn.contains(".process_group(0)"));
    assert!(spawn.contains(".stdin(Stdio::null())"));
    assert_before(
        &spawn,
        ".env_clear()",
        "command.env(name, value)",
        "env_clear precedes the allowlist",
    );
}

/// Stage 14 Design Revision 5 §33.3 `017_no_worker` (Phase 14.5): the step is
/// single-threaded. No helper thread, reader join, async runtime, channel, or
/// blocking read-to-EOF (the `systemd_service.rs` capture pattern) exists in
/// fencing code.
#[test]
fn mkm_arch_017_no_worker() {
    for module in ["fencing", "fencing_backend"] {
        let code = production_source(module);
        for forbidden in [
            "thread::spawn",
            "thread::Builder",
            "thread::scope",
            "spawn_scoped",
            "JoinHandle",
            ".join(",
            "async fn",
            "tokio",
            "mpsc",
            "read_to_end",
            "read_to_string(",
            "wait_with_output",
            ".output()",
            "capture_stdout",
            "join_reader",
        ] {
            assert!(!code.contains(forbidden), "{module}: {forbidden}");
        }
    }
}

/// Stage 14 Design Revision 5 §33.3 `017_pending_reap_single_slot` (Phase
/// 14.5 subset; the shutdown-path part belongs to the later shutdown
/// integration). Source shape only: ownership, gating, and polling behavior
/// are proven by the §34.22 PR tests in `fencing_backend.rs`.
#[test]
fn mkm_arch_017_pending_reap_single_slot() {
    let backend = production_source("fencing_backend");
    assert_eq!(
        backend.matches("pending_reap: Option<PendingReap<").count(),
        1
    );
    // No second retained-leader location under another name.
    assert_eq!(backend.matches("Option<PendingReap<").count(), 1);
    for forbidden in [
        "Vec<PendingReap",
        "Vec<Child",
        "VecDeque",
        "HashMap",
        "BTreeMap",
        "pending_reap = None",
        ".wait()",
        "waitpid",
        ".kill()",
    ] {
        assert!(!backend.contains(forbidden), "fencing_backend: {forbidden}");
    }
    // The only slot writer is the transfer, which refuses an occupied slot.
    assert_eq!(backend.matches("self.pending_reap = Some(").count(), 1);
    let transfer = function_body(&backend, "fn transfer(");
    assert_before(
        &transfer,
        "if let Some(existing) = &self.pending_reap",
        "self.pending_reap = Some(",
        "transfer requires an empty slot",
    );
    // The only slot clearing is a reap that returned an exit status.
    assert_eq!(backend.matches("self.pending_reap.take()").count(), 1);
    let poll = function_body(&backend, "pub fn poll_pending_reap(");
    assert_before(
        &poll,
        "ReapResult::Exited(status) =>",
        "self.pending_reap.take()",
        "only an exit status empties the slot",
    );
    for forbidden in ["signal_group", "sleep", "spawn", "loop", "while"] {
        assert!(!poll.contains(forbidden), "poll_pending_reap: {forbidden}");
    }
    assert_eq!(poll.matches("try_reap(").count(), 1);
    // Spawn gate: poll, then refuse while occupied, before any deadline or
    // trust check or spawn.
    let step = function_body(&backend, "pub fn run_step(");
    assert_before(
        &step,
        "self.poll_pending_reap()",
        "self.pending_reap.is_some()",
        "gate polls first",
    );
    // The refusal depends on occupancy alone, never on the poll result
    // (a gate-poll error or EINTR still refuses; behavior: F14.5-03 M19).
    assert!(step.contains("if self.pending_reap.is_some() {"));
    for later in [
        "let step_started_at",
        "StepDeadlines::compute_for(",
        "check_trust(",
        "self.driver.spawn(",
    ] {
        assert_before(
            &step,
            "self.pending_reap.is_some()",
            later,
            "gate precedes the step",
        );
    }
    // Every exit query and reap is non-blocking.
    let exit_query = function_body(&backend, "pub fn leader_exited_without_reaping(");
    assert!(exit_query.contains("WEXITED | WNOWAIT | WNOHANG"));
    assert_eq!(backend.matches("waitid(P_PID").count(), 1);
    let reap = function_body(
        &backend,
        "fn try_reap(&mut self, leader: &mut Child) -> ReapResult",
    );
    assert!(reap.contains("leader.try_wait()"));
    let attributes = item_attributes(&backend, "pub struct PendingReap<L>");
    for forbidden in ["Clone", "Copy", "Serialize", "Deserialize"] {
        assert!(
            !attributes.contains(forbidden),
            "PendingReap derives {forbidden}"
        );
    }
    let attributes = item_attributes(&backend, "pub struct CommandBackend<");
    assert!(!attributes.contains("Clone"));
}

/// Stage 14 Design Revision 5 §16.6 bounded step, source-shape part (Phase
/// 14.5). The deadlines are computed once with checked arithmetic; sub-waits
/// are bounded by `POLL_SLICE` and the active phase deadline; Finalization
/// runs the final group SIGKILL and both closes before the reap, and skips the
/// reap at `return_deadline`. Termination and return bounds themselves are
/// behavioral (§34.21 FR01 tests); no source-shape claim is made about them.
#[test]
fn mkm_arch_017_bounded_step_shape() {
    let backend = production_source("fencing_backend");
    // v0.7 G-2: one checked-arithmetic computation (`compute_with`) serves both deadline sets; a
    // step computes its set once (`compute_for`, by kind). Fencing steps keep the §16.6.1 graces,
    // and only the route step uses the RH-only graces, which sum to the 3.0 s budget.
    let compute = function_body(&backend, "fn compute_with(");
    assert_eq!(compute.matches("checked_add(").count(), 4);
    assert_eq!(backend.matches("StepDeadlines::compute_for(").count(), 1);
    let compute_for = function_body(&backend, "pub fn compute_for(");
    assert!(compute_for.contains(
        "StepKind::Action | StepKind::Verify => Self::compute(step_started_at, timeout),"
    ));
    for grace in [
        "ROUTE_TERM_GRACE",
        "ROUTE_KILL_REAP_GRACE",
        "ROUTE_FINALIZATION_RETURN_ALLOWANCE",
    ] {
        assert_eq!(
            backend.matches(grace).count(),
            3,
            "{grace}: definition, budget assert, use"
        );
    }
    let fencing_compute = function_body(&backend, "pub fn compute(");
    for grace in [
        "TERM_GRACE,",
        "KILL_REAP_GRACE,",
        "FINALIZATION_RETURN_ALLOWANCE,",
    ] {
        assert!(fencing_compute.contains(grace), "{grace}");
    }
    assert!(!fencing_compute.contains("ROUTE_"));
    let execute = function_body(&backend, "fn execute<D: ProcessDriver>(");
    assert!(execute.contains("POLL_SLICE.min(phase_deadline - now)"));
    assert_eq!(execute.matches("driver.sleep(").count(), 1);
    assert_eq!(execute.matches("GroupSignal::Term").count(), 1);
    assert_eq!(execute.matches("GroupSignal::Kill").count(), 1);
    assert_eq!(execute.matches("signal_group(").count(), 1);
    // A wake at or after `hard_deadline` goes straight to Finalization
    // (§16.6.6); the late-wake behavior itself is proven by the F14.5-02
    // matrix test.
    for escalation in ["GroupSignal::Term", "GroupSignal::Kill", "signal_group("] {
        assert_before(
            &execute,
            "if now >= deadlines.hard_deadline",
            escalation,
            "hard_deadline dominates escalation",
        );
    }
    assert!(execute.contains("driver.leader_exited(leader)"));
    let finalize = function_body(&backend, "fn finalize(");
    assert!(!finalize.contains("sleep"));
    assert!(!finalize.contains("drain"));
    assert!(!finalize.contains("GroupSignal::Term"));
    assert_eq!(finalize.matches("signal_group(").count(), 1);
    assert_before(
        &finalize,
        "signal_group(pid, GroupSignal::Kill)",
        "close_read_end(",
        "final kill before close",
    );
    assert_before(
        &finalize,
        "close_read_end(&mut leader, Stream::Stderr)",
        "try_reap(",
        "close before reap",
    );
    assert_before(
        &finalize,
        ">= deadlines.return_deadline",
        "try_reap(",
        "reap skipped at return_deadline",
    );
    assert_eq!(finalize.matches("try_reap(").count(), 1);
}

/// Stage 14 Design Revision 5 §33.3 `017_fencing_timeout_bounds`: the maxima
/// are named constants enforced by the only `StepTimeout` constructors
/// (Phase 14.5), and `[fencing]` configuration validation goes through those
/// same constructors and a named `verify_polls` maximum (Phase 14.7), so the
/// configured and step ranges cannot drift. Behavior: §34.17 / G5 tests.
#[test]
fn mkm_arch_017_fencing_timeout_bounds() {
    let backend = production_source("fencing_backend");
    assert!(backend.contains("pub const MAX_FENCE_TIMEOUT_SEC: u64 = 60;"));
    assert!(backend.contains("pub const MAX_VERIFY_TIMEOUT_SEC: u64 = 30;"));
    assert!(function_body(&backend, "pub fn fence(").contains("MAX_FENCE_TIMEOUT_SEC"));
    assert!(function_body(&backend, "pub fn verify(").contains("MAX_VERIFY_TIMEOUT_SEC"));
    assert!(function_body(&backend, "fn bounded(").contains("(1..=maximum).contains(&seconds)"));
    // Private fields; the struct literals are in `bounded` and (v0.7 G-2) in the fixed route
    // constructor, which takes no input and is not configurable (contract R4.1 §5.1).
    let timeout = function_body(&backend, "impl StepTimeout {");
    assert_eq!(timeout.matches("Self {").count(), 2, "no third constructor");
    assert!(function_body(&timeout, "fn bounded(").contains("Self {"));
    let route: String = function_body(&timeout, "pub const fn route() -> StepTimeout {")
        .split_whitespace()
        .collect();
    assert!(route.contains("Self{kind:StepKind::Route,duration:ROUTE_EXECUTION,}"));
    assert!(
        backend.contains("pub const ROUTE_EXECUTION: Duration = Duration::from_millis(2_000);")
    );

    // Configuration part (Phase 14.7).
    assert!(backend.contains("pub const MAX_VERIFY_POLLS: u64 = 60;"));
    let from_config = function_body(&backend, "pub fn from_config(");
    for required in [
        "StepTimeout::fence,",
        "StepTimeout::verify,",
        "(1..=MAX_VERIFY_POLLS).contains(&polls)",
    ] {
        assert!(from_config.contains(required), "from_config: {required}");
    }
    let configured = function_body(&backend, "fn configured_timeout(");
    assert!(configured.contains("seconds.map(bounded)"));
    for body in [&from_config, &configured] {
        for literal in ["60", "30", "61", "31"] {
            assert!(
                !body.contains(literal),
                "duplicated bound literal {literal}"
            );
        }
    }
    let config = production_source("config");
    for forbidden in ["MAX_", "..=60", "..=30", "<= 60", "<= 30", "StepTimeout"] {
        assert!(!config.contains(forbidden), "config: {forbidden}");
    }
    assert!(
        function_body(&config, "pub fn validate(").contains(
            "crate::fencing_backend::FencingSettings::from_config(self.fencing.as_ref())"
        )
    );
}

/// Stage 14 Design Revision 5 §16.1 / §16.2 (Phase 14.7, DC-14.7-01 Option
/// 1): the optional strict `[fencing]` section, the startup-only trust check,
/// and the single owner holding validated settings without running them.
///
/// Invariant protected: settings are validated and trust-checked exactly once,
/// by the runtime owner's constructor on the daemon startup path, before any
/// backend is built; no other command reaches the startup check; nothing in
/// production reads the held settings, so nothing can hand them to
/// `run_step` (production `run_step` callers stay 0 in
/// `mkm_arch_017_fencing_backend_spawn_free_ownership`). Behavior is proven by
/// the stage14_7 tests (G5, §34.17, acceptance 35, startup refusal).
#[test]
fn mkm_arch_017_fencing_config_startup() {
    let config = production_source("config");
    assert_before(
        &config,
        "#[serde(deny_unknown_fields)]\npub struct FencingConfig {",
        "pub backend: FencingBackendKind,",
        "the [fencing] section is strict",
    );
    assert!(config.contains("pub fencing: Option<FencingConfig>,"));

    let backend = production_source("fencing_backend");
    let startup = function_body(&backend, "pub fn startup(");
    assert!(startup.contains("Self::startup_with(section, check_executable_trust)"));
    let with = function_body(&backend, "fn startup_with(");
    assert_before(
        &with,
        "Self::from_config(section)",
        "if let Self::Command(command) = &settings",
        "validation precedes trust",
    );
    assert_before(
        &with,
        "if let Self::Command(command) = &settings",
        "trust(&argv[0])",
        "only the command backend is trust-checked",
    );
    assert!(with.contains("[(\"fence\", &command.fence), (\"verify\", &command.verify)]"));
    assert_eq!(with.matches("trust(").count(), 1);

    // Exactly one production startup call, in the owner's constructor,
    // after config validation and before any backend is built.
    let mut callers = Vec::new();
    for (module, code) in production_modules() {
        let count = code.matches("FencingSettings::startup(").count();
        if count > 0 && module != "fencing_backend" {
            callers.push((module, count));
        }
    }
    assert_eq!(callers, [("linux_node_runtime".to_string(), 1)]);
    let runtime = production_source("linux_node_runtime");
    let new = function_body(&runtime, "pub(crate) fn new(\n        config: &Config,");
    assert!(new.contains("FencingSettings::startup(config.fencing.as_ref())"));
    assert_before(
        &new,
        ".validate()",
        "FencingSettings::startup(",
        "startup trust follows validation",
    );
    assert_before(
        &new,
        "FencingSettings::startup(",
        ".network_config(",
        "startup trust precedes every backend",
    );
    assert_before(
        &new,
        "if let Some(notice) = fencing_settings.startup_notice() {\n            eprintln!(\"mikagami: {notice}\");",
        "Ok(Self {",
        "the transitional notice is emitted",
    );

    // Phase 14.9 (DC-14.9-01 Option B): read only by the fencing gate and
    // step. The backend kind is read by gate G; argv and timeouts only by the
    // single step site; the poll budget only by `drive_fencing_step`. Every
    // other mention is the field, the constructor value, the test fixture,
    // and the test accessor.
    assert_eq!(
        runtime
            .matches("fencing_settings: crate::fencing_backend::FencingSettings,")
            .count(),
        1
    );
    let gate = function_body(&runtime, "pub(crate) fn fencing_gate(");
    let drive = function_body(&runtime, "pub(crate) fn drive_fencing_step(");
    let step = function_body(&runtime, "fn run_fencing_process(");
    assert_eq!(gate.matches("self.fencing_settings.backend()").count(), 1);
    assert_eq!(step.matches("self.fencing_settings.command()").count(), 1);
    assert_eq!(drive.matches(".fencing_settings").count(), 1);
    // The fourth read is the test accessor; the one write is the
    // `#[cfg(test)]` setter the Phase 14.9 runtime tests configure with.
    assert!(runtime.contains(
        "#[cfg(test)]\n    fn set_fencing_settings_for_test(&mut self, settings: crate::fencing_backend::FencingSettings) {\n        self.fencing_settings = settings;"
    ));
    // Plus the automatic trigger's read-only "is the backend a command" fact.
    assert_eq!(runtime.matches(".fencing_settings").count(), 6);
    assert_eq!(
        function_body(&runtime, "pub(crate) fn fencing_backend_is_command(")
            .matches(".fencing_settings")
            .count(),
        1
    );
    let accessor = function_body(&runtime, "pub(crate) fn fencing_settings_for_test(");
    assert!(accessor.contains("&self.fencing_settings"));
    assert_eq!(runtime.matches("fencing_settings").count(), 13);
    for (field, body) in [
        (".fence_timeout", &step),
        (".verify_timeout", &step),
        (".verify_polls", &drive),
    ] {
        assert_eq!(runtime.matches(field).count(), 1, "{field}");
        assert_eq!(body.matches(field).count(), 1, "{field}");
    }
    assert!(!runtime.contains("CommandFencing"));
}

/// Stage 14 Design Revision 5 §33.3 `017_sole_fencing_executor_owner`, Phase
/// 14.6 spawn-free ownership form (DC-14.6-01 Option 1). This replaces the
/// Phase 14.5 `mkm_arch_017_fencing_backend_runtime_inactive` guard, whose
/// "no production reference at all" invariant is intentionally ended: the
/// backend now has exactly one runtime owner (`LinuxNodeRuntime`) and exactly
/// two runtime edges, the §16.7.5 foreground poll and the §16.7.8 shutdown
/// poll.
///
/// Invariant protected: production code outside `fencing_backend.rs` may own
/// the backend and poll its slot, and runs a process step only through the
/// one permitted site. Phase 14.9 (DC-14.9-01 Option B) replaces the former
/// "production `run_step` callers = 0" with its designed successor: exactly
/// one `run_step(` call, inside `LinuxNodeRuntime::run_fencing_process`,
/// whose only callers are gate G (the fence action) and
/// `drive_fencing_step` (the verify poll). The daemon never runs a step.
///
/// Authorized: the `fencing_backend: CommandBackend` field and its
/// `CommandBackend::system()` construction in `linux_node_runtime.rs`;
/// `foreground_pending_reap` in `poll_pending_reap_foreground`;
/// `shutdown_pending_reap` in `shutdown_for_daemon`;
/// `poll_pending_reap_foreground()` as the first statement of the Linux
/// daemon's foreground tick.
///
/// Still forbidden in every production module except the backend:
/// `run_step(`, trust checks, `StepRequest`/`StepTimeout`/`SpawnPlan`,
/// `ProcessDriver`, `SystemProcessDriver`, `CommandBackend::new(` (any
/// non-system driver), and the backend's poll/transfer primitives.
///
/// Known lexical limits: an alias (`use … as X`), a macro, or a helper
/// defined in another module could hide a call. Behavior is proven by the
/// Phase 14.6 tests: the scripted driver panics on any spawn, signal or
/// sleep, and the real-owner tests. This guard is the cheap tripwire for the
/// ordinary spelling.
#[test]
fn mkm_arch_017_fencing_backend_spawn_free_ownership() {
    const STEP_TOKENS: [&str; 10] = [
        "run_step(",
        "check_executable_trust(",
        "check_trust(",
        "StepRequest",
        "StepTimeout",
        "SpawnPlan",
        "ProcessDriver",
        "SystemProcessDriver",
        "CommandBackend::new(",
        ".transfer(",
    ];
    for (module, code) in production_modules() {
        match module.as_str() {
            "fencing_backend" => continue,
            "main" => {
                assert_eq!(
                    code.matches("fencing_backend").count(),
                    1,
                    "module declaration only"
                );
                continue;
            }
            "linux_node_runtime" | "daemon" => {}
            _ => {
                // Phase 14.7: `Config::validate` reports the one `[fencing]`
                // validator's errors. That single call is config's only
                // backend reference; every step token below stays forbidden.
                let permitted = if module == "config" {
                    code.matches(
                        "crate::fencing_backend::FencingSettings::from_config(self.fencing.as_ref())",
                    )
                    .count()
                } else {
                    0
                };
                assert_eq!(
                    code.matches("fencing_backend").count(),
                    permitted,
                    "{module}: fencing_backend"
                );
                assert!(permitted <= 1, "{module}: more than one validator call");
                for forbidden in [
                    "CommandBackend",
                    "poll_pending_reap",
                    "pending_reap_diagnostics(",
                    "foreground_pending_reap(",
                    "shutdown_pending_reap(",
                ] {
                    assert!(!code.contains(forbidden), "{module}: {forbidden}");
                }
            }
        }
        for forbidden in STEP_TOKENS {
            // Phase 14.9: the single step site builds its one request.
            // v0.7 G-2: the second step site, `run_route_process` (one `run_step(`, its
            // `StepRequest` import and literal, and the fixed `StepTimeout::route()`).
            let permitted = match (module.as_str(), forbidden) {
                ("linux_node_runtime", "run_step(") => 2,
                ("linux_node_runtime", "StepRequest") => 4,
                ("linux_node_runtime", "StepTimeout") => 2,
                _ => 0,
            };
            assert_eq!(
                code.matches(forbidden).count(),
                permitted,
                "{module}: production step/spawn edge {forbidden}"
            );
        }
        // The raw primitive stays behind the two lifecycle helpers.
        assert!(!code.contains("poll_pending_reap("), "{module}");
    }

    // Exactly one owner: one backend field, one construction, in the runtime.
    let runtime = production_source("linux_node_runtime");
    assert_eq!(
        runtime
            .matches("fencing_backend: crate::fencing_backend::CommandBackend,")
            .count(),
        1
    );
    // Phase 14.9: the one step site, and its two callers.
    let step = function_body(&runtime, "fn run_fencing_process(");
    assert_eq!(step.matches(".run_step(&request)").count(), 1);
    assert_eq!(step.matches("StepRequest").count(), 2);
    assert_eq!(runtime.matches("run_fencing_process(").count(), 3);
    let gate = function_body(&runtime, "pub(crate) fn fencing_gate(");
    let drive = function_body(&runtime, "pub(crate) fn drive_fencing_step(");
    assert_eq!(gate.matches("run_fencing_process(").count(), 1);
    assert_eq!(drive.matches("run_fencing_process(").count(), 1);
    assert!(gate.contains("crate::fencing_backend::StepKind::Action,"));
    assert!(!gate.contains("StepKind::Verify"));
    assert!(drive.contains("run_fencing_process(StepKind::Verify,"));
    assert!(!drive.contains("StepKind::Action"));
    // v0.7 G-2 (contract R4.1 §5.1, I-3): the one route step site. It runs exactly one bounded
    // step with the fixed RH-only timeout through the same owner (so the same spawn gate, trust
    // re-check, process group and single pending-reap slot), and its only caller is the RH
    // platform, which voids the verified-listen window first.
    let route = function_body(&runtime, "fn run_route_process(");
    assert_eq!(route.matches(".run_step(&request)").count(), 1);
    assert_eq!(route.matches("StepRequest").count(), 2);
    assert_eq!(route.matches("StepTimeout::route()").count(), 1);
    for forbidden in [
        "fence_timeout",
        "verify_timeout",
        "StepKind::Action",
        "StepKind::Verify",
    ] {
        assert!(!route.contains(forbidden), "route step: {forbidden}");
    }
    assert_eq!(runtime.matches("run_route_process(").count(), 2);
    let spawn = function_body(&runtime, "fn spawn_route_step(");
    assert_before(
        &spawn,
        "(self.before_blocking_step)();",
        ".run_route_process(step, record, intent)",
        "a route step voids the listen window first",
    );
    let fencing_step = function_body(&runtime, "fn run_fencing_process(");
    assert!(fencing_step.contains("StepKind::Route => {"));
    assert!(fencing_step.contains("a route-handoff step is not a fencing step"));
    assert!(!daemon_source_has_step_site());
    // `new` and the `#[cfg(test)]` fixture; no other driver type.
    assert_eq!(runtime.matches("CommandBackend::system()").count(), 2);
    assert!(!runtime.contains("CommandBackend<"));
    assert_eq!(runtime.matches(".foreground_pending_reap(").count(), 1);
    assert_eq!(runtime.matches(".shutdown_pending_reap(").count(), 1);
    let foreground = function_body(&runtime, "pub(crate) fn poll_pending_reap_foreground(");
    assert!(foreground.contains(".foreground_pending_reap()"));
    // I-1: the glue samples no clock; a diagnostic age is read by the
    // backend only when a line is produced.
    assert!(!foreground.contains("Instant::now"));
    // Shutdown: one poll, before the unchanged Revision 10 classification,
    // and the verdict is the conjunction with an empty slot.
    let shutdown = function_body(&runtime, "pub(crate) fn shutdown_for_daemon(");
    assert_before(
        &shutdown,
        ".shutdown_pending_reap(",
        "self.snapshot()?",
        "shutdown poll precedes the Revision 10 classification",
    );
    assert!(shutdown.contains("&& pending.slot_empty)"));
    assert!(!shutdown.contains("Instant::now"));
    // The only clean verdict is the final conjunction; no early `Ok(true)`.
    assert!(!shutdown.contains("Ok(true)"));

    // Foreground: the poll is the first statement of the Linux daemon's
    // foreground tick, before its early return.
    let daemon = production_source("daemon");
    assert_eq!(daemon.matches("poll_pending_reap_foreground()").count(), 1);
    for forbidden in [
        "CommandBackend",
        "foreground_pending_reap(",
        "shutdown_pending_reap(",
        "pending_reap_diagnostics(",
    ] {
        assert!(!daemon.contains(forbidden), "daemon: {forbidden}");
    }
    let linux_impl = &daemon[daemon
        .find("impl DaemonRuntime for LinuxDaemonRuntime")
        .expect("Linux daemon runtime impl")..];
    let tick = function_body(linux_impl, "fn foreground_lifecycle_tick(");
    let first = tick[1..].trim_start();
    assert!(
        first.starts_with("self.runtime.poll_pending_reap_foreground();"),
        "the poll must be the first statement: {first}"
    );
    // Phase 14.9: the early return is now the §27.3 fencing step, which
    // still follows the poll (§27.3: the poll runs before the step).
    // F14.9-01 amendment: the step is handed the live shutdown query, not a
    // snapshot sampled here.
    assert_before(
        &tick,
        "poll_pending_reap_foreground()",
        "return self.drive_fencing_step(live_shutdown);",
        "poll precedes the early return",
    );

    // F14.6-01: no direct process creation in the backend-owner modules.
    // Production fencing process execution exists only in
    // fencing_backend.rs (Revision 5 §16.7.4, `017_sole_fencing_executor_owner`).
    // The owner modules delegate every other process to their existing
    // backends, so their production text holds no process API at all.
    for (module, code) in [("linux_node_runtime", &runtime), ("daemon", &daemon)] {
        for forbidden in [
            "process::",
            "std::process",
            ".spawn(",
            "CommandExt",
            ".exec(",
            "libc::",
            "extern \"C\"",
            "posix_spawn",
            "fork(",
            "execv",
        ] {
            assert!(
                !code.contains(forbidden),
                "{module}: direct process execution edge {forbidden}"
            );
        }
        // Any `Command` other than `CommandBackend` (e.g. an imported or
        // aliased std Command).
        // `ServiceManager::Command` is the config enum variant selecting the
        // `command` service adapter (contract A-10); it is no process type.
        assert_eq!(
            code.matches("Command").count() - code.matches("ServiceManager::Command").count(),
            code.matches("CommandBackend").count(),
            "{module}: a Command type other than CommandBackend"
        );
    }
    // The wiring module legitimately uses std::process::ExitCode and
    // libc::signal, so it gets the narrower process-creation set.
    let wiring = production_source("daemon_run");
    for forbidden in [
        "process::Command",
        "Command::new(",
        ".spawn(",
        "CommandExt",
        ".exec(",
        "posix_spawn",
        "fork(",
        "execv",
    ] {
        assert!(
            !wiring.contains(forbidden),
            "daemon_run: direct process execution edge {forbidden}"
        );
    }

    // Inside the backend, `run_step(` is only its own definition.
    let backend = production_source("fencing_backend");
    assert_eq!(backend.matches("run_step(").count(), 1);
    assert!(backend.contains("pub fn run_step("));
    for forbidden in [
        "RuntimeLeaseAuthority",
        "acquire_",
        "begin_lease_",
        "execute_promotion_attempt",
        "promote(",
        "ResourceWorkflow",
        "ResourceExecutor",
        "WitnessSession",
        "NodeMutationStore",
        "FencingClearance",
        "FencingIncident",
        "FencingTransition",
        "ConfirmedBy",
        "confirm_by_",
        "LocalLossEvidence",
        "persist",
        "fs::write",
        "fs::rename",
    ] {
        assert!(
            !backend.contains(forbidden),
            "fencing_backend.rs: {forbidden}"
        );
    }
}

/// Phase 14.9: the daemon module holds no step site of its own.
fn daemon_source_has_step_site() -> bool {
    let daemon = production_source("daemon");
    [
        "run_step(",
        "run_fencing_process(",
        "StepKind",
        "StepRequest",
    ]
    .iter()
    .any(|token| daemon.contains(token))
}

/// Stage 14 Design Revision 5 §16.2 / §16.6.1 (Phase 14.5 remediation
/// F14.5-01): the pre-spawn trust check never makes a blocking call on the
/// untrusted pathname. The final component's type is checked by `lstat`
/// before the only `open`, and that open is `O_NOFOLLOW | O_NONBLOCK`.
/// Behavior (a FIFO at `argv[0]` returns at once and never spawns) is
/// proven by the FIFO regression test.
#[test]
fn mkm_arch_017_trust_check_is_nonblocking() {
    let backend = production_source("fencing_backend");
    let trust = function_body(&backend, "pub fn check_executable_trust(");
    assert_eq!(backend.matches(".open(").count(), 1);
    assert_eq!(trust.matches(".open(path)").count(), 1);
    assert!(trust.contains(".custom_flags(sys::O_NOFOLLOW | sys::O_NONBLOCK)"));
    for check in [
        "fs::symlink_metadata(path)",
        "is_symlink()",
        "if !linked.is_file()",
    ] {
        assert_before(&trust, check, ".open(path)", "type check before open");
    }
}

/// Stage 14 Design Revision 5 §16.3 manual FFI (Phase 14.5 remediation
/// F14.5-04): the hand-written constants and `siginfo_t` layout compile
/// only for explicitly verified targets. Pointer width is not an ABI
/// selector; every other target hits `compile_error!`, and the Linux values
/// are cross-checked against the target's `libc` at build time.
#[test]
fn mkm_arch_017_ffi_abi_explicit_targets() {
    let backend = production_source("fencing_backend");
    assert!(!backend.contains("target_pointer_width"));
    assert_eq!(backend.matches("compile_error!(").count(), 1);
    assert_eq!(backend.matches("mod constants {").count(), 2);
    let mut arches: Vec<&str> = backend
        .match_indices("target_arch = \"")
        .map(|(index, _)| {
            let rest = &backend[index + "target_arch = \"".len()..];
            &rest[..rest.find('"').unwrap()]
        })
        .collect();
    arches.sort_unstable();
    arches.dedup();
    assert_eq!(arches, ["aarch64", "x86_64"]);
    for os in ["linux", "macos"] {
        let gate = format!(
            "target_os = \"{os}\",\n        any(target_arch = \"x86_64\", target_arch = \"aarch64\")"
        );
        assert!(backend.contains(&gate), "{os} gate");
    }
    for value in [
        "WNOWAIT == libc::WNOWAIT",
        "O_NONBLOCK == libc::O_NONBLOCK",
        "ELOOP == libc::ELOOP",
        "size_of::<libc::siginfo_t>() == 128",
    ] {
        assert!(backend.contains(value), "{value}");
    }
}

/// Stage 14 Design Revision 5 §16.7.8 / §28 (Phase 14.6 remediation
/// F14.6-02): the runtime glue emits every pending-reap diagnostic that the
/// backend returns.
///
/// Invariant protected: the foreground poll's INFO/WARN line and every
/// shutdown line, including the required "pending_reap_occupied" WARN,
/// reach the daemon log. The backend tests prove which lines are produced;
/// this guard pins the emission shape of the two glue functions.
/// Behavioral proof on the real owner is
/// `stage14_6_runtime_glue_emits_pending_reap_diagnostics` (Linux), which
/// reads the actual stderr of a child test process.
///
/// Known lexical limits: dead-code wrapping (`if false { … }`) or emission
/// through another helper would satisfy this shape check. The behavioral
/// test covers those.
#[test]
fn mkm_arch_017_pending_reap_diagnostics_emitted() {
    let runtime = production_source("linux_node_runtime");
    let foreground = function_body(&runtime, "pub(crate) fn poll_pending_reap_foreground(");
    assert_before(
        &foreground,
        "if let Some(line) = self.fencing_backend.foreground_pending_reap() {",
        "eprintln!(\"mikagami: {line}\");",
        "the returned foreground line is emitted",
    );
    assert_eq!(foreground.matches("eprintln!(").count(), 1);
    assert!(
        !foreground.contains("let _"),
        "the returned line is never discarded"
    );

    let shutdown = function_body(&runtime, "pub(crate) fn shutdown_for_daemon(");
    assert_before(
        &shutdown,
        "let pending = self.fencing_backend.shutdown_pending_reap();",
        "for line in &pending.log_lines {",
        "every shutdown line is emitted",
    );
    assert_before(
        &shutdown,
        "for line in &pending.log_lines {",
        "eprintln!(\"mikagami: {line}\");",
        "every shutdown line is emitted",
    );
    assert_before(
        &shutdown,
        "eprintln!(\"mikagami: {line}\");",
        "self.snapshot()?",
        "the lines are emitted before any Revision 10 early return",
    );

    // The occupied WARN and its identifying fields are produced by the
    // backend helper that the shutdown glue calls.
    let backend = production_source("fencing_backend");
    let helper = function_body(&backend, "pub fn shutdown_pending_reap(");
    assert!(helper.contains("pending_reap_occupied"));
    assert!(helper.contains("view.log_fields(true,"));
    let fields = function_body(&backend, "pub fn log_fields(");
    for field in [
        "pending_present=",
        "kind=",
        "incident_seq=",
        "attempt_token=",
        "pid=",
        "age_ms=",
        "last_poll=",
    ] {
        assert!(fields.contains(field), "log field {field}");
    }
}

/// Stage 14 Design Revision 5 §18.4-§18.5, §33.3 `017_counted_intent_path`,
/// and the Phase 14.8 attestation-channel boundary (§41 step 6).
///
/// Invariants protected:
/// - one fixed intent name; the CLI installs it only through tmp + `O_EXCL`
///   + `O_NOFOLLOW` + fsync + `link` (never a rename or truncating write);
/// - the reader checks the type with `lstat` before its only non-blocking,
///   no-follow open, then owner, mode, link count, and size;
/// - production callers use the root owner;
/// - the daemon ingestion step exists but has no production caller until
///   `drive_fencing_step` (§27.3, §41 step 7);
/// - ingestion validates before its single T8 write and retires only on a
///   continuity failure; a bad intent writes nothing;
/// - `confirm_by_attestation` has exactly one production call site.
///
/// Behavior is proven by the stage14_8 tests (§34.7 matrix).
#[test]
fn mkm_arch_017_attestation_channel() {
    let attestation = production_source("attestation");
    assert!(
        attestation
            .contains("pub const ATTESTATION_INTENT_FILE: &str = \"fence-attestation.toml\";")
    );
    assert!(attestation.contains("#[serde(deny_unknown_fields)]\npub struct AttestationIntent {"));

    // F14.8-02: the §18.4 4 KiB ceiling is the literal canonical value.
    assert!(attestation.contains("pub const MAX_INTENT_BYTES: u64 = 4096;"));

    // F14.8-01: one inode-bound trusted directory object. It holds no
    // pathname; `open` walks from `/` with no-follow directory opens and
    // validates the opened descriptor itself.
    assert!(attestation.contains("pub struct TrustedDir {\n    dir: File,\n    owner: u32,\n}"));
    let open = function_body(&attestation, "pub fn open(path: &Path, owner: u32)");
    for required in [
        ".open(\"/\")",
        "for component in path.components()",
        "Component::Normal(name) => name",
        "_ => return Err(IntentFault::ParentPath)",
        "sys::O_RDONLY | sys::O_DIRECTORY | sys::O_NOFOLLOW | sys::O_CLOEXEC",
        "dir.metadata()",
        "!metadata.is_dir()",
        "metadata.uid() != owner",
        "metadata.mode() & 0o022 != 0",
    ] {
        assert!(open.contains(required), "TrustedDir::open: {required}");
    }
    assert_before(
        &open,
        "sys::openat(",
        "dir.metadata()",
        "walk before validation",
    );
    assert!(function_body(&attestation, "fn sync(&self)").contains("self.dir.sync_all()"));
    assert!(
        function_body(&attestation, "fn open_read(&self")
            .contains("sys::O_RDONLY | sys::O_NOFOLLOW | sys::O_NONBLOCK | sys::O_CLOEXEC")
    );
    assert!(
        function_body(&attestation, "pub fn create_exclusive(")
            .contains("O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC")
    );
    // No pathname-resolved operation anywhere in the module: the only
    // pathname open is the root that starts the walk.
    assert_eq!(attestation.matches(".open(").count(), 1);
    for forbidden in [
        "fs::symlink_metadata",
        "fs::metadata",
        "fs::read_dir",
        "fs::hard_link",
        "fs::remove_file",
        "fs::rename",
        "fs::write",
        "File::open(",
        "canonicalize",
        ".join(",
        "PathBuf",
        "check_parent",
    ] {
        assert!(
            !attestation.contains(forbidden),
            "attestation: pathname operation {forbidden}"
        );
    }

    let install = function_body(&attestation, "pub fn install_intent(");
    for required in [
        "intent_pending(trusted)",
        "remove_stale_temporaries(trusted)",
        "trusted.create_exclusive(",
        "Permissions::from_mode(0o600)",
        ".sync_all()",
        "trusted.link(temporary.as_bytes(), ATTESTATION_INTENT_FILE.as_bytes())",
        "trusted.sync()",
    ] {
        assert!(install.contains(required), "install_intent: {required}");
    }
    for (first, second) in [
        ("intent_pending(trusted)", "trusted.create_exclusive("),
        (".sync_all()", "trusted.link("),
        (
            "trusted.link(",
            "match trusted.unlink(temporary.as_bytes())",
        ),
        (
            "match trusted.unlink(temporary.as_bytes())",
            "trusted.sync()",
        ),
    ] {
        assert_before(&install, first, second, "install order");
    }
    for forbidden in [".create(true)", ".truncate(", "rename"] {
        assert!(!install.contains(forbidden), "install_intent: {forbidden}");
    }

    let read = function_body(&attestation, "pub fn read_intent(");
    for required in [
        "trusted.entry(name)",
        "linked.mode & S_IFMT == S_IFLNK",
        "linked.mode & S_IFMT != S_IFREG",
        "trusted.open_read(name)",
        "metadata.nlink() != 1",
        "check_intent_metadata(",
        "MAX_INTENT_BYTES + 1",
        "toml::from_str::<AttestationIntent>",
        "ATTESTATION_FORMAT_VERSION",
    ] {
        assert!(read.contains(required), "read_intent: {required}");
    }
    // The special-file refusal happens on the `fstatat` (no-follow) result,
    // before the open, so a device or FIFO is never opened (Phase 14.5
    // F14.5-01).
    for check in [
        "trusted.entry(name)",
        "linked.mode & S_IFMT == S_IFLNK",
        "linked.mode & S_IFMT != S_IFREG",
    ] {
        assert_before(
            &read,
            check,
            "trusted.open_read(name)",
            "type checks before the open",
        );
    }
    let remove = function_body(&attestation, "pub fn remove_intent(");
    assert_before(
        &remove,
        "trusted.unlink(ATTESTATION_INTENT_FILE.as_bytes())",
        "trusted.sync()",
        "unlink then fsync the same directory",
    );
    let metadata = function_body(&attestation, "fn check_intent_metadata(");
    for required in [
        "uid != owner",
        "mode & 0o7777 != 0o600",
        "len > MAX_INTENT_BYTES",
    ] {
        assert!(
            metadata.contains(required),
            "check_intent_metadata: {required}"
        );
    }
    for forbidden in [
        "NodeMutationStore",
        "confirm_by_",
        "apply_fencing_transition",
        "retire_fencing_incident",
        "open_fencing_incident",
        "WitnessSession",
        "RuntimeLeaseAuthority",
        "execute_promotion",
        "fencing_backend",
    ] {
        assert!(!attestation.contains(forbidden), "attestation: {forbidden}");
    }

    // Production owners are root.
    let recover = production_source("recover");
    assert!(function_body(&recover, "pub(crate) fn run(").contains("recover(&request, ROOT_UID,"));
    assert_eq!(recover.matches("install_intent(").count(), 1);
    assert!(recover.contains(".load_existing()"));
    let runtime = production_source("linux_node_runtime");
    assert!(
        function_body(&runtime, "pub(crate) fn ingest_attestation(")
            .contains("crate::attestation::ROOT_UID")
    );

    // F14.8-01: each production side opens the trusted directory once and
    // routes every intent operation through that one handle.
    let mut openers = Vec::new();
    for (module, code) in production_modules() {
        if module != "attestation" {
            for _ in code.matches("TrustedDir::open(") {
                openers.push(module.clone());
            }
        }
    }
    openers.sort();
    // Phase 14.11 (§28 `fencing.attestation`): `status` is a third opener, a
    // presence inspector only. It opens the same trusted directory object and
    // asks `intent_pending`; it never reads, installs, removes, links, or
    // unlinks an intent and never names the file or a pathname operation.
    assert_eq!(openers, ["linux_node_runtime", "recover", "status"]);
    let status = production_source("status");
    assert_eq!(status.matches("TrustedDir::open(").count(), 1);
    assert_eq!(
        status.matches("intent_pending(").count(),
        1,
        "one presence check"
    );
    for forbidden in [
        "install_intent",
        "remove_intent",
        "read_intent",
        "create_exclusive",
        ".link(",
        ".unlink(",
        "ATTESTATION_INTENT_FILE",
        "std::fs",
        "fs::",
        "File::open(",
    ] {
        assert!(
            !status.contains(forbidden),
            "status: intent operation {forbidden}"
        );
    }
    // Neither side touches the intent directory by pathname.
    for forbidden in ["std::fs", "fs::", "ATTESTATION_INTENT_FILE", "File::open("] {
        assert!(
            !recover.contains(forbidden),
            "recover: pathname operation {forbidden}"
        );
    }
    let recover_body = function_body(&recover, "fn recover(");
    for (first, second) in [
        ("TrustedDir::open(dir, owner)", "intent_pending(&trusted)"),
        (
            "intent_pending(&trusted)",
            "install_intent(&trusted, &intent)",
        ),
    ] {
        assert_before(&recover_body, first, second, "recover uses one handle");
    }

    // Phase 14.9: exactly one production caller of the ingestion step,
    // `drive_fencing_step` (§27.3), with the R4 term from the incident-bound
    // record; the definition is the only other mention.
    let drive = function_body(&runtime, "pub(crate) fn drive_fencing_step(");
    assert_eq!(
        drive
            .matches("self.ingest_attestation(context, Some(newest))?")
            .count(),
        1
    );
    for (module, code) in production_modules() {
        let expected = if module == "linux_node_runtime" { 2 } else { 0 };
        assert_eq!(
            code.matches("ingest_attestation(").count(),
            expected,
            "{module}: ingest_attestation has its definition and one caller"
        );
        if module != "linux_node_runtime" {
            assert!(!code.contains("ingest_attestation_as("), "{module}");
        }
    }
    assert_eq!(runtime.matches("ingest_attestation_as(").count(), 2);

    // Validate before the single write; retire only on continuity failure.
    let body = function_body(&runtime, "fn ingest_attestation_as(");
    // F14.8-01: one trusted directory object for read, removal, and fsync;
    // an untrusted directory is rejected with nothing removed.
    assert_eq!(body.matches("TrustedDir::open(").count(), 1);
    assert!(body.contains("crate::attestation::read_intent(&trusted)"));
    assert!(body.contains("crate::attestation::remove_intent(&trusted)"));
    assert_eq!(body.matches("read_intent(").count(), 1);
    assert_eq!(body.matches("remove_intent(").count(), 1);
    for forbidden in ["std::fs", "fs::", "intent_dir.join", "File::open("] {
        assert!(
            !body.contains(forbidden),
            "ingestion: pathname operation {forbidden}"
        );
    }
    // The refusal arm: from the open up to the handle's first use.
    let refused =
        &body[body.find("TrustedDir::open(").unwrap()..body.find("let removed =").unwrap()];
    assert!(
        refused.contains("removed: false"),
        "an untrusted directory is not touched"
    );
    assert!(
        !refused.contains("remove_intent("),
        "no removal before the handle exists"
    );
    for (first, second) in [
        ("persistent.fencing_incident", "TrustedDir::open("),
        ("TrustedDir::open(", "read_intent(&trusted)"),
    ] {
        assert_before(&body, first, second, "ingestion trusted-directory order");
    }
    for (first, second) in [
        ("NodeState::Standby", "read_intent("),
        ("persistent.fencing_incident", "read_intent("),
        ("read_intent(", "validate_intent("),
        ("validate_intent(", ".confirm_by_attestation("),
        (
            ".confirm_by_attestation(",
            ".apply_fencing_transition(transition)",
        ),
        (
            "IntentVerdict::Retire(violation)",
            ".retire_fencing_incident(",
        ),
        (".retire_fencing_incident(", "IntentVerdict::Accept("),
    ] {
        assert_before(&body, first, second, "ingestion order");
    }
    assert_eq!(body.matches(".apply_fencing_transition(").count(), 1);
    assert_eq!(body.matches(".retire_fencing_incident(").count(), 1);
    let reject_arm = &body[body.find("IntentVerdict::Reject(mismatch)").unwrap()
        ..body.find("IntentVerdict::Retire(violation)").unwrap()];
    assert!(
        !reject_arm.contains("mutation_store"),
        "a bad intent writes nothing"
    );
    for forbidden in [
        "open_fencing_incident",
        "mint_fencing_clearance",
        "FencingClearance",
        "execute_promotion",
        "acquire",
        "begin_lease",
        "RuntimeLeaseAuthority",
        "WitnessSession",
        "run_step",
        "fencing_backend",
        "arm_",
    ] {
        assert!(!body.contains(forbidden), "ingestion: {forbidden}");
    }

    // Exactly one production `CONFIRMED(operator)` mint call, the ingestion.
    let mut sites = Vec::new();
    for (module, code) in production_modules() {
        for _ in code.matches(".confirm_by_attestation(") {
            sites.push(module.clone());
        }
    }
    assert_eq!(sites, ["linux_node_runtime"]);
}

/// Stage 14 Phase 14.9 fail-closed fencing composition, amended by Phase
/// 14.10 (Rev5 §24 G-L, §25, §25.1 supersede the DC-14.9-01 Option B
/// deviation). Rev5 §24 G, §27.2, §27.3, §27.5, §26 R4.
///
/// Invariants protected:
/// - gate G sits after the fresh `Authorized` evaluation and the shutdown
///   check, before the only LeaseRequest; every gate decision but a valid
///   `CONFIRMED` retires the attempt `BlockedBeforeMutation`; the one
///   production pass is `Cleared(FencingClearance)`, the test bypass stays
///   `#[cfg(test)]`;
/// - a valid `CONFIRMED` mints the clearance from the store's own durable
///   load at G; exactly one production caller each of the clearance mint
///   (G), `arm_consuming_fencing` (`arm_and_promote`), and the §25.1
///   abort cleanup (`release_attempt_lease_once`);
/// - the blocking steps void the verified-listen window first (§27.5);
/// - no loop, retry, sleep, or thread in the gate, the step, or the step
///   site; one foreground `drive_fencing_step` caller;
/// - the step's R4 input is the incident-bound record, never the fusion
///   `witness_term`.
///
/// Known lexical limits: as for the other 017 guards. Behavior is proven by
/// the Phase 14.9 daemon and Linux runtime tests.
#[test]
fn mkm_arch_017_phase_14_9_fail_closed_composition() {
    let daemon = production_source("daemon");
    let runtime = production_source("linux_node_runtime");
    let fencing = production_source("fencing");

    // G placement inside the one attempt driver.
    let attempt = function_body(&daemon, "pub(crate) fn execute_promotion_attempt(");
    assert_eq!(attempt.matches(".fencing_gate(").count(), 1);
    for (first, second) in [
        (
            ".evaluate_authority_attempt(",
            "if self.shutdown_requested {",
        ),
        ("if self.shutdown_requested {", ".fencing_gate("),
        (".fencing_gate(", ".acquire_attempt_lease_once("),
        (".fencing_gate(", ".execute_attempt_promotion("),
    ] {
        assert_before(&attempt, first, second, "gate G order");
    }
    let gate_match = &attempt[attempt.find(".fencing_gate(").unwrap()
        ..attempt
            .find("let binding = prerequisite.binding();")
            .unwrap()];
    assert_eq!(
        gate_match
            .matches("PromotionAttemptResult::BlockedBeforeMutation,")
            .count(),
        2
    );
    // Whitespace-insensitive: the match now sits one level deeper (the
    // Bootstrap clearance short-circuit wraps it); the arms are unchanged.
    let squeeze = |text: &str| text.split_whitespace().collect::<String>();
    let gate_squeezed = squeeze(gate_match);
    assert!(
        gate_squeezed
            .contains("FencingGate::Blocked(_reason)=>{returnself.retire_promotion_attempt(")
    );
    assert!(gate_match.contains("FencingGate::Failed(error) => {"));
    assert!(gate_match.contains("self.state = DaemonState::Failed;"));
    assert!(
        gate_match.contains(
            "FencingGate::Cleared(clearance) => FencingPrerequisite::Cleared(clearance),"
        )
    );
    assert!(gate_squeezed.contains(
        "#[cfg(test)]FencingGate::BypassedForStage13Test=>FencingPrerequisite::BypassedForStage13Test,"
    ));
    // The one production pass carries the clearance; the bypass is test-only
    // everywhere it appears.
    assert_eq!(
        item_members(&daemon, "pub(crate) enum FencingGate {", true),
        ["Blocked", "Failed", "Cleared", "BypassedForStage13Test"]
    );
    assert_eq!(
        item_members(&daemon, "pub(crate) enum FencingPrerequisite {", true),
        ["Cleared", "Bootstrap", "BypassedForStage13Test"]
    );
    for bypass in daemon.match_indices("BypassedForStage13Test") {
        let before = &daemon[..bypass.0];
        let line_start = before.rfind('\n').unwrap();
        let previous = &before[..line_start];
        let attribute = &previous[previous.rfind('\n').unwrap() + 1..];
        let same_line = &before[line_start + 1..];
        assert!(
            attribute.trim() == "#[cfg(test)]"
                || same_line.contains("FencingGate::BypassedForStage13Test => "),
            "BypassedForStage13Test must be #[cfg(test)]: {attribute:?} / {same_line:?}"
        );
    }

    // Every gate decision but the clearance is a block.
    assert_eq!(
        item_members(&fencing, "pub enum FencingGateBlock {", true),
        [
            "NotEligible",
            "FencingUnavailable",
            "StoreUnavailable",
            "FencingRequired",
            "FencingUnconfirmed",
            "FencingInProgress",
        ]
    );
    let gate = function_body(&runtime, "pub(crate) fn fencing_gate(");
    let confirmed = function_body(&gate, "(FencingState::Confirmed(_), _) =>");
    assert!(confirmed.contains("self.mutation_store.mint_fencing_clearance("));
    assert!(confirmed.contains("Ok(clearance) => Ok(FencingGateDecision::Clear {"));
    assert_eq!(gate.matches("FencingGateDecision::Clear {").count(), 1);

    // Exactly one production caller each: the clearance mint at G, the
    // success ARM in `arm_and_promote`, the §25.1 cleanup in
    // `release_attempt_lease_once`. `FencingClearance` stays out of every
    // module but the fencing model, the store, and the two compositions.
    for (module, code) in production_modules() {
        let expected = |call: &str| match (module.as_str(), call) {
            ("node_mutation", _) => 1,
            ("linux_node_runtime", _) => 1,
            _ => 0,
        };
        for call in [
            "mint_fencing_clearance(",
            "arm_consuming_fencing(",
            "retire_incident_and_arm_cleanup_obligation(",
        ] {
            assert_eq!(
                code.matches(call).count(),
                expected(call),
                "{module}: {call}"
            );
        }
        if !matches!(
            module.as_str(),
            "fencing" | "node_mutation" | "daemon" | "linux_node_runtime"
        ) {
            assert!(
                !code.contains("FencingClearance"),
                "{module}: FencingClearance"
            );
        }
    }
    assert_eq!(
        function_body(&runtime, "pub(crate) fn arm_and_promote(")
            .matches(".arm_consuming_fencing(")
            .count(),
        1
    );
    assert_eq!(
        function_body(&runtime, "pub(crate) fn release_attempt_lease_once(")
            .matches(".retire_incident_and_arm_cleanup_obligation(")
            .count(),
        1
    );

    // §27.5: the blocking step follows the void, in both callers.
    let drive = function_body(&runtime, "pub(crate) fn drive_fencing_step(");
    for body in [&gate, &drive] {
        assert_eq!(body.matches("before_blocking_step();").count(), 1);
        assert_before(
            body,
            "before_blocking_step();",
            "run_fencing_process(",
            "void before the blocking step",
        );
    }
    // J27 (audit a01 NB-1): the closure also marks the iteration for `peer_tick_at`
    // (`j27_window_opened_at_a_pre_step_now_never_counts`); it still voids before each step.
    assert_eq!(
        daemon
            .matches("let mut void = || {\n            *stepped = true;\n            peer.void_listen_window_for_fencing_step();\n        };")
            .count(),
        2
    );

    // §27.3: at most one step per call; no loop, retry, or pacing of its own.
    let step = function_body(&runtime, "fn run_fencing_process(");
    // The step site's one `for` walks the finished report's log lines.
    let log = "for line in self.fencing_backend.step_log_lines(&report) {";
    assert_eq!(step.matches("for ").count(), 1);
    assert_eq!(step.matches(log).count(), 1);
    let step_without_log = step.replace(log, "");
    for body in [&gate, &drive, &step_without_log] {
        for forbidden in [
            "loop ",
            "loop{",
            "while ",
            "for ",
            "sleep",
            "thread",
            "retry",
            "Instant::now",
        ] {
            assert!(
                !body.contains(forbidden),
                "fencing composition: {forbidden}"
            );
        }
    }
    // The step never runs a fence action and never opens an incident.
    assert!(!drive.contains("open_fencing_incident("));
    assert!(!drive.contains("request_again("));
    assert!(!drive.contains("action_returned("));

    // The daemon maps a gate/step result exactly: pre-commit store failure
    // blocks (G) or waits for the cadence (step); every other error is
    // class D. The R4 record is carried over only for the same incident.
    for required in [
        "(Some(mut kept), Some(fresh)) if kept.incident == fresh.incident => {",
        "Err(error) => FencingGate::Failed(error.to_string()),",
        "FencingStepOutcome::Retired(_)) => {\n                self.fencing_term_record = None;",
    ] {
        assert_eq!(daemon.matches(required).count(), 1, "daemon: {required}");
    }
    // Phase 14.10 added two more `Err(error) => Err(error.to_string()),`
    // mappings (K recheck, cleanup); the step wrapper's own is pinned here.
    let step_wrapper = function_body(
        &daemon[daemon.find("impl LinuxDaemonRuntime {").unwrap()..],
        "fn drive_fencing_step(",
    );
    assert_eq!(
        step_wrapper
            .matches("Err(error) => Err(error.to_string()),")
            .count(),
        1
    );

    // One foreground caller, inside the Standby early return, after the
    // pending-reap poll; it is given the daemon's live shutdown query
    // (F14.9-01, `mkm_arch_017_phase_14_9_live_shutdown_boundaries`).
    assert_eq!(daemon.matches("self.drive_fencing_step(").count(), 1);
    assert_eq!(
        daemon.matches("self.runtime.drive_fencing_step(").count(),
        1
    );
    assert_eq!(
        daemon
            .matches(".fencing_gate(view_term, &context, shutdown_requested, &mut void)")
            .count(),
        1
    );

    // R4: the incident-bound record, never the fusion term.
    assert!(drive.contains(".filter(|record| record.incident == incident_ref)"));
    assert!(drive.contains("WitnessEpoch::LatestObserved(Some(newest))"));
    assert!(!drive.contains("witness_term"));
    assert!(!gate.contains("witness_term"));
    let linux_impl = &daemon[daemon
        .find("impl LinuxDaemonRuntime {")
        .expect("Linux daemon runtime")..];
    let observation = function_body(linux_impl, "pub(crate) fn authority_observation_tick(");
    assert_before(
        &observation,
        "ObservationProgress::Ready(authority_view) => {",
        "record.record_term(authority_view.term());",
        "R4 record update on the authenticated completion",
    );
    assert_eq!(daemon.matches(".record_term(").count(), 2);

    // The one ingestion caller uses the production root owner; the only
    // other owner is a `#[cfg(test)]` seam for non-root test runs.
    let ingest = function_body(&runtime, "pub(crate) fn ingest_attestation(");
    assert_before(
        &ingest,
        "let owner = crate::attestation::ROOT_UID;",
        "self.ingest_attestation_as(context, latest_observed_term, owner)",
        "production owner",
    );
    assert_eq!(runtime.matches("attestation_owner_for_test").count(), 4);
    assert_eq!(
        runtime
            .matches("#[cfg(test)]\n        let owner = self.attestation_owner_for_test.unwrap_or(owner);")
            .count(),
        1
    );
    assert_eq!(
        runtime
            .matches("#[cfg(test)]\n    attestation_owner_for_test: Option<u32>,")
            .count(),
        1
    );
    assert_eq!(
        runtime
            .matches("#[cfg(test)]\n            attestation_owner_for_test: None,")
            .count(),
        1
    );
    assert_eq!(daemon.matches("fencing_term_record").count(), 8);
}

/// Stage 14 Phase 14.9 F14.9-01 (independent audit): shutdown is live at the
/// fencing boundaries. Rev5 §17.2, §18.5, §26 R7, §27.2 step 3, §27.4.
///
/// Invariants protected:
/// - no second shutdown authority: one signal latch (`SHUTDOWN_REQUESTED`),
///   one Daemon requested state set only by `request_shutdown`, and a
///   read-only Daemon reader of the latch attached exactly once in
///   production, from the same reader the loop's `should_stop` uses;
/// - every `should_stop` observation in the loop propagates
///   `request_shutdown`, and the last one precedes `tick_at` (no window in
///   which a stop was seen but the tick still runs a fencing step);
/// - the Daemon hands the gate and the foreground step a live query (its
///   requested state or the raised latch), never a bool snapshot; the Stage
///   13 lifecycle query is unchanged;
/// - the gate and the step sample the query at entry, immediately before
///   the spawn (and, in the step, before ingestion), and after the bounded
///   process returned, feeding that post-return sample into the §17.2 /
///   §27.2 recheck; no sample is stored across the step.
///
/// Known lexical limits: as for the other 017 guards. The temporal property
/// is proven by the F14.9-01 behavioral tests (`stage14_9_f01_*` in
/// `linux_node_runtime`, `daemon`, and `daemon_run`), not by this guard.
#[test]
fn mkm_arch_017_phase_14_9_live_shutdown_boundaries() {
    let compact = |body: &str| body.split_whitespace().collect::<String>();
    let wiring = production_source("daemon_run");
    let daemon = production_source("daemon");
    let runtime = production_source("linux_node_runtime");

    // One latch, one requested state, one read-only reader attachment.
    let mut latches = 0;
    for (module, code) in production_modules() {
        latches += code
            .matches("static SHUTDOWN_REQUESTED: AtomicBool")
            .count();
        if module != "daemon_run" && module != "recovery" {
            assert!(!code.contains("AtomicBool"), "{module}: a shutdown flag");
        }
        if module != "daemon" && module != "daemon_run" {
            assert!(!code.contains("attach_shutdown_signal("), "{module}");
            assert!(!code.contains("request_shutdown("), "{module}");
        }
    }
    assert_eq!(latches, 1);
    assert_eq!(wiring.matches("SHUTDOWN_REQUESTED.store(true").count(), 1);
    assert_eq!(daemon.matches("self.shutdown_requested = true").count(), 1);
    assert_before(
        &function_body(&daemon, "pub(crate) fn request_shutdown("),
        "{",
        "self.shutdown_requested = true;",
        "the requested state is set only by request_shutdown",
    );
    assert_eq!(daemon.matches("self.shutdown_signal =").count(), 1);
    let attach = function_body(&daemon, "pub(crate) fn attach_shutdown_signal(");
    assert!(attach.contains("self.shutdown_signal = ShutdownSignal(Some(Box::new(read)));"));
    let reader = function_body(&daemon, "fn raised(&self) -> bool");
    assert_eq!(
        compact(&reader),
        "{self.0.as_ref().is_some_and(|read|read())}"
    );
    assert_eq!(wiring.matches("attach_shutdown_signal(").count(), 1);
    let run = function_body(&wiring, "pub(super) fn run_daemon_inner(");
    assert!(run.contains("daemon.attach_shutdown_signal(move ||"));
    assert!(run.contains("verify_lock(&lock_for_signal"));
    assert!(run.contains("verify_lock(&lock_for_loop"));
    assert!(
        compact(&run)
            .contains("run_observation_loop_checked(&mutdaemon,interval,lock_lost,should_stop,")
    );
    assert_before(
        &run,
        "daemon.attach_shutdown_signal(move ||",
        "run_observation_loop_checked(",
        "the reader is attached before the loop starts",
    );
    assert_before(
        &run,
        "let lock_lost = move ||",
        "run_observation_loop_checked(",
        "the loop's dedicated lock-loss predicate is built",
    );
    assert!(
        run.contains("LoopExit::ControlLockLost(error)")
            && run.contains("return Err(format!(\"the control lock became unsafe"),
        "a lock-path failure must win over every loop exit word: {run}"
    );
    let lock_arm = run
        .split("LoopExit::ControlLockLost(error)")
        .nth(1)
        .and_then(|tail| tail.split("other =>").next())
        .unwrap_or("");
    assert!(
        lock_arm.contains("return Err(") && lock_arm.contains("the control lock became unsafe"),
        "the ControlLockLost arm must map to its own non-zero error: {lock_arm}"
    );
    assert!(
        run.contains("!verify_lock(&lock_for_signal, &error_for_signal) || shutdown_requested()"),
        "the live shutdown query must be true on lock loss (the `!` is essential)"
    );
    assert!(
        run.contains("let should_stop = shutdown_requested;"),
        "normal shutdown must be driven only by the signal, not by verify_lock"
    );
    assert!(
        !compact(&run).contains("should_stop=move||verify_lock"),
        "normal shutdown must not be used for a lock loss"
    );
    assert!(
        run.contains("if result.is_ok()") && run.contains("control_lock.verify()"),
        "a final lock check must prevent Clean from masking a late loss"
    );
    let verify = function_body(&wiring, "fn verify_lock(");
    assert!(
        verify.contains("lock.verify()")
            && verify.contains("slot = Some(problem.to_string())")
            && verify.contains("slot.is_none()"),
        "verify_lock must retain the first error and never overwrite it"
    );
    let checked = function_body(&wiring, "fn run_observation_loop_checked<");
    assert_before(
        &checked,
        "if let Some(error) = lock_lost()",
        "if should_stop()",
        "lock loss is checked before the normal shutdown request",
    );
    let promote_at = checked.find("promote(daemon)").expect("promotion call");
    let pre_promote = &checked[..promote_at];
    assert!(
        pre_promote.matches("lock_lost()").count() >= 2,
        "lock loss must be checked before promotion starts"
    );
    let tick_at = checked.find("daemon.tick_at(now)").expect("tick call");
    let pre_tick = &checked[..tick_at];
    assert!(
        pre_tick.matches("lock_lost()").count() >= 3,
        "lock loss must be checked before the tick/cleanup path"
    );

    // The loop: every observed stop is propagated; the last precedes the tick.
    let body = function_body(&wiring, "fn run_observation_loop_checked<");
    assert_eq!(body.matches("should_stop()").count(), 4);
    assert_eq!(body.matches("!should_stop()").count(), 0);
    assert_eq!(body.matches("if should_stop() {").count(), 4);
    assert_eq!(body.matches("daemon.request_shutdown()").count(), 4);
    let pre_tick = &body[body.find("let now = clock();").expect("clock sample")
        ..body.find("match daemon.tick_at(now)").expect("the tick")];
    assert_eq!(
        compact(pre_tick),
        "letnow=clock();ifshould_stop(){intent.discard();let_=daemon.request_shutdown();}else{prime(daemon,now);}"
    );

    // The Daemon hands both fencing callers the live query.
    // Gate and step, plus (Phase 14.10) the K recheck's shutdown item, plus
    // (Phase 14.12 E3b; was 3) the attempt-bound observation step's live
    // query. `mkm_arch_017_phase_14_12_e3b_attempt_bound_observation` pins it.
    // Plus the Bootstrap Admission decision's live read (contract K-1) and the
    // automatic trigger's input (it only ever suppresses a request).
    assert_eq!(daemon.matches("self.shutdown_signal.raised()").count(), 8);
    assert!(
        function_body(&daemon, "fn bootstrap_admission(").contains("self.shutdown_signal.raised()")
    );
    assert!(function_body(&daemon, "fn evaluate_auto(").contains("self.shutdown_signal.raised()"));
    assert!(
        compact(&function_body(
            &daemon,
            "pub(crate) fn execute_promotion_attempt("
        ))
        .contains("letshutdown=self.shutdown_requested||self.shutdown_signal.raised();ifshutdown")
    );
    let tick = compact(&function_body(&daemon, "pub(crate) fn tick_at("));
    assert!(tick.contains(
        ".foreground_lifecycle_tick(&||self.shutdown_requested,&||self.shutdown_requested||self.shutdown_signal.raised(),&||self.control_lock_guard.lost().is_none(),)"
    ));
    // R-16/R-17: the live control-lock guard is sampled by the shutdown
    // branch and around the cleanup workflow; it is deliberately separate
    // from the combined shutdown signal.
    assert!(tick.contains(".shutdown_bounded_step(&||self.control_lock_guard.lost().is_none())"));
    assert!(tick.contains(".shutdown(&||self.control_lock_guard.lost().is_none())"));
    // v0.7 G-2: two more, bracketing the route-handoff tick (the last blocking work of an
    // observed iteration), which itself receives the live control-lock predicate.
    assert_eq!(
        tick.matches("self.require_control_lock()?;").count(),
        7,
        "the lock guard must bracket the shutdown/foreground/route effects"
    );
    assert!(tick.contains(
        "self.evaluate_auto(now);self.require_control_lock()?;self.runtime.route_handoff_tick(&||self.control_lock_guard.lost().is_none()).map_err(DaemonError::ObservationInvariant)?;self.require_control_lock()?;Ok(TickResult::Observed)"
    ));
    let attempt = compact(&function_body(
        &daemon,
        "pub(crate) fn execute_promotion_attempt(",
    ));
    assert!(attempt.contains(
        ".fencing_gate(&evaluation,&||{self.shutdown_requested||self.shutdown_signal.raised()})"
    ));
    let linux = &daemon[daemon
        .find("impl LinuxDaemonRuntime {")
        .expect("Linux daemon runtime")..];
    let wrapper = function_body(linux, "fn drive_fencing_step(");
    assert!(compact(&wrapper).contains(
        "self.runtime.drive_fencing_step(&context,self.fencing_term_record.as_ref(),live_shutdown,&mutvoid,)"
    ));
    for signature in [
        "fn drive_fencing_step(&mut self, live_shutdown: &dyn Fn() -> bool)",
        "live_shutdown: &dyn Fn() -> bool,\n        control_lock_safe: &dyn Fn() -> bool,\n    ) -> Result<(), String> {",
        "shutdown_requested: &dyn Fn() -> bool,\n    ) -> FencingGate {",
    ] {
        assert!(daemon.contains(signature), "daemon: {signature}");
    }

    // R-16: the cleanup workflow samples the same guard before each new
    // protected effect. The ZeroResource re-establishment used by the bounded
    // shutdown join is the same workflow, not an unguarded shortcut.
    let workflow = production_source("resource_workflow");
    let inner = function_body(&workflow, "fn cleanup_local_resources_inner_guarded(");
    assert_before(
        &inner,
        "if !control_lock_safe()",
        "self.executor.stop_service()",
        "the service stop must be gated by the live control lock",
    );
    let after_stop = &inner[inner
        .find("self.executor.stop_service()")
        .expect("the service stop call")..];
    assert_before(
        after_stop,
        "if !control_lock_safe()",
        "self.executor.release_vip()",
        "the VIP release must be gated by the live control lock",
    );
    let post = function_body(&runtime, "fn drive_post_cleanup_reconciliation(");
    assert!(
        post.contains("execute_pending_witness_mutation_once_guarded"),
        "the bounded shutdown join must not use the unguarded release path"
    );
    assert!(
        post.contains("cleanup_guarded("),
        "the post-cleanup release must use the guarded cleanup path"
    );

    // The runtime samples live at entry, before the spawn, and after return.
    let gate = function_body(&runtime, "pub(crate) fn fencing_gate(");
    let drive = function_body(&runtime, "pub(crate) fn drive_fencing_step(");
    for (name, body, samples) in [("gate", &gate, 3), ("drive", &drive, 4)] {
        assert_eq!(
            body.matches("shutdown_requested()").count(),
            samples,
            "{name}"
        );
        assert_eq!(
            body.matches("self.fencing_eligible_image(shutdown_requested())?")
                .count(),
            1,
            "{name}: entry sample"
        );
        let spawn = body.find("before_blocking_step();").expect("the void");
        let pre = body[..spawn]
            .rfind("if shutdown_requested() {")
            .expect("pre-spawn sample");
        let between = compact(&body[pre..spawn]);
        assert!(
            between.ends_with("returnOk(FencingGateDecision::Block(outcome));}")
                || between.ends_with("returnOk(FencingStepOutcome::NotEligible);}"),
            "{name}: the pre-spawn sample is the last statement before the void: {between}"
        );
        let after = compact(&body[spawn..]);
        let recheck = after
            .find("self.fencing_result_applies(")
            .expect("post-return recheck");
        assert!(
            after.find("self.run_fencing_process(").unwrap() < recheck,
            "{name}"
        );
        for forbidden in [
            "letshutdown",
            "=shutdown_requested()",
            "shutdown_requested,",
        ] {
            assert!(
                !compact(body).contains(forbidden),
                "{name}: snapshot {forbidden}"
            );
        }
    }
    assert!(compact(&gate).contains(
        "self.fencing_result_applies(&requested,shutdown_requested(),context,WitnessEpoch::GateView(view_term),)?"
    ));
    assert!(
        compact(&drive)
            .contains("self.fencing_result_applies(&incident,shutdown_requested(),context,epoch)?")
    );
    assert_before(
        &drive,
        "if shutdown_requested() {\n            return Ok(FencingStepOutcome::NotEligible);\n        }\n        match self.ingest_attestation(",
        "if used >= budget {",
        "a live sample immediately precedes ingestion",
    );
    for returned in ["FencingGateDecision", "FencingStepOutcome"] {
        let signature = format!(
            "shutdown_requested: &dyn Fn() -> bool,\n        before_blocking_step: &mut dyn FnMut(),\n    ) -> Result<{returned}, LinuxNodeRuntimeError> {{"
        );
        assert_eq!(
            runtime.matches(&signature).count(),
            1,
            "{returned}: live query"
        );
    }
}

/// Production source with `#[cfg(test)]` items removed: every attribute line
/// `#[cfg(test)]` and the item that follows it (to its closing brace or `;`).
fn without_cfg_test_items(code: &str) -> String {
    let mut out = String::with_capacity(code.len());
    let mut rest = code;
    while let Some(at) = rest.find("#[cfg(test)]") {
        out.push_str(&rest[..at]);
        let after = &rest[at + "#[cfg(test)]".len()..];
        // The item ends at the first `;` or `,` outside any bracket, or at
        // the brace that closes its first top-level `{`.
        let mut depth = 0usize;
        let mut end = after.len();
        let bytes = after.as_bytes();
        for (index, &byte) in bytes.iter().enumerate() {
            let arrow = index > 0 && matches!(bytes[index - 1], b'-' | b'=');
            match byte {
                b'(' | b'[' | b'<' => depth += 1,
                b'>' if arrow => {}
                b')' | b']' | b'>' => depth = depth.saturating_sub(1),
                b';' | b',' if depth == 0 => {
                    end = index + 1;
                    break;
                }
                b'{' if depth == 0 => {
                    let mut braces = 0usize;
                    for (offset, inner) in after.as_bytes()[index..].iter().enumerate() {
                        match inner {
                            b'{' => braces += 1,
                            b'}' => {
                                braces -= 1;
                                if braces == 0 {
                                    end = index + offset + 1;
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    break;
                }
                _ => {}
            }
        }
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

/// Stage 14 Design Revision 5 §33.3 `017_atomic_incident_arm` (Phase 14.10).
///
/// Invariants protected: `arm_and_promote` uses `arm_consuming_fencing` (never
/// the plain `arm_release_obligation`); trusted ZeroResource is observed
/// before it, and the authority is restored and Stage 11 entered only after
/// it returned `Ok`; the store operation removes the incident and installs O
/// in one candidate and one `save_locked`, after validating the exact
/// clearance incident, `CONFIRMED`, the clearance episode, anchor + 1, the
/// configured peer, and `O = M = None`.
///
/// Known lexical limits: source shape only. Crash atomicity and the resource
/// barrier are proven by the P10-19..P10-22 and store fault-matrix tests.
#[test]
fn mkm_arch_017_atomic_incident_arm() {
    let runtime = production_source("linux_node_runtime");
    let node_mutation = production_source("node_mutation");

    let arm = function_body(&runtime, "pub(crate) fn arm_and_promote(");
    assert_eq!(arm.matches(".arm_consuming_fencing(").count(), 1);
    assert!(!arm.contains("arm_release_obligation"));
    for (first, second) in [
        (
            "self.observe_trusted_zero_resource()",
            ".arm_consuming_fencing(",
        ),
        (
            ".arm_consuming_fencing(",
            ".restore_installed_lease_authority(",
        ),
        (".restore_installed_lease_authority(", "self.promote()"),
    ] {
        assert_before(&arm, first, second, "success ARM order");
    }
    // Every non-committed ARM outcome returns before the authority restore.
    let outcomes = &arm[arm.find(".arm_consuming_fencing(").unwrap()
        ..arm.find(".restore_installed_lease_authority(").unwrap()];
    for (error, result) in [
        (
            "Err(NodeMutationError::Io(reason)) => {",
            "return Ok(FencedArmOutcome::NotCommitted(reason));",
        ),
        (
            "Err(NodeMutationError::FencingIncident(reason)) => {",
            "return Ok(FencedArmOutcome::Rejected(reason.to_string()));",
        ),
        (
            "Err(error) => return Ok(FencedArmOutcome::RecoveryBlocked(error.to_string())),",
            "Err(error) => return Ok(FencedArmOutcome::RecoveryBlocked(error.to_string())),",
        ),
    ] {
        assert!(outcomes.contains(error), "{error}");
        assert!(outcomes.contains(result), "{result}");
    }

    let store = function_body(&node_mutation, "pub fn arm_consuming_fencing(");
    for required in [
        "&incident.incident_ref() != clearance.incident()",
        "!matches!(incident.state, FencingState::Confirmed(_))",
        "&incident.observer_session_id != clearance.observer_session_id()",
        "incident.observer_loss_generation != clearance.observer_loss_generation()",
        "incident.anchor_term.0.checked_add(1) != Some(term.0)",
        "&incident.target_node_id != configured_peer",
        "state.release_obligation.is_some()",
        "state.outstanding_mutation.is_some()",
    ] {
        assert!(
            store.contains(required),
            "arm_consuming_fencing: {required}"
        );
    }
    single_candidate_incident_to_obligation(&store, "arm_consuming_fencing");
}

/// One candidate: the incident removal and the O install precede exactly one
/// `save_locked`, and nothing else is persisted in the body.
fn single_candidate_incident_to_obligation(body: &str, name: &str) {
    assert_eq!(body.matches("self.save_locked(").count(), 1, "{name}");
    assert_eq!(
        body.matches("state.fencing_incident = None;").count(),
        1,
        "{name}"
    );
    assert_eq!(
        body.matches("state.release_obligation = Some(obligation.clone());")
            .count(),
        1,
        "{name}"
    );
    for (first, second) in [
        ("state.fencing_incident = None;", "self.save_locked("),
        (
            "state.release_obligation = Some(obligation.clone());",
            "self.save_locked(",
        ),
    ] {
        assert_before(body, first, second, name);
    }
    for forbidden in [
        "persist(",
        "save_state(",
        "install_new(",
        "retire_fencing_incident(",
    ] {
        assert!(!body.contains(forbidden), "{name}: {forbidden}");
    }
}

/// Stage 14 Design Revision 5 §33.3 `017_atomic_abort_cleanup` (Phase 14.10).
///
/// Invariants protected: `release_attempt_lease_once` arms the cleanup O with
/// `retire_incident_and_arm_cleanup_obligation` whenever an incident is
/// present (with the attempt's binding), calls the plain
/// `arm_release_obligation` only on the no-incident/no-binding branch, and
/// returns without a Release on every other branch and on a §25.1
/// PreCommitFailure / uncertainty / mismatch; the Release follows only a
/// durable O. The store operation is one candidate that validates the
/// durable binding (not the current episode), the configured peer, and
/// `O = M = None`. The only production plain-ARM caller is that branch.
///
/// Known lexical limits: source shape only. Behavior and crash atomicity are
/// proven by P10-07..P10-18, P10-23..P10-27 and the store fault matrix.
#[test]
fn mkm_arch_017_atomic_abort_cleanup() {
    let runtime = production_source("linux_node_runtime");
    let node_mutation = production_source("node_mutation");
    let release = function_body(&runtime, "pub(crate) fn release_attempt_lease_once(");
    assert_eq!(
        release
            .matches(".retire_incident_and_arm_cleanup_obligation(")
            .count(),
        1
    );
    assert_eq!(release.matches(".arm_release_obligation(").count(), 1);
    let arm = |pattern: &str| {
        let start = release.find(pattern).unwrap_or_else(|| panic!("{pattern}"));
        let open = start + release[start..].find('{').unwrap();
        function_body(&release[open..], "{")
    };
    let with_binding = arm("(true, Some(binding)) =>");
    assert!(with_binding.contains(".retire_incident_and_arm_cleanup_obligation("));
    assert!(with_binding.contains("binding,"));
    assert!(!with_binding.contains("arm_release_obligation"));
    assert!(with_binding.contains(
        "Err(NodeMutationError::Io(reason)) => {\n                            return Ok(AttemptLeaseRelease::CleanupNotCommitted(reason));"
    ));
    assert!(
        with_binding
            .contains("return Ok(AttemptLeaseRelease::RecoveryBlocked(error.to_string()));")
    );
    for refused in ["(true, None) =>", "(false, Some(_)) =>"] {
        let body = arm(refused);
        assert!(
            body.contains("return Ok(AttemptLeaseRelease::RecoveryBlocked("),
            "{refused}"
        );
        assert!(!body.contains("arm_"), "{refused}");
    }
    let plain = arm("(false, None) =>");
    assert!(plain.contains(".arm_release_obligation("));
    assert_before(
        &release,
        "if image.release_obligation.is_none() {",
        "begin_and_execute_lease_release_once",
        "the Release follows the durable cleanup O",
    );
    assert_before(
        &release,
        "ensure_trusted_zero_resource",
        ".retire_incident_and_arm_cleanup_obligation(",
        "trusted ZeroResource before the cleanup",
    );

    let store = function_body(
        &node_mutation,
        "pub fn retire_incident_and_arm_cleanup_obligation(",
    );
    for required in [
        "incident.incident_ref() != incident_ref.incident",
        "incident.observer_session_id != incident_ref.observer_session_id",
        "incident.observer_loss_generation != incident_ref.observer_loss_generation",
        "&incident.target_node_id != configured_peer",
        "state.release_obligation.is_some()",
        "state.outstanding_mutation.is_some()",
    ] {
        assert!(store.contains(required), "abort cleanup: {required}");
    }
    single_candidate_incident_to_obligation(&store, "retire_incident_and_arm_cleanup_obligation");

    // The plain ARM's only production caller is that no-incident branch.
    for (module, code) in production_modules() {
        let code = without_cfg_test_items(&code);
        // Contract K-4 (v1.0 Amendment): the plain ARM has two production
        // callers: the no-incident abort branch and the Bootstrap
        // Admission ARM, which must live in `arm_and_promote_bootstrap`.
        let expected = match module.as_str() {
            "linux_node_runtime" => 2,
            _ => 0,
        };
        assert_eq!(
            code.matches(".arm_release_obligation(").count(),
            expected,
            "{module}: plain ARM caller"
        );
    }
    let runtime_code = without_cfg_test_items(&production_source("linux_node_runtime"));
    assert_eq!(
        function_body(&runtime_code, "pub(crate) fn arm_and_promote_bootstrap(")
            .matches(".arm_release_obligation(")
            .count(),
        1,
        "the Bootstrap Admission ARM is the second plain-ARM caller"
    );
}

/// J21 (OD-J20-6): the startup resolution of a retained LeaseRequest replays the exact request
/// after proving ZeroResource and hands an answered grant to the existing unused-lease cleanup
/// only. It never restores or installs authority, promotes, touches a resource, begins a new
/// request or adds a plain-ARM call site.
#[test]
fn j21_retained_request_resolution_never_installs_authority_or_promotes() {
    let runtime = without_cfg_test_items(&production_source("linux_node_runtime"));
    let body = function_body(&runtime, "pub(crate) fn resolve_retained_request_once(");
    let zero = body
        .find("observe_trusted_zero_resource()")
        .expect("ZeroResource check");
    let replay = body.find("retry_outstanding_once(").expect("exact replay");
    assert!(
        zero < replay,
        "ZeroResource is proven before the replay is sent"
    );
    for forbidden in [
        "restore_installed",
        "install_",
        "promote(",
        "take_installed",
        ".acquire_vip(",
        ".start_service(",
        "arm_release_obligation(",
        "begin_lease_request(",
    ] {
        assert!(
            !body.contains(forbidden),
            "resolve_retained_request_once must not reach {forbidden}"
        );
    }
    assert!(body.contains("self.release_attempt_lease_once("));
    let daemon = without_cfg_test_items(&production_source("daemon"));
    let reconcile = function_body(&daemon, "fn reconcile_startup_obligation(");
    assert!(reconcile.contains("resolve_retained_request_once("));
}

/// J22 (OD-J21-5 B-2): the audited boundaries of the retained-request resolution. They are called
/// but not followed: their internals have their own guards (K-4, BG-8, BG-12 for the unused-lease
/// cleanup, Stage 10 for the exact replay) and legitimately reach resource cleanup.
const J22_RESOLUTION_BOUNDARIES: &[&str] = &[
    "release_attempt_lease_once",
    "retry_outstanding_once",
    // J23 (C-F): the fence send path; its own guard is
    // `j23_generation_fence_exchange_sends_one_reject_only_request_and_writes_nothing`.
    "exchange_generation_fence_once",
];

/// J22 (B-2): the crate functions the resolution path may call, reviewed in J22 (closed world). A
/// call of any other crate function - a new helper in another module, an alias, a method chain, a
/// trait method or a wrapper - fails the guard until it is reviewed and listed here.
const J22_RESOLUTION_REVIEWED_CALLS: &[&str] = &[
    "clone",
    // J23 (C-F): completing the retained request after its fence committed.
    "complete",
    "is_absent",
    // J23 (C-F): the fence id derivation, a pure function; its own guard is
    // `j23_generation_fence_exchange_sends_one_reject_only_request_and_writes_nothing`.
    "generation_fence_request_id",
    // J23 (C-F): the derived fence id must be a canonical request id.
    "is_valid_mutating_request_id",
    "is_stopped",
    "kind",
    "load_existing",
    "new",
    "observe_service",
    "observe_vip",
];

/// J22 (B-2): installing or restoring authority, promotion, lease acquisition or renewal, resource
/// ownership and resource start. Reported as forbidden (not merely unreviewed) when reached.
const J22_RESOLUTION_FORBIDDEN: &[&str] = &[
    "acquire_attempt_lease_once",
    "advance_promotion",
    "arm_and_promote_bootstrap",
    "arm_release_obligation",
    "begin_lease_renew",
    "begin_lease_request",
    "complete_promotion",
    "execute_attempt_promotion",
    "execute_lease_request_once_with_authority",
    "mark_resource_ownership_started",
    "promote",
    "request_promotion_attempt",
    "request_vip_acquire",
    "restore_installed_lease_authority",
    "start_service",
    "take_installed_lease_authority",
    "transition_to_active",
];

/// J22 (B-2): direct OS effects that bypass every crate function (a VIP or a service through a
/// command, a raw syscall, a file or a socket). Not one of them may appear on the resolution path.
const J22_OS_EFFECT_MARKERS: &[&str] = &[
    "Command::",
    "libc::",
    "nix::",
    "std::process",
    "std::fs::",
    "std::net::",
    "fs::",
    "File::",
    "OpenOptions::",
    "net::",
    "TcpStream::",
    "UdpSocket::",
    "UnixStream::",
    "UnixListener::",
    "std::os::",
    "rustix::",
    "process::",
    "unsafe ",
];

/// String and char literals blanked (quotes kept) so that prose is never read as a call. Lifetimes
/// are left alone.
fn j22_blank_literals(code: &str) -> String {
    let bytes = code.as_bytes();
    let mut out = String::with_capacity(code.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'"' {
            out.push_str("\"\"");
            index += 1;
            while index < bytes.len() && bytes[index] != b'"' {
                index += if bytes[index] == b'\\' { 2 } else { 1 };
            }
            index += 1;
        } else if byte == b'\''
            && index + 2 < bytes.len()
            && (bytes[index + 2] == b'\''
                || (bytes[index + 1] == b'\\'
                    && index + 3 < bytes.len()
                    && bytes[index + 3] == b'\''))
        {
            out.push_str("' '");
            index += if bytes[index + 1] == b'\\' { 4 } else { 3 };
        } else {
            out.push(byte as char);
            index += 1;
        }
    }
    out
}

fn j22_is_ident(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Every function with a body in `code`, by name (functions sharing a name are merged). A
/// declaration without a body (a trait method) is skipped. `code` has its literals blanked.
fn j22_fn_bodies(code: &str) -> std::collections::BTreeMap<String, Vec<String>> {
    let bytes = code.as_bytes();
    let mut out: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    let mut at = 0;
    while let Some(found) = code[at..].find("fn ") {
        let start = at + found;
        at = start + 3;
        if start > 0 && j22_is_ident(bytes[start - 1]) {
            continue;
        }
        let name: String = code[start + 3..]
            .bytes()
            .take_while(|byte| j22_is_ident(*byte))
            .map(char::from)
            .collect();
        if name.is_empty() {
            continue;
        }
        let mut depth = 0usize;
        let mut index = start + 3 + name.len();
        while index < bytes.len() {
            match bytes[index] {
                b'(' | b'[' | b'<' => depth += 1,
                b'>' if matches!(bytes[index - 1], b'-' | b'=') => {}
                b')' | b']' | b'>' => depth = depth.saturating_sub(1),
                b';' if depth == 0 => break,
                b'{' if depth == 0 => {
                    let mut braces = 0usize;
                    for (offset, inner) in bytes[index..].iter().enumerate() {
                        match inner {
                            b'{' => braces += 1,
                            b'}' => {
                                braces -= 1;
                                if braces == 0 {
                                    out.entry(name.clone())
                                        .or_default()
                                        .push(code[index..=index + offset].to_string());
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    break;
                }
                _ => {}
            }
            index += 1;
        }
    }
    out
}

/// `use ... as alias` renames in `code`: alias -> original name.
fn j22_use_aliases(code: &str) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    let bytes = code.as_bytes();
    let mut at = 0;
    while let Some(found) = code[at..].find("use ") {
        let start = at + found;
        at = start + 4;
        if start > 0 && j22_is_ident(bytes[start - 1]) {
            continue;
        }
        let end = code[start..]
            .find(';')
            .map_or(code.len(), |offset| start + offset);
        let words: Vec<&str> = code[start..end]
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|word| !word.is_empty())
            .collect();
        for window in words.windows(3) {
            if window[1] == "as" {
                out.insert(window[2].to_string(), window[0].to_string());
            }
        }
    }
    out
}

/// Types (struct, enum, trait, type alias) declared in `code`.
fn j22_local_types(code: &str) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    for keyword in ["struct ", "enum ", "trait ", "type "] {
        let mut at = 0;
        while let Some(found) = code[at..].find(keyword) {
            let start = at + found;
            at = start + keyword.len();
            if start > 0 && j22_is_ident(code.as_bytes()[start - 1]) {
                continue;
            }
            let name: String = code[at..]
                .bytes()
                .take_while(|byte| j22_is_ident(*byte))
                .map(char::from)
                .collect();
            if !name.is_empty() {
                out.insert(name);
            }
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum J22Call {
    /// A function of the inspected module (followed).
    Local(String),
    /// A crate function defined elsewhere (checked against the reviewed and forbidden lists).
    External(String),
}

/// The calls (and qualified function references) in one body, by shape:
/// `self.f(` / `Self::f` / `LocalType::f` / `f(` and `.f(` of a module function are local;
/// `crate::m::f` / `OtherType::f` / `.f(` of any other crate function are external. Macros and
/// names that are not crate functions (std methods, variants, fields, locals) are ignored.
fn j22_calls(
    body: &str,
    local_fns: &std::collections::BTreeMap<String, Vec<String>>,
    local_types: &std::collections::BTreeSet<String>,
    crate_fns: &std::collections::BTreeSet<String>,
    aliases: &std::collections::BTreeMap<String, String>,
) -> std::collections::BTreeSet<J22Call> {
    let bytes = body.as_bytes();
    let mut out = std::collections::BTreeSet::new();
    let mut index = 0;
    while index < bytes.len() {
        if !j22_is_ident(bytes[index]) || (index > 0 && j22_is_ident(bytes[index - 1])) {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len() && j22_is_ident(bytes[index]) {
            index += 1;
        }
        let raw = &body[start..index];
        if raw.as_bytes()[0].is_ascii_digit() {
            continue;
        }
        let name = aliases.get(raw).cloned().unwrap_or_else(|| raw.to_string());
        let mut after = index;
        while after < bytes.len() && bytes[after].is_ascii_whitespace() {
            after += 1;
        }
        let called = bytes.get(after) == Some(&b'(') || body[after..].starts_with("::<");
        if bytes.get(after) == Some(&b'!') {
            continue;
        }
        // What precedes the name, whitespace skipped.
        let mut before = start;
        while before > 0 && bytes[before - 1].is_ascii_whitespace() {
            before -= 1;
        }
        let receiver_or_path = |end: usize| -> String {
            let mut begin = end;
            while begin > 0 && bytes[begin - 1].is_ascii_whitespace() {
                begin -= 1;
            }
            let stop = begin;
            while begin > 0 && j22_is_ident(bytes[begin - 1]) {
                begin -= 1;
            }
            body[begin..stop].to_string()
        };
        let local = local_fns.contains_key(&name);
        let external = crate_fns.contains(&name);
        if before > 0 && bytes[before - 1] == b'.' {
            if !called {
                continue;
            }
            let receiver = receiver_or_path(before - 1);
            if receiver == "self" || local {
                out.insert(if local {
                    J22Call::Local(name)
                } else {
                    J22Call::External(name)
                });
            } else if external {
                out.insert(J22Call::External(name));
            }
        } else if before > 1 && &body[before - 2..before] == "::" {
            let qualifier = receiver_or_path(before - 2);
            if (qualifier == "Self" || local_types.contains(&qualifier)) && local {
                out.insert(J22Call::Local(name));
            } else if qualifier != "Self" && !local_types.contains(&qualifier) && external {
                out.insert(J22Call::External(name));
            }
        } else if called {
            // A bare name counts only when called: a plain name that is not called is read as a
            // variable (a bare function pointer is a documented limit; `Self::f` is detected).
            if local {
                out.insert(J22Call::Local(name));
            } else if external {
                out.insert(J22Call::External(name));
            }
        }
    }
    out
}

/// The violations of the closed-world guard for `runtime` (the production `linux_node_runtime`)
/// and `daemon` (the production `daemon`), with the other production modules for the crate-wide
/// function names and aliases.
fn j22_resolution_violations(
    runtime: &str,
    daemon: &str,
    others: &[(String, String)],
) -> Vec<String> {
    let runtime = j22_blank_literals(&without_cfg_test_items(runtime));
    let daemon = j22_blank_literals(&without_cfg_test_items(daemon));
    let mut crate_fns = std::collections::BTreeSet::new();
    let mut aliases = j22_use_aliases(&runtime);
    for code in others
        .iter()
        .map(|(_, code)| j22_blank_literals(&without_cfg_test_items(code)))
        .chain([runtime.clone(), daemon.clone()])
    {
        crate_fns.extend(j22_fn_bodies(&code).into_keys());
        for (alias, original) in j22_use_aliases(&code) {
            aliases.entry(alias).or_insert(original);
        }
    }
    let local_fns = j22_fn_bodies(&runtime);
    let local_types = j22_local_types(&runtime);
    let mut violations = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut todo = vec!["resolve_retained_request_once".to_string()];
    while let Some(function) = todo.pop() {
        if !seen.insert(function.clone()) {
            continue;
        }
        if J22_RESOLUTION_FORBIDDEN.contains(&function.as_str()) {
            violations.push(format!("the resolution reaches the forbidden {function}"));
        }
        for body in local_fns.get(&function).into_iter().flatten() {
            for marker in J22_OS_EFFECT_MARKERS {
                if body.contains(marker) {
                    violations.push(format!("{function} uses the OS-effect marker {marker}"));
                }
            }
            for call in j22_calls(body, &local_fns, &local_types, &crate_fns, &aliases) {
                match call {
                    J22Call::Local(name) if J22_RESOLUTION_BOUNDARIES.contains(&name.as_str()) => {}
                    J22Call::Local(name) => todo.push(name),
                    J22Call::External(name)
                        if J22_RESOLUTION_FORBIDDEN.contains(&name.as_str()) =>
                    {
                        violations.push(format!("{function} calls the forbidden {name}"))
                    }
                    J22Call::External(name)
                        if !J22_RESOLUTION_REVIEWED_CALLS.contains(&name.as_str())
                            && !J22_RESOLUTION_BOUNDARIES.contains(&name.as_str()) =>
                    {
                        violations.push(format!("{function} calls the unreviewed {name}"))
                    }
                    J22Call::External(_) => {}
                }
            }
        }
    }
    // The daemon side: the retained-request block of the startup reconciliation only resolves and
    // logs; promotion stays with the existing, separately authorized attempt path.
    let reconcile = function_body(&daemon, "fn reconcile_startup_obligation(");
    let block = function_body(&reconcile, "if retained_request ");
    let daemon_fns = j22_fn_bodies(&daemon);
    let daemon_types = j22_local_types(&daemon);
    for call in j22_calls(&block, &daemon_fns, &daemon_types, &crate_fns, &aliases) {
        let (J22Call::Local(name) | J22Call::External(name)) = call;
        if ![
            "resolve_retained_request_once",
            "info_startup_request_resolved",
            "warn_retained_request_release_unconfirmed",
        ]
        .contains(&name.as_str())
        {
            violations.push(format!(
                "the daemon's retained-request block calls the unreviewed {name}"
            ));
        }
    }
    violations
}

fn j22_resolution_inputs() -> (String, String, Vec<(String, String)>) {
    let others = all_production_modules();
    let runtime = others
        .iter()
        .find(|(name, _)| name == "linux_node_runtime")
        .unwrap()
        .1
        .clone();
    let daemon = others
        .iter()
        .find(|(name, _)| name == "daemon")
        .unwrap()
        .1
        .clone();
    (runtime, daemon, others)
}

/// Insert `call` at the start of the body of `signature` and `items` at the start of `code` (the
/// production region ends with the `#[cfg(test)]` of the test module, which would swallow an item
/// appended at the end).
fn j22_inject(code: &str, signature: &str, call: &str, items: &str) -> String {
    let at = code.find(signature).unwrap();
    let open = at + code[at..].find('{').unwrap() + 1;
    format!("{items}\n{}\n{call}\n{}", &code[..open], &code[open..])
}

/// J22 (OD-J21-5 B-2): the startup resolution of a retained LeaseRequest calls only reviewed
/// functions (closed world), transitively through every function of the module it reaches, up to
/// the two audited boundaries; it reaches nothing that installs authority, promotes, acquires a
/// lease or a resource, or begins a request. The daemon block only resolves and logs.
#[test]
fn j22_retained_request_resolution_calls_only_reviewed_functions() {
    let (runtime, daemon, others) = j22_resolution_inputs();
    let violations = j22_resolution_violations(&runtime, &daemon, &others);
    assert!(violations.is_empty(), "{violations:#?}");
}

/// J22 (IA-J22-08): the guard reads the production region of a module up to its `mod tests`. That
/// is the whole production code only if nothing but test-gated items follows: the test module and
/// further items whose `cfg` requires `test` (`#[cfg(test)]`, `#[cfg(all(test, ...))]`). Assert it
/// for the guarded modules.
#[test]
fn j22_guarded_modules_have_only_test_items_after_mod_tests() {
    fn item_end(code: &str, from: usize) -> usize {
        let bytes = code.as_bytes();
        let brace = code[from..].find('{').expect("an item body");
        if let Some(semi) = code[from..].find(';')
            && semi < brace
        {
            // An item without a body (`use`, `const`, a declaration).
            return from + semi + 1;
        }
        let open = from + brace;
        let mut depth = 0usize;
        for (offset, byte) in bytes[open..].iter().enumerate() {
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return open + offset + 1;
                    }
                }
                _ => {}
            }
        }
        panic!("unbalanced item");
    }
    for module in ["linux_node_runtime", "daemon"] {
        let code = strip_comments(&fs::read_to_string(source_path(module)).unwrap());
        let at = code.find("mod tests").expect("a test module");
        let mut rest = item_end(&code, at);
        loop {
            let tail = code[rest..].trim_start();
            if tail.is_empty() {
                break;
            }
            let start = code.len() - tail.len();
            let attribute_end = tail.find(']').map(|offset| offset + 1).unwrap_or(0);
            let attribute = &tail[..attribute_end];
            assert!(
                attribute == "#[cfg(test)]" || attribute.starts_with("#[cfg(all(test,"),
                "{module}: a non-test item follows the test module: {}",
                &tail[..tail.len().min(80)]
            );
            rest = item_end(&code, start + attribute_end);
        }
    }
}

/// J22 (B-2): guard mutation test. Each bypass shape, injected in memory into the real production
/// source, is detected; an unchanged source and a reviewed call are not.
#[test]
fn j22_resolution_guard_detects_bypass_shapes() {
    let (runtime, daemon, others) = j22_resolution_inputs();
    let resolve = "pub(crate) fn resolve_retained_request_once(";
    let sneak_trait = "trait J22Sneak { fn sneak(&mut self); } \
        impl<N, S, C> J22Sneak for LinuxNodeRuntime<N, S, C> { \
        fn sneak(&mut self) { self.executor.request_vip_acquire(); } }";
    let helper = "fn j22_helper(&mut self) { self.controller.mark_resource_ownership_started(); }";
    for (shape, call, items) in [
        ("helper", "self.j22_helper();", helper),
        (
            "alias",
            "j22_go(\"x\");",
            "use crate::operator_log::warn_bootstrap_dropped as j22_go;",
        ),
        (
            "method chain",
            "self.controller.authority().restore_installed_lease_authority();",
            "",
        ),
        ("trait method", "self.sneak();", sneak_trait),
        ("trait path", "J22Sneak::sneak(self);", sneak_trait),
        (
            "wrapper",
            "self.j22_outer();",
            "fn j22_outer(&mut self) { self.j22_inner(); } \
             fn j22_inner(&mut self) { self.controller.mark_resource_ownership_started(); }",
        ),
        (
            "indirect promotion through an existing function",
            "let _ = self.promote();",
            "",
        ),
        (
            "a renewal through an existing function",
            "let _ = self.renew_lease_once(session, || Ok(()));",
            "",
        ),
        (
            "a file through a std::fs alias",
            "let _ = fs::remove_file(\"x\");",
            "use std::fs;",
        ),
        (
            "a file through an imported type",
            "let _ = File::create(\"x\");",
            "",
        ),
        (
            "a Unix socket through an imported type",
            "let _ = UnixStream::connect(\"x\");",
            "",
        ),
        (
            "a socket through an imported type",
            "let _ = TcpStream::connect(\"192.0.2.1:1\");",
            "",
        ),
        (
            "direct OS command",
            "let _ = std::process::Command::new(\"ip\").status();",
            "",
        ),
        ("VIP", "self.executor.request_vip_acquire();", ""),
        ("service", "self.executor.start_service();", ""),
        (
            "function pointer",
            "let f = Self::j22_helper; f(self);",
            helper,
        ),
        (
            "new request",
            "self.mutation_store.begin_lease_request(Term(1), 1, DurationMs(1));",
            "",
        ),
        (
            "unreviewed call",
            "crate::operator_log::warn_bootstrap_dropped(\"x\");",
            "",
        ),
    ] {
        let mutated = j22_inject(&runtime, resolve, call, items);
        assert!(
            !j22_resolution_violations(&mutated, &daemon, &others).is_empty(),
            "the {shape} bypass was not detected"
        );
    }
    let promoting_daemon = j22_inject(
        &daemon,
        "if retained_request ",
        "self.runtime.request_promotion_attempt();",
        "",
    );
    assert!(
        !j22_resolution_violations(&runtime, &promoting_daemon, &others).is_empty(),
        "a promotion from the daemon's retained-request block was not detected"
    );
    assert!(j22_resolution_violations(&runtime, &daemon, &others).is_empty());
    let reviewed = j22_inject(
        &runtime,
        resolve,
        "let _ = self.observe_trusted_zero_resource();",
        "",
    );
    assert!(
        j22_resolution_violations(&reviewed, &daemon, &others).is_empty(),
        "a reviewed call must not be reported"
    );
}

/// J23 (OD-J22-1, C-F): the generation fence is a dedicated send path. It sends exactly one
/// LeaseRelease, accepts only a LEASE_REJECT before classifying, and never writes the node store
/// (no begin, no completion, no release obligation): the fence is derived, never persisted. In the
/// resolution it follows the ZeroResource proof and precedes the exact replay, and the only store
/// write after it is the completion of the retained request itself. The fence can never match a
/// lease: term 0 and the fixed non-UUID lease id.
#[test]
fn j23_generation_fence_exchange_sends_one_reject_only_request_and_writes_nothing() {
    let witness_runtime = without_cfg_test_items(&production_source("node_witness_runtime"));
    let exchange = function_body(
        &witness_runtime,
        "pub(crate) fn exchange_generation_fence_once(",
    );
    assert_eq!(
        exchange.matches("send_lease_release(").count(),
        1,
        "exactly one send"
    );
    for forbidden in [
        "send_lease_request(",
        "send_lease_renew(",
        "self.store",
        ".complete(",
        "complete_owned_release(",
        ".begin",
        "arm_release_obligation(",
        "validate_success_before_commit(",
        "complete_outstanding_exchange(",
    ] {
        assert!(
            !exchange.contains(forbidden),
            "the generation fence exchange must not reach {forbidden}"
        );
    }
    assert_before(
        &exchange,
        "ProtocolMessage::LeaseReject(_)",
        "self.classify(",
        "only a reject is classified",
    );
    assert_before(
        &exchange,
        "if !rejected",
        "self.classify(",
        "an accepted fence fails closed before classification",
    );
    assert!(exchange.contains("payload.term != Term(0)"), "term 0 only");
    assert!(
        exchange.contains("GENERATION_FENCE_LEASE_ID"),
        "the fixed fence lease id only"
    );

    let fence_id = function_body(
        &witness_runtime,
        "pub(crate) fn generation_fence_request_id(",
    );
    assert!(fence_id.contains("Sha256::new()") && fence_id.contains("| 0x40"));
    for impure in [
        "self",
        "store",
        "rand",
        "Instant",
        "SystemTime",
        "Command",
        "fs::",
        "net::",
        "unsafe ",
    ] {
        assert!(
            !fence_id.contains(impure),
            "the fence id is a pure function of the request id and the generation ({impure})"
        );
    }

    let runtime = without_cfg_test_items(&production_source("linux_node_runtime"));
    let fence_of = function_body(&runtime, "pub(crate) fn generation_fence_of(");
    for required in [
        "Term(0)",
        "GENERATION_FENCE_LEASE_ID",
        "is_valid_mutating_request_id(",
        "generation_fence_request_id(",
        "MutationKind::LeaseRequest",
    ] {
        assert!(
            fence_of.contains(required),
            "generation_fence_of must contain {required}"
        );
    }
    assert!(
        !fence_of.contains("mutation_store") && !fence_of.contains("rand"),
        "the fence is a pure function of the durable request"
    );
    let lease_id = witness_runtime
        .split("pub(crate) const GENERATION_FENCE_LEASE_ID: &str = \"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("the fence lease id");
    assert!(
        lease_id.len() != 36 || lease_id.matches('-').count() != 4,
        "the fence lease id must never have the shape of a granted (UUID) lease id"
    );

    let resolve = function_body(&runtime, "pub(crate) fn resolve_retained_request_once(");
    assert_before(
        &resolve,
        "observe_trusted_zero_resource()",
        "exchange_generation_fence_once(",
        "ZeroResource is proven before the fence is sent",
    );
    assert_before(
        &resolve,
        "exchange_generation_fence_once(",
        "retry_outstanding_once(",
        "the fence precedes the exact replay",
    );
    assert_before(
        &resolve,
        "image.release_obligation.is_some() || image.fencing_incident.is_some()",
        "exchange_generation_fence_once(",
        "a coexisting release obligation or fencing incident is checked before the fence",
    );
    assert_eq!(
        resolve.matches(".complete(").count(),
        1,
        "the resolution completes the retained request only after a committed fence"
    );
    for helper in ["fn correlated_response(", "fn classify("] {
        let body = function_body(&witness_runtime, helper);
        assert!(
            !body.contains("self.store") && !body.contains(".complete("),
            "{helper} (used by the fence) must not write the node store"
        );
    }
    assert_eq!(
        resolve.matches("exchange_generation_fence_once(").count(),
        1,
        "one fence per resolution"
    );
    // Between the fence and the replay: only the completion of the retained request, and only
    // in the DeterministicReject arm.
    let fence_at = resolve.find("exchange_generation_fence_once(").unwrap();
    let replay_at = resolve.find("retry_outstanding_once(").unwrap();
    let between = &resolve[fence_at..replay_at];
    assert_eq!(between.matches(".complete(").count(), 1, "{between}");
    assert_before(
        between,
        "NodeWitnessMutationResult::DeterministicReject",
        ".complete(",
        "the request is completed only after a committed fence",
    );
    assert_before(
        between,
        ".complete(",
        "NodeWitnessMutationResult::RetiredStale",
        "a retired-stale fence completes nothing",
    );
    for forbidden in [
        "release_attempt_lease_once(",
        "begin_",
        "complete_owned_release(",
        "LeaseGrant",
    ] {
        assert!(
            !between.contains(forbidden),
            "the fence step must not reach {forbidden}"
        );
    }
}

/// J23 (OD-J22-2, the regression condition of C-F on the Witness): the generation fence is safe only
/// while the Witness's existing LEASE_RELEASE path keeps three properties. If a future change of the
/// Release handling breaks one of them, this guard fails before C-F can become unsafe:
///   R1  a PolicyReject to a LEASE_RELEASE is produced only by committing it (the generation is then
///       filled) or by the duplicate of such a commit; never by a reject that commits nothing;
///   R2  a release requires the current term AND the active lease id AND the holder to match, all
///       checked before the release commit (the fence carries term 0 and a non-UUID lease id);
///   R3  the Witness generates lease ids as UUIDv4 only, so the fixed fence lease id never matches.
#[test]
fn j23_witness_release_path_keeps_the_generation_fence_harmless() {
    let authority = without_cfg_test_items(&production_source("witness_authority"));
    let release = function_body(&authority, "pub fn prepare_lease_release_authority<");
    assert!(
        !release.contains("PolicyReject"),
        "R1: the release path produces a PolicyReject only through commit_release_reject"
    );
    assert_before(
        &release,
        "witness_journal::classify(",
        "commit_release_reject(",
        "R1: the reject is committed only for a NewEligible request",
    );
    let commit = function_body(&authority, "fn commit_release_reject<");
    assert!(commit.contains("WitnessMutationOutcomeCode::PolicyReject"));
    assert_before(
        &commit,
        ".commit_candidate(",
        "prepared_response(",
        "R1: the reject is durable before it is answered",
    );
    // R1 across the crate: outside the Witness authority (and the journal's reconstruction of a
    // committed reject) no production code builds a PolicyReject.
    // A match arm (`::PolicyReject =>`, the node's classification) reads one; any other use of the
    // variant path builds one.
    for (module, code) in all_production_modules() {
        if module == "witness_authority" || module == "witness_journal" {
            continue;
        }
        let code = without_cfg_test_items(&code);
        for (at, _) in code.match_indices("::PolicyReject") {
            let rest = code[at + "::PolicyReject".len()..].trim_start();
            assert!(
                rest.starts_with("=>"),
                "R1: {module} builds a PolicyReject outside the Witness authority"
            );
        }
    }
    let journal = without_cfg_test_items(&production_source("witness_journal"));
    assert_eq!(
        journal
            .matches("WitnessMutationOutcomeCode::PolicyReject")
            .count(),
        1,
        "R1: the journal only reconstructs committed rejects"
    );
    for mismatch in [
        "state.current_term != payload.term",
        "state.active_lease_id.as_ref() != Some(&payload.lease_id)",
        "state.holder_node_id.as_ref() != Some(sender_node_id)",
    ] {
        assert_before(
            &release,
            mismatch,
            "CommittedSemanticResult::LeaseReleased",
            "R2: both mismatches are checked before the release commit",
        );
    }
    let generate = function_body(&authority, "fn generate_lease_id(");
    for uuid in [
        "(bytes[6] & 0x0f) | 0x40",
        "(bytes[8] & 0x3f) | 0x80",
        "format_uuid(",
    ] {
        assert!(generate.contains(uuid), "R3: lease ids are UUIDv4 ({uuid})");
    }
    let grant = function_body(&authority, "pub fn prepare_lease_request_authority<");
    assert!(
        grant.contains("generate_lease_id()") && !grant.contains("LeaseId::new("),
        "R3: a new grant's lease id comes from generate_lease_id only"
    );
}

/// Stage 14 Design Revision 5 §33.3 `017_fencing_gate_precedes_lease` (Phase
/// 14.10), with the H/I/K order of §24.
///
/// Invariants protected: in `execute_promotion_attempt`, G precedes H; the
/// clearance anchor must equal the H view term before the LeaseRequest; the
/// grant check `anchor + 1` follows H and precedes K; the K conditions
/// (live shutdown, Running, attempt identity, lease usable, Witness slot,
/// runtime half) are one condition immediately before
/// `execute_attempt_promotion`; every post-grant abort goes through
/// `abort_after_grant`, which passes the clearance binding to the lease
/// cleanup and turns an uncertain or mismatched cleanup into
/// RecoveryBlocked. The runtime half checks every K item 6-14.
///
/// Known lexical limits: source shape only; the races are proven by
/// P10-05..P10-18.
#[test]
fn mkm_arch_017_fencing_gate_precedes_lease() {
    let daemon = production_source("daemon");
    let runtime = production_source("linux_node_runtime");
    let attempt = function_body(&daemon, "pub(crate) fn execute_promotion_attempt(");
    for (first, second) in [
        (".fencing_gate(", ".acquire_attempt_lease_once("),
        (
            // Contract K-4: the anchor is the prerequisite's (a fencing
            // clearance's or a Bootstrap clearance's), compared before H.
            ".is_some_and(|anchor| anchor != term)",
            ".acquire_attempt_lease_once(",
        ),
        (
            ".acquire_attempt_lease_once(",
            "checked_add(1) != Some(granted.0.0)",
        ),
        (
            "checked_add(1) != Some(granted.0.0)",
            ".fencing_final_recheck(",
        ),
        (".fencing_final_recheck(", ".execute_attempt_promotion("),
    ] {
        assert_before(&attempt, first, second, "G -> H -> I -> K -> L");
    }
    let compact = |body: &str| body.split_whitespace().collect::<String>();
    assert!(compact(&attempt).contains(
        "ifshutdown||self.state!=DaemonState::Running||cancelled||!self.runtime.attempt_lease_usable(bound.lease_authority())||self.runtime.shared_witness_outstanding()||self.runtime.fencing_final_recheck(&prerequisite,granted.0).is_err(){drop(bound);"
    ));
    assert_eq!(
        attempt.matches("self.abort_after_grant(").count(),
        4,
        "I, K, pre-resource shutdown, ARM rejected"
    );
    assert!(
        compact(&attempt)
            .contains("let_=self.runtime.release_attempt_lease(Some(granted),binding.as_ref());")
    );
    let abort = function_body(&daemon, "fn abort_after_grant(");
    assert!(compact(&abort).contains("self.runtime.release_attempt_lease(Some(granted),binding)"));
    assert_before(
        &abort,
        "AttemptCleanup::RecoveryBlocked(reason)",
        "self.state = DaemonState::RecoveryBlocked;",
        "an uncertain or mismatched cleanup blocks recovery",
    );
    assert!(attempt.contains("Ok(AttemptPromotionOutcome::RecoveryBlocked) => {"));
    // The Linux composition passes the attempt's clearance, the live
    // continuity facts, and the durable binding through unchanged, and maps
    // every runtime outcome exactly.
    let linux = &daemon[daemon
        .find("impl PromotionExecutionRuntime for LinuxDaemonRuntime")
        .expect("Linux promotion runtime")..];
    let linux_recheck = compact(&function_body(linux, "fn fencing_final_recheck("));
    for required in [
        "letSome(clearance)=prerequisite.clearance()else{returnErr(",
        "live_episode:live_episode.as_ref(),",
        ".fencing_final_recheck(clearance,&context,grant_term)",
        "Ok(Ok(()))=>Ok(()),",
        "Ok(Err(failure))=>Err(format!(\"{failure:?}\")),",
        "Err(error)=>Err(error.to_string()),",
    ] {
        assert!(linux_recheck.contains(required), "Linux K: {required}");
    }
    let linux_release = compact(&function_body(linux, "fn release_attempt_lease("));
    assert!(linux_release.contains("\"stage13.2attemptabort\".to_string(),binding,)"));
    for (outcome, mapped) in [
        (
            "AttemptLeaseRelease::Executed(_))",
            "Ok(AttemptCleanup::Released)",
        ),
        (
            "AttemptLeaseRelease::CleanupNotCommitted(_))",
            "Ok(AttemptCleanup::NotSent)",
        ),
        (
            "AttemptLeaseRelease::RecoveryBlocked(reason))",
            "Ok(AttemptCleanup::RecoveryBlocked(reason))",
        ),
    ] {
        assert!(
            linux_release.contains(&format!("{outcome}=>{{{mapped}}}")),
            "{outcome}"
        );
    }
    let linux_promote = compact(&function_body(linux, "fn execute_attempt_promotion("));
    assert!(linux_promote.contains(".arm_and_promote(lease.into_authority(),clearance)"));
    for mapped in [
        "Ok(FencedArmOutcome::NotCommitted(_))=>Ok(AttemptPromotionOutcome::ArmNotCommitted),",
        "Ok(FencedArmOutcome::Rejected(_))=>Ok(AttemptPromotionOutcome::ArmRejected),",
        "Ok(FencedArmOutcome::RecoveryBlocked(_))=>{Ok(AttemptPromotionOutcome::RecoveryBlocked)}",
    ] {
        assert!(linux_promote.contains(mapped), "Linux L: {mapped}");
    }
    let recheck = function_body(&runtime, "pub(crate) fn fencing_final_recheck(");
    for (item, failure) in [
        ("NodeState::Standby", "FencingRecheckFailure::LocalState"),
        (
            "self.observe_trusted_zero_resource()",
            "FencingRecheckFailure::ZeroResource",
        ),
        (
            "image.release_obligation.is_some() || image.outstanding_mutation.is_some()",
            "FencingRecheckFailure::ObligationOrMutation",
        ),
        (
            "&incident.incident_ref() == clearance.incident()",
            "FencingRecheckFailure::Incident",
        ),
        (
            "FencingState::Confirmed(_)",
            "FencingRecheckFailure::NotConfirmed",
        ),
        (
            "&incident.target_node_id != context.configured_peer",
            "FencingRecheckFailure::Target",
        ),
        (
            "&incident.observer_session_id != context.current_session",
            "FencingRecheckFailure::ObserverSession",
        ),
        (
            "episode.generation() != clearance.observer_loss_generation()",
            "FencingRecheckFailure::Episode",
        ),
        (
            "clearance.anchor_term().0.checked_add(1) != Some(grant_term.0)",
            "FencingRecheckFailure::WitnessTerm",
        ),
    ] {
        assert_before(&recheck, item, failure, "K recheck item");
    }
}

/// Split `body` at its top-level commas (depth over `(`, `{`, `[`, `<`).
fn split_top_level(body: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for ch in body.chars() {
        match ch {
            '(' | '{' | '[' | '<' => depth += 1,
            ')' | '}' | ']' | '>' => depth -= 1,
            _ => {}
        }
        if ch == ',' && depth == 0 {
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    parts.push(current);
    parts
}

/// The whitespace-free, attribute-free, `pub`-free entries of an enum or
/// struct body (variants, or `name:Type` fields).
fn shape_entries(source: &str, signature: &str) -> Vec<String> {
    let body = function_body(source, signature);
    let inner = body
        .trim()
        .strip_prefix('{')
        .and_then(|rest| rest.strip_suffix('}'))
        .expect("braced body");
    split_top_level(inner)
        .into_iter()
        .map(|entry| {
            let mut text = entry;
            while let Some(start) = text.find("#[") {
                let end = text[start..].find(']').expect("attribute end") + start;
                text.replace_range(start..=end, "");
            }
            text.split_whitespace()
                .collect::<String>()
                .trim_start_matches("pub")
                .to_string()
        })
        .filter(|entry| !entry.is_empty())
        .collect()
}

/// The leading `#[..]` attributes of `text` (each compacted, whitespace-free)
/// and the text after them.
fn split_leading_attributes(text: &str) -> (Vec<String>, String) {
    let mut attributes = Vec::new();
    let mut rest = text.trim_start();
    while rest.starts_with("#[") {
        let mut depth = 0i32;
        let mut end = None;
        for (index, byte) in rest.bytes().enumerate() {
            match byte {
                b'[' => depth += 1,
                b']' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(index + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        let end = end.expect("attribute end");
        attributes.push(rest[..end].split_whitespace().collect::<String>());
        rest = rest[end..].trim_start();
    }
    (attributes, rest.to_string())
}

/// The wire-shape controls among `attributes` of the entry named `ident`:
/// every `serde(..)` setting (and any `cfg_attr` that mentions serde), except
/// a `rename` to the entry's own identifier, which changes nothing on the
/// wire. `derive(..)`, `cfg`, `allow`, and the like are not controls.
fn serde_controls(attributes: &[String], ident: &str) -> Vec<String> {
    let mut controls = Vec::new();
    for attribute in attributes {
        if let Some(inner) = attribute
            .strip_prefix("#[serde(")
            .and_then(|rest| rest.strip_suffix(")]"))
        {
            for setting in split_top_level(inner) {
                if setting.is_empty() || setting == format!("rename=\"{ident}\"") {
                    continue;
                }
                controls.push(format!("{ident}: {setting}"));
            }
        } else if attribute.starts_with("#[cfg_attr(") && attribute.contains("serde") {
            controls.push(format!("{ident}: {attribute}"));
        }
    }
    controls
}

/// Every wire-shape serde control on the item introduced by `signature`
/// (`pub struct X` / `pub enum X`): on the item itself, on each field, and on
/// each variant. A field or variant `rename` to its own name is ignored.
fn wire_serde_controls(source: &str, signature: &str, name: &str) -> Vec<String> {
    let at = source
        .find(signature)
        .unwrap_or_else(|| panic!("item not found: {signature}"));
    // The attributes between the previous item's end and this item.
    let previous_end = source[..at].rfind(['}', ';']).map_or(0, |index| index + 1);
    let (container, leftover) = split_leading_attributes(&source[previous_end..at]);
    assert!(
        leftover.trim().is_empty(),
        "unexpected text before {signature}: {leftover:?}"
    );
    let mut controls = serde_controls(&container, name);
    let after = source[at + signature.len()..].trim_start();
    let (open, close) = match after.chars().next() {
        Some('{') => ('{', '}'),
        Some('(') => ('(', ')'),
        other => panic!("unexpected item start after {signature}: {other:?}"),
    };
    let mut depth = 0i32;
    let mut body_end = None;
    for (index, ch) in after.char_indices() {
        if ch == open {
            depth += 1;
        } else if ch == close {
            depth -= 1;
            if depth == 0 {
                body_end = Some(index);
                break;
            }
        }
    }
    let body = &after[1..body_end.expect("balanced item body")];
    for entry in split_top_level(body) {
        let (attributes, rest) = split_leading_attributes(&entry);
        let rest = rest.trim_start().trim_start_matches("pub").trim_start();
        let ident: String = rest
            .chars()
            .take_while(|ch| ch.is_alphanumeric() || *ch == '_')
            .collect();
        let ident = if ident.is_empty() || open == '(' {
            name.to_string()
        } else {
            ident
        };
        controls.extend(serde_controls(&attributes, &ident));
    }
    controls
}

/// `source` without its `#[cfg(test)]` items (the attribute and the balanced
/// item or block that follows it).
fn strip_cfg_test_items(source: &str) -> String {
    let mut output = String::new();
    let mut rest = source;
    while let Some(start) = rest.find("#[cfg(test)]") {
        output.push_str(&rest[..start]);
        let after = &rest[start + "#[cfg(test)]".len()..];
        // A trailing attribute whose item was cut off (the test module).
        let Some(open) = after.find('{') else {
            return output;
        };
        let mut depth = 0usize;
        let mut end = None;
        for (index, byte) in after.as_bytes()[open..].iter().enumerate() {
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(open + index + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        rest = &after[end.expect("balanced cfg(test) item")..];
    }
    output.push_str(rest);
    output
}

/// Stage 14 Design Revision 5 §33.3 `017_no_wire_change` (Phase 14.11
/// strengthened, §41 step 10). Rev5 requires `PROTOCOL_VERSION = 1` and no new
/// `ProtocolMessage` variant or payload field versus the baseline list. The
/// baseline below is the Stage 10 wire shape (`protocol.rs` has not changed
/// since); Stage 14 adds no persistent or wire element to it.
///
/// Invariants protected: the protocol version, every `MessageType` and
/// `ProtocolMessage` variant with its payload type, and every field of
/// `CommonFields` and of every payload struct, exactly.
///
/// L3 (Phase 14.11 remediation): serde attributes on any wire type, the
/// envelope types, and the nested wire enums are checked too (they change the
/// bytes without changing the field list), as are hand-written serde impls.
///
/// Known lexical limits: source shape only; the direct semantic pin is the
/// byte-exact golden vector test in `protocol`
/// (`wire_shape_is_byte_identical_to_the_frozen_baseline` and
/// `wire_envelope_composition_is_byte_identical_to_the_frozen_baseline`).
#[test]
fn mkm_arch_017_no_wire_change() {
    let protocol = production_source("protocol");
    assert!(protocol.contains("pub const PROTOCOL_VERSION: u32 = 1;"));
    const MESSAGE_TYPES: &[&str] = &[
        "Hello",
        "HelloAck",
        "Heartbeat",
        "HeartbeatAck",
        "StateAnnounce",
        "StateAnnounceAck",
        "PromotionIntent",
        "PromotionAck",
        "PromotionBlock",
        "PromotionUnknown",
        "PromotionCommitted",
        "DemotionIntent",
        "DemotionAck",
        "DemotionCommitted",
        "GetTerm",
        "TermStatus",
        "LeaseRequest",
        "LeaseGrant",
        "LeaseRenew",
        "LeaseRenewed",
        "LeaseRelease",
        "LeaseReleased",
        "LeaseReject",
    ];
    const MESSAGES: &[&str] = &[
        "Hello(HelloPayload)",
        "HelloAck",
        "Heartbeat(NodeStatusPayload)",
        "HeartbeatAck",
        "StateAnnounce(StateAnnouncePayload)",
        "StateAnnounceAck",
        "PromotionIntent(PromotionIntentPayload)",
        "PromotionAck",
        "PromotionBlock",
        "PromotionUnknown",
        "PromotionCommitted(ResourceStatusPayload)",
        "DemotionAck",
        "DemotionIntent(DemotionIntentPayload)",
        "DemotionCommitted(DemotionCommittedPayload)",
        "GetTerm",
        "TermStatus(TermStatusPayload)",
        "LeaseRequest(LeaseRequestPayload)",
        "LeaseGrant(LeaseGrantPayload)",
        "LeaseRenew(LeaseRenewPayload)",
        "LeaseRenewed(LeaseGrantPayload)",
        "LeaseRelease(LeaseReleasePayload)",
        "LeaseReleased(LeaseReleasedPayload)",
        "LeaseReject(LeaseRejectPayload)",
    ];
    assert_eq!(
        shape_entries(&protocol, "pub enum MessageType"),
        MESSAGE_TYPES,
        "MessageType variants changed"
    );
    assert_eq!(
        shape_entries(&protocol, "pub enum ProtocolMessage"),
        MESSAGES,
        "ProtocolMessage variants changed"
    );
    const STRUCTS: &[(&str, &[&str])] = &[
        (
            "CommonFields",
            &[
                "protocol_version:u32",
                "cluster_id:ClusterId",
                "sender_node_id:NodeId",
                "receiver_node_id:NodeId",
                "session_id:SessionId",
                "sequence:Sequence",
                "term:Term",
                "lease_id:Option<LeaseId>",
                "request_id:Option<RequestId>",
                "operation_id:Option<OperationId>",
            ],
        ),
        ("HelloPayload", &["priority:i32"]),
        (
            "NodeStatusPayload",
            &[
                "node_state:NodeState",
                "operation_phase:Option<OperationPhase>",
                "role:Role",
                "service_state:String",
                "health_state:String",
                "vip_state:String",
            ],
        ),
        (
            "StateAnnouncePayload",
            &["status:NodeStatusPayload", "reason:String"],
        ),
        ("PromotionIntentPayload", &["priority:i32", "reason:String"]),
        (
            "ResourceStatusPayload",
            &["service_state:String", "vip_state:String"],
        ),
        (
            "DemotionIntentPayload",
            &["phase:OperationPhase", "reason:String"],
        ),
        (
            "DemotionCommittedPayload",
            &["service_stopped:bool", "vip_released:bool"],
        ),
        (
            "TermStatusPayload",
            &[
                "current_term:Term",
                "current_holder:Option<NodeId>",
                "current_lease_id:Option<LeaseId>",
                "lease_remaining_ms:Option<DurationMs>",
            ],
        ),
        (
            "LeaseRequestPayload",
            &[
                "mutation_generation:u64",
                "observed_term:Term",
                "priority:i32",
                "requested_ttl:DurationMs",
            ],
        ),
        (
            "LeaseGrantPayload",
            &[
                "term:Term",
                "lease_id:LeaseId",
                "holder_node_id:NodeId",
                "lease_ttl_ms:DurationMs",
                "renew_after_ms:DurationMs",
                "lease_remaining_ms:DurationMs",
            ],
        ),
        (
            "LeaseRenewPayload",
            &["mutation_generation:u64", "term:Term", "lease_id:LeaseId"],
        ),
        (
            "LeaseReleasePayload",
            &[
                "mutation_generation:u64",
                "term:Term",
                "lease_id:LeaseId",
                "reason:String",
            ],
        ),
        (
            "LeaseReleasedPayload",
            &["term:Term", "lease_id:LeaseId", "result:String"],
        ),
        (
            "LeaseRejectPayload",
            &["code:WitnessMutationOutcomeCode", "reason:String"],
        ),
    ];
    for (name, fields) in STRUCTS {
        assert_eq!(
            shape_entries(&protocol, &format!("pub struct {name}")),
            *fields,
            "{name} fields changed"
        );
    }

    // The envelope types around the payloads: nothing may be added to, removed
    // from, or re-typed in the signed/unsigned envelope.
    const ENVELOPE: &[(&str, &[&str])] = &[
        (
            "UnsignedEnvelope",
            &["common:CommonFields", "message:ProtocolMessage"],
        ),
        ("Authentication", &["mac:[u8;32]"]),
        (
            "WireMessage",
            &["unsigned:UnsignedEnvelope", "authentication:Authentication"],
        ),
    ];
    for (name, fields) in ENVELOPE {
        assert_eq!(
            shape_entries(&protocol, &format!("pub struct {name}")),
            *fields,
            "{name} fields changed"
        );
    }
    // The newtype wire scalars and the two enums the payloads reuse.
    for declaration in [
        "pub struct ClusterId(String);",
        "pub struct NodeId(String);",
        "pub struct SessionId(String);",
        "pub struct LeaseId(String);",
        "pub struct RequestId(String);",
        "pub struct OperationId(String);",
        "pub struct Term(pub u64);",
        "pub struct Sequence(pub u64);",
        "pub struct DurationMs(pub u64);",
    ] {
        assert!(protocol.contains(declaration), "{declaration} changed");
    }
    assert_eq!(
        shape_entries(&protocol, "pub enum Role"),
        ["Active", "Standby"]
    );
    assert_eq!(
        shape_entries(&protocol, "pub enum WitnessMutationOutcomeCode"),
        [
            "PolicyReject",
            "RetiredStale",
            "Conflict",
            "GenerationGap",
            "TemporarilyUnavailable"
        ]
    );

    // L3: serde attributes are wire-shape controls that `shape_entries`
    // deliberately does not see, so they are checked here on every wire type.
    // The frozen baseline has none: a `rename`, `alias`, `skip*`, `default`,
    // `with`, `flatten`, `tag`, `content`, `untagged`, `rename_all`,
    // `deny_unknown_fields`, or a `cfg_attr` around any of them changes (or
    // can change) the bytes. A `rename` to an entry's own name is a no-op and
    // is ignored. `MessageType` is exempt only because no wire type carries it
    // (asserted below), so a serde setting on it cannot reach the wire; the
    // byte-level pin is the `protocol` golden vector test.
    let machine = production_source("state_machine");
    let mut controls: Vec<String> = Vec::new();
    for (name, _) in STRUCTS.iter().chain(ENVELOPE) {
        controls.extend(wire_serde_controls(
            &protocol,
            &format!("pub struct {name}"),
            name,
        ));
    }
    for name in [
        "ClusterId",
        "NodeId",
        "SessionId",
        "LeaseId",
        "RequestId",
        "OperationId",
        "Term",
        "Sequence",
        "DurationMs",
    ] {
        controls.extend(wire_serde_controls(
            &protocol,
            &format!("pub struct {name}"),
            name,
        ));
    }
    for name in ["ProtocolMessage", "Role", "WitnessMutationOutcomeCode"] {
        controls.extend(wire_serde_controls(
            &protocol,
            &format!("pub enum {name}"),
            name,
        ));
    }
    for name in [
        "NodeState",
        "PromotionPhase",
        "DemotionPhase",
        "OperationPhase",
    ] {
        controls.extend(wire_serde_controls(
            &machine,
            &format!("pub enum {name}"),
            name,
        ));
    }
    assert!(
        controls.is_empty(),
        "serde wire-shape controls on wire types (the frozen baseline has none): {controls:#?}"
    );
    let wire_type_text: String = STRUCTS
        .iter()
        .chain(ENVELOPE)
        .flat_map(|(_, fields)| fields.iter().copied())
        .chain(MESSAGES.iter().copied())
        .collect();
    assert!(
        !wire_type_text.contains("MessageType"),
        "MessageType reached a wire type; its serde settings would be wire-visible"
    );
    // A hand-written `Serialize`/`Deserialize` impl changes the wire without
    // any attribute.
    for (module, source) in [("protocol", &protocol), ("state_machine", &machine)] {
        for needle in ["Serialize for", "Deserialize<'de> for", "Deserialize for"] {
            assert!(
                !source.contains(needle),
                "{module} has a hand-written serde impl: {needle}"
            );
        }
    }
}

/// Phase 14.11 remediation M1 / F2 (Rev5 §25.1): the Daemon's post-grant abort
/// treats a cleanup that returned `Err` exactly as an uncertain one, i.e. the
/// daemon becomes `RecoveryBlocked`; there is no arm that swallows it.
///
/// Invariants protected: `abort_after_grant` matches the cleanup result
/// exhaustively (no `_`/`let _ =` swallowing), and both the `Err` arm and the
/// `RecoveryBlocked` arm set `DaemonState::RecoveryBlocked`.
///
/// Known lexical limits: source shape only; the behavior is proven by
/// `stage14_11_m1_cleanup_result_decides_the_daemon_state_for_every_abort`.
#[test]
fn mkm_arch_017_abort_cleanup_err_fails_closed() {
    let daemon = production_source("daemon");
    let abort = function_body(&daemon, "fn abort_after_grant(");
    assert!(
        abort.contains("match self.runtime.release_attempt_lease(Some(granted), binding)"),
        "the cleanup result must be matched, with the exact binding"
    );
    assert!(!abort.contains("let _ ="), "a cleanup result is swallowed");
    for arm in [
        "Ok(AttemptCleanup::RecoveryBlocked(reason)) => {",
        "Err(error) => {",
    ] {
        let start = abort
            .find(arm)
            .unwrap_or_else(|| panic!("abort_after_grant lacks the arm {arm}"));
        let arm_body = &abort[start..];
        let end = arm_body.find("}\n").unwrap();
        assert!(
            arm_body[..end].contains("self.state = DaemonState::RecoveryBlocked;"),
            "arm {arm} does not fail closed"
        );
    }
    assert!(
        abort.contains("Ok(AttemptCleanup::Released | AttemptCleanup::NotSent) => {}"),
        "the exhaustive arms for the two non-blocking outcomes"
    );
}

/// Phase 14.11 remediation M2 / G6 (Rev5 §34.19), second remediation: `status`
/// prints no PSK location. No `security.*` line exists, no code path in
/// `status.rs` reads the secret-bearing field or even names it, and the
/// presentation rule that neutralizes a validation message naming it lives
/// with the configuration type, which owns the field name. A configuration
/// parse failure is reported by the parser's bare message (its `Display`
/// quotes the offending line).
///
/// Known lexical limits: source shape only; the behavior is proven by
/// `stage14_11_g6_psk_path_is_absent_from_the_whole_report_in_every_state`,
/// `stage14_11_g6_config_load_failures_never_echo_the_psk_path`, and
/// `stage14_11_g6_neutral_reason_keeps_the_required_facts`.
#[test]
fn mkm_arch_017_status_names_no_psk_location() {
    let status = strip_cfg_test_items(&production_source("status"));
    for forbidden in ["psk", "security."] {
        assert!(
            !status.contains(forbidden),
            "status.rs production code mentions `{forbidden}`"
        );
    }
    // The report only asks the configuration type for an operator summary; it
    // does not render a `ConfigError` itself.
    let failure = function_body(&status, "fn config_load_failure(");
    assert!(failure.contains("operator_summary()"));
    assert!(!failure.contains("to_string()"));
    // The presentation rule itself: bare parse message (never the quoted
    // line), and a field-naming validation message replaced by the
    // location-neutral wording.
    let summary = function_body(
        &strip_cfg_test_items(&production_source("config")),
        "pub(crate) fn operator_summary(",
    );
    assert!(summary.contains("parse.message()"));
    assert!(!summary.contains("parse.to_string()") && !summary.contains("{parse}"));
    assert!(summary.contains("SECRET_LOCATION_NEUTRAL"));
    assert!(summary.contains("names_secret_field(message)"));
}

/// Stage 14 Design Revision 5 §33.3 `017_diagnostics_not_evidence` (Phase
/// 14.11; §28, §28.1). The `ListenerInterference` counters, the operator log
/// lines, and the status presentation are diagnostics: they are never
/// evidence, authorization, a clearance, a state-transition input, a Witness
/// input, or a fencing-result input.
///
/// Invariants protected:
/// - no detector, fencing, Node-store, lease-authority, Witness, policy,
///   evidence, or attestation module names a diagnostic identifier or the
///   operator log; `status` reads no counter and never logs;
/// - every operator-log emitter returns `()` and there is no non-test
///   shared state in the module, so nothing can flow back to a caller;
/// - inside the peer runtime the counters are named by exactly the
///   accounting functions and never by an observation, detector, window,
///   snapshot, or frame function;
/// - in the Daemon, the diagnostic values are read only by the logging
///   helpers (`warn_evaluation_blocked`, `warn_k_blocked`), never by the
///   attempt driver, and those helpers return nothing;
/// - every operator-log call in production is a statement (never an operand,
///   binding, condition, or return value).
///
/// Known lexical limits: source shape only. The behavior is proven by
/// `stage14_11_diagnostics_have_no_state_effect` (the detector, window, and
/// connection state are identical with the counters wiped after every tick),
/// the §34.18 tests, and the MF-45 mutants.
#[test]
fn mkm_arch_017_diagnostics_not_evidence() {
    const DIAGNOSTIC_IDENTIFIERS: &[&str] = &[
        "ListenerInterferenceDiagnostics",
        "InterferenceWarn",
        "interference",
        "accept_voided_window",
        "last_recheck_failure",
        "operator_log",
    ];
    // 1. Evidence, authority, and policy modules know nothing of diagnostics.
    for module in [
        "failure_assessment",
        "fencing",
        "fencing_backend",
        "node_mutation",
        "node_lease_authority",
        "node_witness_runtime",
        "witness_runtime",
        "witness_authority",
        "witness_evidence_adapter",
        "witness_state",
        "witness_journal",
        "witness_scheduler",
        "promotion_authorization",
        "failover_policy",
        "evidence_fusion",
        "peer_observer",
        "attestation",
        "recover",
        "status",
        "promotion_attempt",
        "state_machine",
        "resource_workflow",
        "resource_executor",
    ] {
        let path = source_path(module);
        if !path.exists() {
            continue;
        }
        let code = production_source(module);
        for identifier in DIAGNOSTIC_IDENTIFIERS {
            assert!(
                !code.contains(identifier),
                "{module} names the diagnostic identifier {identifier}"
            );
        }
    }
    // 2. The log emitters return nothing and hold no shared production state
    //    (the only shared state is the `#[cfg(test)]` capture buffer).
    let log = strip_cfg_test_items(&production_source("operator_log"));
    //    The one value-returning function is the pure bounded-reason helper
    //    (`&str` in, `String` out, no state): it is the canonical L2 bound
    //    the emitters apply themselves, and it reads nothing but its input.
    let mut emitters = 0;
    for line in log.lines() {
        if line.trim_start().starts_with("pub(crate) fn ") {
            if line.contains("fn bounded_reason(reason: &str) -> String {") {
                continue;
            }
            emitters += 1;
            assert!(
                !line.contains("->"),
                "operator_log emitter returns a value: {line}"
            );
        }
    }
    // v0.7 G-2 added four: `route_handoff_state`, `warn_route_handoff`,
    // `info_promotion_internal_only`, `info_route_step_measured` (no return value, bounded text).
    assert_eq!(emitters, 34, "the documented emitters");
    // L2: every emitter that takes free text applies the one bound itself, so
    // a caller cannot bypass it by handing over a raw error string.
    for (emitter, bounded) in [
        ("fn info_fencing_incident_retired", "bounded_reason(reason)"),
        ("fn info_fencing_incident_consumed", "bounded_reason(how)"),
        ("fn warn_attempt_blocked", "bounded_reason(reason)"),
        ("fn warn_attestation_rejected", "bounded_reason(reason)"),
        ("fn error_abort_cleanup", "bounded_reason(reason)"),
        (
            "fn warn_fencing_step_not_committed",
            "bounded_reason(reason)",
        ),
        ("fn warn_shutdown_step_rejected", "bounded_reason(reason)"),
        (
            "fn warn_fencing_gate_failed_closed",
            "bounded_reason(reason)",
        ),
        ("fn warn_bootstrap_dropped", "bounded_reason(reason)"),
        ("fn info_sor_resolved", "bounded_reason(how)"),
        (
            "fn info_release_settled_not_releasable",
            "bounded_reason(how)",
        ),
        ("fn info_startup_renew_resolved", "bounded_reason(how)"),
        ("fn info_startup_request_resolved", "bounded_reason(how)"),
        (
            "fn warn_retained_request_release_unconfirmed",
            "bounded_reason(how)",
        ),
        ("fn error_recovery_blocked", "bounded_reason(cause)"),
        ("fn info_auto_failover_started", "bounded_reason(origin)"),
        ("fn warn_auto_failover_stopped", "bounded_reason(reason)"),
        ("fn error_witness_session_lost", "bounded_reason(reason)"),
        ("fn warn_startup", "bounded_reason(message)"),
        ("fn warn_demoting", "bounded_reason(reason)"),
        ("fn route_handoff_state", "bounded_reason(reason)"),
        ("fn warn_route_handoff", "bounded_reason(reason)"),
        ("fn info_route_step_measured", "bounded_reason(line)"),
    ] {
        let start = log.find(emitter).unwrap_or_else(|| panic!("no {emitter}"));
        let signature = &log[start..start + log[start..].find('{').expect("body")];
        assert!(
            function_body(&log, emitter).contains(bounded),
            "{emitter} does not apply the canonical bound"
        );
        // The free text is taken by reference, so an emitter cannot even own
        // an unbounded copy of the caller's string.
        assert!(
            signature.contains("&str"),
            "{emitter} does not take its free text by reference: {signature}"
        );
    }
    // 2b. L2, second remediation: no production module outside `operator_log`
    //     formats a `mikagami: WARN ` / `mikagami: ERROR ` line itself. Those
    //     levels belong to the one canonical bounded emitter, so an
    //     operator-facing free-text WARN/ERROR reason cannot bypass
    //     `bounded_reason` by being interpolated at a call site. This is a
    //     narrow structural rule, not a blanket grep: it fires only on a
    //     WARN/ERROR-level line built outside the log module, so ordinary
    //     logging, diagnostics, and non-WARN/ERROR lines are unaffected.
    for (module, code) in production_modules() {
        if module == "operator_log" {
            continue;
        }
        for (index, _) in code.match_indices("eprintln!") {
            let call = code[index + "eprintln!".len()..]
                .split(')')
                .next()
                .unwrap_or_default();
            for level in ["mikagami: WARN ", "mikagami: ERROR "] {
                assert!(
                    !call.contains(level),
                    "{module}: an operator WARN/ERROR line is formatted outside \
                     operator_log, so its free text bypasses bounded_reason: {call}"
                );
            }
        }
        // The daemon's operator lines carry no raw error interpolation at all.
        for site in [
            "bounded shutdown step rejected",
            "fencing gate failed closed",
            "fencing step not committed",
        ] {
            assert!(
                !code.contains(&format!("WARN {site}: {{")),
                "{module}: `{site}` still interpolates a raw error"
            );
        }
    }
    // The log module owns no process, thread, socket, or file: it is a writer
    // of one line to stderr and nothing else.
    for forbidden in [
        "Command",
        "spawn(",
        "thread::",
        "TcpStream",
        "TcpListener",
        "fs::",
        "File::",
        "signal",
        "libc::",
    ] {
        assert!(!log.contains(forbidden), "operator_log owns {forbidden}");
    }
    for forbidden in [
        "thread_local!",
        "static mut",
        "\nstatic ",
        "Mutex",
        "Atomic",
        "OnceLock",
        "LazyLock",
        "RefCell",
    ] {
        assert!(
            !log.contains(forbidden),
            "operator_log holds shared production state: {forbidden:?}"
        );
    }
    // 3. Peer runtime: counters are named only by the accounting functions.
    let peer = production_source("daemon_peer_runtime");
    assert_eq!(peer.matches("self.interference.").count(), 3);
    assert_eq!(peer.matches("accept_voided_window").count(), 5);
    for decision in [
        "fn advance_failure_assessment(",
        "fn record_accept_sample(",
        "fn observe_initiated_contact_failure(",
        "fn observe_session_established_at(",
        "fn observe_established_heartbeat(",
        "fn void_listen_window(",
        "fn mark_identity_uncertainty(",
        "fn process_frame(",
        "fn apply_session_events(",
        "fn snapshot(",
        "fn loss_evidence(",
        "fn failure_assessment(",
        "fn clear_connection_state(",
        "fn expire_handshake_if_due(",
        "fn drain_disconnect(",
    ] {
        let body = function_body(&peer, decision);
        for identifier in ["interference", "accept_voided_window", "operator_log"] {
            assert!(
                !body.contains(identifier),
                "{decision} names the diagnostic {identifier}"
            );
        }
    }
    let arrival = function_body(&peer, "fn note_unauthenticated_arrival(");
    assert!(arrival.contains("self.interference.record("));
    let failure = function_body(&peer, "fn observe_transport_failure(");
    assert_before(
        &failure,
        "self.note_unauthenticated_arrival(now);",
        "self.failure_assessment",
        "the counters are written before, and independently of, the detector",
    );
    // 4. Daemon: the values reach the logging helpers only.
    let daemon = production_source("daemon");
    let attempt = function_body(&daemon, "pub(crate) fn execute_promotion_attempt(");
    for identifier in [
        "listener_interference_recent",
        "last_recheck_failure",
        "interference",
    ] {
        assert!(
            !attempt.contains(identifier),
            "the attempt driver names the diagnostic {identifier}"
        );
    }
    // The trait default, the Linux glue, its one call of the peer accessor,
    // and the one logging helper's read.
    assert_eq!(daemon.matches("listener_interference_recent").count(), 4);
    // The field, its two initializers, the trait default, the Linux accessor
    // (name and body), the one assignment in `fencing_final_recheck`, and the
    // one read in `warn_k_blocked`.
    // Plus (Contract K-4) the Bootstrap branch's own assignment.
    assert_eq!(daemon.matches("last_recheck_failure").count(), 9);
    let recheck_glue = function_body(
        &daemon,
        "fn fencing_final_recheck(
        &mut self,
        prerequisite: &FencingPrerequisite,
        grant_term: crate::protocol::Term,
    ) -> Result<(), String> {
        if let FencingPrerequisite::Bootstrap(clearance) = prerequisite {
            return self.bootstrap_recheck(clearance, grant_term);
        }
        let Some(clearance)",
    );
    assert_eq!(recheck_glue.matches("last_recheck_failure").count(), 1);
    assert!(function_body(&daemon, "fn warn_k_blocked(").contains(".last_recheck_failure()"));
    for helper in ["fn warn_evaluation_blocked(", "fn warn_k_blocked("] {
        let start = daemon.find(helper).expect("helper");
        let signature_end = daemon[start..].find('{').expect("body") + start;
        assert!(
            !daemon[start..signature_end].contains("->"),
            "{helper} returns a value"
        );
    }
    assert!(
        function_body(&daemon, "fn warn_evaluation_blocked(")
            .contains(".listener_interference_recent(")
    );
    // 5. Every production operator-log call is a statement.
    for (module, code) in production_modules() {
        if module == "operator_log" {
            continue;
        }
        for (index, _) in code.match_indices("operator_log::") {
            // Only emitter calls are statements; `BlockedIncident` is the
            // input value of `warn_attempt_blocked`.
            let call = &code[index + "operator_log::".len()..];
            if !(call.starts_with("info_") || call.starts_with("warn_")) {
                continue;
            }
            let before = code[..index]
                .trim_end()
                .trim_end_matches("crate::")
                .trim_end();
            let last = before.chars().last().unwrap_or(';');
            assert!(
                matches!(last, ';' | '{' | '}' | '>'),
                "{module}: an operator_log call is used as a value (preceded by {last:?})"
            );
        }
        if module == "linux_node_runtime" || module == "daemon" {
            assert!(
                !code.contains("= crate::operator_log::")
                    && !code.contains("return crate::operator_log::"),
                "{module}: operator_log result bound or returned"
            );
        }
    }
}

/// Stage 14 Phase 14.11 L1-MEM: the quantified `ListenerInterference` memory
/// bound rests on a scheduling invariant. This pins the invariant's source
/// shape (behaviour is proven by the `stage14_11_l1_*` tests):
///
/// 1. the Active renew floor is 100 ms and is applied to the renew term only —
///    `expiry_in` is never floored and the outstanding-`LeaseRenew` branch
///    returns before the floor;
/// 2. the production loop's `ordinary` cadence is at least one second;
/// 3. the foreground observation loop is the only production tick source (so
///    the tick-spacing premise cannot change silently);
/// 4. the peer-side test copy of the floor equals the production constant;
/// 5. the HA scheduling code names no diagnostic identifier.
#[test]
fn mkm_arch_017_active_wait_floor_bounds_the_diagnostic_window() {
    let runtime = production_source("linux_node_runtime");
    // 1. floor constant, shape of the helper, and its single caller.
    assert!(
        runtime.contains(
            "pub(crate) const ACTIVE_RENEW_MIN_WAIT: Duration = Duration::from_millis(100);"
        ),
        "the Active renew floor must be exactly 100 ms"
    );
    assert_eq!(
        runtime.matches("ACTIVE_RENEW_MIN_WAIT").count(),
        2,
        "the floor constant is defined once and applied once"
    );
    let helper = function_body(&runtime, "pub(crate) fn active_wait_delay(");
    assert!(
        helper.contains("renew_in.max(ACTIVE_RENEW_MIN_WAIT)"),
        "the floor applies to the renew term"
    );
    assert!(
        !helper.contains("expiry_in.max") && !helper.contains("expiry_in.saturating"),
        "expiry_in is never floored"
    );
    assert_before(
        &helper,
        "if renew_outstanding {",
        "ACTIVE_RENEW_MIN_WAIT",
        "the outstanding-LeaseRenew branch must return before the floor",
    );
    assert!(
        helper.contains("return ordinary.min(expiry_in);"),
        "the outstanding-LeaseRenew branch is min(ordinary, expiry_in)"
    );
    assert!(
        helper.contains(".min(expiry_in)") && helper.contains("ordinary\n        .min("),
        "the Active wait is capped by ordinary and by expiry_in"
    );
    let schedule = function_body(&runtime, "pub(crate) fn active_schedule_delay");
    assert!(
        schedule.contains("active_wait_delay(")
            && schedule.contains("delays.renew_in")
            && schedule.contains("delays.expiry_in")
            && !schedule.contains(".min(delays"),
        "active_schedule_delay composes the wait only through active_wait_delay"
    );
    // 2. ordinary >= 1 s.
    let run = production_source("daemon_run");
    assert!(
        run.contains("Duration::from_secs(config.heartbeat.interval_sec.max(1))"),
        "the production ordinary cadence is at least one second"
    );
    // 3. single production tick source.
    let mut tick_at_calls = Vec::new();
    let mut tick_at_with_calls = Vec::new();
    for (module, code) in production_modules() {
        assert!(
            !code.contains(".tick()"),
            "{module}: a Daemon/peer `tick()` convenience call would bypass the loop"
        );
        if module == "witness_evidence_adapter" {
            continue; // the Witness adapter's own `tick_at`, not the peer runtime
        }
        let count = code.matches(".tick_at(").count();
        if count > 0 {
            tick_at_calls.push((module.clone(), count));
        }
        let with = code.matches(".tick_at_with(").count();
        if with > 0 {
            tick_at_with_calls.push((module, with));
        }
    }
    tick_at_calls.sort();
    tick_at_with_calls.sort();
    assert_eq!(
        tick_at_calls,
        vec![
            ("daemon".to_string(), 1),              // Daemon::tick wrapper
            ("daemon_peer_runtime".to_string(), 1), // the `tick()` convenience (no caller)
            ("daemon_run".to_string(), 1),          // the observation loop
        ],
        "a new tick_at caller invalidates the L1-MEM tick-rate bound; re-derive it"
    );
    // Contract K-3: the one peer advance is `tick_at_with` (it carries the
    // probe responder's verdict closure); the peer runtime's own `tick_at`
    // wrapper is its only other caller.
    assert_eq!(
        tick_at_with_calls,
        vec![
            ("daemon".to_string(), 1),
            ("daemon_peer_runtime".to_string(), 1),
        ],
        "a new peer-advance caller invalidates the L1-MEM tick-rate bound; re-derive it"
    );
    assert_eq!(
        production_source("daemon")
            .matches("drive_peer_tick_at(")
            .count(),
        3,
        "drive_peer_tick_at: one definition and two calls inside Daemon::tick_at"
    );
    assert_eq!(
        production_source("daemon_run")
            .matches(".next_wait_delay(")
            .count(),
        1,
        "the loop takes exactly one wait per iteration"
    );
    // 4. the test-side copy of the floor equals the production constant.
    let peer = fs::read_to_string(source_path("daemon_peer_runtime")).unwrap();
    assert!(
        peer.contains("const L1_RENEW_FLOOR_MS: u64 = 100;"),
        "the peer-runtime bound tests must use the production floor"
    );
    // 5. diagnostics are not an input of the HA scheduling code.
    for identifier in [
        "ListenerInterferenceDiagnostics",
        "InterferenceWarn",
        "interference",
        "accept_voided_window",
    ] {
        assert!(
            !runtime.contains(identifier),
            "linux_node_runtime names the diagnostic identifier {identifier}"
        );
    }
}

/// Stage 14 Phase 14.12 E3b (`MIKAGAMI_STAGE_14_PHASE_14_12_E3B_CONTRACT_
/// AMENDMENT.md`): the manual promotion attempt issues its own GET_TERM and
/// waits for that request only; nothing in the background issues one.
///
/// Invariants protected:
/// - the observation loop issues no Witness request and does not poll: its
///   `prime` closure is empty and `Daemon::prime_authority_observation` no
///   longer exists;
/// - the attempt's observation step runs once, before the one
///   `evaluate_authority_attempt` and the shutdown / gate / lease stages, and
///   its refusal retires the attempt `BlockedBeforeMutation` with the live
///   shutdown query;
/// - the step begins one request, never loops back to begin another, never
///   exposes `Ready` (no `poll_observation_at`), waits in slices of at most
///   100 ms that are cut to the deadline, stops at `now >= deadline`, and
///   reads the shutdown query before the request and before every poll;
/// - the stale-answer state is one settled-generation watermark, not a set
///   (Phase 14.12 F7; `mkm_arch_017_phase_14_12_f7_settled_generation_watermark`).
///
/// Known lexical limits: source shape only; the timing, shutdown and
/// fail-closed behavior is proven by the `e3b_*` tests in
/// `witness_evidence_adapter`, `daemon`, and the Linux lab.
#[test]
fn mkm_arch_017_phase_14_12_e3b_attempt_bound_observation() {
    let compact = |body: &str| body.split_whitespace().collect::<String>();
    let wiring = production_source("daemon_run");
    let daemon = production_source("daemon");
    let adapter = production_source("witness_evidence_adapter");

    // The loop and its production wiring send and poll nothing.
    let run = compact(&function_body(&wiring, "pub(super) fn run_daemon_inner("));
    assert!(
        run.contains("|_daemon:&mutDaemon<crate::daemon::LinuxDaemonRuntime>,_now:Instant|{},"),
        "the production prime closure must be empty"
    );
    let loop_body = function_body(&wiring, "pub(crate) fn run_observation_loop<");
    for forbidden in [
        "begin_authority_observation",
        "begin_observation_at",
        "prime_authority_observation",
        "complete_attempt_observation",
        "poll_at",
        "poll_observation_at",
        "evaluate_authority_attempt",
    ] {
        assert!(!loop_body.contains(forbidden), "loop: {forbidden}");
    }
    for (module, code) in production_modules() {
        assert!(
            !code.contains("prime_authority_observation"),
            "{module}: the background priming is retired"
        );
        if module != "daemon" && module != "witness_evidence_adapter" {
            assert!(
                !code.contains("complete_attempt_observation"),
                "{module}: only the Daemon attempt and the adapter name the step"
            );
        }
    }

    // The attempt: one step, before the evaluate and every later stage.
    let attempt = function_body(&daemon, "pub(crate) fn execute_promotion_attempt(");
    assert_eq!(attempt.matches(".complete_attempt_observation(").count(), 1);
    for later in [
        ".evaluate_authority_attempt(",
        ".fencing_gate(",
        ".acquire_attempt_lease_once(",
        ".execute_attempt_promotion(",
    ] {
        assert_before(
            &attempt,
            ".complete_attempt_observation(",
            later,
            "E3b: the observation step precedes every later stage",
        );
    }
    assert!(compact(&attempt).contains(
        "ifletErr(reason)=self.runtime.complete_attempt_observation(&||{self.shutdown_requested||self.shutdown_signal.raised()}){crate::operator_log::warn_attempt_blocked(reason,None);returnself.retire_promotion_attempt(&attempt,PromotionAttemptResult::BlockedBeforeMutation);}"
    ));
    // Nothing else issues an observation request in production.
    assert_eq!(
        daemon.matches(".begin_observation_at(").count(),
        1,
        "the single inherent LinuxDaemonRuntime::begin_authority_observation"
    );

    // The adapter's step.
    let step = function_body(&adapter, "pub(crate) fn complete_attempt_observation(");
    assert_eq!(
        step.matches(".start_at(").count(),
        1,
        "one request per step"
    );
    assert_eq!(step.matches("loop {").count(), 1);
    for forbidden in [
        "poll_observation_at",
        "begin_observation_at",
        "retry",
        "thread",
        "Instant::now",
        "sleep",
    ] {
        assert!(!step.contains(forbidden), "step: {forbidden}");
    }
    assert_eq!(step.matches("shutdown_requested()").count(), 3);
    assert_before(
        &step,
        "if shutdown_requested() {\n            return AttemptObservationWait::NotIssued",
        ".start_at(",
        "no request is issued under shutdown",
    );
    let looped = &step[step.find("loop {").unwrap()..];
    assert_before(
        looped,
        "shutdown_requested()",
        ".poll_at(",
        "shutdown is read before every poll",
    );
    assert_before(
        looped,
        "if now >= deadline {",
        ".poll_at(",
        "the deadline is checked before every poll",
    );
    assert!(compact(looped).contains("pause(ATTEMPT_OBSERVATION_WAIT_SLICE.min(deadline-now))"));
    let slice = adapter
        .split("pub(crate) const ATTEMPT_OBSERVATION_WAIT_SLICE: Duration = Duration::from_millis(")
        .nth(1)
        .expect("the wait slice constant")
        .split(')')
        .next()
        .unwrap()
        .trim()
        .parse::<u64>()
        .expect("a millisecond literal");
    assert!(
        (1..=100).contains(&slice),
        "the wait slice is at most 100 ms"
    );
    assert!(!adapter.contains("expired_generations"));
    assert!(adapter.contains("settled_generation: u64,"));
}

/// Stage 14 Phase 14.12 F7 (`MIKAGAMI_STAGE_14_PHASE_14_12_F7_CONTRACT_
/// AMENDMENT.md`): late answers of timed-out generations are recognised by one
/// settled-generation watermark, not by a bounded or growing set.
///
/// Invariants protected:
/// - no collection of expired generations exists; the watermark is a single
///   `u64` that starts at 0, is written only by `settle` (a `max`) and by
///   nothing else, and is updated on an accepted response and on a discard;
/// - the discard predicate is exactly: authenticated TermStatus from this
///   session's provenance, this adapter's canonical request id, an adapter
///   that has not failed, a generation below the current one and above the
///   watermark;
/// - one `poll_at` reads at most 9 frames (unchanged);
/// - a generation is issued only in `start_at`, by a checked increment.
///
/// Known lexical limits: source shape only; the soundness of the predicate is
/// proven by the `f7_*` tests (the W-invariant random walk and the N / R cases).
#[test]
fn mkm_arch_017_phase_14_12_f7_settled_generation_watermark() {
    let compact = |body: &str| body.split_whitespace().collect::<String>();
    let adapter = production_source("witness_evidence_adapter");
    assert!(!adapter.contains("expired_generations"));
    assert!(!adapter.contains("MAX_EXPIRED_GENERATIONS"));
    assert_eq!(adapter.matches("settled_generation: u64,").count(), 1);
    // Exactly two writes of the field: the constructor and `settle`.
    assert_eq!(adapter.matches("settled_generation:").count(), 2);
    assert_eq!(adapter.matches("self.settled_generation =").count(), 1);
    let settle = compact(&function_body(&adapter, "fn settle("));
    assert_eq!(
        settle,
        "{self.settled_generation=self.settled_generation.max(generation);}"
    );
    assert_eq!(
        adapter.matches("self.settle(").count(),
        2,
        "accept and discard only"
    );
    // The discard predicate.
    let accept = compact(&function_body(&adapter, "fn accept_poll("));
    assert!(accept.contains(
        "&&!self.failed&&generation<self.request_generation&&self.settled_generation<generation"
    ));
    assert!(accept.contains("Arc::ptr_eq(&session.provenance(),&provenance)"));
    assert!(accept.contains("crate::protocol::ProtocolMessage::TermStatus(_)"));
    assert!(accept.contains(".and_then(|id|self.own_generation(id))"));
    // The id is exactly an issued id.
    let own = compact(&function_body(&adapter, "fn own_generation("));
    assert!(own.contains(
        "(id.as_str()==format!(\"{}-{generation}\",self.request_namespace)).then_some(generation)"
    ));
    // At most 9 frames per poll, as before.
    assert!(adapter.contains("const MAX_STALE_FRAMES_PER_POLL: usize = 9;"));
    assert!(
        compact(&function_body(&adapter, "pub(crate) fn poll_at("))
            .contains("for_in0..MAX_STALE_FRAMES_PER_POLL{")
    );
    // Generations are issued only by `start_at`, by a checked increment.
    assert_eq!(adapter.matches("self.request_generation =").count(), 1);
    assert!(
        compact(&function_body(&adapter, "pub(crate) fn start_at("))
            .contains("self.request_generation.checked_add(1)")
    );
    // Overflow is never wrapped.
    assert!(!adapter.contains("wrapping_add"));
}

// ======================================================================
// v1.0 guards (Amendment `MIKAGAMI_STAGE_15_V1_CONTRACT_AMENDMENT.md`):
// BG-1..BG-12 (Bootstrap Admission), the automatic trigger, SOR, the
// `command` service, the Witness server and the health filter. They only
// add to what earlier guards pin: no earlier guard was weakened except the
// listed, justified literal updates.
// ======================================================================

mod v1 {
    use super::*;
    use std::collections::BTreeSet;

    /// Production lines (before the first test-only `mod`) with line numbers.
    fn production_lines(text: &str) -> Vec<&str> {
        let lines: Vec<&str> = text.lines().collect();
        let mut cut = lines.len();
        for (i, line) in lines.iter().enumerate() {
            if line.trim() == "#[cfg(test)]" {
                let next = lines[i + 1..]
                    .iter()
                    .find(|l| !l.trim().is_empty() && !l.trim().starts_with("#["));
                if next.is_some_and(|l| {
                    let t = l.trim_start();
                    t.starts_with("mod ")
                        || t.starts_with("pub(crate) mod ")
                        || t.starts_with("pub mod ")
                }) {
                    cut = i;
                    break;
                }
            }
        }
        lines[..cut].to_vec()
    }

    fn fn_name(line: &str) -> Option<String> {
        let t = line.trim_start();
        let idx = t.find("fn ")?;
        let before = &t[..idx];
        if !(before.is_empty()
            || before.ends_with(' ')
                && before.trim().split_whitespace().all(|w| {
                    matches!(w, "pub" | "const" | "async" | "unsafe" | "extern" | "\"C\"")
                        || w.starts_with("pub(")
                }))
        {
            return None;
        }
        let rest = &t[idx + 3..];
        let end = rest.find(|c: char| !(c.is_alphanumeric() || c == '_'))?;
        Some(rest[..end].to_string())
    }

    /// (file, enclosing fn) of every production, non-test-gated occurrence of
    /// `needle` outside comments.
    fn call_sites(needle: &str) -> BTreeSet<(String, String)> {
        let mut sites = BTreeSet::new();
        for entry in fs::read_dir(manifest_dir().join("src")).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let file = path.file_name().unwrap().to_string_lossy().into_owned();
            let text = fs::read_to_string(&path).unwrap();
            let lines = production_lines(&text);
            for (idx, line) in lines.iter().enumerate() {
                let t = line.trim_start();
                if t.starts_with("//")
                    || !line.contains(needle)
                    || fn_name(line).is_some_and(|n| needle.contains(&n))
                {
                    continue;
                }
                let mut enclosing = None;
                let mut test_gated = false;
                for back in (0..=idx).rev() {
                    if let Some(name) = fn_name(lines[back]) {
                        let mut a = back;
                        while a > 0 {
                            let prev = lines[a - 1].trim();
                            if prev.starts_with("#[") || prev.starts_with("///") {
                                if prev.contains("cfg(test)") {
                                    test_gated = true;
                                }
                                a -= 1;
                            } else {
                                break;
                            }
                        }
                        enclosing = Some(name);
                        break;
                    }
                }
                if !test_gated {
                    sites.insert((file.clone(), enclosing.unwrap_or_else(|| "<none>".into())));
                }
            }
        }
        sites
    }

    fn set(items: &[(&str, &str)]) -> BTreeSet<(String, String)> {
        items
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    fn body(module: &str, signature: &str) -> String {
        function_body(&production_source(module), signature)
    }

    fn linux_part(module: &str) -> String {
        let code = production_source(module);
        let at = code
            .find("impl DaemonRuntime for LinuxDaemonRuntime")
            .expect("Linux DaemonRuntime impl");
        code[at..].to_string()
    }

    fn compact(text: &str) -> String {
        text.split_whitespace().collect()
    }

    fn assert_absent(label: &str, text: &str, forbidden: &[&str]) {
        for token in forbidden {
            assert!(!text.contains(token), "{label} contains `{token}`");
        }
    }

    /// BG-8 / BG-11 (contract K-1, K-3): the peer is advanced from exactly
    /// one place (the ordinary `Daemon::tick_at`), immediately after the
    /// observation and with nothing in between; one promotion attempt is one
    /// synchronous call that never ticks the peer, spawns, sleeps or waits.
    #[test]
    fn bg_8_11_peer_tick_origin_and_attempt_shape() {
        assert_eq!(
            call_sites(".peer_tick_at("),
            set(&[("daemon.rs", "drive_peer_tick_at")])
        );
        assert_eq!(
            call_sites("self.drive_peer_tick_at("),
            set(&[("daemon.rs", "tick_at")])
        );
        assert_eq!(
            call_sites(".tick_at_with("),
            set(&[
                ("daemon.rs", "peer_tick_at"),
                ("daemon_peer_runtime.rs", "tick_at")
            ])
        );
        assert_eq!(
            call_sites("execute_promotion_attempt("),
            set(&[("daemon_run.rs", "run_daemon_inner")])
        );
        let attempt = body("daemon", "pub(crate) fn execute_promotion_attempt(");
        assert_absent(
            "execute_promotion_attempt",
            &attempt,
            &[
                "tick", "peer", "thread", ".spawn(", "sleep", "mpsc", "async", ".await", "Arc<",
                "Mutex",
            ],
        );
        assert_eq!(attempt.matches("take_attempt_lease_authority(").count(), 1);
        assert_eq!(attempt.matches("execute_attempt_promotion(").count(), 1);
        assert_eq!(attempt.matches("acquire_attempt_lease_once(").count(), 1);
        // BG-11: observe -> context -> peer advance, nothing in between.
        let tick = compact(&body("daemon", "pub(crate) fn tick_at("));
        assert!(
            tick.contains(
                "self.cached=Some(snapshot);self.last_observation_error=None;letfacts=self.probe_facts();self.runtime.set_probe_context(Some(facts));self.drive_peer_tick_at(now);"
            ),
            "the peer advance follows the successful observation directly"
        );
        assert!(
            tick.contains("self.runtime.set_probe_context(None);self.drive_peer_tick_at(now);")
        );
        assert_before(
            &tick,
            "self.runtime.observe()",
            "self.drive_peer_tick_at(now)",
            "observe precedes the peer advance",
        );
    }

    /// BG-8 (contract K-1): grants and protected resources have fixed
    /// sites; the Bootstrap ARM+promote is an explicitly listed entry.
    #[test]
    fn bg_8_acquisition_sites_are_fixed() {
        assert_eq!(
            call_sites("take_attempt_lease_authority("),
            set(&[("daemon.rs", "execute_promotion_attempt")])
        );
        assert_eq!(
            call_sites("acquire_attempt_lease_once("),
            set(&[("daemon.rs", "execute_promotion_attempt")])
        );
        assert_eq!(
            call_sites(".restore_installed_lease_authority("),
            set(&[
                ("linux_node_runtime.rs", "arm_and_promote"),
                ("linux_node_runtime.rs", "arm_and_promote_bootstrap"),
                ("linux_node_runtime.rs", "restore_installed_lease_authority"),
            ])
        );
        assert_eq!(
            call_sites(".acquire_vip("),
            set(&[("resource_workflow.rs", "promote")])
        );
        assert_eq!(
            call_sites(".start_service("),
            set(&[("resource_workflow.rs", "promote")])
        );
        assert_eq!(
            call_sites("arm_and_promote("),
            set(&[("daemon.rs", "execute_attempt_promotion")])
        );
        assert_eq!(
            call_sites("arm_and_promote_bootstrap("),
            set(&[("daemon.rs", "execute_attempt_promotion")])
        );
        assert_eq!(
            call_sites("arm_consuming_fencing("),
            set(&[("linux_node_runtime.rs", "arm_and_promote")])
        );
        assert_eq!(
            call_sites(".arm_release_obligation("),
            set(&[
                ("linux_node_runtime.rs", "arm_and_promote_bootstrap"),
                ("linux_node_runtime.rs", "release_attempt_lease_once"),
            ])
        );
        // The production threads: the Witness server's own (Witness host
        // only). Nothing in a node's promotion path. The systemd backend has
        // no reader thread any more (FH-1: it polls a non-blocking pipe).
        assert_eq!(
            call_sites("thread::spawn("),
            set(&[
                ("witness_server.rs", "install"),
                ("witness_server.rs", "serve"),
            ])
        );
        // The dispatch of the promotion handoff: both entries live in the one
        // function, and the no-prerequisite case still has no ARM.
        let promotion = compact(&production_source("daemon"));
        assert!(promotion.contains("FencingPrerequisite::Cleared(clearance)=>self.runtime.arm_and_promote(lease.into_authority(),clearance)"));
        assert!(promotion.contains("FencingPrerequisite::Bootstrap(clearance)=>self.runtime.arm_and_promote_bootstrap(lease.into_authority(),clearance)"));
        assert!(promotion.contains("returnErr(\"nofencingclearance:noARM\".into());"));
    }

    /// BG-1 / BG-9 (contract K-2, K-3): the responder reads state and answers;
    /// it can call no mutation API, and the peer runtime evaluates its
    /// verdict at most once per tick, after the frame loop.
    #[test]
    fn bg_1_9_responder_cannot_mutate() {
        let forbidden = [
            "transition_to",
            "promote(",
            "demote(",
            "arm_",
            "begin_",
            "persist",
            "fs::write",
            "spawn",
            "restore_installed",
            "take_installed",
            "take_attempt",
            "reconcile",
            "request_demotion",
            "ResourceWorkflow",
            "mutation_store",
            "controller",
            "acquire_",
            "install_",
        ];
        let verdict = body("bootstrap_admission", "pub(crate) fn responder_verdict(");
        assert_absent("responder_verdict", &verdict, &forbidden);
        let linux_tick = function_body(&linux_part("daemon"), "fn peer_tick_at(");
        assert_absent("Linux peer_tick_at", &linux_tick, &forbidden);
        // Its only runtime input is the existing local-safety definition.
        assert_eq!(
            linux_tick
                .matches("failover_local_safety_snapshot(")
                .count(),
            1
        );
        let peer = body("daemon_peer_runtime", "pub(crate) fn tick_at_with(");
        assert_eq!(peer.matches("self.answer_probes(").count(), 1);
        assert_absent(
            "tick_at_with",
            &peer,
            &["self.runtime", "mutation", "thread", "sleep"],
        );
        let answer = body("daemon_peer_runtime", "fn answer_probes(");
        assert_eq!(
            answer.matches("verdict()").count(),
            1,
            "one verdict per tick"
        );
        assert_before(
            &answer,
            "std::mem::take(&mut self.pending_probe_requests)",
            "verdict()",
            "taken, then evaluated once",
        );
        // Probes are not stored beyond the tick that read them.
        let source = production_source("daemon_peer_runtime");
        assert_eq!(source.matches("pending_probe_requests.clear()").count(), 1);
    }

    /// BG-2 (contract K-4): the clearance is not copyable or serializable,
    /// has one mint site, and its only consumers are the attempt dispatch,
    /// the K recheck and the Bootstrap ARM.
    #[test]
    fn bg_2_clearance_single_mint_single_consumer() {
        let ba = production_source("bootstrap_admission");
        let attributes = item_attributes(&ba, "pub(crate) struct BootstrapClearance");
        for forbidden in ["Clone", "Copy", "Serialize", "Deserialize", "Default"] {
            assert!(
                !attributes.contains(forbidden),
                "BootstrapClearance derives {forbidden}"
            );
        }
        assert!(!ba.contains("impl Clone for BootstrapClearance"));
        assert_eq!(ba.matches("fn mint(").count(), 1);
        assert_eq!(ba.matches("BootstrapClearance::mint(").count(), 1);
        assert!(
            function_body(&ba, "pub(crate) fn decide(")
                .contains("BootstrapClearance::mint(session)")
        );
        let mut users: Vec<String> = production_modules()
            .into_iter()
            .filter(|(_, code)| code.contains("BootstrapClearance"))
            .map(|(name, _)| name)
            .collect();
        users.sort();
        assert_eq!(
            users,
            ["bootstrap_admission", "daemon", "linux_node_runtime"]
        );
        assert_eq!(
            call_sites("arm_and_promote_bootstrap("),
            set(&[("daemon.rs", "execute_attempt_promotion")])
        );
    }

    /// BG-3 / BG-5 (INV-BA-8): no clock, heartbeat age, duration comparison,
    /// I/O or thread in the BA decision, the trigger machine, SOR's decision
    /// or the health filter; the BA branch of the attempt reads none either.
    #[test]
    fn bg_3_5_decisions_read_no_clock() {
        let clockless = [
            "Instant",
            "SystemTime",
            "Duration",
            ".elapsed(",
            "last_received",
            "std::process",
            "thread",
            "sleep",
            "AtomicBool",
        ];
        for module in ["bootstrap_admission", "auto_failover", "health_hysteresis"] {
            let code = production_source(module);
            assert_absent(module, &code, &clockless);
            assert_absent(module, &code, &["std::fs", "std::net", "File::"]);
            assert!(
                forbidden_dependencies(&code).is_empty(),
                "{module} depends on a mutation layer"
            );
        }
        let reconciliation = production_source("obligation_reconciliation");
        assert_absent("obligation_reconciliation", &reconciliation, &clockless);
        assert_absent(
            "obligation_reconciliation::decide",
            &function_body(&reconciliation, "pub(crate) fn decide("),
            &["store", "session", "NodeWitness", "WitnessSession"],
        );
        let daemon = production_source("daemon");
        for function in [
            "fn bootstrap_admission(",
            "fn bootstrap_applies(",
            "fn bootstrap_recheck(",
        ] {
            assert_absent(
                function,
                &function_body(&daemon, function),
                &[
                    "Instant",
                    "Duration",
                    "elapsed",
                    "last_received",
                    "heartbeat",
                    "preferred",
                    "priority",
                ],
            );
        }
        // The priority never enters the admission inputs (BAP-9).
        let inputs = item_members(
            &ba_source(),
            "pub(crate) struct AdmissionInputs<'a> {",
            false,
        );
        for member in inputs {
            assert!(
                !member.contains("prefer") && !member.contains("priority"),
                "{member}"
            );
        }
    }

    fn ba_source() -> String {
        production_source("bootstrap_admission")
    }

    /// BG-4 / BG-7: one probe reason constant; a probe is requested only by
    /// the anchor branch, after the session exists, and its nonce is drawn at
    /// the send, not at the request.
    #[test]
    fn bg_4_7_probe_reason_and_order() {
        let mut literal = 0;
        for (_, code) in production_modules() {
            literal += code.matches("mkm-bootstrap-probe/1").count();
        }
        assert_eq!(literal, 1, "the probe reason has one definition");
        assert_eq!(ba_source().matches("const PROBE_REASON").count(), 1);
        assert_eq!(
            call_sites("request_bootstrap_probe("),
            set(&[("daemon.rs", "bootstrap_admission")])
        );
        assert_eq!(
            call_sites(".request_probe("),
            set(&[("daemon.rs", "request_bootstrap_probe")])
        );
        let admission = compact(&body("daemon", "fn bootstrap_admission("));
        assert_before(
            &admission,
            "Admission::Anchored(session)=>",
            "self.runtime.request_bootstrap_probe()",
            "the probe is requested after the anchor exists",
        );
        let request = body("daemon_peer_runtime", "pub(crate) fn request_probe(");
        assert!(request.contains("self.bootstrap_stamp().is_none()"));
        assert!(!request.contains("getrandom"));
        assert!(production_source("daemon_peer_runtime").contains("getrandom"));
    }

    /// BG-6 (BAP-6): H uses the anchor as `observed_term`; attempt 2 clears
    /// only with the same term and no holder; the grant must be anchor + 1.
    #[test]
    fn bg_6_anchor_term_binds_the_lease_chain() {
        let attempt = body("daemon", "pub(crate) fn execute_promotion_attempt(");
        assert_before(
            &attempt,
            ".is_some_and(|anchor| anchor != term)",
            ".acquire_attempt_lease_once(",
            "the anchor equals the H term before the LeaseRequest",
        );
        let decide = compact(&function_body(&ba_source(), "pub(crate) fn decide("));
        assert!(decide.contains("anchor_term:inputs.witness_term,"));
        assert!(decide.contains("||inputs.witness_term!=session.anchor_term"));
        assert!(decide.contains("AuthorityViewCompatibility::CompatibleNoHolder"));
        assert!(compact(&attempt).contains("anchor.0.checked_add(1)!=Some(granted.0.0)"));
        let recheck = compact(&body(
            "linux_node_runtime",
            "pub(crate) fn bootstrap_final_recheck(",
        ));
        assert!(recheck.contains("anchor_term.0.checked_add(1)!=Some(grant_term.0)"));
    }

    /// The depth-0 statements of a function body (outer braces included). A
    /// statement ends at a `;` or at the `}` that closes a block statement
    /// (`if`, `match`, ...) unless the block continues (`else`, `.`, `?`).
    /// Parentheses, brackets and braces nest. Comments are already stripped
    /// and the guarded bodies contain no braces inside string literals.
    fn top_level_statements(function: &str) -> Vec<String> {
        let inner = &function[1..function.len() - 1];
        let mut statements = Vec::new();
        let mut current = String::new();
        let mut depth = 0i32;
        let mut rest = inner.chars().peekable();
        while let Some(c) = rest.next() {
            current.push(c);
            match c {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' => depth -= 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        let following: String = rest.clone().collect();
                        let next = following.trim_start();
                        if !(next.starts_with("else")
                            || next.starts_with('.')
                            || next.starts_with('?')
                            || next.starts_with(';'))
                        {
                            statements.push(std::mem::take(&mut current));
                        }
                    }
                }
                ';' if depth == 0 => statements.push(std::mem::take(&mut current)),
                _ => {}
            }
        }
        if !current.trim().is_empty() {
            statements.push(current);
        }
        statements
            .into_iter()
            .map(|statement| statement.trim().to_string())
            .collect()
    }

    /// `(scrutinee, [(pattern, body)])` of a `match` statement. Arms end at a
    /// depth-0 comma or at the brace that closes a block body.
    fn match_parts(statement: &str) -> Option<(String, Vec<(String, String)>)> {
        let rest = statement.strip_prefix("match ")?;
        let mut paren = 0i32;
        let mut open = None;
        for (index, c) in rest.char_indices() {
            match c {
                '(' | '[' => paren += 1,
                ')' | ']' => paren -= 1,
                '{' if paren == 0 => {
                    open = Some(index);
                    break;
                }
                _ => {}
            }
        }
        let open = open?;
        let scrutinee = rest[..open].trim().to_string();
        let inner = rest[open + 1..].trim_end().strip_suffix('}')?;
        let mut arms = Vec::new();
        let mut current = String::new();
        let mut depth = 0i32;
        for c in inner.chars() {
            match c {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' => depth -= 1,
                '}' => depth -= 1,
                _ => {}
            }
            if depth == 0 && c == ',' {
                arms.push(std::mem::take(&mut current));
                continue;
            }
            current.push(c);
            if depth == 0 && c == '}' && current.contains("=>") {
                arms.push(std::mem::take(&mut current));
            }
        }
        arms.push(current);
        let arms = arms
            .into_iter()
            .map(|arm| arm.trim().trim_start_matches(',').trim().to_string())
            .filter(|arm| !arm.is_empty())
            .map(|arm| {
                let (pattern, body) = arm.split_once("=>")?;
                Some((pattern.trim().to_string(), body.trim().to_string()))
            })
            .collect::<Option<Vec<_>>>()?;
        Some((scrutinee, arms))
    }

    /// Strip one pair of block braces and trailing `;` / `,` from an arm body.
    fn arm_expression(body: &str) -> String {
        let mut text = compact(body);
        loop {
            let before = text.clone();
            text = text.trim_end_matches([',', ';']).to_string();
            if text.starts_with('{') && text.ends_with('}') {
                text = text[1..text.len() - 1].to_string();
            }
            if text == before {
                return text;
            }
        }
    }

    /// BG-12 control-flow check on the text of
    /// `arm_and_promote_bootstrap`. Not a general analysis: it accepts exactly
    /// one shape, whose dominance property is easy to see, and rejects any
    /// other. The accepted shape is five top-level statements:
    ///
    /// 1. `let _ = clearance.anchor_term();`
    /// 2. the Conservative / trusted-ZeroResource gate, whose only effect is
    ///    `return Err(..)`;
    /// 3. a `match` whose scrutinee is exactly the one plain ARM routed
    ///    through `plain_arm_gate`, with four named arms: `Committed`
    ///    (logging only, no way out) and one arm per refusal
    ///    (`NotCommitted`, `Rejected`, `RecoveryBlocked`), each of which does
    ///    nothing but `return Ok(<the same-named FencedArmOutcome>)`;
    /// 4. the authority restore;
    /// 5. the final expression, `promote`.
    ///
    /// Because statement 3 is top-level it always runs, and because every
    /// arm but `Committed` returns, statements 4 and 5 are reachable only
    /// when the ARM committed. A wildcard or or-pattern arm, a nested ARM, a
    /// second restore/promote, or anything between the statements is
    /// rejected. LIMITS: the text of one function is checked; the meaning of
    /// `plain_arm_gate` is covered by its own execution tests and the
    /// `Committed`-count check, and the Linux runtime itself is not executed
    /// on the Host. A helper that smuggled a restore into another function
    /// is caught only by the call-site counts around this check.
    fn check_bootstrap_arm_function(function: &str) -> Result<(), String> {
        let statements = top_level_statements(function);
        if statements.len() != 5 {
            return Err(format!(
                "expected 5 top-level statements, found {}",
                statements.len()
            ));
        }
        let compacted: Vec<String> = statements.iter().map(|s| compact(s)).collect();
        if compacted[0] != "let_=clearance.anchor_term();" {
            return Err("statement 1 is not the anchor read".into());
        }
        if compacted[1]
            != "if!self.controller.is_conservative()||!self.observe_trusted_zero_resource(){returnErr(AuthorityError::RecoveryBlocked.into());}"
        {
            return Err("statement 2 is not the Conservative / ZeroResource gate".into());
        }
        let Some((scrutinee, arms)) = match_parts(&statements[2]) else {
            return Err("statement 3 is not a match".into());
        };
        let scrutinee = compact(&scrutinee).replace(",)", ")");
        if scrutinee
            != "crate::node_mutation::plain_arm_gate(self.mutation_store.arm_release_obligation(authority.term(),authority.lease_id().clone()))"
        {
            return Err(format!(
                "the match scrutinee is not the plain ARM: {scrutinee}"
            ));
        }
        let patterns: Vec<String> = arms.iter().map(|(pattern, _)| compact(pattern)).collect();
        let expected = [
            "ArmGate::Committed",
            "ArmGate::NotCommitted(reason)",
            "ArmGate::Rejected(reason)",
            "ArmGate::RecoveryBlocked(reason)",
        ];
        if patterns != expected {
            return Err(format!(
                "the arms are not exactly the four named ones: {patterns:?}"
            ));
        }
        let committed = arm_expression(&arms[0].1);
        if committed != "crate::operator_log::info_bootstrap_activated(authority.term().0)" {
            return Err(format!("the Committed arm does more than log: {committed}"));
        }
        for (arm, outcome) in [
            (&arms[1], "NotCommitted"),
            (&arms[2], "Rejected"),
            (&arms[3], "RecoveryBlocked"),
        ] {
            let want = format!("returnOk(FencedArmOutcome::{outcome}(reason))");
            if arm_expression(&arm.1) != want {
                return Err(format!("the {outcome} arm does not return {want}"));
            }
        }
        if compacted[3] != "self.controller.restore_installed_lease_authority(authority)?;" {
            return Err("statement 4 is not the authority restore".into());
        }
        if compacted[4] != "Ok(FencedArmOutcome::Promoted(self.promote()?))" {
            return Err("statement 5 is not promote".into());
        }
        for (needle, count) in [
            (".restore_installed_lease_authority(", 1),
            ("self.promote()", 1),
            (".arm_release_obligation(", 1),
            ("plain_arm_gate(", 1),
        ] {
            if function.matches(needle).count() != count {
                return Err(format!("`{needle}` does not occur exactly {count} time(s)"));
            }
        }
        Ok(())
    }

    /// BG-12 (contract K-4, finding F15-M4): the authority restore and
    /// `promote` of the Bootstrap hand-off are reachable only after a
    /// committed ARM, and the three refusals stay distinct. See
    /// `check_bootstrap_arm_function` for the exact shape and its limits.
    #[test]
    fn bg_12_bootstrap_arm_order() {
        let function = body(
            "linux_node_runtime",
            "pub(crate) fn arm_and_promote_bootstrap(",
        );
        check_bootstrap_arm_function(&function)
            .unwrap_or_else(|reason| panic!("arm_and_promote_bootstrap breaks BG-12: {reason}"));
        assert_absent(
            "arm_and_promote_bootstrap",
            &function,
            &["thread", "sleep", "spawn", "session", "Witness"],
        );
        // The mapping the match relies on: `Committed` is built exactly once,
        // for `Ok`, and nothing else in the module can build it.
        let gate = body("node_mutation", "pub(crate) fn plain_arm_gate<");
        let gate = compact(&gate);
        assert!(
            gate.starts_with("{matchresult{Ok(_)=>ArmGate::Committed,Err("),
            "{gate}"
        );
        assert_eq!(gate.matches("ArmGate::Committed").count(), 1, "{gate}");
        assert_eq!(gate.matches("Ok(").count(), 1, "{gate}");
        assert!(!gate.contains("_=>"), "{gate}");
        let node_mutation = production_source("node_mutation");
        assert_eq!(node_mutation.matches("ArmGate::Committed").count(), 1);
        assert_eq!(
            call_sites("plain_arm_gate("),
            set(&[("linux_node_runtime.rs", "arm_and_promote_bootstrap")])
        );
        // The Linux runtime reaches the plain ARM from this hand-off and from
        // the unused-lease cleanup (which never restores an authority or
        // promotes), and from nowhere else.
        let arm_sites = call_sites(".arm_release_obligation(");
        let linux: BTreeSet<_> = arm_sites
            .into_iter()
            .filter(|(file, _)| file == "linux_node_runtime.rs")
            .collect();
        assert_eq!(
            linux,
            set(&[
                ("linux_node_runtime.rs", "arm_and_promote_bootstrap"),
                ("linux_node_runtime.rs", "release_attempt_lease_once"),
            ])
        );
    }

    /// BG-12 self-check: the guard's own verdict on the independent audit's
    /// dead-branch counterexample (`guard-arm-bypass.patch`) and on the other
    /// ways the dominance could be broken. Each mutation edits the real
    /// function text in memory and must be rejected; an unchanged text must
    /// be accepted, so a rejection is the mutation's doing.
    #[test]
    fn bg_12_rejects_every_arm_bypass_mutation() {
        let original = body(
            "linux_node_runtime",
            "pub(crate) fn arm_and_promote_bootstrap(",
        );
        check_bootstrap_arm_function(&original).expect("the real function is accepted");

        let start = original
            .find("match crate::node_mutation::plain_arm_gate(")
            .expect("the ARM match");
        let restore = original.rfind("self.controller").expect("the restore");
        let arm_pair_end = restore;
        let mutations: Vec<(&str, String)> = vec![
            (
                "independent audit: the whole ARM match in `if false`",
                format!(
                    "{}if false {{\n{}}}\n{}",
                    &original[..start],
                    &original[start..arm_pair_end],
                    &original[arm_pair_end..]
                ),
            ),
            (
                "the whole ARM match in `if true`",
                format!(
                    "{}if true {{\n{}}}\n{}",
                    &original[..start],
                    &original[start..arm_pair_end],
                    &original[arm_pair_end..]
                ),
            ),
            (
                "the ARM match in a loop that may skip it",
                format!(
                    "{}for _ in 0..0 {{\n{}}}\n{}",
                    &original[..start],
                    &original[start..arm_pair_end],
                    &original[arm_pair_end..]
                ),
            ),
            (
                "the restore moved under `if false`",
                format!(
                    "{}if false {{\n{}",
                    &original[..restore],
                    original[restore..]
                        .replacen("?;\n", "?;\n}\n", 1)
                ),
            ),
            (
                "the ARM replaced by a constant Committed",
                original.replacen(
                    "plain_arm_gate(\n            self.mutation_store\n                .arm_release_obligation(authority.term(), authority.lease_id().clone()),\n        )",
                    "ArmGate::Committed",
                    1,
                ),
            ),
            (
                "a wildcard arm swallowing the refusals",
                original.replacen(
                    "ArmGate::Rejected(reason) => return Ok(FencedArmOutcome::Rejected(reason)),",
                    "_ => {}",
                    1,
                ),
            ),
            (
                "Rejected folded into the Committed arm",
                original.replacen(
                    "ArmGate::Committed =>",
                    "ArmGate::Committed | ArmGate::Rejected(_) =>",
                    1,
                ),
            ),
            (
                "NotCommitted no longer returns",
                original.replacen(
                    "ArmGate::NotCommitted(reason) => return Ok(FencedArmOutcome::NotCommitted(reason)),",
                    "ArmGate::NotCommitted(reason) => drop(reason),",
                    1,
                ),
            ),
            (
                "NotCommitted reported as Rejected",
                original.replacen(
                    "return Ok(FencedArmOutcome::NotCommitted(reason))",
                    "return Ok(FencedArmOutcome::Rejected(reason))",
                    1,
                ),
            ),
            (
                "RecoveryBlocked reported as NotCommitted",
                original.replacen(
                    "return Ok(FencedArmOutcome::RecoveryBlocked(reason));",
                    "return Ok(FencedArmOutcome::NotCommitted(reason));",
                    1,
                ),
            ),
            (
                "the restore before the ARM",
                original
                    .replacen(
                        "self.controller\n            .restore_installed_lease_authority(authority)?;\n",
                        "",
                        1,
                    )
                    .replacen(
                        "match crate::node_mutation::plain_arm_gate(",
                        "self.controller.restore_installed_lease_authority(authority)?;\n        match crate::node_mutation::plain_arm_gate(",
                        1,
                    ),
            ),
            (
                "a second restore inside the Committed arm",
                original.replacen(
                    "ArmGate::Committed => crate::operator_log::info_bootstrap_activated(authority.term().0),",
                    "ArmGate::Committed => {\n                self.controller.restore_installed_lease_authority(authority)?;\n            }",
                    1,
                ),
            ),
            (
                "the ARM result dropped",
                original.replacen(
                    "match crate::node_mutation::plain_arm_gate(",
                    "let _ = crate::node_mutation::plain_arm_gate(",
                    1,
                ),
            ),
            (
                "the Conservative / ZeroResource gate weakened",
                original.replacen(
                    "if !self.controller.is_conservative() || !self.observe_trusted_zero_resource() {",
                    "if !self.controller.is_conservative() {",
                    1,
                ),
            ),
        ];
        for (label, mutated) in mutations {
            assert_ne!(mutated, original, "{label}: the mutation did not apply");
            let verdict = check_bootstrap_arm_function(&mutated);
            assert!(verdict.is_err(), "the guard accepted the mutation: {label}");
            println!("{label}: {}", verdict.unwrap_err());
        }
    }

    /// BG-10 (contract K-5): Bootstrap Admission needs the Conservative mode
    /// at every stage, and the configuration offers no other mode.
    #[test]
    fn bg_10_bootstrap_is_conservative_only() {
        let decide = function_body(&ba_source(), "pub(crate) fn decide(");
        assert!(
            decide
                .trim_start_matches('{')
                .trim_start()
                .starts_with("let drop_with")
        );
        assert_before(
            &decide,
            "!inputs.conservative",
            "inputs.shutdown_requested",
            "mode first",
        );
        assert!(
            body(
                "linux_node_runtime",
                "pub(crate) fn bootstrap_final_recheck("
            )
            .contains("is_conservative()")
        );
        assert!(
            body(
                "linux_node_runtime",
                "pub(crate) fn arm_and_promote_bootstrap("
            )
            .contains("is_conservative()")
        );
        let config = production_source("config");
        let cluster = function_body(&config, "struct RawCluster");
        assert!(
            !cluster.contains("mode"),
            "`cluster.mode` must not be a key"
        );
        assert!(
            production_source("node_lease_authority").contains("pub(crate) fn is_conservative(")
        );
    }

    /// The automatic trigger only raises a one-shot request: it has one
    /// consumption point and cannot reach the attempt, the gate or a lease.
    #[test]
    fn auto_trigger_only_raises_a_request() {
        assert_eq!(
            call_sites("take_auto_request("),
            set(&[("daemon_run.rs", "run_observation_loop_checked")])
        );
        assert_eq!(
            call_sites("set_trigger_origin("),
            set(&[("daemon_run.rs", "run_observation_loop_checked")])
        );
        let evaluate = body("daemon", "fn evaluate_auto(");
        assert_absent(
            "evaluate_auto",
            &evaluate,
            &[
                "execute_promotion_attempt",
                "promote(",
                "fencing_gate",
                "acquire_",
                "arm_",
                "transition_to",
                "thread",
                "sleep",
                "spawn",
            ],
        );
        assert_eq!(
            body("daemon", "pub(crate) fn take_auto_request(")
                .matches("pending_auto")
                .count(),
            1
        );
        let machine = production_source("auto_failover");
        assert_absent(
            "auto_failover",
            &machine,
            &[
                "execute_promotion_attempt",
                "NodeMutationStore",
                "WitnessSession",
                "fencing_backend",
            ],
        );
        // The origin only changes the request-id prefix, never a decision.
        let wiring = production_source("daemon_run");
        assert_eq!(wiring.matches("PromotionRequestId::new").count(), 1);
        assert!(compact(&wiring).contains("operator_intent=intent.consume()"));
    }

    /// SOR (contract A-4): the obligation is resolved only after trusted
    /// ZeroResource, only by the exact release or the superseded-clear, and
    /// SOR installs no authority and never promotes.
    #[test]
    fn sor_clears_only_after_zero_resource_and_grants_nothing() {
        assert_eq!(
            call_sites("clear_superseded_obligation("),
            set(&[("obligation_reconciliation.rs", "reconcile")])
        );
        let reconcile = body("obligation_reconciliation", "pub(crate) fn reconcile(");
        assert_before(
            &reconcile,
            "if !zero_resource",
            "clear_superseded_obligation(",
            "ZeroResource first",
        );
        assert_before(
            &reconcile,
            "if !zero_resource",
            "begin_and_execute_lease_release_once(",
            "ZeroResource first",
        );
        assert_absent(
            "reconcile",
            &reconcile,
            &[
                "restore_installed",
                "install_",
                "promote(",
                "take_",
                "transition_to",
                "arm_",
            ],
        );
        let store = body("node_mutation", "pub fn clear_superseded_obligation(");
        for required in [
            "obligation.term != term || &obligation.lease_id != lease_id",
            "state.outstanding_mutation.is_some()",
            "state.fencing_incident.is_some()",
            "state.release_obligation = None;",
        ] {
            assert!(store.contains(required), "{required}");
        }
        assert_eq!(
            store.matches("self.save_locked(").count(),
            1,
            "one candidate"
        );
        // J35 (cf30): the daemon's startup now runs with the live control-lock
        // predicate (`startup_guarded`) and reaches the runtime through the
        // guarded entry; the unguarded runtime entry only delegates to it.
        assert_eq!(
            call_sites("reconcile_startup_obligation("),
            set(&[("daemon.rs", "startup_guarded")])
        );
        assert_eq!(
            call_sites("reconcile_startup_obligation_guarded("),
            set(&[
                ("daemon.rs", "reconcile_startup_obligation"),
                ("linux_node_runtime.rs", "reconcile_startup_obligation")
            ])
        );
        // The runtime half proves ZeroResource before it asks the module.
        let runtime = compact(&body(
            "linux_node_runtime",
            "pub(crate) fn reconcile_startup_obligation_guarded(",
        ));
        assert_before(
            &runtime,
            "self.ensure_trusted_zero_resource_guarded(control_lock_safe)",
            "obligation_reconciliation::reconcile(",
            "SOR order",
        );
    }

    /// The `command` service adapter: argv only, cleared environment, own
    /// process group, no threads, no shell, none of the fencing runner's names.
    #[test]
    fn command_service_is_argv_only_bounded_and_separate() {
        let code = production_source("command_service");
        for required in ["env_clear()", "process_group(0)", "Stdio::null()"] {
            assert!(code.contains(required), "command_service lacks {required}");
        }
        assert_absent(
            "command_service",
            &code,
            &[
                "\"sh\"",
                "\"-c\"",
                "/bin/sh",
                "bash",
                "thread::spawn",
                "read_to_end",
                "tokio",
                "async ",
                ".await",
                "check_executable_trust(",
                "run_step(",
                "check_trust(",
                "StepRequest",
                "StepTimeout",
                "SpawnPlan",
                "ProcessDriver",
                "SystemProcessDriver",
                "CommandBackend",
                "fencing_backend",
                "operator_log",
            ],
        );
        assert_eq!(code.matches("Command::new(").count(), 1, "one spawn site");
        // Both service adapters are reached only through the adapter enum.
        let executor = production_source("resource_executor");
        assert!(executor.contains("enum ServiceAdapter"));
    }

    /// The command runner learns that a child ended, and that its pid still
    /// pins the process group, only by waiting for its own children. So:
    /// (1) it never blocks on one, (2) it checks (reads, never writes) the
    /// process-wide `SIGCHLD` setting at construction and right before the
    /// spawn, and (3) nothing else in the crate touches `SIGCHLD`, ignores a
    /// signal with `SIG_IGN`, waits for any child (`waitpid(-1`) or becomes a
    /// subreaper. Source shape only; the behavior (in isolated child
    /// processes, as the setting is process-wide) is proven by the
    /// `sigchld_*` and `nf3` tests in `command_service.rs`.
    ///
    /// Known lexical limit: a dependency, or code built from pieces of these
    /// names, is not seen; the static review of the locked dependencies found
    /// none (Stage 15 investigation).
    #[test]
    fn command_runner_waits_without_blocking_and_sigchld_is_untouched() {
        let code = production_source("command_service");
        // (1) no blocking wait; the one exit query is non-blocking.
        assert_absent(
            "command_service",
            &code,
            &[
                ".wait()",
                "waitpid(",
                "wait4(",
                "waitpid",
                "wait_with_output",
            ],
        );
        assert_eq!(code.matches("waitid(").count(), 2, "declaration + one call");
        assert!(code.contains("WEXITED | WNOWAIT | WNOHANG"));
        assert_eq!(
            code.matches("try_wait()").count(),
            1,
            "one non-blocking reap"
        );
        // (2) the check reads only: a null new action, in exactly one call.
        assert_eq!(
            code.matches("sigaction(").count(),
            2,
            "declaration + one call"
        );
        assert!(code.contains("sigaction(SIGCHLD, std::ptr::null(), &mut current)"));
        let run = function_body(&code, "    fn run(");
        assert_before(
            &run,
            "check_sigchld(self.sigchld)",
            "Command::new(",
            "the SIGCHLD check precedes the spawn",
        );
        assert_before(
            &run,
            "InvalidTimeout",
            "check_sigchld(self.sigchld)",
            "nothing fallible is left after the check",
        );
        let constructor = function_body(&code, "pub(crate) fn with_policy(");
        assert!(
            constructor.contains("check_sigchld(sys::sigchld_state)"),
            "the daemon does not start under a SIGCHLD setting that hides exits"
        );
        assert_eq!(code.matches("check_sigchld(").count(), 3, "fn + run + ctor");
        // The accepted state is the default one only.
        let check = function_body(&code, "fn check_sigchld(");
        assert!(check.contains("Ok(sys::SigchldState::Default) => Ok(())"));
        assert_eq!(check.matches("=> Ok(").count(), 1);
        // (3) no other module touches the setting or becomes a reaper. The
        // walk covers `src/manual/**` too (v0.4 audit F-05).
        let all = all_production_modules();
        assert!(
            all.iter().any(|(name, _)| name == "manual/agent"),
            "the R-2 guard must scan the manual plane: {all:?}"
        );
        for (module, source) in all {
            if module == "command_service" {
                continue;
            }
            assert_absent(
                &module,
                &source,
                &[
                    "SIGCHLD",
                    "SIG_IGN",
                    "SA_NOCLDWAIT",
                    "SA_NOCLDSTOP",
                    "sigaction(",
                    "waitpid(-1",
                    "waitpid(- 1",
                    "PR_SET_CHILD_SUBREAPER",
                    "SUBREAPER",
                ],
            );
        }
    }

    /// FH-2 (Owner ruling): a refused `SIGCHLD` state forbids NEW spawns, not
    /// the cleanup that was already owed. Source shape only: `run` discharges
    /// the owed cleanup first, the refusal returns before the one spawn and
    /// signals nothing itself, and every group signal sits in one of the three
    /// functions that check the pin first. The behavior (six cases, signals
    /// of the owed cleanup told apart from signals of a new child) is proven
    /// by the `fh2_*` tests in `command_service.rs`.
    #[test]
    fn fh2_a_refused_sigchld_forbids_new_spawns_but_not_the_owed_cleanup() {
        let code = production_source("command_service");
        let run = function_body(&code, "    fn run(");
        assert_before(
            &run,
            "self.clear_pending()",
            "check_sigchld(self.sigchld)",
            "the owed cleanup is discharged before the SIGCHLD check, not after it",
        );
        assert_before(
            &run,
            "check_sigchld(self.sigchld)",
            "command.spawn()",
            "the SIGCHLD check precedes the spawn",
        );
        assert_before(
            &run,
            "RunEnd::PendingBlocked",
            "RunEnd::SigchldRefused",
            "an unfinished cleanup blocks before the SIGCHLD refusal is reached",
        );
        assert_eq!(run.matches("command.spawn()").count(), 1, "one spawn");
        // The refusal is an immediate return: nothing between the check and
        // its return signals, settles, reaps or spawns.
        let check = run.find("check_sigchld(self.sigchld)").unwrap();
        let refusal = &run[check
            ..check
                + run[check..]
                    .find("RunEnd::SigchldRefused(refusal)")
                    .unwrap()];
        for forbidden in ["(self.signal)(", "settle", "reap", "spawn", "Command::new("] {
            assert!(
                !refusal.contains(forbidden),
                "refusal path contains {forbidden}"
            );
        }
        // Group signals: only the three functions below send one, and the
        // retry checks the pin before it kills.
        assert_eq!(code.matches("(self.signal)(").count(), 4);
        assert_eq!(
            function_body(&code, "fn clear_pending(")
                .matches("(self.signal)(")
                .count(),
            1
        );
        assert_eq!(
            function_body(&code, "fn settle_exited_leader(")
                .matches("(self.signal)(")
                .count(),
            1
        );
        assert_eq!(run.matches("(self.signal)(").count(), 2, "TERM and KILL");
        assert_before(
            &function_body(&code, "fn clear_pending("),
            "LeaderState::PinLost",
            "(self.signal)(",
            "the pin is observed before the retry's kill",
        );
        assert_before(
            &run,
            "LeaderState::PinLost",
            "(self.signal)(leader.pgid, sys::SIGTERM)",
            "the pin is confirmed right before the deadline TERM",
        );
    }

    /// FH-1: the systemd backend runs a command on the calling thread alone.
    /// No reader thread, join, blocking wait or read-to-EOF; the child is
    /// waited for only through the non-blocking `try_wait`; the deadline
    /// arithmetic precedes the one spawn and the owed child is dealt with
    /// before it; a failed wait query is not followed by a signal. Source
    /// shape only; the behavior is proven by the FH-1 tests in
    /// `systemd_service.rs`.
    #[test]
    fn fh1_the_systemd_backend_is_single_threaded_and_bounded() {
        let code = production_source("systemd_service");
        assert_absent(
            "systemd_service",
            &code,
            &[
                "thread::spawn",
                "thread::Builder",
                "thread::scope",
                "spawn_scoped",
                "JoinHandle",
                ".join(",
                "mpsc",
                "async fn",
                "tokio",
                ".wait()",
                "wait_with_output",
                "read_to_end",
                "read_to_string(",
                ".output()",
                "capture_stdout",
                "join_reader",
                "waitpid",
                "waitid",
                "killpg",
                "sigaction",
            ],
        );
        assert_eq!(code.matches("Command::new(").count(), 1, "one spawn site");
        assert_eq!(code.matches(".spawn()").count(), 1, "one spawn");
        // The only wait on a child is the injected non-blocking `try_wait`,
        // the only signal the injected `kill`.
        assert_eq!(code.matches("Child::try_wait").count(), 1);
        assert_eq!(code.matches("Child::kill").count(), 1);
        assert_eq!(
            code.matches("pending: Option<Child>").count(),
            1,
            "one owed child"
        );
        let spawn = function_body(&code, "fn spawn_and_wait(");
        assert_before(
            &spawn,
            "children.discharge()",
            "checked_add(timeout)",
            "an owed child is dealt with before the deadline is computed",
        );
        assert_before(
            &spawn,
            "checked_add(timeout)",
            "command.spawn()",
            "the deadline arithmetic precedes the spawn (NF-1)",
        );
        let wait = function_body(&code, "fn wait_for_child(");
        assert_before(
            &wait,
            "set_nonblocking",
            "capture.drain(",
            "the pipe is made non-blocking before it is read",
        );
        assert!(
            wait.contains("Err(_) => return time_out(children, child, false)"),
            "a failed wait query must not be followed by a signal"
        );
        let time_out = function_body(&code, "fn time_out(");
        assert_before(
            &time_out,
            "may_signal && (ops.kill)",
            "reap(&ops",
            "the kill precedes the bounded reap",
        );
        assert!(
            time_out.contains("children.pending = Some(child)"),
            "an unreaped child is parked"
        );
    }

    /// BL-1 (Stage 15 lifecycle investigation, L-5): an owed child (the
    /// systemd backend's `Children.pending`, the command backend's
    /// `Runner.pending`) lives only inside its backend, and dropping or
    /// replacing a backend neither kills nor reaps it. That is safe only while
    /// the process builds ONE service backend and ONE executor and never
    /// rebuilds or drops either before it exits. Source shape only: this pins
    /// the construction sites, the absence of a rebuild path and the absence
    /// of any `Drop` on the types that own the debt. A change that trips it
    /// needs a new lifecycle review (the owed child must then be handed over,
    /// not lost), not just a new expected value here.
    #[test]
    fn bl1_one_service_backend_and_one_executor_per_process() {
        use std::collections::BTreeMap;
        let count = |needle: &str| -> BTreeMap<String, usize> {
            production_modules()
                .into_iter()
                .filter_map(|(module, code)| {
                    let found = code.matches(needle).count();
                    (found > 0).then_some((module, found))
                })
                .collect()
        };
        let only = |module: &str, found: usize| BTreeMap::from([(module.to_string(), found)]);
        // Construction sites: exactly one each, all inside `LinuxNodeRuntime::new`.
        for needle in [
            "LinuxSystemdServiceBackend::new(",
            "ExternalServiceBackend::new(",
            "ResourceExecutor::new(",
            "ServiceAdapter::Systemd(",
            "ServiceAdapter::External(",
        ] {
            assert_eq!(count(needle), only("linux_node_runtime", 1), "{needle}");
            assert_eq!(
                call_sites(needle),
                set(&[("linux_node_runtime.rs", "new")]),
                "{needle}"
            );
        }
        // The inner constructors: the definition and the single call in `new`.
        assert_eq!(count("with_systemctl_path("), only("systemd_service", 2));
        assert_eq!(count("with_policy("), only("command_service", 2));
        assert_eq!(count("Children::new("), only("systemd_service", 1));
        assert_eq!(count("Runner::new("), only("command_service", 1));
        // The only path to a runtime: process start builds it once.
        assert_eq!(count("LinuxNodeRuntime::new("), only("daemon", 1));
        assert_eq!(
            call_sites("LinuxNodeRuntime::new("),
            set(&[("daemon.rs", "new")])
        );
        assert_eq!(count("LinuxDaemonRuntime::new("), only("daemon_run", 1));
        assert_eq!(
            call_sites("LinuxDaemonRuntime::new("),
            set(&[("daemon_run.rs", "prepare_daemon")])
        );
        assert_eq!(
            count("prepare_daemon("),
            only("daemon_run", 2),
            "definition + one call"
        );
        assert_eq!(
            call_sites("prepare_daemon("),
            set(&[("daemon_run.rs", "run_daemon_inner")])
        );
        // No rebuild or swap path in the types that hold the executor.
        for module in ["resource_executor", "linux_node_runtime", "daemon"] {
            let code = compact(&production_source(module));
            // `daemon` has an unrelated `self.service` (a cached state).
            if module != "daemon" {
                assert!(
                    !code.contains("self.service="),
                    "{module} replaces the service"
                );
            }
            for forbidden in [
                "self.executor=",
                "mem::replace(",
                "mem::take(",
                "mem::swap(",
                "Option<ResourceExecutor",
                "Option<ServiceAdapter",
            ] {
                assert!(!code.contains(forbidden), "{module} contains {forbidden}");
            }
        }
        // No `Drop` on any type that owns, or sits above, the owed child.
        for module in [
            "resource_executor",
            "systemd_service",
            "command_service",
            "linux_node_runtime",
            "daemon",
        ] {
            let code = production_source(module);
            assert!(!code.contains("Drop for "), "{module} implements Drop");
        }
        for (module, code) in production_modules() {
            let code = compact(&code);
            for (at, _) in code.match_indices("Dropfor") {
                // The implementing type, whatever its path or generics.
                let rest = &code[at + "Dropfor".len()..];
                let end = rest
                    .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == ':'))
                    .unwrap_or(rest.len());
                let owner = rest[..end].rsplit("::").next().unwrap_or_default();
                assert!(
                    ![
                        "Children",
                        "ChildOps",
                        "LinuxSystemdServiceBackend",
                        "Runner",
                        "Leader",
                        "Responsibility",
                        "ExternalServiceBackend",
                        "ServiceAdapter",
                        "ResourceExecutor",
                        "LinuxNodeRuntime",
                        "LinuxDaemonRuntime",
                        "Daemon",
                    ]
                    .contains(&owner),
                    "{module}: Drop for {owner}"
                );
            }
        }
    }

    /// The Witness server hosts the existing authority code and adds none:
    /// it computes no term, lease or grant of its own, and has no test seam
    /// or atomic flag in production.
    #[test]
    fn witness_server_hosts_but_does_not_decide() {
        let code = production_source("witness_server");
        assert_absent(
            "witness_server",
            &code,
            &[
                "AtomicBool",
                "HostBoot",
                "current_term",
                "checked_add(1)",
                "observed_term",
                "lease_remaining",
                "renew_after",
            ],
        );
        check_witness_delegation(
            &code,
            &production_source("witness_authority"),
            &production_source("witness_runtime"),
        )
        .unwrap_or_else(|reason| panic!("the Witness server does not delegate: {reason}"));
        // The request handler is reached through the four authority handlers
        // and from nowhere else in production.
        assert_eq!(
            call_sites("handle_pending_witness_request("),
            set(&[
                ("witness_authority.rs", "handle_get_term_authority"),
                ("witness_authority.rs", "handle_lease_request_authority"),
                ("witness_authority.rs", "handle_lease_renew_authority"),
                ("witness_authority.rs", "handle_lease_release_authority"),
            ])
        );
        assert_eq!(
            call_sites("run_until_cancelled("),
            set(&[("witness_server.rs", "serve")])
        );
    }

    /// The Witness server's delegation, checked on source text.
    ///
    /// What it proves: the server answers a request only through the four
    /// existing authority handlers (each of which calls
    /// `handle_pending_witness_request` exactly once and then the existing
    /// `prepare_*` decision), dispatching each message type to its own
    /// handler and sending only the prepared answer; and `serve` creates the
    /// `WitnessExpiryScheduler`, runs it on a thread it supervises (a finished
    /// scheduler is fatal), and cancels and joins it after the accept loop.
    /// The spawn, the supervision and the shutdown are top-level statements
    /// of `serve`, so a dead branch around them is rejected.
    ///
    /// What it does not prove: that the handlers decide correctly (their own
    /// tests do), or the runtime behavior of the threads. It checks shape,
    /// not execution.
    fn check_witness_delegation(
        server: &str,
        authority: &str,
        runtime: &str,
    ) -> Result<(), String> {
        if !runtime.contains("pub fn handle_pending_witness_request(") {
            return Err("witness_runtime lacks handle_pending_witness_request".into());
        }
        for (handler, prepare) in [
            ("handle_get_term_authority", "prepare_get_term_response("),
            (
                "handle_lease_request_authority",
                "prepare_lease_request_authority(",
            ),
            (
                "handle_lease_renew_authority",
                "prepare_lease_renew_authority(",
            ),
            (
                "handle_lease_release_authority",
                "prepare_lease_release_authority(",
            ),
        ] {
            let signature = format!("pub fn {handler}<");
            if !authority.contains(&signature) {
                return Err(format!("witness_authority lacks {handler}"));
            }
            let handler_body = compact(&function_body(authority, &signature));
            if handler_body.matches("handle_pending_witness_request(").count() != 1
                || !handler_body.starts_with(
                    "{letobservation=handle_pending_witness_request(connection,pending).map_err(WitnessAuthorityError::Runtime)?;",
                )
                || !handler_body.contains(prepare)
            {
                return Err(format!("{handler} no longer delegates to the request handler"));
            }
        }
        // Dispatch: each message type to its own handler; the server sends
        // only what the handler prepared.
        let connection = compact(&function_body(server, "fn serve_connection<"));
        for needle in [
            "ProtocolMessage::GetTerm=>{matchhandle_get_term_authority(&mutwitness,&pending,&store){Ok(prepared)=>send_prepared_term_status(&mutwitness,&mutprocess,prepared,",
            "ProtocolMessage::LeaseRequest(_)=>{handle_lease_request_authority(&mutwitness,&pending,&store)}",
            "ProtocolMessage::LeaseRenew(_)=>{handle_lease_renew_authority(&mutwitness,&pending,&store)}",
            "_=>handle_lease_release_authority(&mutwitness,&pending,&store),",
            "Ok(prepared)=>send_prepared_lease_response(&mutwitness,&mutprocess,prepared,",
        ] {
            if !connection.contains(needle) {
                return Err(format!("serve_connection lost its dispatch: {needle}"));
            }
        }
        for handler in [
            "handle_get_term_authority(",
            "handle_lease_request_authority(",
            "handle_lease_renew_authority(",
            "handle_lease_release_authority(",
        ] {
            if connection.matches(handler).count() != 1 {
                return Err(format!("serve_connection must call {handler} exactly once"));
            }
        }
        if server.contains("handle_pending_witness_request(") || server.contains("prepare_") {
            return Err("the server reaches below the authority handlers".into());
        }
        // The scheduler: created, run on a supervised thread, cancelled and
        // joined after the accept loop. Top-level statements of `serve`.
        let serve = function_body(server, "pub(crate) fn serve<");
        let statements = top_level_statements(&serve);
        let compacted: Vec<String> = statements.iter().map(|s| compact(s)).collect();
        let find = |prefix: &str| compacted.iter().position(|s| s.starts_with(prefix));
        let Some(created) = find("letscheduler=WitnessExpiryScheduler::new(SCHEDULER_RETRY);")
        else {
            return Err("serve does not create the WitnessExpiryScheduler".into());
        };
        let Some(spawned) =
            find("letscheduler_handle:JoinHandle<Result<(),String>>=std::thread::spawn(")
        else {
            return Err("the scheduler thread is not spawned at the top level of serve".into());
        };
        if !compacted[spawned]
            .contains("scheduler.run_until_cancelled(&scheduler_store,&scheduler_cancel)")
        {
            return Err("the scheduler thread does not run the scheduler".into());
        }
        let Some(accepting) = find("while!shutdown.is_requested(){") else {
            return Err("serve has no top-level accept loop".into());
        };
        let supervision = "ifscheduler_handle.as_ref().is_some_and(JoinHandle::is_finished){";
        if !compacted[accepting].contains(supervision)
            || !compacted[accepting].contains("shutdown.fail(reason);break;}")
        {
            return Err("the accept loop no longer treats a finished scheduler as fatal".into());
        }
        let Some(cancelled) = find("cancel.cancel();") else {
            return Err("serve does not cancel the scheduler at the top level".into());
        };
        let Some(joined) = find("ifletSome(handle)=scheduler_handle{") else {
            return Err("serve does not join the scheduler".into());
        };
        if !(created < spawned
            && spawned < accepting
            && accepting < cancelled
            && cancelled < joined)
        {
            return Err(
                "the scheduler is not created, supervised, cancelled and joined in order".into(),
            );
        }
        if !compacted[joined].contains("handle.join()") {
            return Err("the scheduler handle is not joined".into());
        }
        Ok(())
    }

    /// Self-check of `check_witness_delegation`: the real sources pass, and
    /// each way of making the server stop delegating or stop running /
    /// supervising the scheduler is rejected.
    #[test]
    fn witness_delegation_check_rejects_removed_handlers_and_scheduler() {
        let server = production_source("witness_server");
        let authority = production_source("witness_authority");
        let runtime = production_source("witness_runtime");
        check_witness_delegation(&server, &authority, &runtime).expect("the real sources pass");

        let server_mutations: Vec<(&str, String)> = vec![
            (
                "handler call removed (GetTerm)",
                server.replacen(
                    "match handle_get_term_authority(&mut witness, &pending, &store) {",
                    "match Err::<PreparedTermStatus, _>(WitnessAuthorityError::NotGetTerm) {",
                    1,
                ),
            ),
            (
                "handler call removed (LeaseRenew)",
                server.replacen(
                    "handle_lease_renew_authority(&mut witness, &pending, &store)",
                    "handle_lease_request_authority(&mut witness, &pending, &store)",
                    1,
                ),
            ),
            (
                "the server decides on its own",
                server.replacen(
                    "handle_lease_release_authority(&mut witness, &pending, &store),",
                    "prepare_lease_release_authority(&store, &observation, pending.message().unsigned()),",
                    1,
                ),
            ),
            (
                "the request handler called directly",
                server.replacen(
                    "let result = match &pending.message().unsigned().message {",
                    "let _ = handle_pending_witness_request(&mut witness, &pending);\n        let result = match &pending.message().unsigned().message {",
                    1,
                ),
            ),
            (
                "scheduler never created",
                server.replacen(
                    "let scheduler = WitnessExpiryScheduler::new(SCHEDULER_RETRY);",
                    "let scheduler = WitnessExpiryScheduler::new(std::time::Duration::ZERO);",
                    1,
                ),
            ),
            (
                "scheduler thread does not run the scheduler",
                server.replacen(
                    ".run_until_cancelled(&scheduler_store, &scheduler_cancel)",
                    ".cancellation_only(&scheduler_store, &scheduler_cancel)",
                    1,
                ),
            ),
            (
                "scheduler spawn in a dead branch",
                server.replacen(
                    "let scheduler_handle: JoinHandle<Result<(), String>> = std::thread::spawn(move || {",
                    "if false { std::thread::spawn(|| ()); }\n    let scheduler_handle: JoinHandle<Result<(), String>> = { let _ = 0; std::thread::spawn(move || {",
                    1,
                )
                .replacen(
                    "    let slots = Arc::new(ConnectionSlots {",
                    "    }); let slots = Arc::new(ConnectionSlots {",
                    1,
                ),
            ),
            (
                "scheduler supervision removed",
                server.replacen(
                    ".is_some_and(JoinHandle::is_finished)",
                    ".is_some_and(|_| false)",
                    1,
                ),
            ),
            (
                "a finished scheduler no longer fails the server",
                server.replacen("shutdown.fail(reason);\n            break;", "break;", 1),
            ),
            (
                "scheduler never cancelled",
                server.replacen("    cancel.cancel();\n", "", 1),
            ),
            (
                "scheduler never joined",
                server.replacen(
                    "if let Some(handle) = scheduler_handle {\n        let _ = handle.join();\n    }",
                    "if let Some(_handle) = scheduler_handle {}",
                    1,
                ),
            ),
        ];
        for (label, mutated) in server_mutations {
            assert_ne!(mutated, server, "{label}: the mutation did not apply");
            let verdict = check_witness_delegation(&mutated, &authority, &runtime);
            assert!(verdict.is_err(), "the check accepted: {label}");
            println!("{label}: {}", verdict.unwrap_err());
        }
        let authority_mutations: Vec<(&str, String)> = vec![
            (
                "an authority handler stops calling the request handler",
                authority.replacen(
                    "let observation = handle_pending_witness_request(connection, pending)\n        .map_err(WitnessAuthorityError::Runtime)?;\n    prepare_lease_renew_authority(",
                    "let observation = WitnessRequestObservation::GetTerm { request_id: RequestId::new(\"x\"), sender_node_id: NodeId::new(\"x\"), term: Term(0) };\n    prepare_lease_renew_authority(",
                    1,
                ),
            ),
            (
                "an authority handler is gone",
                authority.replacen("pub fn handle_get_term_authority<", "pub fn handle_get_term_other<", 1),
            ),
        ];
        for (label, mutated) in authority_mutations {
            assert_ne!(mutated, authority, "{label}: the mutation did not apply");
            assert!(
                check_witness_delegation(&server, &mutated, &runtime).is_err(),
                "the check accepted: {label}"
            );
        }
        let no_runtime = runtime.replacen(
            "pub fn handle_pending_witness_request(",
            "pub fn handle_pending_witness_other(",
            1,
        );
        assert!(check_witness_delegation(&server, &authority, &no_runtime).is_err());
    }

    /// The health filter has one production observer and one consumer.
    #[test]
    fn health_filter_is_advisory() {
        let daemon = production_source("daemon");
        assert_eq!(daemon.matches("health_filter.observe(").count(), 1);
        assert_eq!(daemon.matches("warn_health_unhealthy(").count(), 1);
        for module in [
            "resource_workflow",
            "resource_executor",
            "node_lease_authority",
        ] {
            let code = production_source(module);
            assert!(
                !code.contains("health_hysteresis"),
                "{module} reads the filtered health"
            );
        }
    }
}

// ===========================================================================
// Prototype v0.2: the manual control plane (`src/manual/`)
//
// The manual control plane is an operator-driven orchestrator, not an HA
// engine. These guards keep it a separate island: it must not reach the HA
// daemon's promotion / lease / resource-mutation layers, none of those layers
// may reach it, its only shell-free process execution is `manual::exec`, and
// every mutating agent operation passes the exclusive-mode check.
// ===========================================================================

/// The production code of a file of the plane as `manual_scan` reads it:
/// comments removed, test-only items cut out by bracket matching (not by the
/// words "mod tests"), white space squashed, string literals kept as written.
/// A string that says `//` or `mod tests` therefore hides nothing (audit
/// RA-E-05: the old helper cut the file at the text "mod tests" and did not
/// know strings).
fn production_code_of(module: &str, text: &str) -> String {
    manual_scan::load(&["crate", "manual", module], text).with_literals()
}

/// Production code (see [`production_code_of`]) of one file under
/// `src/manual/`.
fn manual_production_source(file: &str) -> String {
    let path = manifest_dir().join("src").join("manual").join(file);
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {path:?}: {e}"));
    production_code_of(file.trim_end_matches(".rs"), &text)
}

#[test]
fn the_production_view_is_not_fooled_by_strings_that_look_like_comments_or_test_modules() {
    // The audit's forms (RA-E-05): the old helper cut a file at the text
    // "mod tests" and stripped from a `//` inside a string, so a call placed
    // after such a string was not seen by the checks that look for it.
    let text = "const A: &str = \"//\";\nconst B: &str = \"mod tests\";\n\
                fn f() { service_action(u, a); }\n\
                #[cfg(test)]\nmod tests { fn t() { only_in_tests(); } }\n";
    let code = production_code_of("chrony_agent", text);
    assert!(code.contains("service_action("), "{code}");
    assert!(!code.contains("only_in_tests("), "{code}");
    // Literals are kept as written, so a check can still read what they say.
    assert!(code.contains("\"mod tests\""), "{code}");
    // The operation list is read from the squashed form.
    let proto = production_code_of(
        "proto",
        "pub(crate) mod op {\n    pub(crate) const PING: &str = \"ping\";\n    \
         pub(crate) const X_Y: &str = \"x.y\";\n}\n",
    );
    assert_eq!(op_constants(&proto), ["PING", "X_Y"]);
}

/// Every `.rs` file below `src/manual/`, sub-directories included, as a path
/// relative to it.
fn manual_files() -> Vec<String> {
    let base = manifest_dir().join("src").join("manual");
    let mut files: Vec<String> = manual_scan::walk_rs(&base)
        .iter()
        .map(|p| {
            p.strip_prefix(&base)
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    files.sort();
    files
}

fn src_dir() -> PathBuf {
    manifest_dir().join("src")
}

fn src_tops() -> std::collections::BTreeSet<String> {
    manual_scan::top_level_modules(&src_dir())
}

/// A file under `src/`, loaded for the checks of `manual_scan`.
fn load_src(path: &Path) -> manual_scan::Source {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {path:?}: {e}"));
    let module = manual_scan::module_of(&src_dir(), path);
    let module: Vec<&str> = module.iter().map(String::as_str).collect();
    manual_scan::load(&module, &text)
}

/// The manual control plane has no dependency on the HA engine except the one
/// audited, side-effect-free executable trust check. An allow list: the only
/// things a file of the plane may reach under `crate::` are the plane itself
/// and that one function, however the path is spelled (`use` groups, aliases,
/// `super::super`, blanks, line breaks, `#[path]`, sub-directories; see
/// `manual_scan` and its evasion tests).
#[test]
fn manual_plane_does_not_reach_the_ha_engine() {
    let tops = src_tops();
    let mut violations = Vec::new();
    let base = manifest_dir().join("src").join("manual");
    let files = manual_scan::walk_rs(&base);
    assert!(files.len() >= 10, "src/manual must exist: {files:?}");
    for path in &files {
        let who = format!(
            "manual/{}",
            path.strip_prefix(&base).unwrap().to_string_lossy()
        );
        violations.extend(manual_scan::check_manual_file(&who, &load_src(path), &tops));
    }
    assert!(violations.is_empty(), "{violations:#?}");
}

/// No HA module depends on the manual plane in any spelling; only the three
/// CLI wiring modules may name it (and then only the entry points, below).
/// Sub-directories of `src/` are scanned too.
#[test]
fn ha_engine_does_not_reach_the_manual_plane() {
    let tops = src_tops();
    let mut violations = Vec::new();
    let manual_dir = manifest_dir().join("src").join("manual");
    let mut scanned = 0;
    for path in manual_scan::walk_rs(&src_dir()) {
        if path.starts_with(&manual_dir) {
            continue;
        }
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        if path.parent() == Some(src_dir().as_path())
            && matches!(name.as_str(), "main" | "cli" | "status")
        {
            continue;
        }
        scanned += 1;
        violations.extend(manual_scan::check_ha_file(&name, &load_src(&path), &tops));
    }
    assert!(scanned >= 40, "the HA modules were not found ({scanned})");
    assert!(
        violations.is_empty(),
        "HA modules reaching src/manual: {violations:#?}"
    );
}

/// The wiring modules use the plane only through the command entry points and
/// the status overview, each named completely (not by prefix); they gain no
/// mutation API.
#[test]
fn cli_wiring_reaches_only_the_manual_run_entry_points() {
    let tops = src_tops();
    let mut violations = Vec::new();
    for module in ["main", "cli", "status"] {
        let path = source_path(module);
        violations.extend(manual_scan::check_wiring_file(
            module,
            &load_src(&path),
            &tops,
        ));
    }
    assert!(violations.is_empty(), "{violations:#?}");
}

/// Every marker of MKM-13.5-07 that exists in the HA wiring guard is also
/// looked for in the manual plane; a use there needs a listed exception with
/// its reason, and an exception nobody uses any more is removed. (The
/// exceptions are for the plane, a separate island under the Owner's
/// limited, Prototype-only approval (`prototype/v0.2/LIMITATIONS.md` item 44);
/// the HA daemon's own guard above is not relaxed.)
#[test]
fn manual_plane_uses_forbidden_markers_only_where_an_exception_says_so() {
    // The list in `manual_scan` must contain every marker of the HA guard.
    let this = fs::read_to_string(manifest_dir().join("tests").join("architecture.rs")).unwrap();
    let guard = this
        .find("fn mkm_arch_015_no_pid_ipc_or_control_plane()")
        .unwrap();
    let list_start = guard
        + this[guard..]
            .find("const FORBIDDEN_MARKERS: &[&str] = &[")
            .unwrap();
    let list_end = list_start + this[list_start..].find("];").unwrap();
    for line in this[list_start..list_end].lines().skip(1) {
        if let Some(marker) = line
            .trim()
            .strip_prefix('"')
            .and_then(|l| l.split('"').next())
        {
            assert!(
                manual_scan::FORBIDDEN_MARKERS.contains(&marker),
                "manual_scan::FORBIDDEN_MARKERS lacks {marker:?} of MKM-13.5-07"
            );
        }
    }
    let tops = src_tops();
    let base = manifest_dir().join("src").join("manual");
    let mut used: std::collections::BTreeSet<(String, String)> = Default::default();
    for path in manual_scan::walk_rs(&base) {
        let file = path
            .strip_prefix(&base)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        for marker in manual_scan::markers_used(&load_src(&path)) {
            used.insert((file.clone(), marker.to_string()));
        }
    }
    let mut violations = Vec::new();
    for (file, marker) in &used {
        let listed = manual_scan::MARKER_EXCEPTIONS
            .iter()
            .any(|(f, m, why)| f == file && m == marker && !why.is_empty());
        if !listed {
            violations.push(format!(
                "manual/{file} uses {marker:?} without a listed exception"
            ));
        }
    }
    for (f, m, _) in manual_scan::MARKER_EXCEPTIONS {
        if !used.contains(&((*f).to_string(), (*m).to_string())) {
            violations.push(format!("stale exception: {f} {m}"));
        }
    }
    let _ = tops;
    assert!(violations.is_empty(), "{violations:#?}");
}

/// The system calls the plane makes through `libc` are the listed ones, per
/// file, each with its reason.
#[test]
fn manual_plane_libc_use_is_listed_per_file() {
    let tops = src_tops();
    let base = manifest_dir().join("src").join("manual");
    let mut violations = Vec::new();
    // Every allowance carries its reason (audit RA-E-03: the reason of the
    // `libc` allow list was never checked).
    for (file, items, reason) in manual_scan::LIBC_ALLOWED {
        if !items.is_empty() && reason.trim().is_empty() {
            violations.push(format!("manual/{file}: libc allowance without a reason"));
        }
    }
    for path in manual_scan::walk_rs(&base) {
        let file = path
            .strip_prefix(&base)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let items = manual_scan::libc_items(&load_src(&path), &tops);
        let allowed: Vec<&str> = manual_scan::LIBC_ALLOWED
            .iter()
            .filter(|(f, _, _)| *f == file)
            .flat_map(|(_, items, _)| items.iter().copied())
            .collect();
        for item in items {
            if !allowed.contains(&item.as_str()) {
                violations.push(format!(
                    "manual/{file} uses libc::{item} without a listed reason"
                ));
            }
        }
    }
    assert!(violations.is_empty(), "{violations:#?}");
}

/// External processes are started in exactly one place, never through a
/// shell, and the SSH policy never disables host-key checking. Aliases
/// (`use std::process::{Command as C}`), blanks, other shells, `libc` exec
/// functions, split or concatenated option strings and sub-directories are
/// covered; the literals of the one function that builds the ssh arguments
/// are pinned as well.
#[test]
fn manual_plane_spawns_only_through_exec_and_never_a_shell() {
    let tops = src_tops();
    let base = manifest_dir().join("src").join("manual");
    let mut violations = Vec::new();
    for path in manual_scan::walk_rs(&base) {
        let file = path
            .strip_prefix(&base)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        violations.extend(manual_scan::check_spawn_file(
            &format!("manual/{file}"),
            &load_src(&path),
            &tops,
            file == "exec.rs",
        ));
    }
    assert!(violations.is_empty(), "{violations:#?}");

    // `remote.rs::argv` is where every ssh option is spelled: its literals are
    // exactly these. A new or changed option needs this list (and a review).
    let remote = load_src(&base.join("remote.rs"));
    let mut found: Vec<String> = {
        let start = remote.code.find("fn argv(").expect("argv");
        let end = start
            + remote.code[start..]
                .find("impl Remote for SshRemote")
                .expect("end of argv");
        remote.literals_in(&remote.code[start..end])
    };
    found.sort();
    let mut expected: Vec<&str> = vec![
        "-F",
        "/dev/null",
        "-i",
        "-T",
        "ProxyCommand=none",
        "PermitLocalCommand=no",
        "RequestTTY=no",
        "BatchMode=yes",
        "IdentitiesOnly=yes",
        "PasswordAuthentication=no",
        "KbdInteractiveAuthentication=no",
        "StrictHostKeyChecking=accept-new",
        "UserKnownHostsFile={}",
        "HostKeyAlias={}",
        "ConnectTimeout={}",
        "ServerAliveInterval=5",
        "ServerAliveCountMax=3",
        "ControlMaster=no",
        "ControlPath=none",
        "ForwardAgent=no",
        "ClearAllForwardings=yes",
        "LogLevel=ERROR",
        "-o",
        "--",
        "{}@{}",
        "{} -n {} agent",
    ];
    expected.sort_unstable();
    assert_eq!(
        found, expected,
        "the ssh argument literals changed; review them, then update this list"
    );
}

/// Agent operations, by what they may do. A new operation must be placed in
/// exactly one class: that is the decision this guard forces (audit EX-08).
///
/// * gated: changes something the HA daemon also manages (a service unit, the
///   ownership record). Must call `require_exclusive` *before* its first
///   change and must return when the gate says no.
/// * read-only: changes nothing (`chrony.validate` writes and removes a
///   private temporary copy only).
/// * file-only: changes chrony configuration files only, which the HA daemon
///   never touches. Deliberately NOT gated (EX-06): a gate there stopped the
///   rollback of an apply half way.
const GATED_OPS: &[&str] = &[
    "SERVICE_CONTROL",
    "CONTROL_INTENT_BEGIN",
    "LEASE_INIT",
    "LEASE_ACQUIRE",
    "LEASE_PHASE",
    "LEASE_COMMIT",
    "LEASE_ABORT",
    "LEASE_RECONCILE",
];
const READ_ONLY_OPS: &[&str] = &[
    "PING",
    "SERVICE_STATUS",
    "PROBE",
    "CHRONY_STATE",
    "CHRONY_READ",
    "CHRONY_VALIDATE",
    "CONTROL_INTENT_STATUS",
    "LEASE_STATUS",
];
/// Operations that change only the durable barrier's cleanup state. They
/// take the kernel lock (no HA process may run while the record disappears)
/// but not the HA-mask proof: a refused command must still be able to remove
/// its own no-effect barrier after the HA state changed under it.
const LOCK_ONLY_OPS: &[&str] = &["CONTROL_INTENT_RESOLVE"];
const FILE_ONLY_OPS: &[&str] = &[
    "CHRONY_BACKUP",
    "CHRONY_STAGE",
    "CHRONY_PUBLISH",
    "CHRONY_RESTORE",
    "CHRONY_CLEANUP",
];

/// The names of the `op::*` constants declared in `src/manual/proto.rs`.
fn declared_agent_ops() -> Vec<String> {
    op_constants(&manual_production_source("proto.rs"))
}

/// The constants of `pub(crate) mod op { .. }` in squashed code.
fn op_constants(proto: &str) -> Vec<String> {
    let start = proto.find("pub(crate)mod op{").expect("op module");
    let body = &proto[start + "pub(crate)mod op{".len()..];
    let body = &body[..body.find('}').expect("end of op module")];
    body.split(';')
        .filter_map(|item| {
            let item = item.trim();
            // A constant of another visibility would never be classified:
            // refuse it instead of skipping it (final re-audit N-3, form 5).
            assert!(
                item.is_empty() || item.starts_with("pub(crate)const "),
                "unexpected item in the op module: {item:?}"
            );
            item.strip_prefix("pub(crate)const ")
                .and_then(|rest| rest.split(':').next())
                .map(str::to_string)
        })
        .collect()
}

/// Every agent operation is classified, and every one that changes something
/// the HA daemon also manages first proves the exclusion from it, in the
/// right order, using the answer.
#[test]
fn every_mutating_agent_operation_checks_exclusive_mode() {
    // 1. Every declared operation has exactly one class.
    let declared = declared_agent_ops();
    assert!(
        declared.len() >= 19,
        "operation list not read: {declared:?}"
    );
    for name in &declared {
        let classes = [GATED_OPS, READ_ONLY_OPS, FILE_ONLY_OPS, LOCK_ONLY_OPS]
            .iter()
            .filter(|class| class.contains(&name.as_str()))
            .count();
        assert_eq!(
            classes, 1,
            "agent operation {name} must be listed in exactly one of GATED_OPS / READ_ONLY_OPS / \
             FILE_ONLY_OPS (tests/architecture.rs)"
        );
    }
    for name in GATED_OPS
        .iter()
        .chain(READ_ONLY_OPS)
        .chain(FILE_ONLY_OPS)
        .chain(LOCK_ONLY_OPS)
    {
        assert!(declared.iter().any(|d| d == name), "stale entry {name}");
    }

    // The checks run on the squashed code of the agent: no comments, no
    // literals (a name inside a string counts for nothing), test items cut
    // out by bracket matching (`manual_scan::check_gate` and its evasion
    // tests: a discarded answer, a gate after the change, a gate inside
    // `if false`, a gate that does not return).
    let agent = load_src(&manifest_dir().join("src").join("manual").join("agent.rs")).code;

    // 2. service.control: gate, then fencing admission, then the action.
    let service_arm = &agent[agent.find("op::SERVICE_CONTROL=>").expect("service arm")..];
    let service_arm = &service_arm[..service_arm.find("op::PROBE=>").expect("probe arm")];
    manual_scan::check_gate(service_arm, &[".admit(", "service_action("], 1)
        .unwrap_or_else(|e| panic!("service.control: {e}"));

    // 3. lease writes: one gate before the dispatch of every writing op, after
    // the read-only `lease.status` returned.
    let lease = function_body(&agent, "fn handle_lease(");
    manual_scan::check_gate(
        &lease,
        &[
            "store.init(",
            "store.acquire(",
            "store.phase(",
            "store.commit(",
            "store.abort(",
            "store.reconcile(",
        ],
        1,
    )
    .unwrap_or_else(|e| panic!("lease writes: {e}"));
    let gate = lease.find("require_exclusive").unwrap();
    let status_return = lease.find("op::LEASE_STATUS").expect("status early return");
    assert!(status_return < gate, "lease.status stays readable");
    for name in GATED_OPS.iter().filter(|n| n.starts_with("LEASE_")) {
        assert!(
            lease.contains(&format!("op::{name}=>")),
            "handle_lease has no arm for {name}"
        );
    }

    // 3a. The durable manual-operation barrier: `begin` takes the normal
    // gate; `status` returns before it; `resolve` is cleanup and takes only
    // the kernel lock (it must still work when the HA mask changed under a
    // command that changed nothing).
    let intent = function_body(&agent, "fn handle_control_intent(");
    manual_scan::check_gate(&intent, &["crate::manual_barrier::begin("], 1)
        .unwrap_or_else(|e| panic!("control.intent.begin: {e}"));
    let intent_gate = intent.find("require_exclusive").expect("intent gate");
    let intent_status = intent.find("CONTROL_INTENT_STATUS").expect("status branch");
    assert!(
        intent_status < intent_gate,
        "control.intent.status stays readable while HA runs"
    );
    let resolve_at = intent
        .find("CONTROL_INTENT_RESOLVE")
        .expect("resolve branch");
    let resolve_end = intent[resolve_at..]
        .find("let proof=")
        .map_or(intent.len(), |offset| resolve_at + offset);
    let resolve_body = &intent[resolve_at..resolve_end];
    assert!(
        resolve_body
            .find("acquire_control_lock")
            .is_some_and(|lock| {
                lock < resolve_body
                    .find("manual_barrier::resolve(")
                    .unwrap_or(usize::MAX)
            }),
        "control.intent.resolve must hold the kernel lock before deleting the record"
    );
    assert!(
        !resolve_body.contains("require_exclusive"),
        "resolve must not depend on the HA mask it may have to clean up after"
    );

    // 3b. Every arm of the dispatch is an `op::NAME` constant, so that the
    // classification above sees every operation: a literal arm
    // (`"x.force" => ..`) would be one nobody classified (audit RA-E-05).
    // Only the arms of the operation match itself count (a string pattern on
    // an argument is not one), and the match must be found: `handle` of
    // agent.rs only wraps `dispatch`, an earlier form of this check looked at
    // the wrapper and so at nothing (final re-audit, G-literal-arm).
    let chrony_code = load_src(
        &manifest_dir()
            .join("src")
            .join("manual")
            .join("chrony_agent.rs"),
    )
    .code;
    // `whole`: the function holds no string argument patterns of its own, so
    // every literal arm anywhere in it (also in a nested match of the
    // fallback arm) is a finding; `dispatch` has `matches!(action, "start" |
    // ..)` on an argument and is checked at the top level of its match only.
    for (who, body, head, whole) in [
        (
            "agent.rs dispatch",
            function_body(&agent, "fn dispatch("),
            "match request.op.as_str()",
            false,
        ),
        ("agent.rs handle_lease", lease.clone(), "match name", true),
        (
            "chrony_agent.rs handle",
            function_body(&chrony_code, "fn handle("),
            "match name",
            true,
        ),
    ] {
        if whole {
            assert_eq!(
                manual_scan::literal_match_arms(&body),
                0,
                "{who}: a string literal arm (also a nested one)"
            );
        } else {
            assert_eq!(
                manual_scan::literal_arrow_arms(&body),
                0,
                "{who}: a nested match has a string literal arm"
            );
        }
        assert!(
            body.matches("op::").count() >= 3,
            "{who}: the checked body has no operation arms ({} bytes)",
            body.len()
        );
        assert_eq!(
            manual_scan::literal_arms_of_match(&body, head),
            0,
            "{who}: an operation is dispatched by a string literal"
        );
    }

    // 4. The file-only chrony operations are deliberately not gated and never
    // touch a service unit (EX-06).
    let chrony = manual_production_source("chrony_agent.rs");
    assert!(
        !chrony.contains("require_exclusive"),
        "chrony file operations must not depend on the HA daemon (audit EX-06)"
    );
    assert!(
        !chrony.contains("service_action("),
        "chrony file operations must not change a service unit"
    );

    // 5. Only the agent's own exclusion module decides what "proven" means.
    let exclusion = manual_production_source("exclusion.rs");
    assert!(
        function_body(&exclusion, "pub(crate)fn refusal(")
            .contains("HaState::Masked|HaState::Absent=>None"),
        "only a masked or acknowledged-absent HA daemon passes"
    );
}

/// v0.3 (audit B LOW-2, mutant G1): a value of the zero-sized `ExclusiveProof`
/// can be made out of nothing by `&*(1usize as *const _)`, with the type
/// inferred, so the naming rule of the proof guard is not enough. Every
/// `unsafe` block of the manual plane must therefore be a call into `libc`,
/// and may not turn an address into a reference (`&*`, `as *const`,
/// `as *mut`) except the one signal-handler cast in `signals.rs`.
#[test]
fn no_unsafe_block_of_the_manual_plane_can_make_a_reference_out_of_nothing() {
    let squash = |text: &str| -> String { text.chars().filter(|c| !c.is_whitespace()).collect() };
    let mut blocks = 0usize;
    for path in manual_scan::walk_rs(&src_dir()) {
        let name = path.strip_prefix(src_dir()).unwrap().display().to_string();
        let file = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.starts_with("manual")
            || file.ends_with("_tests.rs")
            || file == "testkit.rs"
            || file == "fakes.rs"
        {
            continue;
        }
        let code = squash(&load_src(&path).code);
        for (at, _) in code.match_indices("unsafe{") {
            // the matching close brace
            let mut depth = 0usize;
            let mut end = code.len();
            for (i, c) in code[at + 6..].char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = at + 6 + i + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let block = &code[at..end];
            blocks += 1;
            assert!(
                block.contains("libc::"),
                "{name}: an `unsafe` block that is not a call into libc: {block}"
            );
            if file != "signals.rs" {
                for bad in [
                    "&*",
                    "as*const",
                    "as*mut",
                    "ptr::read",
                    "ptr::write",
                    "transmute",
                ] {
                    assert!(
                        !block.contains(bad),
                        "{name}: `{bad}` inside an `unsafe` block could make a reference out of an address: {block}"
                    );
                }
            }
        }
    }
    assert!(
        blocks >= 8,
        "the scan found only {blocks} unsafe blocks; it no longer reads the sources"
    );
}

/// The exclusion from the HA daemon is a **type**: `ExclusiveProof` can be
/// made only by `AgentEnv::require_exclusive`, and the operations that change a
/// service unit or the ownership record take one as an argument. This test pins
/// what makes that true (final R7, R-5/R-6): a route that does not pass the
/// gate, by whatever dispatch shape, does not compile, so the text checks of
/// the dispatch are no longer the only protection.
#[test]
fn the_exclusion_proof_can_only_be_made_by_the_gate_and_the_writers_take_it() {
    let squash = |text: &str| -> String { text.chars().filter(|c| !c.is_whitespace()).collect() };
    let manual = src_dir().join("manual");
    let exclusion_raw = fs::read_to_string(manual.join("exclusion.rs")).expect("read exclusion.rs");

    // 1. The type: a private field, no derive, no trait that copies or makes it.
    let at = exclusion_raw
        .find("pub(crate) struct ExclusiveProof {")
        .expect("the private-field ExclusiveProof struct in exclusion.rs");
    let above: Vec<&str> = exclusion_raw[..at].lines().rev().take(12).collect();
    let attribute_block: String = above
        .iter()
        .take_while(|l| {
            let t = l.trim_start();
            t.starts_with("///") || t.starts_with("#[") || t.is_empty() || t.starts_with("//")
        })
        .copied()
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !attribute_block.contains("derive"),
        "ExclusiveProof must not derive anything (Clone, Copy, Default would copy or make it)"
    );

    // 2. Over all production code of the crate.
    let mut prove_calls = Vec::new();
    let mut state_path_uses: Vec<(String, usize, usize)> = Vec::new();
    for path in manual_scan::walk_rs(&src_dir()) {
        let file = path.file_name().unwrap().to_string_lossy().into_owned();
        // Files that only exist in the test build (`#[cfg(test)] mod x;`).
        if file.ends_with("_tests.rs") || file == "testkit.rs" || file == "fakes.rs" {
            continue;
        }
        let source = load_src(&path);
        let code = squash(&source.code);
        let name = path.strip_prefix(src_dir()).unwrap().display().to_string();
        assert!(
            !code.contains("forExclusiveProof"),
            "{name}: a trait implemented for ExclusiveProof could make or copy it"
        );
        // The test constructor exists only in the test build; a production file
        // that used it would pass the tests and not compile for release.
        assert!(
            !code.contains("ExclusiveProof::for_test("),
            "{name}: production code uses the test constructor of the proof"
        );
        assert!(
            !code.contains("ExclusiveProof::issue"),
            "{name}: the old constructor `issue` is back"
        );
        if name.starts_with("manual") {
            // A `static` that keeps a proof would let a stale one be reused.
            for (at, _) in code.match_indices("static") {
                let tail: String = code[at..].chars().take(160).collect();
                let statement = tail.split(';').next().unwrap_or("");
                assert!(
                    !statement.contains("ExclusiveProof"),
                    "{name}: a static holds a proof: {statement}"
                );
            }
            for forged in [
                "zeroed",
                "transmute",
                "MaybeUninit",
                "assume_init",
                "dangling",
                "from_raw_parts",
                "uninitialized",
                "ManuallyDrop",
                "ptr::copy",
            ] {
                assert!(
                    !code.contains(forged),
                    "{name}: `{forged}` could forge a value of a type that proves something"
                );
            }
            // v0.3 (audit B LOW-2, mutant G1): the type may be *named* only as a
            // borrowed parameter (`&ExclusiveProof`), as the value of the one
            // gate (`Result<ExclusiveProof,..>`), or in a `use`. A raw pointer
            // to it (`*const ExclusiveProof`, `&*(1usize as *const ..)`,
            // `NonNull<ExclusiveProof>`, `ptr::read`) is how a zero-sized proof
            // can be made out of nothing.
            if name != "manual/exclusion.rs" {
                for (at, _) in code.match_indices("ExclusiveProof") {
                    let before: String = code[..at]
                        .chars()
                        .rev()
                        .take(7)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect();
                    let statement_start = code[..at].rfind([';', '}']).map_or(0, |i| i + 1);
                    let statement = &code[statement_start..at];
                    let allowed = before.ends_with('&')
                        || before.ends_with("Result<")
                        || statement.starts_with("use")
                        || statement.starts_with("pub(crate)use");
                    assert!(
                        allowed,
                        "{name}: `ExclusiveProof` is named in a way that is not a borrowed parameter, \
                         the gate's result or a `use`: ...{before}ExclusiveProof"
                    );
                }
                for forged in ["ptr::read", "read_unaligned", "read_volatile", "NonNull"] {
                    assert!(
                        !code.contains(forged),
                        "{name}: `{forged}` in the manual plane could make a reference to a zero-sized proof"
                    );
                }
            }
        }
        if name.starts_with("manual") {
            // every spelling of the two names counts: a field access, a destructuring
            // pattern, a method of the same name (audit v0.3 LOW-1, mutant AG4)
            let fence = code.matches("fence_state").count();
            let lease = code.matches("lease_state").count();
            if fence + lease > 0 {
                state_path_uses.push((name.clone(), fence, lease));
            }
        }
        for (at, _) in code.match_indices(".prove(") {
            prove_calls.push((name.clone(), code[..at].len()));
        }
        // `HaReport::prove(&report)` (UFCS) is the same call written so that the
        // text count above does not see it.
        assert!(
            !code.contains("::prove(") && !code.contains("::admit("),
            "{name}: `prove` or `admit` called through its path"
        );
        // `ExclusiveProof(())` / `ExclusiveProof { .. }` as an expression.
        if name != "manual/exclusion.rs" {
            assert!(
                !code.contains("ExclusiveProof(()")
                    && !code.contains("ExclusiveProof{")
                    && !code.contains("ExclusiveProof::"),
                "{name}: builds or names the proof other than as a type"
            );
        }
    }
    assert_eq!(
        prove_calls.len(),
        1,
        "`.prove(` has exactly one caller in production code: {prove_calls:?}"
    );
    assert_eq!(prove_calls[0].0, "manual/agent.rs");
    // v0.3 (audit B LOW-2, mutants G3/G4; v0.3 audit LOW-1, mutant AG4): the paths of the
    // fencing mark and of the ownership record are named in a fixed number of places (the
    // counts below pin every spelling of the two names, field access or pattern); each was
    // read in one place (the gate's `fence` and
    // `lease` accessors in agent.rs, which hand them to the stores that take
    // the proof). A second use is a route to delete or write the state files
    // without a proof, and must be reviewed.
    assert_eq!(
        state_path_uses,
        vec![
            // agent.rs: the config field, its default, the parse and the one gate accessor;
            // vip.rs: a local variable named `lease_state` (a parsed record, not a path)
            ("manual/agent.rs".to_string(), 5, 3),
            ("manual/vip.rs".to_string(), 0, 3),
        ],
        "`fence_state` / `lease_state` are named in a place that is not in the pinned list"
    );
    // Inside exclusion.rs the proof carries the kernel lock. The production
    // constructor is `prove`; `for_test` exists only in the test build and is
    // not a way to make a production proof.
    let exclusion = squash(&load_src(&manual.join("exclusion.rs")).code);
    let declaration = function_body(&exclusion, "structExclusiveProof");
    assert!(
        declaration.contains("_lock:crate::control_lock::ControlLock"),
        "ExclusiveProof must own the kernel lock: {declaration}"
    );
    assert!(
        !declaration.contains("pub"),
        "ExclusiveProof's field must stay private: {declaration}"
    );
    assert!(
        !exclusion.contains("Self(())") && !exclusion.contains("ExclusiveProof(())"),
        "the old zero-sized proof constructor is back"
    );
    assert!(
        function_body(&exclusion, "fnprove(").contains("ExclusiveProof{_lock:lock}"),
        "the production constructor must be `prove(lock)`"
    );
    let full_exclusion = squash(&strip_comments(&exclusion_raw));
    let for_test = function_body(&full_exclusion, "fnfor_test(");
    assert!(
        for_test.contains("ControlLock::for_test()"),
        "the test proof must use the test lock"
    );
    assert!(
        full_exclusion.contains("#[cfg(test)]pub(crate)fnfor_test("),
        "for_test must be compiled only in the test build"
    );
    // The report that `prove` looks at cannot be built outside exclusion.rs: its
    // fields are private (a hand-built "all clear" report would be a proof).
    let report_body = function_body(&exclusion, "structHaReport");
    assert!(
        !report_body.contains("pub"),
        "the fields of HaReport must be private: {report_body}"
    );
    // Fence admission takes the proof too.
    let fence = squash(&load_src(&manual.join("fence.rs")).code);
    assert!(
        fence.contains("pub(crate)fnadmit(&self,_proof:&ExclusiveProof,token:&Token"),
        "FenceStore::admit must take the proof"
    );
    let agent = squash(&load_src(&manual.join("agent.rs")).code);
    let gate = function_body(&agent, "fnrequire_exclusive(");
    assert!(
        gate.contains("acquire_control_lock(") && gate.contains(".prove(lock)"),
        "the gate must acquire the lock and hand it to `prove`: {gate}"
    );

    // 3. The operations that change something take the proof.
    assert!(
        agent.contains("fnservice_action(&self,proof:&ExclusiveProof,unit:&str,action:&str"),
        "SystemOps::service_action must take the proof"
    );
    let lease = squash(&load_src(&manual.join("lease.rs")).code);
    for writer in ["init", "acquire", "phase", "commit", "abort", "reconcile"] {
        assert!(
            lease.contains(&format!(
                "pub(crate)fn{writer}(&self,_proof:&ExclusiveProof,"
            )),
            "LeaseStore::{writer} must take the proof"
        );
    }
    // Any other `pub(crate)` function of the store is a reviewed read.
    let mut exposed: Vec<String> = lease
        .match_indices("pub(crate)fn")
        .map(|(at, _)| {
            lease[at + "pub(crate)fn".len()..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect::<String>()
        })
        .collect();
    exposed.sort();
    exposed.dedup();
    for name in &exposed {
        assert!(
            [
                "init",
                "acquire",
                "phase",
                "commit",
                "abort",
                "reconcile",
                "status",
                "new",
                "with_lock_wait",
                "mutating",
                "next",
                "parse",
                "name",
                "compute_checksum",
            ]
            .contains(&name.as_str()),
            "LeaseStore exposes `{name}`, which is neither a writer that takes the proof nor a reviewed read: \
             add it to this list only after checking it does not change the ownership record"
        );
    }
    // The methods of the trait through which the agent acts on the host. A new
    // one must be added here after checking whether it changes anything; if it
    // does, it takes the proof (audit L-1: G8/G10).
    let ops_trait = {
        let at = agent.find("pub(crate)traitSystemOps{").expect("SystemOps");
        let rest = &agent[at..];
        function_body(rest, "traitSystemOps")
    };
    let mut methods: Vec<String> = ops_trait
        .match_indices("fn")
        .map(|(at, _)| {
            ops_trait[at + 2..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect::<String>()
        })
        .filter(|n| !n.is_empty())
        .collect();
    methods.sort();
    assert_eq!(
        methods,
        [
            "boot_id",
            "chronyc_tracking",
            "chronyd_check",
            "ha_processes",
            "pending_jobs",
            "probe",
            "service_action",
            "service_state",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>(),
        "SystemOps changed: review whether the new method changes anything (then it takes the proof)"
    );
    // Fence admission writes the fencing mark: one caller, after the gate.
    let mut admits = Vec::new();
    for path in manual_scan::walk_rs(&manual) {
        let file = path.file_name().unwrap().to_string_lossy().into_owned();
        // Files that only exist in the test build (`#[cfg(test)] mod x;`).
        if file.ends_with("_tests.rs") || file == "testkit.rs" || file == "fakes.rs" {
            continue;
        }
        let n = squash(&load_src(&path).code).matches(".admit(").count();
        if n > 0 {
            admits.push((path.file_name().unwrap().to_string_lossy().into_owned(), n));
        }
    }
    assert_eq!(
        admits,
        vec![("agent.rs".to_string(), 1)],
        "fence admission has exactly one caller (the service arm)"
    );
    // The only place that turns an action into a systemctl command line.
    let calls = agent.matches("action_args(").count();
    assert_eq!(
        calls, 2,
        "action_args is defined once and called once (service_action)"
    );
}

/// The test-only retry of a script that is still open for writing ("Text file
/// busy") lives in the test module of `remote.rs` and nowhere in the code that
/// ships: a production retry of a remote call would repeat a request whose
/// effect is unknown (final re-audit, ETXTBSY).
#[test]
fn the_text_file_busy_retry_exists_only_in_the_test_module() {
    let raw = std::fs::read_to_string(manifest_dir().join("src").join("manual").join("remote.rs"))
        .expect("read remote.rs");
    let split = raw
        .find("#[cfg(test)]\nmod tests {")
        .expect("the test module of remote.rs");
    let (production, tests) = raw.split_at(split);
    for needle in ["Text file busy", "ETXTBSY", "retry_while_text_file_busy"] {
        assert!(
            !production.contains(needle),
            "`{needle}` appears in the production part of remote.rs"
        );
    }
    assert!(
        tests.contains("retry_while_text_file_busy"),
        "the test module no longer has the helper this guard is about"
    );
    // No other file of the manual plane tests for a busy script either. The
    // code is read with the test items cut out (a raw prefix before the first
    // `#[cfg(test)]` would skip most of the files that start with a test hook);
    // the text is looked for in the string literals, the identifiers in the code.
    for entry in std::fs::read_dir(manifest_dir().join("src").join("manual")).expect("read dir") {
        let path = entry.expect("entry").path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        // Files that only exist in the test build (`#[cfg(test)] mod x;`).
        if name.ends_with("_tests.rs") || name == "testkit.rs" {
            continue;
        }
        let source = load_src(&path);
        for literal in source.string_literals() {
            assert!(
                !literal.to_lowercase().contains("file busy"),
                "{name} has the text of a busy-script error outside any test item"
            );
        }
        for needle in [
            "ETXTBSY",
            "ExecutableFileBusy",
            "retry_while_text_file_busy",
            "Some(26)",
            "EBUSY",
        ] {
            assert!(
                !source.code.contains(needle),
                "{name} mentions `{needle}` outside any test item"
            );
        }
    }
}

/// In `body` (squashed code), every `change_aliases(` call is preceded by an
/// `ha_recheck(` that comes after the previous alias change and no more than
/// 700 characters before it: each change has its own re-check (audit RA-E-05;
/// the old rule looked for any re-check in the 700 characters before, which
/// the re-check of an earlier change could satisfy).
fn every_alias_change_has_its_own_recheck(body: &str) -> Result<(), String> {
    for (call, _) in body.match_indices("change_aliases(") {
        let before = &body[..call];
        let Some(recheck) = before.rfind("ha_recheck(") else {
            return Err("an alias change has no ha_recheck before it".to_string());
        };
        if before
            .rfind("change_aliases(")
            .is_some_and(|previous| previous > recheck)
        {
            return Err(
                "an alias change is only covered by the re-check of an earlier change".to_string(),
            );
        }
        if call - recheck > 700 {
            return Err("the nearest ha_recheck is more than 700 characters away".to_string());
        }
    }
    Ok(())
}

#[test]
fn the_recheck_rule_tells_a_covered_change_from_an_uncovered_one() {
    let ok = "ha_recheck(a);change_aliases(x);ha_recheck(b);change_aliases(y);";
    assert!(every_alias_change_has_its_own_recheck(ok).is_ok());
    for (name, bad) in [
        ("no re-check at all", "change_aliases(x);"),
        (
            "second change relies on the first one's re-check",
            "ha_recheck(a);change_aliases(x);change_aliases(y);",
        ),
        (
            "re-check after the change",
            "change_aliases(x);ha_recheck(a);",
        ),
    ] {
        assert!(
            every_alias_change_has_its_own_recheck(bad).is_err(),
            "{name}"
        );
    }
    let far = format!("ha_recheck(a);{}change_aliases(x);", "x".repeat(800));
    assert!(every_alias_change_has_its_own_recheck(&far).is_err());
}

/// The agent reads its one request through `read_request`, which starts the
/// time backstop first (audit RA-E-09); `run_stdio` has no other read of
/// standard input, and nothing reads it before.
#[test]
fn the_agent_reads_its_request_under_the_time_backstop() {
    let agent = load_src(&manifest_dir().join("src").join("manual").join("agent.rs")).code;
    let run = function_body(&agent, "fn run_stdio(");
    let read_at = run
        .find("read_request(")
        .expect("run_stdio reads its request");
    assert!(
        !run.contains("read_to_end(") && !run.contains("read_line(") && !run.contains(".lines()"),
        "run_stdio reads standard input itself, outside the backstop"
    );
    assert!(
        !run[..read_at].contains("stdin()"),
        "standard input is touched before the backstop is armed"
    );
    // The helper arms the backstop before it reads.
    let helper = function_body(&agent, "fn read_request<");
    let arm = helper.find("spawn(").expect("the backstop thread");
    let read = helper.find("read_to_end(").expect("the read");
    assert!(arm < read, "the backstop must be armed before the read");
}

/// On the controller side, no cloud alias change is issued without the three
/// hosts having been asked, just before, whether the exclusion from the HA
/// daemon still holds; and neither is the commit (audit EX-03, EX-08).
#[test]
fn every_alias_change_and_the_commit_follow_an_ha_recheck() {
    let mut definitions = 0;
    for file in manual_files() {
        let code = manual_production_source(&file);
        for (at, _) in code.match_indices("change_aliases(") {
            if code[..at].ends_with("fn ") {
                definitions += 1;
                continue;
            }
            assert_eq!(file, "vip.rs", "{file} issues alias changes");
        }
    }
    assert_eq!(definitions, 1, "exactly one alias change function");

    let vip = manual_production_source("vip.rs");
    for function in ["fn execute(", "fn rollback("] {
        let body = function_body(&vip, function);
        let calls: Vec<usize> = body
            .match_indices("change_aliases(")
            .map(|(i, _)| i)
            .collect();
        assert!(!calls.is_empty(), "{function} changes aliases");
        every_alias_change_has_its_own_recheck(&body).unwrap_or_else(|e| panic!("{function}: {e}"));
        let _ = calls;
    }
    // The re-check also stops the move: its failure is propagated.
    let execute = function_body(&vip, "fn execute(");
    let precommit = function_body(&vip, "fn precommit_checks(");
    let recheck = precommit.find("ha_recheck(").expect("commit re-check");
    assert!(
        precommit[recheck..].starts_with("ha_recheck(ctx,plan,state,\"before_commit\")?"),
        "the commit re-check must propagate its failure"
    );
    for point in ["before_release", "before_assign"] {
        assert!(
            execute.contains(&format!("ha_recheck(ctx,plan,state,\"{point}\")?")),
            "{point}"
        );
    }
}

/// The agent rewrites only paths it derived itself: identifiers from the
/// controller are validated before they are joined to a directory.
#[test]
fn chrony_agent_validates_identifiers_before_building_paths() {
    let chrony = load_src(
        &manifest_dir()
            .join("src")
            .join("manual")
            .join("chrony_agent.rs"),
    );
    let handle = function_body(&chrony.code, "fn handle(");
    // Per operation, not per function: the arm that takes a stage id checks
    // the stage id, the arm that takes a backup id checks the backup id.
    let arm = |name: &str| -> String {
        let start = handle
            .find(&format!("op::{name}=>"))
            .unwrap_or_else(|| panic!("no arm for {name}"));
        let rest = &handle[start + 1..];
        let end = rest
            .find("op::CHRONY_")
            .map_or(handle.len(), |i| start + 1 + i);
        handle[start..end].to_string()
    };
    for (op, check) in [
        ("CHRONY_PUBLISH", "stage_id_ok("),
        ("CHRONY_CLEANUP", "stage_id_ok("),
        ("CHRONY_RESTORE", "backup_id_ok("),
    ] {
        assert!(
            arm(op).contains(check),
            "{op}: the identifier must be validated in its own arm ({check})"
        );
    }
    // No request argument is ever used as a path directly, and every `join`
    // argument is one of the reviewed forms: a new one needs a line here.
    let text = chrony.with_literals();
    let mut joins: Vec<String> = Vec::new();
    for (at, _) in text.match_indices(".join(") {
        let rest = &text[at + ".join(".len()..];
        let mut depth = 1;
        let mut stop = rest.len();
        for (i, c) in rest.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        stop = i;
                        break;
                    }
                }
                _ => {}
            }
        }
        joins.push(rest[..stop].to_string());
    }
    joins.sort();
    joins.dedup();
    const REVIEWED_JOINS: &[&str] = &[
        // fixed names and names derived from a prefix constant, a validated or
        // a random identifier
        "\".chrony.lock\"",
        "&backup_id",
        "backup_id",
        "format!(\"{STAGE_PREFIX}{stage_id}.conf\")",
        "format!(\"{VALIDATE_PREFIX}{}.conf\",super::proto::random_hex(8))",
        "format!(\"{RESTORE_PREFIX}{}{}.conf\",super::proto::random_hex(8),&expect_backup[..16])",
    ];
    for call in &joins {
        assert!(
            REVIEWED_JOINS.contains(&call.as_str()),
            "chrony_agent.rs joins a path in a form nobody reviewed: {call}"
        );
    }
    for marker in ["Path::new(arg", "PathBuf::from(arg", "join(arg("] {
        assert!(!chrony.code.contains(marker), "{marker}");
    }
    // The wider forms (audit RA-E-06): no path made from a string, no request
    // value as the path of a file-system call.
    let violations = manual_scan::check_path_building(
        "chrony_agent.rs",
        &chrony,
        &[
            "stage_id",
            "backup_id",
            "expect_current",
            "expect_new",
            "expect_backup",
        ],
    );
    assert!(violations.is_empty(), "{violations:#?}");
}

/// v0.5: the HA daemon's first effect is the shared control lock, followed by
/// the durable manual-operation barrier; the PSK, the Witness session, the
/// peer runtime and any resource construction come after both. `Config::load`
/// and the signal handlers are read-only. A lock/barrier refusal therefore
/// cannot have left a Witness, peer or VIP effect behind.
#[test]
fn v05_the_control_gate_precedes_every_startup_effect() {
    let wiring = production_source("daemon_run");
    let prepare = function_body(&wiring, "pub(super) fn prepare_daemon(");
    assert_before(
        &prepare,
        "startup_control_gate(&config)?;",
        "Psk::load(",
        "the control gate runs before the PSK is read",
    );
    assert_before(
        &prepare,
        "startup_control_gate(&config)?;",
        "connect_witness_session(",
        "the control gate runs before the Witness connection",
    );
    assert_before(
        &prepare,
        "startup_control_gate(&config)?;",
        "LinuxDaemonRuntime::new(",
        "the control gate runs before the runtime/resources exist",
    );
    let gate = function_body(&wiring, "pub(super) fn startup_control_gate(");
    assert_before(
        &gate,
        "ControlLock::acquire(",
        "manual_barrier::check(",
        "the lock is taken before the durable barrier is read",
    );
    assert!(
        gate.contains("BarrierState::Open(record)") && gate.contains("refusing to start"),
        "an open barrier must refuse startup"
    );
    let run = function_body(&wiring, "pub(super) fn run_daemon_inner(");
    assert!(
        run.contains("let (mut daemon, interval, control_lock) = prepare_daemon("),
        "the daemon must keep the control lock alive for the loop: {run}"
    );
    assert!(
        run.contains("control_lock") && !run.contains("drop(control_lock)"),
        "the lock binding must live for the whole function, not be dropped before the loop"
    );
}

/// v0.5: the controller writes the durable barrier before it acquires the
/// Witness lease. Otherwise a controller crash in the window would look like
/// "nothing happened" to the next HA start. This is source-shape only; the
/// behavior is also asserted through the fake remote's call order.
#[test]
fn v05_barrier_begin_precedes_the_lease_in_the_move_controller() {
    let vip = production_source("manual/vip");
    let body = function_body(&vip, "pub(crate) fn move_vip(");
    assert_before(
        &body,
        "begin_intents(",
        "lease_call(",
        "the barrier is written before the lease request",
    );
    let begin = body.find("begin_intents(").expect("begin");
    let lease = body[begin..]
        .find("op::LEASE_ACQUIRE")
        .map(|offset| begin + offset)
        .expect("lease acquire after begin");
    assert!(begin < lease);
}

/// J24 (N-3, RR-7): the crate functions the generation-fence send path may call, reviewed in J24
/// (closed world). The path is followed through every function of `node_witness_runtime` it
/// reaches; a call of any other crate function fails the guard until it is reviewed and listed.
const J24_FENCE_REVIEWED_CALLS: &[&str] = &[
    // Accessors of identifiers and of received envelopes.
    "as_str",
    "clone",
    "message",
    "unsigned",
    // The pure conversion of the derived fence to its protocol message (node_mutation).
    "to_protocol_message",
    // The Witness session (witness_runtime): one send, the correlated receive, stale-answer
    // discarding, the response bookkeeping and the reset of the session's outstanding slot.
    "send_lease_release",
    "receive_pending",
    "discard_stale_response",
    "handle_pending_response",
    "reset_outstanding",
];

/// J24 (N-3): the modules that define the reviewed calls of the fence send path. None of them can
/// name the node store, a local resource, the lease authority or a dynamic callback, so whatever
/// they do, they cannot write the node store or touch a resource
/// (`j24_fence_transport_modules_cannot_reach_the_node_store_or_a_resource`).
const J24_FENCE_TRANSPORT_MODULES: &[&str] = &[
    "framing",
    "protocol",
    "receive",
    "security",
    "session",
    "tcp",
    "transport",
    "witness_runtime",
];

/// J24 (N-3): what a module would have to name to write the node store, touch a local resource,
/// install authority or run a dynamic callback - and (J24 r2, audit C-3) to write, create, rename,
/// remove or chmod a file, or to call into C outside the reviewed socket calls.
const J24_CAPABILITY_MARKERS: &[&str] = &[
    "node_mutation",
    "NodeMutationStore",
    "mutation_store",
    "linux_node_runtime",
    "linux_network",
    "systemd_service",
    "resource_executor",
    "node_lease_authority",
    "crate::daemon",
    "gce_operation_journal",
    "gce_fencing",
    "gce_vip",
    "fencing_backend",
    "Command::",
    "std::process",
    "dyn ",
    "libc::",
    "fs::write",
    "fs::rename",
    "fs::remove",
    "fs::create_dir",
    "fs::copy",
    "set_permissions",
    "File::create",
    ".write(true)",
    ".create(true)",
    ".create_new(true)",
    ".append(true)",
    ".truncate(true)",
];

/// J24 (N-3): the `NodeMutationStore` methods that only read. Every other method of the store is a
/// writer; the fence send path may reach none of the writers (closed world: a new store method
/// counts as a writer until it is listed here).
const J24_NODE_STORE_READS: &[&str] = &["load_existing", "outstanding", "release_obligation"];

/// The methods of `impl NodeMutationStore` in the production `node_mutation`, and (J24 r2, audit
/// C-2) the methods of every `impl <Trait> for NodeMutationStore` block in any production module:
/// a trait method of the store is a store method too.
fn j24_node_store_methods(modules: &[(String, String)]) -> std::collections::BTreeSet<String> {
    let mut methods = std::collections::BTreeSet::new();
    for (_, code) in modules {
        let code = j22_blank_literals(&without_cfg_test_items(code));
        for marker in ["impl NodeMutationStore {", " for NodeMutationStore {"] {
            let mut rest = code.as_str();
            while let Some(at) = rest.find(marker) {
                let block = function_body(&rest[at..], marker);
                methods.extend(j22_fn_bodies(&block).into_keys());
                rest = &rest[at + block.len()..];
            }
        }
    }
    methods
}

/// The violations of the closed-world guard of the fence send path: `witness_runtime` is the
/// production `node_witness_runtime`, `others` every production module.
fn j24_fence_path_violations(witness_runtime: &str, others: &[(String, String)]) -> Vec<String> {
    let witness_runtime = j22_blank_literals(&without_cfg_test_items(witness_runtime));
    let mut crate_fns = std::collections::BTreeSet::new();
    let mut aliases = j22_use_aliases(&witness_runtime);
    for code in others
        .iter()
        .map(|(_, code)| j22_blank_literals(&without_cfg_test_items(code)))
    {
        crate_fns.extend(j22_fn_bodies(&code).into_keys());
        for (alias, original) in j22_use_aliases(&code) {
            aliases.entry(alias).or_insert(original);
        }
    }
    let writers: std::collections::BTreeSet<String> = j24_node_store_methods(others)
        .into_iter()
        .filter(|name| !J24_NODE_STORE_READS.contains(&name.as_str()))
        .collect();
    let local_fns = j22_fn_bodies(&witness_runtime);
    let local_types = j22_local_types(&witness_runtime);
    let mut violations = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut todo = vec!["exchange_generation_fence_once".to_string()];
    while let Some(function) = todo.pop() {
        if !seen.insert(function.clone()) {
            continue;
        }
        if writers.contains(&function) {
            violations.push(format!(
                "the fence path reaches the node-store writer {function}"
            ));
        }
        for body in local_fns.get(&function).into_iter().flatten() {
            if body.contains(".store") || body.contains("store.") {
                violations.push(format!("{function} uses the node store"));
            }
            // J24 r2 (audit C-2): `let Self { store: s, .. } = self` would rename the store field.
            let squeezed: String = body.split_whitespace().collect();
            if squeezed.contains("Self{") {
                violations.push(format!("{function} destructures self"));
            }
            for marker in J22_OS_EFFECT_MARKERS
                .iter()
                .chain(&["dyn ", " as fn", "fn("])
            {
                if body.contains(marker) {
                    violations.push(format!("{function} uses the marker {marker}"));
                }
            }
            for call in j22_calls(body, &local_fns, &local_types, &crate_fns, &aliases) {
                match call {
                    J22Call::Local(name) => todo.push(name),
                    J22Call::External(name) if writers.contains(&name) => {
                        violations.push(format!("{function} calls the node-store writer {name}"))
                    }
                    J22Call::External(name)
                        if J22_RESOLUTION_FORBIDDEN.contains(&name.as_str()) =>
                    {
                        violations.push(format!("{function} calls the forbidden {name}"))
                    }
                    J22Call::External(name)
                        if !J24_FENCE_REVIEWED_CALLS.contains(&name.as_str()) =>
                    {
                        violations.push(format!("{function} calls the unreviewed {name}"))
                    }
                    J22Call::External(_) => {}
                }
            }
        }
    }
    violations
}

/// J24 (N-3, RR-7): the generation-fence send path is closed world. From
/// `exchange_generation_fence_once` every function of `node_witness_runtime` it reaches is
/// followed; none of them uses the node store (the runtime's `store` field), an OS effect, a trait
/// object or a function pointer, and every crate function called outside the module is reviewed.
/// The node-store writers (every `NodeMutationStore` method but the reviewed reads) are reported as
/// such. The behavior is observed by `j24_fence_exchange_writes_no_byte_of_the_node_store`.
#[test]
fn j24_generation_fence_send_path_is_closed_world_and_never_writes_the_node_store() {
    let others = all_production_modules();
    let witness_runtime = &others
        .iter()
        .find(|(name, _)| name == "node_witness_runtime")
        .unwrap()
        .1;
    let violations = j24_fence_path_violations(witness_runtime, &others);
    assert!(violations.is_empty(), "{violations:#?}");
}

/// J24 r2 (audit C-3): the only foreign functions the transport modules may declare (both are
/// socket calls on the Witness connection: `fcntl` for the non-blocking flag in `tcp`, `setsockopt`
/// for SO_LINGER in `witness_runtime`).
const J24_TRANSPORT_FOREIGN_FUNCTIONS: &[&str] = &["fcntl", "setsockopt"];

/// J24 r2 (audit C-3): the only items of `state_machine` the transport modules may name (types,
/// never a transition: `state_machine` uses the lease authority's gate).
const J24_TRANSPORT_STATE_MACHINE_TYPES: &[&str] = &[
    "NodeState",
    "OperationPhase",
    "PromotionPhase",
    "DemotionPhase",
];

/// The names after `fn ` in `block` (declarations without a body included).
fn j24_declared_fns(block: &str) -> Vec<String> {
    block
        .match_indices("fn ")
        .map(|(at, _)| {
            block[at + 3..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect()
        })
        .collect()
}

/// The violations of the capability guard: every transport module is free of the capability
/// markers, and every other definition of a reviewed fence call (the guard resolves calls by name,
/// so each same-named function counts) is free of them and of OS effects too.
fn j24_fence_transport_violations(modules: &[(String, String)]) -> Vec<String> {
    let mut violations = Vec::new();
    for (name, code) in modules {
        let code = j22_blank_literals(&without_cfg_test_items(code));
        let transport = J24_FENCE_TRANSPORT_MODULES.contains(&name.as_str());
        if transport {
            for marker in J24_CAPABILITY_MARKERS {
                if code.contains(marker) {
                    violations.push(format!("the transport module {name} names {marker}"));
                }
            }
            // Every crate module a transport module names is a transport module, or
            // `state_machine` for its reviewed types only.
            for (at, _) in code.match_indices("crate::") {
                let after = &code[at + "crate::".len()..];
                let module: String = after
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if module == "state_machine" {
                    let rest = after["state_machine".len()..].trim_start_matches("::");
                    let items: Vec<String> = if let Some(group) = rest.strip_prefix('{') {
                        group[..group.find('}').unwrap_or(group.len())]
                            .split(',')
                            .filter_map(|item| item.split_whitespace().next().map(str::to_string))
                            .collect()
                    } else {
                        vec![
                            rest.chars()
                                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                                .collect(),
                        ]
                    };
                    for item in items.iter().filter(|item| !item.is_empty()) {
                        if !J24_TRANSPORT_STATE_MACHINE_TYPES.contains(&item.as_str()) {
                            violations.push(format!(
                                "the transport module {name} names state_machine::{item}"
                            ));
                        }
                    }
                } else if !J24_FENCE_TRANSPORT_MODULES.contains(&module.as_str()) {
                    violations.push(format!("the transport module {name} names crate::{module}"));
                }
            }
            // Foreign functions: only the reviewed socket calls, and only in `unsafe extern` blocks.
            let mut rest = code.as_str();
            while let Some(at) = rest.find("extern \"\"") {
                let block = function_body(&rest[at..], "extern \"\"");
                for function in j24_declared_fns(&block) {
                    if !J24_TRANSPORT_FOREIGN_FUNCTIONS.contains(&function.as_str()) {
                        violations.push(format!(
                            "the transport module {name} declares the foreign {function}"
                        ));
                    }
                }
                rest = &rest[at + block.len()..];
            }
            continue;
        }
        for (function, bodies) in j22_fn_bodies(&code) {
            if !J24_FENCE_REVIEWED_CALLS.contains(&function.as_str()) {
                continue;
            }
            for body in bodies {
                for marker in J24_CAPABILITY_MARKERS.iter().chain(J22_OS_EFFECT_MARKERS) {
                    if body.contains(marker) || body.contains(".store") {
                        violations.push(format!(
                            "{name}::{function} (a reviewed fence call by name) uses {marker}"
                        ));
                    }
                }
            }
        }
    }
    for module in J24_FENCE_TRANSPORT_MODULES {
        if !modules.iter().any(|(name, _)| name == module) {
            violations.push(format!("the transport module {module} is missing"));
        }
    }
    violations
}

/// J24 (N-3): the fence's reviewed calls cannot write the node store or touch a resource, also
/// beyond the closed-world boundary: the modules that implement the Witness session cannot even
/// name the store, a resource, the lease authority or a dynamic callback, and every same-named
/// definition elsewhere is effect-free.
#[test]
fn j24_fence_transport_modules_cannot_reach_the_node_store_or_a_resource() {
    let violations = j24_fence_transport_violations(&all_production_modules());
    assert!(violations.is_empty(), "{violations:#?}");
}

/// J24 (N-3): the one store write of the resolution is the exact completion of the retained
/// request itself, by its durable identity, as retired-stale - not a completion chosen by name.
/// `retained` is the store's own outstanding LeaseRequest.
#[test]
fn j24_retained_request_completion_is_the_exact_fenced_record() {
    let runtime = j22_blank_literals(&without_cfg_test_items(&production_source(
        "linux_node_runtime",
    )));
    let resolve = function_body(&runtime, "pub(crate) fn resolve_retained_request_once(");
    let squeezed: String = resolve.split_whitespace().collect();
    assert_eq!(squeezed.matches(".complete(").count(), 1);
    assert!(
        squeezed.contains(
            "self.mutation_store.complete(&retained.request_id,retained.mutation_generation,crate::node_mutation::MutationKind::LeaseRequest,crate::node_mutation::TerminalMutationDisposition::RetiredStale,)?;"
        ),
        "the completion must name the retained request's own identity"
    );
    assert!(
        squeezed.contains(
            "letSome(retained)=image.outstanding_mutation.clone().filter(|outstanding|{outstanding.kind()==crate::node_mutation::MutationKind::LeaseRequest})"
        ),
        "retained must be the store's own outstanding LeaseRequest"
    );
    assert_before(
        &squeezed,
        "letimage=self.mutation_store.load_existing()?;",
        "letSome(retained)=",
        "retained comes from the store image",
    );
    for shape in ["&dyn", "Box<dyn", "asfn", "implFn"] {
        assert!(!squeezed.contains(shape), "the resolution uses {shape}");
    }
}

/// J24 (N-3): the J24 guards fire on the shapes they exist for (a store write behind the fence
/// boundary, an unreviewed call, a trait object, a transport module that names the store, an
/// effectful same-named function).
#[test]
fn j24_fence_guards_detect_bypass_shapes() {
    let others = all_production_modules();
    let witness_runtime = others
        .iter()
        .find(|(name, _)| name == "node_witness_runtime")
        .unwrap()
        .1
        .clone();
    assert!(j24_fence_path_violations(&witness_runtime, &others).is_empty());
    for (signature, call, expected) in [
        (
            "fn correlated_response(",
            "let _ = self.store.load_existing();",
            "correlated_response uses the node store",
        ),
        (
            "fn classify(",
            "crate::linux_network::j24_probe();",
            "classify calls the unreviewed j24_probe",
        ),
        (
            "pub(crate) fn exchange_generation_fence_once(",
            "let _probe: Option<&dyn Fn()> = None;",
            "exchange_generation_fence_once uses the marker dyn ",
        ),
    ] {
        let mutated = j22_inject(&witness_runtime, signature, call, "");
        let mut modules = others.clone();
        if expected.contains("j24_probe") {
            modules.push((
                "linux_network_probe".to_string(),
                "fn j24_probe() {}".to_string(),
            ));
        }
        let violations = j24_fence_path_violations(&mutated, &modules);
        assert!(
            violations.iter().any(|violation| violation == expected),
            "{expected}: {violations:#?}"
        );
    }
    // A store writer reached by name.
    let mutated = j22_inject(
        &witness_runtime,
        "fn classify(",
        "crate::node_mutation::arm_release_obligation();",
        "",
    );
    let violations = j24_fence_path_violations(&mutated, &others);
    assert!(
        violations
            .iter()
            .any(|violation| violation
                == "classify calls the node-store writer arm_release_obligation"),
        "{violations:#?}"
    );

    assert!(j24_fence_transport_violations(&others).is_empty());
    let mut named = others.clone();
    let session = named
        .iter_mut()
        .find(|(name, _)| name == "witness_runtime")
        .unwrap();
    session.1 = format!(
        "use crate::node_mutation::NodeMutationStore;\n{}",
        session.1
    );
    assert!(
        j24_fence_transport_violations(&named).iter().any(
            |violation| violation == "the transport module witness_runtime names node_mutation"
        ),
    );
    let mut effectful = others.clone();
    effectful.push((
        "j24_probe_module".to_string(),
        "fn unsigned(&self) { std::process::exit(0) }".to_string(),
    ));
    assert!(
        j24_fence_transport_violations(&effectful)
            .iter()
            .any(|violation| violation.starts_with("j24_probe_module::unsigned")),
    );
}

/// J24 r2 (audit C-1): the functions of `linux_node_runtime` the retained-request resolution reaches
/// (the J22 closed-world traversal, boundaries not followed), with their bodies.
fn j24_resolution_reached(runtime: &str, others: &[(String, String)]) -> Vec<(String, String)> {
    let runtime = j22_blank_literals(&without_cfg_test_items(runtime));
    let mut crate_fns = std::collections::BTreeSet::new();
    let mut aliases = j22_use_aliases(&runtime);
    for code in others
        .iter()
        .map(|(_, code)| j22_blank_literals(&without_cfg_test_items(code)))
        .chain([runtime.clone()])
    {
        crate_fns.extend(j22_fn_bodies(&code).into_keys());
        for (alias, original) in j22_use_aliases(&code) {
            aliases.entry(alias).or_insert(original);
        }
    }
    let local_fns = j22_fn_bodies(&runtime);
    let local_types = j22_local_types(&runtime);
    let mut reached = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut todo = vec!["resolve_retained_request_once".to_string()];
    while let Some(function) = todo.pop() {
        if !seen.insert(function.clone()) {
            continue;
        }
        for body in local_fns.get(&function).into_iter().flatten() {
            reached.push((function.clone(), body.clone()));
            for call in j22_calls(body, &local_fns, &local_types, &crate_fns, &aliases) {
                if let J22Call::Local(name) = call
                    && !J22_RESOLUTION_BOUNDARIES.contains(&name.as_str())
                {
                    todo.push(name);
                }
            }
        }
    }
    reached
}

/// J24 r2 (audit C-1): the store completions anywhere on the resolution path (method or path call
/// of `complete`), with the function that contains each.
fn j24_resolution_completions(runtime: &str, others: &[(String, String)]) -> Vec<String> {
    let mut found = Vec::new();
    for (function, body) in j24_resolution_reached(runtime, others) {
        let squeezed: String = body.split_whitespace().collect();
        for shape in [".complete(", "::complete("] {
            for _ in squeezed.matches(shape) {
                found.push(function.clone());
            }
        }
    }
    found
}

/// J24 r2 (audit C-1): the one store completion of the resolution is the one in
/// `resolve_retained_request_once` itself (`j24_retained_request_completion_is_the_exact_fenced_record`
/// fixes its form); no function the resolution reaches completes anything else.
#[test]
fn j24_retained_request_resolution_completes_exactly_once_on_its_whole_path() {
    let (runtime, _daemon, others) = j22_resolution_inputs();
    assert_eq!(
        j24_resolution_completions(&runtime, &others),
        vec!["resolve_retained_request_once".to_string()]
    );
}

/// J24 r2: the counterexamples of the separate-agent audit (C-1, C-2, C-3) are detected.
#[test]
fn j24_guards_detect_the_audit_counterexamples() {
    let (runtime, _daemon, others) = j22_resolution_inputs();
    // C-1: a second completion hidden in a new local helper of the resolution.
    let hidden = j22_inject(
        &runtime,
        "pub(crate) fn resolve_retained_request_once(",
        "self.j24_hidden_completion();",
        "impl<N, S, C> LinuxNodeRuntime<N, S, C> { fn j24_hidden_completion(&mut self) { \
         let _ = self.mutation_store.complete(&self.j24_id, 1, self.j24_kind, self.j24_disposition); } }",
    );
    let completions = j24_resolution_completions(&hidden, &others);
    assert!(
        completions.contains(&"j24_hidden_completion".to_string()),
        "{completions:?}"
    );

    // C-2: a trait method of the store, reached through a renamed field.
    let witness_runtime = others
        .iter()
        .find(|(name, _)| name == "node_witness_runtime")
        .unwrap()
        .1
        .clone();
    let mut with_trait = others.clone();
    let store = with_trait
        .iter_mut()
        .find(|(name, _)| name == "node_mutation")
        .unwrap();
    store.1 = format!(
        "trait J24Probe {{ fn reset_outstanding(&self); }}\n\
         impl J24Probe for NodeMutationStore {{ fn reset_outstanding(&self) {{}} }}\n{}",
        store.1
    );
    let renamed = j22_inject(
        &witness_runtime,
        "fn correlated_response(",
        "let Self { store: s, .. } = self; s.reset_outstanding();",
        "",
    );
    let violations = j24_fence_path_violations(&renamed, &with_trait);
    for expected in [
        "correlated_response destructures self",
        "correlated_response calls the node-store writer reset_outstanding",
    ] {
        assert!(
            violations.iter().any(|violation| violation == expected),
            "{expected}: {violations:#?}"
        );
    }

    // C-3: a file write, a new foreign function, a state_machine function and another crate
    // module in a transport module.
    for (module, code, expected) in [
        (
            "protocol",
            "fn j24_probe() { let _ = std::fs::write(\"x\", b\"y\"); }",
            "the transport module protocol names fs::write",
        ),
        (
            "witness_runtime",
            "unsafe extern \"C\" { fn kill(pid: i32, sig: i32) -> i32; }",
            "the transport module witness_runtime declares the foreign kill",
        ),
        (
            "protocol",
            "fn j24_probe() { crate::state_machine::j24_transition(); }",
            "the transport module protocol names state_machine::j24_transition",
        ),
        (
            "session",
            "fn j24_probe() { crate::obligation_reconciliation::j24(); }",
            "the transport module session names crate::obligation_reconciliation",
        ),
    ] {
        let mut modules = others.clone();
        let target = modules.iter_mut().find(|(name, _)| name == module).unwrap();
        target.1 = format!("{code}\n{}", target.1);
        let violations = j24_fence_transport_violations(&modules);
        assert!(
            violations.iter().any(|violation| violation == expected),
            "{expected}: {violations:#?}"
        );
    }
}

/// J24 candidate (suspend, audit F-2): on Linux the node's lease clock reads `CLOCK_BOOTTIME` - its
/// origin and every `now` - and nothing else; other platforms keep `Instant`. A clock that counts
/// suspended time is the whole point of the candidate, and a runtime comparison cannot show it on a
/// host that was never suspended.
#[test]
fn j24_candidate_lease_clock_reads_clock_boottime_on_linux() {
    let code = j22_blank_literals(&without_cfg_test_items(&production_source(
        "node_lease_authority",
    )));
    let boottime = function_body(&code, "fn boottime_ms(");
    assert!(boottime.contains("libc::clock_gettime(libc::CLOCK_BOOTTIME,"));
    assert!(!boottime.contains("CLOCK_MONOTONIC") && !boottime.contains("Instant"));
    let clock = function_body(&code, "impl MonotonicClock for SystemMonotonicClock {");
    let linux_now = &clock[clock
        .find("#[cfg(target_os = \"\")]")
        .expect("cfg-split now")..];
    assert!(clock.contains("#[cfg(not(target_os = \"\"))]"));
    let squeezed: String = clock.split_whitespace().collect();
    assert!(squeezed.contains("letnow=boottime_ms().ok_or(ClockError::Unavailable)?;"));
    assert!(squeezed.contains("letorigin=self.origin_ms.ok_or(ClockError::Unavailable)?;"));
    assert!(linux_now.contains("boottime_ms()"));
    let new = function_body(&code, "impl SystemMonotonicClock {");
    let squeezed: String = new.split_whitespace().collect();
    assert!(squeezed.contains("origin_ms:boottime_ms(),"));
}

// ---------------------------------------------------------------------------------------------
// Phase 1-J25: the GCE fencing backend candidate (`gce_fence_backend`, `mikagami-gce-fence`)
// ---------------------------------------------------------------------------------------------

/// The raw text of `src/<relative>` with whole-line `//` comments removed (string literals that
/// contain `//`, such as URLs, are kept intact).
fn j25_code_lines(relative: &str) -> String {
    fs::read_to_string(manifest_dir().join("src").join(relative))
        .unwrap()
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Occurrences of `needle` that are not part of a longer `e<needle>` (so `print!(` does not count
/// `eprint!(`).
fn j25_count_not_after_e(text: &str, needle: &str) -> usize {
    text.match_indices(needle)
        .filter(|(at, _)| *at == 0 || text.as_bytes()[at - 1] != b'e')
        .count()
}

/// J25 G25-1: the daemon never reaches the decision core (it is registered for tests only and no
/// production module names it), and the core performs no I/O of its own: the transport, the
/// record store, the probe, the hooks and the clock are all supplied by the caller.
#[test]
fn j25_gce_fence_core_is_test_only_in_the_daemon_and_performs_no_io() {
    let main = strip_comments(&fs::read_to_string(source_path("main")).unwrap());
    let registration = main
        .find("pub(crate) mod gce_fence_backend;")
        .expect("the J25 core is registered");
    assert!(
        main[..registration].trim_end().ends_with("#[cfg(test)]"),
        "the J25 core is compiled into the daemon for tests only"
    );
    assert_eq!(main.matches("gce_fence_backend").count(), 1);
    for (name, code) in all_production_modules() {
        if name == "main" || name == "gce_fence_backend" || name.starts_with("bin/") {
            continue;
        }
        assert!(
            !code.contains("gce_fence_backend"),
            "{name}: a production module names the J25 core"
        );
    }
    let core = production_source("gce_fence_backend");
    for forbidden in [
        "std::fs",
        "fs::",
        "std::process",
        "Command",
        "TcpStream",
        "UdpSocket",
        "std::io",
        "libc",
        "unsafe",
        "std::env",
        "Instant",
        "SystemTime",
        "thread::",
        "File",
        "print!",
        "crate::",
    ] {
        assert!(!core.contains(forbidden), "the J25 core names {forbidden}");
    }
}

/// J25 G25-2: only the reviewed observations isolate. `MethodVerdict::Isolated` has exactly two
/// mint sites - the stop after DONE without error and TERMINATED of the identified id, and the
/// alias after the hold and the probe - the final `Isolated` comes only from `combine`, the
/// `isolated` output only from it, and the evidence is saved before `verify` returns it.
#[test]
fn j25_only_identified_terminal_or_held_removal_observations_isolate() {
    let core = production_source("gce_fence_backend");
    // Construction sites (the other occurrences are patterns).
    assert_eq!(core.matches("MethodVerdict::Isolated(format!").count(), 2);
    assert_eq!(
        core.matches("MethodVerdict::Isolated(").count(),
        core.matches("MethodVerdict::Isolated(format!").count()
            + core
                .matches("Some(MethodVerdict::Isolated(detail))")
                .count()
    );
    let stop = function_body(&core, "fn verify_stop(");
    assert_eq!(stop.matches("MethodVerdict::Isolated(").count(), 1);
    assert!(stop.contains("(false, \"TERMINATED\") =>"));
    for check in [
        "op.target_id != target.instance_id",
        "op.operation_type != \"stop\"",
        "op.status != OperationStatus::Done",
        "Observed::IdentityMismatch",
    ] {
        assert_before(&stop, check, "MethodVerdict::Isolated(", "stop proof order");
    }
    let alias = function_body(&core, "fn verify_alias(");
    assert_eq!(alias.matches("MethodVerdict::Isolated(").count(), 1);
    // J26 audit N-1: every Unknown branch after the record is loaded goes through restart_hold,
    // which clears both stamps durably.
    let restart = function_body(&core, "fn restart_hold(");
    assert!(restart.contains("record.removal_first_seen_ms = None;"));
    assert!(restart.contains("record.removal_last_seen_ms = None;"));
    assert!(restart.contains("context.store.save(record)"));
    // J26 re-audit NB-2: the two new direct returns are the poll marker and the poll outcome
    // saves; both leave the marker set in the store, so the next poll restarts the hold.
    assert_eq!(
        alias.matches("return MethodVerdict::Unknown(").count(),
        5,
        "only no [alias], the unsaved marker, the unpersisted observation, the hold not yet \
         elapsed and the unsaved outcome return Unknown directly"
    );
    assert_before(
        &alias,
        "record.alias_poll_open = true;",
        "operation(context.api",
        "the poll marker is durable before any API call",
    );
    for check in [
        "Observed::IdentityMismatch",
        // J25 audit B-1: overlap by address on every NIC, the hold restarted when a range is
        // seen again, and the clock read after the observation.
        "may_overlap(range, &protected)",
        "if present > 0",
        "return match restart_hold(context, &mut record, detail.clone())",
        "let Some(now_ms) = (context.clock)()",
        // J26 audit N-1 / N-4: the observation gap restarts the hold, and every range is probed.
        "let gap_exceeded = match (record.removal_first_seen_ms, record.removal_last_seen_ms)",
        "held < alias.propagation_hold_ms",
        "if alias.probe_required",
        "for range in &alias.ranges",
    ] {
        assert_before(
            &alias,
            check,
            "MethodVerdict::Isolated(",
            "alias proof order",
        );
    }
    assert_eq!(
        core.matches("FinalVerdict::Isolated(all_summary)").count(),
        1
    );
    assert!(
        function_body(&core, "pub fn combine(").contains("FinalVerdict::Isolated(all_summary)")
    );
    assert_eq!(core.matches("\"isolated\\n\"").count(), 1);
    assert!(
        function_body(&core, "pub fn verify_output(")
            .contains("FinalVerdict::Isolated(_) => (0, \"isolated\\n\")")
    );
    let verify = function_body(&core, "pub fn verify(");
    assert_before(
        &verify,
        "context.store.save(&record)",
        "(verdicts, verdict)",
        "the evidence is persisted before the verdict is returned",
    );
    // The fence action: describe first, persist the intent, then exactly one mutating call; an
    // existing record of the attempt sends nothing.
    let action = function_body(&core, "fn fence_one(");
    assert_eq!(action.matches("context.api.call(").count(), 1);
    assert_before(
        &action,
        "AlreadyRecorded",
        "context.api.call(",
        "a recorded attempt sends nothing",
    );
    assert_before(
        &action,
        "observe(context.api, &plan.target)",
        "context.api.call(",
        "describe first",
    );
    assert_before(
        &action,
        "context.store.save(&record)",
        "context.api.call(",
        "intent first",
    );
}

/// J25 G25-3: the helper reports through the verify grammar only, never puts the bearer token in
/// an argument list or the environment, includes the reviewed core, and fires its crash points
/// only in a `j25-fault-injection` build.
#[test]
fn j25_helper_reports_only_through_the_verify_grammar_and_keeps_the_token_out_of_argv() {
    let bin = j25_code_lines("bin/mikagami-gce-fence.rs");
    assert!(bin.contains("#[path = \"../gce_fence_backend.rs\"]"));
    assert_eq!(bin.matches("mod gce_fence_backend;").count(), 1);
    assert_eq!(j25_count_not_after_e(&bin, "print!("), 1);
    assert!(bin.contains("print!(\"{stdout}\");"));
    // v0.7 G-2: the bare `assign` is removed; the route steps print one fixed-grammar answer and
    // `operator-assign` prints its result. The verify grammar is unchanged.
    assert_eq!(
        j25_count_not_after_e(&bin, "println!("),
        2,
        "only the route step answer and the operator-assign result are printed"
    );
    assert_eq!(bin.matches("println!(\"{answer}\");").count(), 2);
    assert!(!bin.contains("\"assign\" =>"));
    assert!(!bin.contains("fn assign("));
    assert!(bin.contains("let (code, stdout) = verify_output(&verdict);"));
    for line in bin.lines() {
        if line.contains("token") {
            for forbidden in [
                ".arg(",
                ".args(",
                ".env(",
                "eprint",
                "log.line",
                "format!(\"{",
            ] {
                assert!(
                    !line.contains(forbidden) || line.contains("token unavailable"),
                    "the token reaches {forbidden}: {line}"
                );
            }
        }
    }
    // Whitespace-free, so a rustfmt reflow of the argument list does not hide or fake it (J25 SA-1).
    let compact: String = bin.split_whitespace().collect();
    assert!(
        compact.contains("\"-K\",\"-\","),
        "the request configuration goes on curl's stdin"
    );
    assert!(bin.contains(".env_clear()"));
    // The crash points live in `mod faults`, which exists only in a `j25-fault-injection` build, so
    // any call of them outside that feature cannot compile: the production build of the helper
    // (built and run in J25) proves there is none. The guard pins the gate of the module itself
    // (J25 SA-1: a line-window check broke on a rustfmt reflow).
    let module = bin.find("mod faults {").expect("the helper's fault module");
    assert!(
        bin[..module]
            .trim_end()
            .ends_with("#[cfg(feature = \"j25-fault-injection\")]"),
        "the helper's fault module is feature-gated"
    );
    assert_eq!(bin.matches("mod faults").count(), 1);
}

/// J25 G25-4: every daemon crash point is behind `j25-fault-injection`, and no J25 feature is a
/// default feature; the helper binary needs its own feature.
#[test]
fn j25_fault_points_are_feature_gated_and_no_j25_feature_is_default() {
    // J27: one more daemon point (after the grant) and three peer-runtime points (the new
    // observation of a live episode).
    for (module, expected) in [
        ("daemon.rs", 2usize),
        ("linux_node_runtime.rs", 2),
        ("daemon_peer_runtime.rs", 3),
    ] {
        let text = fs::read_to_string(manifest_dir().join("src").join(module)).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let mut found = 0;
        for (index, line) in lines.iter().enumerate() {
            if line.contains("j25_fault_injection::crash_if(") {
                found += 1;
                assert!(
                    lines[index.saturating_sub(3)..index]
                        .iter()
                        .any(|previous| previous
                            .contains("#[cfg(feature = \"j25-fault-injection\")]")),
                    "{module}: an ungated crash point: {line}"
                );
            }
        }
        assert_eq!(found, expected, "{module}: the reviewed crash points");
    }
    let main = fs::read_to_string(source_path("main")).unwrap();
    let module = main.find("pub(crate) mod j25_fault_injection;").unwrap();
    assert!(
        main[..module]
            .trim_end()
            .ends_with("#[cfg(feature = \"j25-fault-injection\")]")
    );
    let cargo = fs::read_to_string(manifest_dir().join("Cargo.toml")).unwrap();
    for line in cargo.lines() {
        if line.trim_start().starts_with("default") {
            assert!(!line.contains("j25"), "a J25 feature is a default feature");
        }
    }
    let bin = &cargo[cargo.find("[[bin]]").expect("the helper bin")..];
    assert!(bin.contains("name = \"mikagami-gce-fence\""));
    assert!(bin.contains("required-features = [\"j25-gce-fence\"]"));
}

/// J25 G25-5 (audit N-1): whitespace-free tripwires for the bypass shapes the J25 audit named.
/// Every `Isolated(` form of the core is one of the reviewed ones (a `Self::Isolated(..)` helper,
/// a new `FinalVerdict::Isolated(..)` or a `use … as` alias changes the set); the core imports
/// only `std::fmt` and `std::net::Ipv4Addr`; the helper writes stdout only through the verify
/// grammar and the `assign` report, starts exactly two processes with fixed argv and environment
/// forms, and reads the bearer token at exactly one place. A pinned count that changes means the
/// change needs a guard review, not that it is wrong.
#[test]
fn j25_guards_pin_every_isolated_form_import_and_helper_output() {
    let compact =
        |relative: &str| -> String { j25_code_lines(relative).split_whitespace().collect() };
    let core = compact("gce_fence_backend.rs");
    let isolated: Vec<usize> = core
        .match_indices("Isolated(")
        .map(|(at, _)| at)
        .filter(|at| !core[..*at].ends_with("Not"))
        .collect();
    let reviewed = [
        ("{Isolated(String),NotIsolated(String)", 2),
        ("matches!(self,Self::Isolated(_))", 1),
        ("ifletFinalVerdict::Isolated(summary)=&verdict", 1),
        ("MethodVerdict::Isolated(format!(", 2),
        ("Some(MethodVerdict::Isolated(detail))", 1),
        ("returnFinalVerdict::Isolated(all_summary);", 1),
        ("FinalVerdict::Isolated(_)=>(0,\"isolated\\n\")", 1),
    ];
    for (form, count) in reviewed {
        assert_eq!(core.matches(form).count(), count, "reviewed form {form}");
    }
    assert_eq!(
        isolated.len(),
        reviewed.iter().map(|(_, count)| count).sum::<usize>(),
        "an Isolated( form outside the reviewed set"
    );
    for forbidden in [
        "Isolatedas",
        "useMethodVerdict",
        "useFinalVerdict",
        "useself::",
        "super::",
        "include!",
        "macro_rules!",
        "extern",
    ] {
        assert!(
            !core.contains(forbidden),
            "the J25 core contains {forbidden}"
        );
    }
    // J26 re-audit NB-1 added `std::iter::once` (no I/O).
    assert_eq!(core.matches("std::").count(), 3);
    assert!(
        core.contains("usestd::fmt;")
            && core.contains("std::net::Ipv4Addr")
            && core.contains("std::iter::once(")
    );

    let bin = compact("bin/mikagami-gce-fence.rs");
    assert_eq!(j25_count_not_after_e(&bin, "print!("), 1);
    assert!(bin.contains("print!(\"{stdout}\");"));
    // v0.7 G-2: the route step answer and the operator-assign result (the bare `assign`, which
    // printed `{report}`, is removed); the route answer is flushed like the verify output.
    assert_eq!(j25_count_not_after_e(&bin, "println!("), 2);
    assert_eq!(bin.matches("println!(\"{answer}\");").count(), 2);
    assert!(!bin.contains("println!(\"{report}\");"));
    assert_eq!(bin.matches("stdout()").count(), 2);
    assert!(bin.contains("std::io::stdout().flush()"));
    assert_eq!(bin.matches("Command::new(").count(), 2);
    assert_eq!(bin.matches(".arg(").count(), 1);
    assert!(bin.contains(".arg(format!(\"{STATUS_MARK}%{{http_code}}\"))"));
    assert_eq!(bin.matches(".args(").count(), 2);
    assert!(bin.contains(".args([\"-q\",\"--globoff\",\"-sS\",\"--max-time\","));
    assert!(bin.contains(".args(args).env_clear()"));
    assert_eq!(bin.matches(".env(").count(), 3);
    assert_eq!(
        bin.matches(".env(\"PATH\",\"/usr/sbin:/usr/bin:/sbin:/bin\")")
            .count()
            + bin.matches(".env(\"LANG\",\"C\")").count(),
        3,
        "only the fixed PATH and LANG reach a child's environment"
    );
    assert_eq!(bin.matches(".env_clear()").count(), 2);
    let token_reads = bin
        .match_indices(".token")
        .filter(|(at, _)| !bin[at + ".token".len()..].starts_with("_url"))
        .count();
    assert_eq!(token_reads, 1, "the bearer token is read at one place");
    assert!(bin.contains("\"Authorization:Bearer{}\",self.token)"));
    assert_eq!(
        bin.matches("token").count(),
        21,
        "a new use of `token` needs a guard review"
    );
}

// ---------------------------------------------------------------------------------------------
// Phase 1-J27: local-loss freshness after a long fencing (OD-J26-6)
// ---------------------------------------------------------------------------------------------

/// J27 G27-1: the release of a half-open connection is one function with one call site, right
/// after the detector advanced in `tick_at_with`. It needs a live episode and an authenticated
/// session, ends the connection through the existing `disconnect_current`, and touches no
/// detector input: no observation, no freshness field, no time (§10.3 stays the closed list).
#[test]
fn j27_half_open_release_is_one_guarded_call_and_records_no_observation() {
    let peer = production_source("daemon_peer_runtime");
    let code: String = peer.split_whitespace().collect();
    assert_eq!(
        code.matches("fnrelease_connection_of_live_loss_episode(")
            .count(),
        1
    );
    assert_eq!(
        code.matches("release_connection_of_live_loss_episode(")
            .count(),
        2,
        "one definition and one call"
    );
    assert!(code.contains(
        "self.advance_failure_assessment(now)?;self.release_connection_of_live_loss_episode(now);Ok(processed)"
    ));
    let start = code
        .find("fnrelease_connection_of_live_loss_episode(")
        .unwrap();
    let body = &code[start..start + code[start..].find("fnprocess_frame(").unwrap()];
    assert_eq!(
        body,
        "fnrelease_connection_of_live_loss_episode(&mutself,now:Instant){letSome(token)=self.current_tokenelse{return;};if!self.is_established()||self.failure_assessment.loss_evidence().is_none(){return;}self.disconnect_current(token,now);}",
        "a change of the release needs a guard review"
    );
    for forbidden in [
        "observe_",
        "last_failed_contact_at",
        "record_permitted_observation",
        "lost_at",
        "freshness",
        "Instant::now",
        "listen_window",
    ] {
        assert!(!body.contains(forbidden), "the release names {forbidden}");
    }
}

/// J27 G27-2: the J27 test modules are compiled for tests only, and the freshness bound of
/// Stage 13.3 R-01 is unchanged (30 s).
#[test]
fn j27_test_modules_are_test_only_and_the_freshness_bound_is_unchanged() {
    let peer = strip_comments(&fs::read_to_string(source_path("daemon_peer_runtime")).unwrap());
    let compact: String = peer.split_whitespace().collect();
    assert!(
        compact.contains("#[cfg(test)]#[path=\"j27_freshness_tests.rs\"]modj27_freshness_tests;")
    );
    let main: String = strip_comments(&fs::read_to_string(source_path("main")).unwrap())
        .split_whitespace()
        .collect();
    assert!(main.contains("#[cfg(test)]modj27_freshness_gate_tests;"));
    let assessment: String = production_source("failure_assessment")
        .split_whitespace()
        .collect();
    assert!(
        assessment
            .contains("pubconstLOCAL_LOSS_EVIDENCE_MAX_AGE:Duration=Duration::from_secs(30);")
    );
}

/// J27 G27-3 (audit a01 NB-1): every blocking fencing step of the composition marks the iteration,
/// and the next peer tick voids the window it opened at the iteration's pre-step `now`.
#[test]
fn j27_window_opened_at_a_pre_step_now_never_counts() {
    let daemon: String = production_source("daemon").split_whitespace().collect();
    assert_eq!(
        daemon
            .matches("peer.void_listen_window_for_fencing_step()")
            .count(),
        4,
        "three step sites (fence action, verify poll, v0.7 G-2 route step) and the post-tick void"
    );
    assert_eq!(
        daemon
            .matches("letstepped=&mutself.fencing_step_since_peer_tick;letmutvoid=||{*stepped=true;peer.void_listen_window_for_fencing_step();};")
            .count(),
        2,
        "both blocking fencing steps mark the iteration"
    );
    assert!(daemon.contains(
        "letadvanced=peer.tick_at_with(now,&mutverdict);ifself.fencing_step_since_peer_tick{self.fencing_step_since_peer_tick=false;peer.void_listen_window_for_fencing_step();}advanced"
    ));
    // v0.7 G-2: the route-handoff tick marks the iteration the same way (one more use).
    assert!(daemon.contains(
        "letstepped=&mutself.fencing_step_since_peer_tick;letpeer=&mutself.peer;letmutvoid=||{*stepped=true;ifletSome(peer)=peer.as_mut(){peer.void_listen_window_for_fencing_step();}};"
    ));
    assert_eq!(daemon.matches("fencing_step_since_peer_tick").count(), 8);
}

// ---------------------------------------------------------------------------------------------
// Phase 1-J28: the automatic fence path over long partitions (H-1, H-2)
// ---------------------------------------------------------------------------------------------

/// J28 G28-1 (H-1): the trigger's facts of an `UNKNOWN` incident carry the attempt-token
/// high-water, from one pure mapping that the runtime's read uses.
#[test]
fn j28_unknown_incident_facts_carry_the_token_high_water() {
    let runtime: String = production_source("linux_node_runtime")
        .split_whitespace()
        .collect();
    assert_eq!(runtime.matches("fnauto_incident_facts_of(").count(), 1);
    assert!(runtime.contains(".fencing_incident.as_ref().map(auto_incident_facts_of))"));
    assert!(runtime.contains(
        "FencingState::Unknown(_)=>(IncidentKind::Unknown,incident.attempt_token_high_water)"
    ));
    assert!(!runtime.contains("FencingState::Unknown(_)=>(IncidentKind::Unknown,0)"));
}

/// J28 G28-2 (H-2): a `FAILED` incident seen by any poll holds the fence path; only the peer's
/// authenticated return (`Healthy`) clears the hold, and the budgets of the contract are unchanged.
#[test]
fn j28_failed_hold_is_cleared_only_by_the_authenticated_return() {
    let machine: String = production_source("auto_failover")
        .split_whitespace()
        .collect();
    assert_eq!(machine.matches("self.not_isolated_hold=false;").count(), 1);
    assert!(machine.contains("PeerFailureAssessment::Healthy=>{self.not_isolated_hold=false;"));
    // J29 C1 adds the third: a `FAILED` verdict counted by the runtime holds as well.
    assert_eq!(machine.matches("self.not_isolated_hold=true;").count(), 3);
    // ... and both checks precede the assessment match (J29 audit a01 NB-5).
    assert!(machine.contains(
        "ifinputs.incident.is_some_and(|incident|incident.kind==IncidentKind::Failed){self.not_isolated_hold=true;}ifinputs.activity.not_isolated_verdicts>self.not_isolated_seen{"
    ));
    assert!(machine.contains(
        "ifself.not_isolated_hold{self.fence.latched=true;returnAutoDecision::Exhausted(NOT_ISOLATED);}"
    ));
    for constant in [
        "pub(crate)constMIN_UPTIME_MS:u64=30_000;",
        "constPROCESS_WINDOW_MS:u64=600_000;",
        "constPROCESS_CYCLE_LIMIT:usize=3;",
        "constATTEMPT_REQUEST_LIMIT:u32=8;",
    ] {
        assert!(machine.contains(constant), "{constant}");
    }
}

/// J28 G28-3: the J28 test modules are compiled for tests only.
#[test]
fn j28_test_modules_are_test_only() {
    for (module, declaration) in [
        (
            "auto_failover",
            "#[cfg(test)]#[path=\"j28_auto_fencing_tests.rs\"]modj28_auto_fencing_tests;",
        ),
        (
            "main",
            "#[cfg(all(test,target_os=\"linux\"))]modj28_incident_facts_tests;",
        ),
    ] {
        let code: String = strip_comments(&fs::read_to_string(source_path(module)).unwrap())
            .split_whitespace()
            .collect();
        assert!(code.contains(declaration), "{module}");
    }
}

// ---------------------------------------------------------------------------------------------
// Phase 1-J29 (B1 / C1): the trigger counts fence actions and takes the FAILED hold from the
// runtime's own counts, made at the fencing step itself.
// ---------------------------------------------------------------------------------------------

/// J29 G29-1 (B1): a fence action is counted from `FenceActivity::actions_run` only - never
/// inferred from the incident facts - and a request that ran none is a reject.
#[test]
fn j29_fence_actions_are_counted_from_the_runtime_count_only() {
    let machine: String = production_source("auto_failover")
        .split_whitespace()
        .collect();
    assert!(machine.contains(
        "letran=inputs.activity.actions_run.saturating_sub(pending.actions_before);ifran>0{cycle.fence_actions=cycle.fence_actions.saturating_add(u32::try_from(ran).unwrap_or(u32::MAX));}elseifpending.could_fence{cycle.pre_incident_rejects+=1;}"
    ));
    assert_eq!(machine.matches("cycle.fence_actions=").count(), 1);
    assert!(
        !machine.contains("fence_actions+="),
        "no other fence-count increment"
    );
    assert!(!machine.contains("pending.before"));
    assert!(machine.contains("actions_before:inputs.activity.actions_run,"));
}

/// J29 G29-2 (B1 / C1): the runtime counts exactly where the step happens - one increment
/// immediately before the fence action process, one where a `FAILED` verdict is committed - and
/// nowhere else; the counts are runtime-only (no store or wire type carries them).
#[test]
fn j29_fence_activity_is_counted_only_at_the_steps() {
    let runtime: String = production_source("linux_node_runtime")
        .split_whitespace()
        .collect();
    assert_eq!(
        runtime
            .matches("auto_fence_activity.actions_run+=1;")
            .count(),
        1
    );
    assert!(runtime.contains(
        "before_blocking_step();self.auto_fence_activity.actions_run+=1;letreport=self.run_fencing_process(crate::fencing_backend::StepKind::Action,"
    ));
    assert_eq!(
        runtime
            .matches("auto_fence_activity.not_isolated_verdicts+=1;")
            .count(),
        1
    );
    assert!(runtime.contains(
        "Some(written)=>{ifmatches!(written.state,crate::fencing::FencingState::Failed{..}){self.auto_fence_activity.not_isolated_verdicts+=1;}VerifyApplied::Written(written.state)}"
    ));
    assert_eq!(
        runtime.matches("auto_fence_activity:").count(),
        3,
        "field and two constructors"
    );
    for module in ["node_mutation", "fencing", "protocol", "witness_runtime"] {
        let code: String = production_source(module).split_whitespace().collect();
        assert!(!code.contains("FenceActivity"), "{module}");
    }
}

/// J29 G29-3 (C1): a newer `FAILED` verdict count sets the hold before the assessment is read,
/// so an authenticated return in the same poll still clears it, and nothing else does.
#[test]
fn j29_a_failed_verdict_count_takes_the_hold() {
    let machine: String = production_source("auto_failover")
        .split_whitespace()
        .collect();
    assert!(machine.contains(
        "ifinputs.activity.not_isolated_verdicts>self.not_isolated_seen{self.not_isolated_seen=inputs.activity.not_isolated_verdicts;self.not_isolated_hold=true;}matchinputs.assessment{"
    ));
    assert_eq!(machine.matches("self.not_isolated_seen=").count(), 1);
}

/// J29 G29-4: the J29 test modules are compiled for tests only.
#[test]
fn j29_test_modules_are_test_only() {
    let code: String = strip_comments(&fs::read_to_string(source_path("auto_failover")).unwrap())
        .split_whitespace()
        .collect();
    assert!(
        code.contains(
            "#[cfg(test)]#[path=\"j29_auto_fencing_tests.rs\"]modj29_auto_fencing_tests;"
        )
    );
}

/// J35 (cf30, Amendment C): every exceptional settle of an owned Release has
/// exactly its approved call site - A-4d and C-l in the startup
/// reconciliation, C-a(1) in the in-process Release reconciliation - and the
/// startup reconciliation never installs authority, promotes, or uses the
/// accepted-release completion. RetiredStale reaches only the C-l resolver.
#[test]
fn j35_exceptional_settles_have_their_approved_call_sites_only() {
    let mut rejected = Vec::new();
    let mut retired = Vec::new();
    for (name, code) in all_production_modules() {
        let code = strip_cfg_test_items(&code);
        let r = code.matches(".settle_rejected_owned_release(").count();
        let s = code.matches(".settle_retired_owned_release(").count();
        if r > 0 {
            rejected.push((name.clone(), r));
        }
        if s > 0 {
            retired.push((name, s));
        }
    }
    rejected.sort();
    assert_eq!(
        rejected,
        [
            ("linux_node_runtime".to_string(), 1),
            ("obligation_reconciliation".to_string(), 1)
        ],
        "C-a(1) and A-4d"
    );
    assert_eq!(
        retired,
        [("obligation_reconciliation".to_string(), 1)],
        "C-l"
    );
    let sor = strip_cfg_test_items(&production_source("obligation_reconciliation"));
    for forbidden in [
        "install_validated_grant",
        "arm_and_promote",
        "promote(",
        "complete_owned_release(",
        "clear_superseded_obligation(&outstanding",
    ] {
        assert!(!sor.contains(forbidden), "SOR names {forbidden}");
    }
    // L-3: the in-process C-a(1) settle installs no authority and promotes
    // nothing either.
    let linux = strip_cfg_test_items(&production_source("linux_node_runtime"));
    let settle = function_body(&linux, "fn settle_not_releasable_once(");
    for forbidden in [
        "install_",
        "promote(",
        "arm_and_promote",
        "restore_installed",
        "complete_owned_release(",
    ] {
        assert!(!settle.contains(forbidden), "C-a(1) names {forbidden}");
    }
    // L-1: the unguarded startup entry is not used in production; the daemon
    // starts through `startup_guarded`, whose trait default is the only
    // production `.startup()` call (for runtimes without protected startup
    // effects).
    let daemon = production_source("daemon");
    assert_eq!(
        daemon.matches(".startup()").count(),
        1,
        "one .startup() call"
    );
    assert!(function_body(&daemon, "fn startup_guarded(").contains("self.startup()"));
    // `Daemon::start` with the live predicate, and the Linux runtime's own
    // unguarded `startup` wrapper (not called in production).
    assert_eq!(daemon.matches(".startup_guarded(").count(), 2);
    assert!(
        daemon
            .split_whitespace()
            .collect::<String>()
            .contains(".startup_guarded(&||guard.lost().is_none())")
    );
    // The only RetiredStale arm of the SOR result match calls the resolver.
    let arms: Vec<_> = sor
        .match_indices("NodeWitnessMutationResult::RetiredStale")
        .collect();
    assert_eq!(arms.len(), 1, "one RetiredStale arm");
    let arm = &sor[arms[0].0..];
    let arm = &arm[..arm.find("Ok(other)").expect("next arm")];
    assert!(arm.contains("resolve_retired("), "{arm}");
    assert!(!arm.contains("settle_"), "{arm}");
}

/// cf31 M-1: the production daemon starts behind the live control-lock
/// guard. Before cf31, `prepare_daemon` called `daemon.start()` and the guard
/// was attached afterwards in `run_daemon_inner`, so the startup
/// reconciliation read the default "no reader" guard (F-3 b05 / k14).
#[test]
fn cf31_m1_production_start_runs_behind_the_live_control_lock_guard() {
    let wiring = production_source("daemon_run");
    let compact = |text: &str| text.split_whitespace().collect::<String>();
    assert_eq!(
        wiring.matches(".start()").count(),
        1,
        "one production Daemon::start call"
    );
    assert_eq!(
        wiring.matches(".attach_control_lock_guard(").count(),
        1,
        "one production control-lock guard"
    );
    let helper = function_body(&wiring, "fn start_with_live_control_lock<");
    assert_before(
        &helper,
        ".attach_control_lock_guard(",
        ".start()",
        "the live guard is attached before start",
    );
    assert_before(
        &helper,
        ".start()",
        "live.first_error()",
        "a startup lock error is read after start",
    );
    assert_before(
        &helper,
        "live.first_error()",
        "recovery_gate(",
        "a lock error wins over the start result",
    );
    let prepare = compact(&function_body(&wiring, "fn prepare_daemon("));
    assert!(prepare.contains(
        "letcontrol_lock=startup_control_gate(&config)?;letlive_lock=LiveControlLock::new(control_lock);"
    ));
    assert!(prepare.contains("start_with_live_control_lock(&mutdaemon,&live_lock)?;"));
    assert!(
        !prepare.contains(".start()"),
        "prepare_daemon starts only via the helper"
    );
    let inner = compact(&function_body(&wiring, "fn run_daemon_inner("));
    assert!(inner.contains("letlock_error=Arc::clone(&control_lock.error);"));
    assert!(inner.contains("letcontrol_lock=Arc::clone(&control_lock.lock);"));
}

// ---------------------------------------------------------------------------------------------
// v0.7 G-2: route handoff (G2_SAFETY_CONTRACT.md R4.1)
// ---------------------------------------------------------------------------------------------

/// G-2 (contract §2 G-A4/G-A5, §3.1): the one automatic GCE write is the helper's `route-assign`,
/// named in exactly one place (`RhStep::words`) and chosen only from `INTENT_RECORDED` after a
/// successful `route-check`. `sent = true` is set and persisted before the helper is spawned, is
/// never set back to `false`, and the daemon, the runtime and the status report never name a
/// route subcommand themselves. The bare `assign` is gone from the helper, and `operator-assign`
/// exists only in the helper.
#[test]
fn g2_route_assign_is_the_one_automatic_write_and_sent_is_monotonic() {
    let rh = production_source("route_handoff");
    assert_eq!(rh.matches("\"route-assign\"").count(), 1);
    assert_eq!(
        rh.matches("RhStep::Assign =>").count(),
        1,
        "one argv mapping"
    );
    let choose = function_body(&rh, "fn choose_step(");
    assert_eq!(choose.matches("RhStep::Assign").count(), 1);
    assert!(choose.contains("RhState::IntentRecorded => Some(if !self.record.checked {"));
    let tick = function_body(&rh, "pub(crate) fn tick(");
    assert_before(
        &tick,
        "self.record.sent = true;",
        "self.store.save(&self.record)",
        "the send marker is persisted",
    );
    assert_before(
        &tick,
        "self.store.save(&self.record)",
        ".spawn_route_step(",
        "the send marker is durable before the spawn",
    );
    assert!(tick.contains("if self.record.sent || !self.record.checked {"));
    assert!(tick.contains("RH_MIN_LEASE_REMAINING"));
    assert_eq!(rh.matches(".sent = true").count(), 1);
    assert_eq!(rh.matches(".sent = false").count(), 0);
    assert_eq!(
        rh.matches("sent: false,").count(),
        1,
        "only the fresh record of begin"
    );
    assert!(
        !rh.contains("fencing_backend"),
        "the RH core does not touch the executor"
    );
    for module in ["daemon", "linux_node_runtime", "status", "daemon_run"] {
        let code = production_source(module);
        for word in [
            "route-assign",
            "route-check",
            "route-observe",
            "operator-assign",
        ] {
            assert!(!code.contains(word), "{module} names {word}");
        }
    }
    let bin = production_source("bin/mikagami-gce-fence");
    assert!(!bin.contains("\"assign\" =>"));
    assert!(bin.contains("\"operator-assign\" => return operator("));
    for (module, code) in production_modules() {
        if module != "route_handoff" && module != "linux_node_runtime" {
            assert!(
                !code.contains("RhDriver::begin("),
                "{module}: the RH begins only in the runtime"
            );
        }
    }
    let runtime = production_source("linux_node_runtime");
    assert_eq!(runtime.matches("RhDriver::begin(").count(), 1);
    let begin = function_body(&runtime, "pub(crate) fn begin_route_handoff(");
    assert!(begin.contains("crate::route_handoff::RhDriver::begin("));
    // Started only after the attempt's `Succeeded` boundary, with the mint-time provenance.
    let daemon: String = production_source("daemon").split_whitespace().collect();
    assert_eq!(
        daemon
            .matches(".begin_route_handoff(route_origin(&prerequisite),granted.0);")
            .count(),
        1
    );
    assert!(daemon.contains(
        "Ok(AttemptPromotionOutcome::Promoted)=>{self.runtime.begin_route_handoff(route_origin(&prerequisite),granted.0);self.retire_promotion_attempt(&attempt,PromotionAttemptResult::Succeeded)}"
    ));
}

/// r17 (contract R5 §R, Owner OD-R17-2): the only other automatic GCE write is the helper's
/// `route-reissue` of the identical request, named in exactly one place (`RhStep::words`), chosen
/// only from `ROUTE_UNKNOWN` when the last complete cycle made it ready, allowed only while
/// `reissue_allowed` holds at the spawn, and with `reissued = true` persisted before the helper is
/// spawned and never set back. No other daemon module names the subcommand.
#[test]
fn r17_route_reissue_is_once_per_term_and_its_marker_is_durable_first() {
    let rh = production_source("route_handoff");
    assert_eq!(rh.matches("\"route-reissue\"").count(), 1);
    assert_eq!(
        rh.matches("RhStep::Reissue =>").count(),
        1,
        "one answer mapping"
    );
    let choose = function_body(&rh, "fn choose_step(");
    assert_eq!(choose.matches("RhStep::Reissue").count(), 1);
    assert!(
        choose.contains("RhState::RouteUnknown if self.reissue_ready => Some(RhStep::Reissue),")
    );
    let tick = function_body(&rh, "pub(crate) fn tick(");
    let reissue = tick
        .split_once("if step == RhStep::Reissue {")
        .expect("the re-issue guard block")
        .1;
    assert_before(
        reissue,
        "if !fresh || !self.reissue_allowed(facts.now_ms) {",
        "self.record.reissued = true;",
        "allowed at the spawn",
    );
    assert_before(
        reissue,
        "self.record.reissued = true;",
        "self.store.save(&self.record)",
        "the re-issue marker is persisted",
    );
    assert_before(
        reissue,
        "self.store.save(&self.record)",
        ".spawn_route_step(",
        "the re-issue marker is durable before the spawn",
    );
    assert_eq!(rh.matches(".reissued = true").count(), 1);
    assert_eq!(rh.matches(".reissued = false").count(), 0);
    assert_eq!(rh.matches(".op_seen = false").count(), 0);
    assert_eq!(
        rh.matches("reissued: false,").count(),
        1,
        "only the fresh record of begin"
    );
    let allowed = function_body(&rh, "fn reissue_allowed(");
    for condition in [
        "self.record.state == RhState::RouteUnknown",
        "self.record.sent",
        "!self.record.reissued",
        "!self.record.op_seen",
        "RH_REISSUE_MIN_AFTER_SEND",
    ] {
        assert!(
            allowed.contains(condition),
            "reissue_allowed lacks {condition}"
        );
    }
    for module in ["daemon", "linux_node_runtime", "status", "daemon_run"] {
        assert!(
            !production_source(module).contains("route-reissue"),
            "{module} names route-reissue"
        );
    }
    let bin = production_source("bin/mikagami-gce-fence");
    assert!(bin.contains("(\"route-reissue\", None) => {"));
    assert!(bin.contains("route_reissue(&mut api, plan, &binding, &mut fence_store, store)"));
}

/// Two-node topology: the decision core is pure (TWO_NODE_SAFETY_MODEL.md). It reads no
/// clock, performs no file, network or process I/O and cannot reach a mutation-capable
/// layer, so every gate is decided on injected observations only and the simulation tests
/// exercise exactly the production decisions. Durable writes go only through the
/// `DurableStore` it is handed.
#[test]
fn mkm_arch_2n_001_two_node_controller_is_pure() {
    let path = manifest_dir().join("src/two_node/controller.rs");
    let source = strip_comments(&fs::read_to_string(&path).expect("controller source"));
    for forbidden in [
        "std::fs",
        "std::net",
        "std::process",
        "std::thread",
        "Instant",
        "SystemTime",
        "resource_executor",
        "resource_workflow",
        "fencing_backend",
        "linux_node_runtime",
        "node_lease_authority",
        "witness",
        "libc::",
    ] {
        assert!(
            !source.contains(forbidden),
            "src/two_node/controller.rs must stay pure: found `{forbidden}`"
        );
    }
}

/// Two-node topology: it never touches the Witness topology's authority modules, and the
/// Witness topology's daemon never reaches the two-node runtime except through the single
/// `daemon run` dispatch on `cluster.topology`.
#[test]
fn mkm_arch_2n_002_two_node_is_separate_from_witness_authority() {
    for file in [
        "controller.rs",
        "store.rs",
        "wire.rs",
        "runtime.rs",
        "config.rs",
        "cli.rs",
    ] {
        let path = manifest_dir().join("src/two_node").join(file);
        let source = strip_comments(&fs::read_to_string(&path).expect("two-node source"));
        for forbidden in [
            "node_lease_authority",
            "witness_runtime",
            "witness_authority",
            "node_mutation::NodeMutationStore",
            "obligation_reconciliation",
            "bootstrap_admission",
        ] {
            assert!(
                !source.contains(forbidden),
                "src/two_node/{file} must not use `{forbidden}`"
            );
        }
    }
    for file in ["daemon.rs", "daemon_run.rs", "linux_node_runtime.rs"] {
        let path = manifest_dir().join("src").join(file);
        let source = strip_comments(&fs::read_to_string(&path).expect("witness source"));
        assert!(
            !source.contains("two_node"),
            "src/{file} must not depend on the two-node topology"
        );
    }
}
