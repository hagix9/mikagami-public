//! What an operator may do next, and what they must not do, for a given
//! observed verdict (v0.3).
//!
//! Pure functions of the verdict and of the observed facts that are passed in;
//! nothing here reads, guesses or changes anything. The lists are static
//! sentences keyed by the verdict, so a value that was not observed never
//! turns into advice. Commands named as *allowed* are the ones the controller
//! itself would accept in that state (it still checks again when run);
//! *forbidden* are the actions that would make an unresolved or unknown state
//! worse, and are refused by the controller wherever it can tell.

use serde::Serialize;
use serde_json::Value;
use std::fmt::Write as _;

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub(crate) struct Guidance {
    /// Commands that are not ruled out by what was observed. The controller still
    /// checks every command when it is run and may refuse it; a line here is
    /// never a promise.
    pub(crate) allowed: Vec<String>,
    /// Actions that must not be taken now, with the reason.
    pub(crate) forbidden: Vec<String>,
}

impl Guidance {
    pub(crate) fn text(&self) -> String {
        let mut out = String::new();
        for line in &self.allowed {
            let _ = writeln!(out, "  next (allowed):   {line}");
        }
        for line in &self.forbidden {
            let _ = writeln!(out, "  next (forbidden): {line}");
        }
        out
    }
}

fn s(text: &str) -> String {
    text.to_string()
}

/// The facts about one node that the VIP advice depends on.
pub(crate) struct NodeFact<'a> {
    pub(crate) name: &'a str,
    /// The cloud's status of the instance (`RUNNING`, `TERMINATED`, ...), if observed.
    pub(crate) cloud_status: Option<&'a str>,
}

/// What `for_vip` is a function of. Nothing else is read.
pub(crate) struct VipFacts<'a> {
    pub(crate) verdict: &'a str,
    /// The owner in the Witness record (`None` when the store is not initialised or unreadable).
    pub(crate) recorded_owner: Option<&'a str>,
    /// The nodes that the cloud shows holding the VIP (empty when not observed).
    pub(crate) holders: &'a [String],
    pub(crate) nodes: Vec<NodeFact<'a>>,
    /// The id and phase of the recorded operation.
    pub(crate) op_id: Option<&'a str>,
    /// `Some(true)` once the recorded phase may have changed a resource.
    pub(crate) op_mutating: Option<bool>,
}

/// What must not be done by hand while the picture is not "consistent and idle": every
/// one of these makes the record, the cloud or the services disagree (v0.3 audit MEDIUM-2e).
fn hand_edits() -> [String; 4] {
    [
        s(
            "changing the VIP alias with gcloud or the console   (a recorded change may still land; the record would no longer match)",
        ),
        s(
            "starting or stopping the VIP service by hand on either node   (the record would no longer match)",
        ),
        s("deleting or editing files under the state directories of the nodes or the Witness"),
        s(
            "starting the HA daemon or running install.sh --ha-mode   (QUICKSTART section 6: only after the readiness check says READY)",
        ),
    ]
}

/// Guidance for the VIP resource.
pub(crate) fn for_vip(f: &VipFacts<'_>) -> Guidance {
    let mut g = Guidance::default();
    let status =
        s("mkg resource status vip   (read-only; repeat it until the picture stops changing)");
    match f.verdict {
        "consistent" => {
            let owner = f.holders.first().map(String::as_str);
            let mut offered = false;
            for node in f
                .nodes
                .iter()
                .filter(|n| Some(n.name) != owner && n.cloud_status == Some("RUNNING"))
            {
                offered = true;
                g.allowed.extend([format!(
                    "mkg resource move vip --to {}   (hand the VIP over by hand)",
                    node.name
                )]);
            }
            if !offered {
                g.allowed.extend([s(
                    "no move is offered: no other node is observed RUNNING in the cloud (start that instance first)",
                )]);
            }
            g.allowed
                .extend([s("mkg chronyd show --node NODE   (read-only)")]);
            g.forbidden.extend(hand_edits());
        }
        "unresolved_operation" => {
            g.allowed.extend([status]);
            if f.op_mutating == Some(false) {
                g.allowed.extend([s(
                    "mkg resource reconcile vip   (the recorded phase has not changed anything yet: accepted once the operation has expired)",
                )]);
            }
            let id = f.op_id.unwrap_or("OP_ID");
            g.allowed.extend([format!(
                "mkg resource reconcile vip --abandon-op {id}   (refused for the first 15 minutes after the last record of that operation, \
                 and while a cloud operation of either instance is open; it adopts the observed state only if exactly one node holds the VIP, \
                 runs the service and answers it, and the other node is provably quiet - look at both instances and the cloud operation list yourself first)"
            )]);
            g.forbidden.extend([s(
                "mkg resource move vip   (refused while an operation is recorded)",
            )]);
            g.forbidden.extend(hand_edits());
        }
        "mismatch" => {
            g.allowed.extend([status]);
            match (f.recorded_owner, f.holders) {
                (None, [holder]) => g.allowed.extend([format!(
                    "mkg resource init vip --owner {holder}   (the store is not initialised: records the observed owner once; refused unless the owner runs \
                     the service and answers the VIP and the other node is quiet)"
                )]),
                (None, _) => g.allowed.extend([s(
                    "the store is not initialised and the cloud does not show exactly one holder: make exactly one node hold the VIP first (init needs it)",
                )]),
                (Some(_), _) => g.allowed.extend([s(
                    "mkg resource reconcile vip   (adopts the observed state only when it can be proven; otherwise it stops with the reason)",
                )]),
            }
            g.forbidden.extend([s(
                "mkg resource move vip   (the record and the cloud disagree about the owner)",
            )]);
            g.forbidden.extend(hand_edits());
        }
        "ha_conflict" => {
            g.allowed.extend([s(
                "stop the HA daemon on the host named in the problems, then run mkg resource status vip",
            )]);
            g.forbidden.extend([
                s("mkg resource move vip, reconcile vip and mkg chronyd apply|start|stop|restart   (an HA daemon is running or queued)"),
                s("any change of the VIP alias or of the service"),
            ]);
        }
        _ => {
            // unknown: something could not be observed. Every prohibition of the
            // less uncertain states holds here too.
            g.allowed.extend([
                s("remove the cause named in the problems (an unreachable host, the Witness, the cloud API), then run mkg resource status vip"),
                status,
            ]);
            g.forbidden.extend([
                s("mkg resource move vip   (the state is not established)"),
                s("mkg resource reconcile vip --abandon-op ... or --accept-unconfirmed-cloud-change   (only after you looked at both instances and the cloud operation list yourself)"),
                s("treating the VIP as owned by either node"),
            ]);
            g.forbidden.extend(hand_edits());
        }
    }
    g
}

/// Guidance for the chronyd resource from the `resource::chronyd_status` document
/// (`nodes.<name>.{error, problems, tracking_ok, unit_active}`). The advice follows the
/// problems of every node, not the summary flag `healthy` (it ignores kept versions).
/// `ha_unproven` names the nodes whose exclusion from the HA daemon is not proven (the
/// status overview knows it; `resource status chronyd` alone does not and says so).
pub(crate) fn for_chronyd(value: &Value, ha_unproven: &[String]) -> Guidance {
    let mut g = Guidance::default();
    let mut unobserved = Vec::new();
    let mut kept = Vec::new();
    let mut other = Vec::new();
    if let Some(nodes) = value["nodes"].as_object() {
        for (name, n) in nodes {
            if n["error"].is_string() {
                unobserved.extend([name.clone()]);
                continue;
            }
            let problems: Vec<&str> = n["problems"]
                .as_array()
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            if problems
                .iter()
                .any(|p| p.contains("kept version") || p.contains("cannot say whether kept"))
            {
                kept.extend([name.clone()]);
            } else if !problems.is_empty() || n["tracking_ok"] == false || n["unit_active"] == false
            {
                other.extend([name.clone()]);
            }
        }
    }
    let clean = unobserved.is_empty() && kept.is_empty() && other.is_empty();
    if clean {
        g.allowed.extend([
            s("mkg chronyd validate --node NODE FILE, mkg chronyd diff --node NODE FILE   (read-only)"),
            s("mkg chronyd apply --node NODE FILE   (validates, backs up, publishes atomically, restarts, verifies, rolls back on failure; \
               refused with exit 3 while the exclusion from the HA daemon is not proven on that node: see mkg resource status vip)"),
        ]);
    } else {
        g.allowed.extend([s(
            "mkg resource status chronyd   (read-only; it decides after any apply that ended UNKNOWN)",
        )]);
    }
    for node in &unobserved {
        g.allowed.extend([format!(
            "{node}: make the node reachable (its agent over SSH), then run mkg resource status chronyd"
        )]);
    }
    for node in &kept {
        g.allowed.extend([format!(
            "{node}: compare the kept file(s) .mkg-displaced-* (and any .mkg-stage-* / .mkg-restore-* left over) in the chrony directory with the live \
             configuration, keep what you need, then delete the rest yourself (QUICKSTART section 11)"
        )]);
        g.forbidden.extend([format!(
            "mkg chronyd apply --node {node}   (refused while kept versions exist)"
        )]);
    }
    for node in unobserved.iter().chain(&other) {
        g.forbidden.extend([format!(
            "mkg chronyd apply --node {node}   (the node is not observed healthy; an apply could hide the cause)"
        )]);
    }
    for node in ha_unproven {
        g.forbidden.extend([format!(
            "mkg chronyd apply --node {node}   (the exclusion from the HA daemon is not proven on that host: the apply is refused)"
        )]);
    }
    if !clean {
        g.forbidden.extend([s(
            "deleting .mkg-* files in the chrony directory before you compared them with the live configuration",
        )]);
    }
    g
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn node<'a>(name: &'a str, status: &'a str) -> NodeFact<'a> {
        NodeFact {
            name,
            cloud_status: Some(status),
        }
    }

    fn facts<'a>(verdict: &'a str, holders: &'a [String]) -> VipFacts<'a> {
        VipFacts {
            verdict,
            recorded_owner: Some("node-a"),
            holders,
            nodes: vec![node("node-a", "RUNNING"), node("node-b", "RUNNING")],
            op_id: None,
            op_mutating: None,
        }
    }

    fn joined(items: &[String]) -> String {
        items.join("\n")
    }

    fn a() -> Vec<String> {
        vec!["node-a".to_string()]
    }

    #[test]
    fn a_consistent_vip_offers_the_move_to_the_other_running_node_only() {
        let holders = a();
        let g = for_vip(&facts("consistent", &holders));
        let allowed = joined(&g.allowed);
        assert!(allowed.contains("move vip --to node-b"), "{allowed}");
        assert!(!allowed.contains("move vip --to node-a"), "{allowed}");
        // hand edits are warned against in the quiet state as well (audit MEDIUM-2e)
        let forbidden = joined(&g.forbidden);
        assert!(forbidden.contains("gcloud"), "{forbidden}");
        assert!(forbidden.contains("install.sh --ha-mode"), "{forbidden}");
    }

    #[test]
    fn a_peer_that_is_not_running_is_not_offered_as_a_target() {
        // audit MEDIUM-2b: after a fenced move the old source is TERMINATED
        let holders = vec!["node-b".to_string()];
        let mut f = facts("consistent", &holders);
        f.recorded_owner = Some("node-b");
        f.nodes = vec![node("node-a", "TERMINATED"), node("node-b", "RUNNING")];
        let allowed = joined(&for_vip(&f).allowed);
        assert!(!allowed.contains("move vip --to"), "{allowed}");
        assert!(allowed.contains("no move is offered"), "{allowed}");
        f.nodes = vec![
            NodeFact {
                name: "node-a",
                cloud_status: None,
            },
            node("node-b", "RUNNING"),
        ];
        let allowed = joined(&for_vip(&f).allowed);
        assert!(!allowed.contains("move vip --to node-a"), "{allowed}");
    }

    #[test]
    fn an_unresolved_operation_names_the_operation_and_offers_the_plain_reconcile_only_before_the_mutation()
     {
        let holders = a();
        let mut f = facts("unresolved_operation", &holders);
        f.op_id = Some("move-abc123");
        f.op_mutating = Some(true);
        let g = for_vip(&f);
        let allowed = joined(&g.allowed);
        assert!(allowed.contains("--abandon-op move-abc123"), "{allowed}");
        assert!(allowed.contains("first 15 minutes"), "{allowed}");
        assert!(
            !allowed.contains("mkg resource reconcile vip   ("),
            "{allowed}"
        );
        assert!(!allowed.contains("move vip --to"));
        let forbidden = joined(&g.forbidden);
        assert!(forbidden.contains("mkg resource move vip"), "{forbidden}");
        assert!(forbidden.contains("gcloud"), "{forbidden}");
        assert!(forbidden.contains("HA daemon"), "{forbidden}");
        assert!(
            forbidden.contains("deleting or editing files"),
            "{forbidden}"
        );
        // before the mutation the plain reconcile is accepted once the operation expired
        f.op_mutating = Some(false);
        let allowed = joined(&for_vip(&f).allowed);
        assert!(
            allowed.contains("mkg resource reconcile vip   ("),
            "{allowed}"
        );
        // an unknown phase offers neither
        f.op_mutating = None;
        let allowed = joined(&for_vip(&f).allowed);
        assert!(
            !allowed.contains("mkg resource reconcile vip   ("),
            "{allowed}"
        );
    }

    #[test]
    fn an_unobserved_state_offers_no_move_and_no_abandon_and_keeps_every_prohibition() {
        let holders = a();
        let g = for_vip(&facts("unknown", &holders));
        let allowed = joined(&g.allowed);
        assert!(
            !allowed.contains("move vip") && !allowed.contains("abandon"),
            "{allowed}"
        );
        let forbidden = joined(&g.forbidden);
        assert!(forbidden.contains("mkg resource move vip"), "{forbidden}");
        // audit MEDIUM-2e: nothing weaker than in `unresolved_operation`
        assert!(forbidden.contains("--abandon-op"), "{forbidden}");
        assert!(forbidden.contains("gcloud"), "{forbidden}");
        assert!(forbidden.contains("by hand"), "{forbidden}");
        assert!(
            forbidden.contains("deleting or editing files"),
            "{forbidden}"
        );
        assert!(forbidden.contains("install.sh --ha-mode"), "{forbidden}");
    }

    #[test]
    fn a_mismatch_advises_init_when_the_store_is_empty_and_reconcile_otherwise() {
        let holders = a();
        // an initialised store: reconcile may adopt
        let g = for_vip(&facts("mismatch", &holders));
        let allowed = joined(&g.allowed);
        assert!(allowed.contains("reconcile vip"), "{allowed}");
        assert!(!allowed.contains("init vip"), "{allowed}");
        let forbidden = joined(&g.forbidden);
        assert!(
            forbidden.contains("disagree about the owner"),
            "{forbidden}"
        );
        assert!(forbidden.contains("gcloud"), "{forbidden}");
        // audit MEDIUM-2c: the first state of every installation
        let mut f = facts("mismatch", &holders);
        f.recorded_owner = None;
        let allowed = joined(&for_vip(&f).allowed);
        assert!(allowed.contains("init vip --owner node-a"), "{allowed}");
        assert!(!allowed.contains("reconcile vip"), "{allowed}");
        // no single holder: init is not offered either
        let two = vec!["node-a".to_string(), "node-b".to_string()];
        f.holders = &two;
        let allowed = joined(&for_vip(&f).allowed);
        assert!(!allowed.contains("init vip --owner"), "{allowed}");
        assert!(allowed.contains("exactly one node hold"), "{allowed}");
    }

    #[test]
    fn an_ha_conflict_forbids_every_change() {
        let holders = a();
        let g = for_vip(&facts("ha_conflict", &holders));
        assert!(joined(&g.forbidden).contains("any change"));
        assert!(joined(&g.forbidden).contains("chronyd apply"));
        assert!(joined(&g.allowed).contains("stop the HA daemon"));
    }

    fn node_doc(problems: &[&str]) -> Value {
        json!({"tracking_ok": true, "unit_active": true, "problems": problems})
    }

    #[test]
    fn a_clean_chronyd_offers_validate_diff_and_apply_with_the_ha_refusal_named() {
        let v =
            json!({"healthy": true, "nodes": {"node-a": node_doc(&[]), "node-b": node_doc(&[])}});
        let g = for_chronyd(&v, &[]);
        let allowed = joined(&g.allowed);
        assert!(allowed.contains("chronyd apply"), "{allowed}");
        assert!(
            allowed.contains("exclusion from the HA daemon is not proven"),
            "{allowed}"
        );
        assert!(g.forbidden.is_empty());
    }

    #[test]
    fn kept_versions_on_an_otherwise_healthy_node_are_advised_and_forbid_the_apply() {
        // audit MEDIUM-2a: `healthy` ignores the kept versions
        let v = json!({"healthy": true, "nodes": {
            "node-a": node_doc(&["1 kept version(s) of a configuration that somebody else wrote"]),
            "node-b": node_doc(&[])}});
        let g = for_chronyd(&v, &[]);
        let allowed = joined(&g.allowed);
        let forbidden = joined(&g.forbidden);
        assert!(
            allowed.contains("node-a: compare the kept file(s)"),
            "{allowed}"
        );
        assert!(!allowed.contains("mkg chronyd apply"), "{allowed}");
        assert!(
            forbidden.contains("chronyd apply --node node-a"),
            "{forbidden}"
        );
        assert!(forbidden.contains("deleting .mkg-* files"), "{forbidden}");
        // the unreadable-listing problem is treated the same way
        let v = json!({"healthy": true, "nodes": {
            "node-a": node_doc(&["the agent cannot say whether kept versions of a configuration exist"])}});
        let g = for_chronyd(&v, &[]);
        assert!(joined(&g.forbidden).contains("chronyd apply --node node-a"));
    }

    #[test]
    fn an_unobserved_or_unhealthy_node_forbids_the_apply_on_that_node() {
        let v = json!({"healthy": false, "nodes": {
            "node-a": {"tracking_ok": false, "unit_active": true, "problems": []},
            "node-b": {"error": "unreachable"}}});
        let g = for_chronyd(&v, &[]);
        let allowed = joined(&g.allowed);
        let forbidden = joined(&g.forbidden);
        assert!(
            allowed.contains("node-b: make the node reachable"),
            "{allowed}"
        );
        assert!(allowed.contains("mkg resource status chronyd"), "{allowed}");
        assert!(!allowed.contains("mkg chronyd apply"), "{allowed}");
        assert!(
            forbidden.contains("chronyd apply --node node-a"),
            "{forbidden}"
        );
        assert!(
            forbidden.contains("chronyd apply --node node-b"),
            "{forbidden}"
        );
        assert!(forbidden.contains("deleting .mkg-* files"), "{forbidden}");
    }

    #[test]
    fn a_node_without_a_proven_ha_exclusion_has_the_apply_forbidden() {
        // audit MEDIUM-2d
        let v =
            json!({"healthy": true, "nodes": {"node-a": node_doc(&[]), "node-b": node_doc(&[])}});
        let g = for_chronyd(&v, &["node-b".to_string()]);
        let forbidden = joined(&g.forbidden);
        assert!(
            forbidden.contains("chronyd apply --node node-b"),
            "{forbidden}"
        );
        assert!(
            forbidden.contains("exclusion from the HA daemon is not proven"),
            "{forbidden}"
        );
        assert!(!forbidden.contains("--node node-a"), "{forbidden}");
    }

    #[test]
    fn the_text_lists_allowed_before_forbidden() {
        let holders = a();
        let mut f = facts("unresolved_operation", &holders);
        f.op_id = Some("move-1");
        let text = for_vip(&f).text();
        let first_forbidden = text.find("next (forbidden)").unwrap();
        let last_allowed = text.rfind("next (allowed)").unwrap();
        assert!(last_allowed < first_forbidden);
    }
}
