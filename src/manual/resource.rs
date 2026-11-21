//! Resource catalogue and read-only status of the manual control plane.

use super::chrony_ctl;
use super::vip::{self, Reach, describe_node, ping, probe, svc_status};
use super::{Ctx, Res};
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ResourceRow {
    pub(crate) name: &'static str,
    pub(crate) kind: &'static str,
    /// Facts taken from the configuration file.
    pub(crate) configured: Value,
    /// Facts observed now; `null` members are *unknown*, never "healthy".
    pub(crate) runtime: Value,
}

pub(crate) fn list(ctx: &Ctx<'_>) -> Res<Vec<ResourceRow>> {
    let cfg = ctx.cfg;
    let cidr = cfg.vip_cidr();
    let mut holders = Vec::new();
    let mut cloud_known = true;
    for node in &cfg.nodes {
        match describe_node(ctx, node) {
            Ok(view) => {
                if view.info.has_alias(&cidr) {
                    holders.push(view.node.name.clone());
                }
            }
            Err(_) => cloud_known = false,
        }
    }
    let recorded = vip::lease_status(ctx)
        .ok()
        .map(|v| (v.state.owner, v.state.epoch));
    let mut chrony_nodes = serde_json::Map::new();
    for node in &cfg.nodes {
        let active = ctx
            .node_target(&node.name)
            .ok()
            .and_then(|t| svc_status(ctx, &t, &cfg.chrony_unit).ok())
            .map(|s| s.active);
        chrony_nodes.insert(node.name.clone(), json!({"active": active}));
    }
    let mut demo_nodes = serde_json::Map::new();
    for node in &cfg.nodes {
        let active = ctx
            .node_target(&node.name)
            .ok()
            .and_then(|t| svc_status(ctx, &t, &cfg.service).ok())
            .map(|s| s.active);
        demo_nodes.insert(node.name.clone(), json!({"active": active}));
    }
    Ok(vec![
        ResourceRow {
            name: "vip",
            kind: "gce-alias-ip",
            configured: json!({"address": cfg.vip, "port": cfg.vip_port, "nodes": cfg.node_names()}),
            runtime: json!({
                "cloud_holders": if cloud_known { json!(holders) } else { Value::Null },
                "recorded_owner": recorded.as_ref().and_then(|r| r.0.clone()),
                "epoch": recorded.as_ref().map(|r| r.1),
            }),
        },
        ResourceRow {
            name: "chronyd",
            kind: "systemd-service",
            configured: json!({"unit": cfg.chrony_unit, "nodes": cfg.node_names(), "mode": "both nodes run it; not moved with the VIP"}),
            runtime: json!({"nodes": chrony_nodes}),
        },
        ResourceRow {
            name: "demo",
            kind: "systemd-service",
            configured: json!({"unit": cfg.service, "nodes": cfg.node_names(), "mode": "follows the VIP; changed only by `resource move vip`"}),
            runtime: json!({"nodes": demo_nodes}),
        },
    ])
}

pub(crate) fn chronyd_status(ctx: &Ctx<'_>, only: Option<&str>) -> Res<Value> {
    let names: Vec<String> = match only {
        Some(n) => vec![ctx.node(n)?.name.clone()],
        None => ctx.cfg.node_names(),
    };
    let mut nodes = serde_json::Map::new();
    let mut all_ok = true;
    for name in &names {
        let value = chrony_ctl::status_value(ctx, name);
        let ok = value.get("error").is_none()
            && value["unit_active"].as_bool() == Some(true)
            && value["tracking_ok"].as_bool() == Some(true)
            && value["conf_trusted"].as_bool() == Some(true)
            && value["unit_matches"].as_bool() == Some(true);
        all_ok &= ok;
        nodes.insert(name.clone(), value);
    }
    Ok(json!({"resource": "chronyd", "healthy": all_ok, "nodes": nodes}))
}

pub(crate) fn demo_status(ctx: &Ctx<'_>) -> Res<Value> {
    let mut nodes = serde_json::Map::new();
    for node in &ctx.cfg.nodes {
        let mut entry = json!({});
        match ctx.node_target(&node.name) {
            Ok(target) => match ping(ctx, &node.name, &target) {
                Ok(Reach::Up(_)) => {
                    entry["reachable"] = json!(true);
                    entry["active"] = svc_status(ctx, &target, &ctx.cfg.service)
                        .map(|s| json!(s.active))
                        .unwrap_or(Value::Null);
                    entry["local_id"] = probe(ctx, &target, "127.0.0.1", ctx.cfg.vip_port)
                        .ok()
                        .flatten()
                        .map_or(Value::Null, Value::from);
                }
                Ok(Reach::Down(m)) => {
                    entry["reachable"] = json!(false);
                    entry["error"] = json!(m);
                }
                Err(f) => entry["error"] = json!(f.message()),
            },
            Err(f) => entry["error"] = json!(f.message()),
        }
        nodes.insert(node.name.clone(), entry);
    }
    Ok(json!({"resource": "demo", "nodes": nodes}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manual::fakes::World;

    #[test]
    fn list_separates_configuration_from_observation() {
        let w = World::new("res-list");
        let rows = list(&w.ctx()).unwrap();
        assert_eq!(
            rows.iter().map(|r| r.name).collect::<Vec<_>>(),
            ["vip", "chronyd", "demo"]
        );
        assert_eq!(rows[0].configured["address"], "10.0.0.130");
        assert_eq!(rows[0].runtime["cloud_holders"], json!(["node-a"]));
        assert_eq!(rows[0].runtime["recorded_owner"], "node-a");
        assert_eq!(rows[1].runtime["nodes"]["node-a"]["active"], true);
        assert_eq!(rows[2].runtime["nodes"]["node-b"]["active"], false);
    }

    #[test]
    fn unknown_runtime_facts_are_null_not_healthy() {
        let w = World::new("res-list-unknown");
        w.remote.host("node-b").reachable.set(false);
        w.gce.fail_describe("inst-b", true);
        let rows = list(&w.ctx()).unwrap();
        assert!(rows[0].runtime["cloud_holders"].is_null());
        assert!(rows[1].runtime["nodes"]["node-b"]["active"].is_null());
    }

    #[test]
    fn chronyd_status_reports_each_node_and_overall_health() {
        let w = World::new("res-chrony");
        let ok = chronyd_status(&w.ctx(), None).unwrap();
        assert_eq!(ok["healthy"], true);
        w.remote
            .host("node-b")
            .sys
            .set_service("chrony.service", "inactive");
        let bad = chronyd_status(&w.ctx(), None).unwrap();
        assert_eq!(bad["healthy"], false);
        assert_eq!(bad["nodes"]["node-b"]["unit_active"], false);
        w.remote.host("node-b").reachable.set(false);
        let down = chronyd_status(&w.ctx(), Some("node-b")).unwrap();
        assert_eq!(down["healthy"], false);
        assert!(down["nodes"]["node-b"]["error"].is_string());
    }

    #[test]
    fn demo_status_shows_where_the_service_runs() {
        let w = World::new("res-demo");
        let v = demo_status(&w.ctx()).unwrap();
        assert_eq!(v["nodes"]["node-a"]["active"], true);
        assert_eq!(v["nodes"]["node-a"]["local_id"], "node-a");
        assert_eq!(v["nodes"]["node-b"]["active"], false);
    }
}
