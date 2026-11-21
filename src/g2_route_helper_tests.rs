//! v0.7 G-2: the helper's route decisions (`gce_fence_backend` route core, contract R4.1 §3.1),
//! against a scripted Compute API fake and in-memory stores. No real API is called.
//!
//! Test-only: everything is inside `mod tests`, so the architecture guards (which read a module
//! up to `mod tests`) never count it as production code.

#[cfg(test)]
mod tests {

    use crate::gce_fence_backend::*;
    use serde_json::{Value, json};
    use std::collections::{HashMap, VecDeque};

    const CLUSTER: &str = "c1";
    const PEER_NODE: &str = "node-a";
    const INCIDENT: &str = "11111111-1111-4111-8111-111111111111";
    const VIP: &str = "10.0.0.50/32";

    fn peer() -> InstanceIdentity {
        InstanceIdentity {
            project: "p".to_string(),
            zone: "z1".to_string(),
            name: "vm-a".to_string(),
            instance_id: "1001".to_string(),
        }
    }

    fn own() -> InstanceIdentity {
        InstanceIdentity {
            project: "p".to_string(),
            zone: "z2".to_string(),
            name: "vm-b".to_string(),
            instance_id: "2002".to_string(),
        }
    }

    fn plan(methods: Vec<FenceMethod>, combine: Combine) -> FencePlan {
        let alias = methods
            .contains(&FenceMethod::AliasIp)
            .then(|| AliasPolicy {
                nic: "nic0".to_string(),
                ranges: vec![VIP.to_string()],
                inventory_complete: false,
                propagation_hold_ms: 30_000,
                max_observation_gap_ms: 15_000,
                probe_required: true,
                short_hold_for_test: false,
            });
        FencePlan {
            cluster: CLUSTER.to_string(),
            target_node: PEER_NODE.to_string(),
            target: peer(),
            methods,
            combine,
            alias,
        }
    }

    fn full_plan() -> FencePlan {
        plan(vec![FenceMethod::Stop, FenceMethod::AliasIp], Combine::All)
    }

    fn intent(confirmed_by: &str) -> RouteIntent {
        RouteIntent {
            version: ROUTE_RECORD_VERSION,
            cluster: CLUSTER.to_string(),
            node: "node-b".to_string(),
            peer_node: PEER_NODE.to_string(),
            term: 8,
            origin: RouteOrigin::Fencing {
                incident_seq: 3,
                incident_id: INCIDENT.to_string(),
                attempt_token: 2,
                confirmed_by: confirmed_by.to_string(),
            },
        }
    }

    fn binding_for(plan: &FencePlan, confirmed_by: &str) -> RouteBinding {
        RouteBinding::from_intent(
            plan,
            &own(),
            &intent(confirmed_by),
            Some(INCIDENT),
            Some("2"),
        )
        .unwrap()
    }

    fn fence_binding() -> AttemptBinding {
        AttemptBinding {
            cluster: CLUSTER.to_string(),
            target_node: PEER_NODE.to_string(),
            incident_id: INCIDENT.to_string(),
            attempt_token: 2,
        }
    }

    #[derive(Default)]
    struct Records {
        fence: HashMap<(String, u64, &'static str), ActionRecord>,
        observation: HashMap<String, RouteObservation>,
        assign: HashMap<String, RouteAssignRecord>,
        reissue: HashMap<String, RouteAssignRecord>,
        fail_assign_save: bool,
        fail_reissue_save: bool,
        /// r17 R-9: `Some(true)` another route record is newer; `None` the check fails.
        newer: Option<bool>,
    }

    impl RecordStore for Records {
        fn load(
            &mut self,
            binding: &AttemptBinding,
            method: FenceMethod,
        ) -> Result<Option<ActionRecord>, StoreError> {
            Ok(self
                .fence
                .get(&(
                    binding.incident_id.clone(),
                    binding.attempt_token,
                    method.as_str(),
                ))
                .cloned())
        }
        fn save(&mut self, record: &ActionRecord) -> Result<(), StoreError> {
            self.fence.insert(
                (
                    record.binding.incident_id.clone(),
                    record.binding.attempt_token,
                    record.method.as_str(),
                ),
                record.clone(),
            );
            Ok(())
        }
    }

    impl RouteStore for Records {
        fn load_observation(&mut self, key: &str) -> Result<Option<RouteObservation>, StoreError> {
            Ok(self.observation.get(key).cloned())
        }
        fn save_observation(&mut self, record: &RouteObservation) -> Result<(), StoreError> {
            self.observation.insert(record.key.clone(), record.clone());
            Ok(())
        }
        fn load_assign(&mut self, key: &str) -> Result<Option<RouteAssignRecord>, StoreError> {
            Ok(self.assign.get(key).cloned())
        }
        fn save_assign(&mut self, record: &RouteAssignRecord) -> Result<(), StoreError> {
            if self.fail_assign_save {
                return Err(StoreError::Io("injected".to_string()));
            }
            self.assign.insert(record.key.clone(), record.clone());
            Ok(())
        }
        fn load_reissue(&mut self, key: &str) -> Result<Option<RouteAssignRecord>, StoreError> {
            Ok(self.reissue.get(key).cloned())
        }
        fn save_reissue(&mut self, record: &RouteAssignRecord) -> Result<(), StoreError> {
            if self.fail_reissue_save {
                return Err(StoreError::Io("injected".to_string()));
            }
            self.reissue.insert(record.key.clone(), record.clone());
            Ok(())
        }
        fn newer_route_records(&mut self, _key: &str) -> Result<bool, StoreError> {
            self.newer
                .ok_or_else(|| StoreError::Io("injected".to_string()))
        }
    }

    fn confirmed_record(
        binding: &AttemptBinding,
        method: FenceMethod,
        phase: ActionPhase,
    ) -> ActionRecord {
        ActionRecord {
            version: RECORD_VERSION,
            binding: binding.clone(),
            method,
            target: peer(),
            request_id: request_id(binding, method),
            phase,
            removal_first_seen_ms: None,
            removal_last_seen_ms: None,
            alias_poll_open: false,
            confirmed: Some(ConfirmedEvidence {
                observed_at_ms: 1,
                summary: "isolated".to_string(),
            }),
            plan_digest: Some(plan_digest(&full_plan())),
        }
    }

    fn proven_records() -> Records {
        let mut records = Records::default();
        let fence = fence_binding();
        records
            .save(&confirmed_record(
                &fence,
                FenceMethod::Stop,
                ActionPhase::Accepted {
                    operation: "op-stop".to_string(),
                },
            ))
            .unwrap();
        records
            .save(&confirmed_record(
                &fence,
                FenceMethod::AliasIp,
                ActionPhase::Accepted {
                    operation: "op-remove".to_string(),
                },
            ))
            .unwrap();
        records
    }

    /// A scripted Compute API: answers in order; records every call.
    struct Api {
        answers: VecDeque<HttpOutcome>,
        calls: Vec<(HttpMethod, String, Option<String>)>,
    }

    impl Api {
        fn new(answers: Vec<HttpOutcome>) -> Self {
            Self {
                answers: answers.into(),
                calls: Vec::new(),
            }
        }
    }

    impl ComputeTransport for Api {
        fn call(&mut self, method: HttpMethod, path: &str, body: Option<&str>) -> HttpOutcome {
            self.calls
                .push((method, path.to_string(), body.map(str::to_string)));
            self.answers
                .pop_front()
                .unwrap_or(HttpOutcome::Transport("unscripted".to_string()))
        }
    }

    fn ok(value: Value) -> HttpOutcome {
        HttpOutcome::Response {
            status: 200,
            body: value.to_string(),
        }
    }

    fn instance(identity: &InstanceIdentity, status: &str, ranges: Vec<Value>) -> HttpOutcome {
        ok(json!({
            "id": identity.instance_id,
            "name": identity.name,
            "status": status,
            "networkInterfaces": [{
                "name": "nic0",
                "fingerprint": "fp-1",
                "aliasIpRanges": ranges,
            }],
        }))
    }

    fn operation(name: &str, target: &str, kind: &str, status: &str, error: bool) -> HttpOutcome {
        let mut value = json!({
            "name": name,
            "operationType": kind,
            "targetId": target,
            "status": status,
        });
        if error {
            value["error"] = json!({"errors": [{"code": "RESOURCE_IN_USE"}]});
        }
        ok(value)
    }

    // ---- route-check (G-A3) ---------------------------------------------------------------------

    #[test]
    fn g2h_route_check_needs_both_confirmed_records_of_the_same_attempt() {
        let plan = full_plan();
        let binding = binding_for(&plan, "backend");
        assert!(route_check(&plan, &binding, &mut proven_records()).is_ok());
        // The alias NotNeeded + confirmed record also proves the removal.
        let mut records = proven_records();
        records
            .save(&confirmed_record(
                &fence_binding(),
                FenceMethod::AliasIp,
                ActionPhase::NotNeeded,
            ))
            .unwrap();
        assert!(route_check(&plan, &binding, &mut records).is_ok());
    }

    #[test]
    fn g2h_route_check_refusals() {
        let plan = full_plan();
        let binding = binding_for(&plan, "backend");
        // Operator-attested (T8) origin: no fence binding.
        assert!(
            route_check(
                &plan,
                &binding_for(&plan, "operator"),
                &mut proven_records()
            )
            .is_err()
        );
        // A plan that is not stop + alias with combine = all.
        for other in [plan_any(), stop_only_plan()] {
            let mut records = proven_records();
            let alt_binding = RouteBinding::from_intent(
                &plan,
                &own(),
                &intent("backend"),
                Some(INCIDENT),
                Some("2"),
            )
            .unwrap();
            assert!(route_check(&other, &alt_binding, &mut records).is_err());
        }
        // A missing, unconfirmed, foreign-token or unfinished record.
        let mut missing = proven_records();
        missing.fence.remove(&(INCIDENT.to_string(), 2, "stop"));
        assert!(route_check(&plan, &binding, &mut missing).is_err());
        let mut unconfirmed = proven_records();
        unconfirmed
            .fence
            .get_mut(&(INCIDENT.to_string(), 2, "alias-ip"))
            .unwrap()
            .confirmed = None;
        assert!(route_check(&plan, &binding, &mut unconfirmed).is_err());
        let mut foreign = proven_records();
        let mut other_token = fence_binding();
        other_token.attempt_token = 9;
        foreign
            .fence
            .get_mut(&(INCIDENT.to_string(), 2, "stop"))
            .unwrap()
            .binding = other_token;
        assert!(route_check(&plan, &binding, &mut foreign).is_err());
        let mut intent_only = proven_records();
        intent_only
            .fence
            .get_mut(&(INCIDENT.to_string(), 2, "stop"))
            .unwrap()
            .phase = ActionPhase::Intent;
        assert!(route_check(&plan, &binding, &mut intent_only).is_err());
    }

    fn stop_only_plan() -> FencePlan {
        plan(vec![FenceMethod::Stop], Combine::All)
    }

    fn plan_any() -> FencePlan {
        plan(
            vec![FenceMethod::Stop, FenceMethod::AliasIp],
            Combine::AnySufficient,
        )
    }

    /// Audit M-3: the fence records name the plan they ran under; a plan changed afterwards
    /// (other protected ranges, another NIC, another combination) is refused, and a record
    /// written before G-2 (no digest) never proves anything for the route.
    #[test]
    fn g2h_route_check_refuses_a_plan_changed_after_the_fence() {
        let mut changed = full_plan();
        changed.alias.as_mut().unwrap().ranges = vec!["10.0.0.60/32".to_string()];
        let binding = RouteBinding::from_intent(
            &changed,
            &own(),
            &intent("backend"),
            Some(INCIDENT),
            Some("2"),
        )
        .unwrap();
        let error = route_check(&changed, &binding, &mut proven_records()).unwrap_err();
        assert!(error.contains("another fencing plan"), "{error}");
        let mut nic = full_plan();
        nic.alias.as_mut().unwrap().nic = "nic1".to_string();
        let binding =
            RouteBinding::from_intent(&nic, &own(), &intent("backend"), Some(INCIDENT), Some("2"))
                .unwrap();
        assert!(route_check(&nic, &binding, &mut proven_records()).is_err());
        let plan = full_plan();
        let binding = binding_for(&plan, "backend");
        let mut legacy = proven_records();
        for record in legacy.fence.values_mut() {
            record.plan_digest = None;
        }
        assert!(route_check(&plan, &binding, &mut legacy).is_err());
        // The same plan with its ranges listed in another order is the same plan.
        let mut two = full_plan();
        two.alias.as_mut().unwrap().ranges = vec![VIP.to_string(), "10.0.1.0/30".to_string()];
        let mut swapped = two.clone();
        swapped.alias.as_mut().unwrap().ranges.reverse();
        assert_eq!(plan_digest(&two), plan_digest(&swapped));
        assert_ne!(plan_digest(&two), plan_digest(&full_plan()));
    }

    #[test]
    fn g2h_fence_records_carry_the_plan_digest() {
        let plan = full_plan();
        let mut records = Records::default();
        let mut api = Api::new(vec![
            instance(&peer(), "RUNNING", vec![json!({"ipCidrRange": VIP})]),
            operation("op-r", "1001", "updateNetworkInterface", "RUNNING", false),
            instance(&peer(), "RUNNING", vec![]),
            operation("op-s", "1001", "stop", "RUNNING", false),
        ]);
        let reports = fence(&mut ActionContext {
            plan: &plan,
            binding: &fence_binding(),
            api: &mut api,
            store: &mut records,
            hooks: &mut NoFaults,
        });
        assert_eq!(reports.len(), 2);
        for record in records.fence.values() {
            assert_eq!(
                record.plan_digest.as_deref(),
                Some(plan_digest(&plan).as_str())
            );
        }
    }

    /// Audit M-1: a failed peer describe (not 404) is a definitive C-3 failure, not "no answer".
    #[test]
    fn g2h_peer_describe_failure_is_c3_not_holding() {
        let plan = full_plan();
        let binding = binding_for(&plan, "backend");
        for status in [500, 503, 403] {
            let mut api = Api::new(vec![HttpOutcome::Response {
                status,
                body: "{}".to_string(),
            }]);
            assert_eq!(observe_peer(&mut api, &binding).unwrap(), "peer unknown");
        }
        let mut api = Api::new(vec![HttpOutcome::Timeout]);
        assert_eq!(observe_peer(&mut api, &binding).unwrap(), "peer unknown");
    }

    // ---- binding ---------------------------------------------------------------------------------

    #[test]
    fn g2h_binding_is_checked_against_the_configuration_and_the_step() {
        let plan = full_plan();
        let mut wrong_cluster = intent("backend");
        wrong_cluster.cluster = "other".to_string();
        assert!(
            RouteBinding::from_intent(&plan, &own(), &wrong_cluster, Some(INCIDENT), Some("2"))
                .is_err()
        );
        let mut wrong_peer = intent("backend");
        wrong_peer.peer_node = "node-x".to_string();
        assert!(
            RouteBinding::from_intent(&plan, &own(), &wrong_peer, Some(INCIDENT), Some("2"))
                .is_err()
        );
        // The step identity must be the intent's incident and attempt.
        assert!(
            RouteBinding::from_intent(&plan, &own(), &intent("backend"), Some(INCIDENT), Some("3"))
                .is_err()
        );
        assert!(
            RouteBinding::from_intent(&plan, &own(), &intent("backend"), None, Some("2")).is_err()
        );
        // The own instance can never be the fencing target.
        assert!(
            RouteBinding::from_intent(
                &plan,
                &peer(),
                &intent("backend"),
                Some(INCIDENT),
                Some("2")
            )
            .is_err()
        );
        // Key and request id are stable identity only.
        let a = binding_for(&plan, "backend");
        let b = binding_for(&plan, "backend");
        assert_eq!(a.key(), b.key());
        assert_eq!(a.request_id(), b.request_id());
        assert!(is_canonical_uuid_v4(&a.request_id()));
        let mut next = intent("backend");
        next.term = 10;
        let c = RouteBinding::from_intent(&plan, &own(), &next, Some(INCIDENT), Some("2")).unwrap();
        assert_ne!(a.key(), c.key());
        assert_ne!(a.request_id(), c.request_id());
    }

    #[test]
    fn g2h_the_daemon_intent_format_is_the_helper_intent_format() {
        let daemon = crate::route_handoff::RhIntent {
            version: crate::route_handoff::RH_RECORD_VERSION,
            cluster: CLUSTER.to_string(),
            node: "node-b".to_string(),
            peer_node: PEER_NODE.to_string(),
            term: 8,
            origin: crate::route_handoff::RhOrigin::Fencing {
                incident_seq: 3,
                incident_id: INCIDENT.to_string(),
                attempt_token: 2,
                confirmed_by: crate::route_handoff::RhConfirmation::Backend,
            },
        };
        let text = serde_json::to_string(&daemon).unwrap();
        let helper: RouteIntent = serde_json::from_str(&text).unwrap();
        assert_eq!(helper, intent("backend"));
        for origin in [
            crate::route_handoff::RhOrigin::Bootstrap,
            crate::route_handoff::RhOrigin::Unknown,
        ] {
            let mut copy = daemon.clone();
            copy.origin = origin;
            let parsed: RouteIntent =
                serde_json::from_str(&serde_json::to_string(&copy).unwrap()).unwrap();
            assert!(matches!(
                parsed.origin,
                RouteOrigin::Bootstrap | RouteOrigin::Unknown
            ));
        }
    }

    // ---- route-observe ----------------------------------------------------------------------------

    #[test]
    fn g2h_observe_own_classifies_and_records_the_whole_nic() {
        let plan = full_plan();
        let binding = binding_for(&plan, "backend");
        let other = json!({"ipCidrRange": "10.0.9.0/24", "subnetworkRangeName": "pods"});
        for (ranges, expected) in [
            (vec![json!({"ipCidrRange": VIP}), other.clone()], "own all"),
            (vec![other.clone()], "own none"),
        ] {
            let mut records = Records::default();
            let mut api = Api::new(vec![instance(&own(), "RUNNING", ranges.clone())]);
            assert_eq!(
                observe_own(&mut api, &binding, &mut records).unwrap(),
                expected
            );
            assert_eq!(api.calls.len(), 1);
            let observation = records.observation.get(&binding.key()).unwrap();
            assert_eq!(observation.fingerprint, "fp-1");
            assert_eq!(observation.alias_entries, ranges);
        }
        let mut records = Records::default();
        let mut mismatch = Api::new(vec![instance(&peer(), "RUNNING", vec![])]);
        assert_eq!(
            observe_own(&mut mismatch, &binding, &mut records).unwrap(),
            "own mismatch"
        );
        let mut failed = Api::new(vec![HttpOutcome::Timeout]);
        assert!(observe_own(&mut failed, &binding, &mut records).is_err());
    }

    #[test]
    fn g2h_observe_peer_is_by_address_on_every_nic() {
        let plan = full_plan();
        let binding = binding_for(&plan, "backend");
        let cases = vec![
            (instance(&peer(), "TERMINATED", vec![]), Ok("peer absent")),
            (
                instance(
                    &peer(),
                    "TERMINATED",
                    vec![json!({"ipCidrRange": "10.0.0.48/28"})],
                ),
                Ok("peer present"),
            ),
            (
                instance(
                    &peer(),
                    "TERMINATED",
                    vec![json!({"ipCidrRange": "garbage"})],
                ),
                Ok("peer present"),
            ),
            (
                HttpOutcome::Response {
                    status: 404,
                    body: "{}".to_string(),
                },
                Ok("peer missing"),
            ),
            (instance(&own(), "RUNNING", vec![]), Ok("peer mismatch")),
        ];
        for (answer, expected) in cases {
            let mut api = Api::new(vec![answer]);
            assert_eq!(
                observe_peer(&mut api, &binding),
                expected.map_err(|e: &str| e.to_string())
            );
        }
        let mut failed = Api::new(vec![HttpOutcome::Response {
            status: 503,
            body: "{}".to_string(),
        }]);
        assert_eq!(observe_peer(&mut failed, &binding).unwrap(), "peer unknown");
    }

    #[test]
    fn g2h_observe_op_matches_only_the_terms_own_request() {
        let plan = full_plan();
        let binding = binding_for(&plan, "backend");
        let key = binding.key();
        let record = |phase: ActionPhase| RouteAssignRecord {
            version: ROUTE_RECORD_VERSION,
            key: key.clone(),
            request_id: binding.request_id(),
            own: own(),
            nic: "nic0".to_string(),
            phase,
            base: None,
        };
        let mut records = Records::default();
        assert_eq!(
            observe_op(&mut Api::new(vec![]), &binding, &mut records).unwrap(),
            "op none"
        );
        // r17: no operation name (intent only, or outcome unknown) is looked up by the requestId;
        // an unscripted (failed) list read is `op unknown`, never `op absent`.
        for (phase, expected) in [
            (ActionPhase::Intent, "op unknown"),
            (
                ActionPhase::Refused {
                    failure: ApiFailure::PreconditionFailed,
                },
                "op refused",
            ),
            (
                ActionPhase::OutcomeUnknown {
                    failure: ApiFailure::Timeout,
                },
                "op unknown",
            ),
        ] {
            records.assign.insert(key.clone(), record(phase));
            assert_eq!(
                observe_op(&mut Api::new(vec![]), &binding, &mut records).unwrap(),
                expected
            );
        }
        records.assign.insert(
            key.clone(),
            record(ActionPhase::Accepted {
                operation: "op-1".to_string(),
            }),
        );
        for (answer, expected) in [
            (
                operation("op-1", "2002", "updateNetworkInterface", "RUNNING", false),
                "op pending",
            ),
            (
                operation("op-1", "2002", "updateNetworkInterface", "DONE", false),
                "op done-ok",
            ),
            (
                operation("op-1", "2002", "updateNetworkInterface", "DONE", true),
                "op done-error",
            ),
            // Stale or foreign operations never count.
            (
                operation("op-1", "1001", "updateNetworkInterface", "DONE", false),
                "op mismatch",
            ),
            (
                operation("op-1", "2002", "stop", "DONE", false),
                "op mismatch",
            ),
            (
                operation("op-9", "2002", "updateNetworkInterface", "DONE", false),
                "op mismatch",
            ),
        ] {
            let mut api = Api::new(vec![answer]);
            assert_eq!(
                observe_op(&mut api, &binding, &mut records).unwrap(),
                expected
            );
            assert_eq!(api.calls.len(), 1);
        }
        // A record of another request id is not this term's request.
        let mut foreign = record(ActionPhase::Accepted {
            operation: "op-1".to_string(),
        });
        foreign.request_id = "22222222-2222-4222-8222-222222222222".to_string();
        records.assign.insert(key.clone(), foreign);
        assert_eq!(
            observe_op(&mut Api::new(vec![]), &binding, &mut records).unwrap(),
            "op mismatch"
        );
    }

    // ---- route-assign -----------------------------------------------------------------------------

    fn observed(records: &mut Records, binding: &RouteBinding, entries: Vec<Value>) {
        let mut api = Api::new(vec![instance(&own(), "RUNNING", entries)]);
        observe_own(&mut api, binding, records).unwrap();
    }

    #[test]
    fn g2h_route_assign_keeps_every_other_entry_and_sends_once() {
        let plan = full_plan();
        let binding = binding_for(&plan, "backend");
        let mut fence = proven_records();
        let mut records = Records::default();
        let other = json!({"ipCidrRange": "10.0.9.0/24", "subnetworkRangeName": "pods"});
        observed(&mut records, &binding, vec![other.clone()]);
        let mut api = Api::new(vec![operation(
            "op-1",
            "2002",
            "updateNetworkInterface",
            "RUNNING",
            false,
        )]);
        let answer = route_assign(&mut api, &plan, &binding, &mut fence, &mut records);
        assert_eq!(answer, "accepted");
        assert_eq!(api.calls.len(), 1, "one API call per step");
        let (method, path, body) = &api.calls[0];
        assert_eq!(*method, HttpMethod::Patch);
        assert!(path.contains("instances/vm-b/updateNetworkInterface?networkInterface=nic0"));
        assert!(path.ends_with(&format!("requestId={}", binding.request_id())));
        let body: Value = serde_json::from_str(body.as_deref().unwrap()).unwrap();
        assert_eq!(body["fingerprint"], "fp-1");
        assert_eq!(
            body["aliasIpRanges"],
            json!([other, {"ipCidrRange": VIP}]),
            "the other range and its subnetworkRangeName are kept unchanged"
        );
        // A second invocation of the term never sends again.
        let mut again = Api::new(vec![]);
        assert_eq!(
            route_assign(&mut again, &plan, &binding, &mut fence, &mut records),
            "already accepted"
        );
        assert!(again.calls.is_empty());
    }

    #[test]
    fn g2h_route_assign_failure_classes() {
        let plan = full_plan();
        let binding = binding_for(&plan, "backend");
        for (answer, expected) in [
            (
                HttpOutcome::Response {
                    status: 412,
                    body: "{}".to_string(),
                },
                "refused",
            ),
            (
                HttpOutcome::Response {
                    status: 403,
                    body: "{}".to_string(),
                },
                "refused",
            ),
            (HttpOutcome::Timeout, "unknown"),
            (
                HttpOutcome::Response {
                    status: 503,
                    body: "{}".to_string(),
                },
                "unknown",
            ),
            (
                operation("op-1", "1001", "updateNetworkInterface", "RUNNING", false),
                "unknown",
            ),
        ] {
            let mut fence = proven_records();
            let mut records = Records::default();
            observed(&mut records, &binding, vec![]);
            let mut api = Api::new(vec![answer]);
            assert_eq!(
                route_assign(&mut api, &plan, &binding, &mut fence, &mut records),
                expected
            );
            // The intent was durable before the request, whatever the outcome.
            assert!(records.assign.contains_key(&binding.key()));
            let mut again = Api::new(vec![]);
            assert!(
                route_assign(&mut again, &plan, &binding, &mut fence, &mut records)
                    .starts_with("already")
            );
            assert!(again.calls.is_empty());
        }
    }

    #[test]
    fn g2h_route_assign_never_sends_without_proof_observation_or_intent() {
        let plan = full_plan();
        let binding = binding_for(&plan, "backend");
        // G-A3 fails: refused, nothing sent.
        let mut no_proof = Records::default();
        let mut records = Records::default();
        observed(&mut records, &binding, vec![]);
        let mut api = Api::new(vec![]);
        assert_eq!(
            route_assign(&mut api, &plan, &binding, &mut no_proof, &mut records),
            "refused"
        );
        assert!(api.calls.is_empty());
        // No own observation: blocked.
        let mut fence = proven_records();
        let mut empty = Records::default();
        assert_eq!(
            route_assign(&mut api, &plan, &binding, &mut fence, &mut empty),
            "blocked"
        );
        assert!(api.calls.is_empty());
        // An overlapping range that is not the protected one: blocked.
        let mut overlap = Records::default();
        observed(
            &mut overlap,
            &binding,
            vec![json!({"ipCidrRange": "10.0.0.48/28"})],
        );
        assert_eq!(
            route_assign(&mut api, &plan, &binding, &mut fence, &mut overlap),
            "blocked"
        );
        assert!(api.calls.is_empty());
        // The intent cannot be persisted: blocked, nothing sent.
        let mut failing = Records::default();
        observed(&mut failing, &binding, vec![]);
        failing.fail_assign_save = true;
        assert_eq!(
            route_assign(&mut api, &plan, &binding, &mut fence, &mut failing),
            "blocked"
        );
        assert!(api.calls.is_empty());
        // Already present: not-needed, nothing sent.
        let mut present = Records::default();
        observed(&mut present, &binding, vec![json!({"ipCidrRange": VIP})]);
        assert_eq!(
            route_assign(&mut api, &plan, &binding, &mut fence, &mut present),
            "not-needed"
        );
        assert!(api.calls.is_empty());
    }

    // ---- operator-assign --------------------------------------------------------------------------

    #[test]
    fn g2h_operator_assign_requires_the_peer_stopped_and_free() {
        let plan = full_plan();
        let request = "33333333-3333-4333-8333-333333333333";
        let mut records = Records::default();
        let mut running = Api::new(vec![instance(&peer(), "RUNNING", vec![])]);
        assert!(
            operator_assign(&mut running, &plan, &own(), request, &mut records)
                .starts_with("refused")
        );
        assert_eq!(running.calls.len(), 1);
        let mut holding = Api::new(vec![instance(
            &peer(),
            "TERMINATED",
            vec![json!({"ipCidrRange": VIP})],
        )]);
        assert!(
            operator_assign(&mut holding, &plan, &own(), request, &mut records)
                .starts_with("refused")
        );
        let mut fine = Api::new(vec![
            instance(&peer(), "TERMINATED", vec![]),
            instance(&own(), "RUNNING", vec![]),
            operation("op-7", "2002", "updateNetworkInterface", "RUNNING", false),
        ]);
        assert_eq!(
            operator_assign(&mut fine, &plan, &own(), request, &mut records),
            "accepted"
        );
        assert_eq!(
            fine.calls
                .iter()
                .filter(|c| c.0 == HttpMethod::Patch)
                .count(),
            1
        );
        let mut again = Api::new(vec![
            instance(&peer(), "TERMINATED", vec![]),
            instance(&own(), "RUNNING", vec![]),
        ]);
        assert!(
            operator_assign(&mut again, &plan, &own(), request, &mut records)
                .starts_with("already")
        );
        assert!(again.calls.iter().all(|c| c.0 == HttpMethod::Get));
        assert!(
            operator_assign(
                &mut Api::new(vec![]),
                &plan,
                &own(),
                "not-a-uuid",
                &mut records
            )
            .starts_with("blocked")
        );
    }

    // ---- r17: requestId lookup and the one re-issue (contract R5) ---------------------------------

    fn list_item(
        name: &str,
        target: &str,
        kind: &str,
        status: &str,
        client: Option<&str>,
    ) -> Value {
        let mut value = json!({
            "name": name,
            "operationType": kind,
            "targetId": target,
            "status": status,
            "zone": "https://www.googleapis.com/compute/v1/projects/p/zones/z2",
        });
        if let Some(client) = client {
            value["clientOperationId"] = json!(client);
        }
        value
    }

    fn list(items: Option<Vec<Value>>) -> Value {
        let mut value = json!({
            "kind": "compute#operationList",
            "id": "projects/p/zones/z2/operations",
        });
        if let Some(items) = items {
            value["items"] = json!(items);
        }
        value
    }

    fn unknown_record(binding: &RouteBinding, failure: ApiFailure) -> RouteAssignRecord {
        RouteAssignRecord {
            version: ROUTE_RECORD_VERSION,
            key: binding.key(),
            request_id: binding.request_id(),
            own: own(),
            nic: "nic0".to_string(),
            phase: ActionPhase::OutcomeUnknown { failure },
            base: None,
        }
    }

    #[test]
    fn r17h_lookup_finds_only_the_terms_request_in_a_complete_list() {
        let plan = full_plan();
        let binding = binding_for(&plan, "backend");
        let rid = binding.request_id();
        let mut records = Records::default();
        records
            .assign
            .insert(binding.key(), unknown_record(&binding, ApiFailure::Timeout));
        let other = "33333333-3333-4333-8333-333333333333";
        let cases: Vec<(Value, &str)> = vec![
            (
                list(Some(vec![list_item(
                    "op-1",
                    "2002",
                    "updateNetworkInterface",
                    "DONE",
                    Some(&rid),
                )])),
                "op done-ok",
            ),
            (
                list(Some(vec![list_item(
                    "op-1",
                    "2002",
                    "updateNetworkInterface",
                    "RUNNING",
                    Some(&rid),
                )])),
                "op pending",
            ),
            (
                {
                    let mut item =
                        list_item("op-1", "2002", "updateNetworkInterface", "DONE", Some(&rid));
                    item["error"] = json!({"errors": [{"code": "CONDITION_NOT_MET"}]});
                    list(Some(vec![item]))
                },
                "op done-error",
            ),
            // Complete, but without this term's requestId: absent (not proof of anything).
            (list(None), "op absent"),
            (list(Some(vec![])), "op absent"),
            (
                list(Some(vec![
                    list_item(
                        "op-7",
                        "2002",
                        "updateNetworkInterface",
                        "DONE",
                        Some(other),
                    ),
                    list_item("op-8", "2002", "stop", "DONE", None),
                ])),
                "op absent",
            ),
            // Two operations of the same request, or one of another type: not explainable.
            (
                list(Some(vec![
                    list_item("op-1", "2002", "updateNetworkInterface", "DONE", Some(&rid)),
                    list_item("op-2", "2002", "updateNetworkInterface", "DONE", Some(&rid)),
                ])),
                "op mismatch",
            ),
            (
                list(Some(vec![list_item(
                    "op-1",
                    "2002",
                    "stop",
                    "DONE",
                    Some(&rid),
                )])),
                "op mismatch",
            ),
        ];
        for (answer, expected) in cases {
            let mut api = Api::new(vec![ok(answer.clone())]);
            assert_eq!(
                observe_op(&mut api, &binding, &mut records).unwrap(),
                expected,
                "{answer}"
            );
            assert_eq!(api.calls.len(), 1, "one API call");
            assert_eq!(api.calls[0].0, HttpMethod::Get);
            assert_eq!(api.calls[0].1, term_operation_list_path(&own()));
            assert!(api.calls[0].1.contains("filter=targetId%20%3D%202002"));
        }
    }

    #[test]
    fn r18h_the_operation_list_query_has_a_filter_and_no_sort_order() {
        // r18: GCE refuses a list filter together with orderBy (HTTP 400, run t RR-R17-3 A).
        let path = term_operation_list_path(&own());
        assert_eq!(
            path,
            "projects/p/zones/z2/operations?filter=targetId%20%3D%202002&maxResults=500"
        );
        assert!(!path.contains("orderBy"), "{path}");
        assert!(!path.to_ascii_lowercase().contains("order"), "{path}");
    }

    #[test]
    fn r18h_the_lookup_does_not_depend_on_the_order_of_the_list() {
        let plan = full_plan();
        let binding = binding_for(&plan, "backend");
        let rid = binding.request_id();
        let mut records = Records::default();
        records
            .assign
            .insert(binding.key(), unknown_record(&binding, ApiFailure::Timeout));
        let other = "33333333-3333-4333-8333-333333333333";
        let mine = list_item("op-2", "2002", "updateNetworkInterface", "DONE", Some(&rid));
        let older = list_item(
            "op-1",
            "2002",
            "updateNetworkInterface",
            "DONE",
            Some(other),
        );
        let start = list_item("op-0", "2002", "start", "DONE", None);
        let orders = [
            vec![mine.clone(), older.clone(), start.clone()],
            vec![start.clone(), older.clone(), mine.clone()],
            vec![older.clone(), mine.clone(), start.clone()],
        ];
        for items in orders {
            let mut api = Api::new(vec![ok(list(Some(items.clone())))]);
            assert_eq!(
                observe_op(&mut api, &binding, &mut records).unwrap(),
                "op done-ok",
                "{items:?}"
            );
            assert_eq!(api.calls.len(), 1, "one API call");
        }
        // the same set without this term's request is absent in every order
        for items in [vec![older.clone(), start.clone()], vec![start, older]] {
            let mut api = Api::new(vec![ok(list(Some(items.clone())))]);
            assert_eq!(
                observe_op(&mut api, &binding, &mut records).unwrap(),
                "op absent",
                "{items:?}"
            );
        }
    }

    #[test]
    fn r17h_a_list_that_is_not_provably_complete_is_never_absent() {
        let plan = full_plan();
        let binding = binding_for(&plan, "backend");
        let rid = binding.request_id();
        let mut records = Records::default();
        records
            .assign
            .insert(binding.key(), unknown_record(&binding, ApiFailure::Timeout));
        let good = || list(Some(vec![]));
        let mut cases: Vec<HttpOutcome> = Vec::new();
        let mut with = |edit: &dyn Fn(&mut Value)| {
            let mut value = good();
            edit(&mut value);
            cases.push(ok(value));
        };
        with(&|v| v["nextPageToken"] = json!("tok"));
        with(&|v| v["warning"] = json!({"code": "PARTIAL_SUCCESS"}));
        with(&|v| v["warning"] = json!({"code": "NO_RESULTS_ON_PAGE"}));
        with(&|v| v["kind"] = json!("compute#instanceList"));
        with(&|v| {
            v.as_object_mut().unwrap().remove("kind");
        });
        with(&|v| v["id"] = json!("projects/p/zones/z1/operations"));
        with(&|v| v["id"] = json!("projects/q/zones/z2/operations"));
        with(&|v| v["items"] = json!(null));
        with(&|v| v["items"] = json!({"op": 1}));
        with(&|v| {
            v["items"] = json!([list_item(
                "op-1",
                "1001",
                "updateNetworkInterface",
                "DONE",
                None
            )])
        });
        with(&|v| {
            let mut item = list_item("op-1", "2002", "updateNetworkInterface", "DONE", None);
            item["zone"] = json!("https://www.googleapis.com/compute/v1/projects/p/zones/z1");
            v["items"] = json!([item]);
        });
        with(&|v| {
            let item = list_item("op-1", "2002", "updateNetworkInterface", "DONE", None);
            v["items"] = json!([item.clone(), item]);
        });
        with(&|v| {
            let mut item = list_item("op-1", "2002", "updateNetworkInterface", "DONE", None);
            item["clientOperationId"] = json!(7);
            v["items"] = json!([item]);
        });
        with(&|v| v["items"] = json!([{"name": "op-1", "targetId": "2002", "status": "DONE"}]));
        cases.push(HttpOutcome::Timeout);
        cases.push(HttpOutcome::Response {
            status: 503,
            body: "{}".to_string(),
        });
        cases.push(HttpOutcome::Response {
            status: 403,
            body: "{}".to_string(),
        });
        cases.push(HttpOutcome::Response {
            status: 200,
            body: "not json".to_string(),
        });
        let _ = rid;
        for answer in cases {
            let mut api = Api::new(vec![answer.clone()]);
            assert_eq!(
                observe_op(&mut api, &binding, &mut records).unwrap(),
                "op unknown",
                "{answer:?}"
            );
        }
    }

    #[test]
    fn r17h_an_accepted_reissue_names_the_operation() {
        let plan = full_plan();
        let binding = binding_for(&plan, "backend");
        let mut records = Records::default();
        records
            .assign
            .insert(binding.key(), unknown_record(&binding, ApiFailure::Timeout));
        let mut reissue = unknown_record(&binding, ApiFailure::Timeout);
        reissue.phase = ActionPhase::Accepted {
            operation: "op-2".to_string(),
        };
        records.reissue.insert(binding.key(), reissue.clone());
        let mut api = Api::new(vec![operation(
            "op-2",
            "2002",
            "updateNetworkInterface",
            "DONE",
            false,
        )]);
        assert_eq!(
            observe_op(&mut api, &binding, &mut records).unwrap(),
            "op done-ok"
        );
        assert!(api.calls[0].1.ends_with("/operations/op-2"));
        // A re-issue record of another request is not this term's.
        reissue.request_id = "22222222-2222-4222-8222-222222222222".to_string();
        records.reissue.insert(binding.key(), reissue);
        assert_eq!(
            observe_op(&mut Api::new(vec![]), &binding, &mut records).unwrap(),
            "op mismatch"
        );
    }

    /// The original request timed out (outcome unknown), with its base persisted; the own NIC is
    /// observed unchanged; nothing newer was written.
    fn after_timeout(
        entries: Vec<Value>,
    ) -> (FencePlan, RouteBinding, Records, Records, String, String) {
        let plan = full_plan();
        let binding = binding_for(&plan, "backend");
        let mut fence = proven_records();
        let mut records = Records {
            newer: Some(false),
            ..Records::default()
        };
        observed(&mut records, &binding, entries.clone());
        let mut api = Api::new(vec![HttpOutcome::Timeout]);
        assert_eq!(
            route_assign(&mut api, &plan, &binding, &mut fence, &mut records),
            "unknown"
        );
        let (_, path, body) = api.calls[0].clone();
        observed(&mut records, &binding, entries);
        (plan, binding, fence, records, path, body.unwrap())
    }

    #[test]
    fn r17h_route_assign_persists_the_base_of_its_body() {
        let other = json!({"ipCidrRange": "10.0.9.0/24", "subnetworkRangeName": "pods"});
        let (_, binding, _, records, _, body) = after_timeout(vec![other.clone()]);
        let record = records.assign.get(&binding.key()).unwrap();
        let base = record
            .base
            .as_ref()
            .expect("base persisted with the intent");
        assert_eq!(base.fingerprint, "fp-1");
        assert_eq!(base.alias_entries, vec![other]);
        use sha2::{Digest, Sha256};
        let digest: String = Sha256::digest(body.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(base.body_sha256, digest);
    }

    #[test]
    fn r17h_reissue_sends_the_identical_request_once() {
        let other = json!({"ipCidrRange": "10.0.9.0/24", "subnetworkRangeName": "pods"});
        let (plan, binding, mut fence, mut records, path, body) = after_timeout(vec![other]);
        let mut api = Api::new(vec![operation(
            "op-2",
            "2002",
            "updateNetworkInterface",
            "PENDING",
            false,
        )]);
        assert_eq!(
            route_reissue(&mut api, &plan, &binding, &mut fence, &mut records),
            "accepted"
        );
        assert_eq!(api.calls.len(), 1, "one API call");
        let (method, again_path, again_body) = &api.calls[0];
        assert_eq!(*method, HttpMethod::Patch);
        assert_eq!(*again_path, path, "the same requestId and target");
        assert_eq!(
            again_body.as_deref(),
            Some(body.as_str()),
            "the same body text"
        );
        assert_eq!(
            records.reissue.get(&binding.key()).unwrap().phase,
            ActionPhase::Accepted {
                operation: "op-2".to_string()
            }
        );
        // Never a second re-issue (and the original record is unchanged).
        let mut more = Api::new(vec![]);
        assert_eq!(
            route_reissue(&mut more, &plan, &binding, &mut fence, &mut records),
            "already accepted"
        );
        assert!(more.calls.is_empty());
        assert!(matches!(
            records.assign.get(&binding.key()).unwrap().phase,
            ActionPhase::OutcomeUnknown { .. }
        ));
    }

    #[test]
    fn r17h_reissue_outcome_classes_and_intent_first() {
        for (answer, expected) in [
            (HttpOutcome::Timeout, "unknown"),
            (
                HttpOutcome::Response {
                    status: 412,
                    body: "{}".to_string(),
                },
                "refused",
            ),
            (
                HttpOutcome::Response {
                    status: 503,
                    body: "{}".to_string(),
                },
                "unknown",
            ),
        ] {
            let (plan, binding, mut fence, mut records, _, _) = after_timeout(vec![]);
            let mut api = Api::new(vec![answer]);
            assert_eq!(
                route_reissue(&mut api, &plan, &binding, &mut fence, &mut records),
                expected
            );
            assert!(
                records.reissue.contains_key(&binding.key()),
                "intent durable first"
            );
            let mut more = Api::new(vec![]);
            assert!(
                route_reissue(&mut more, &plan, &binding, &mut fence, &mut records)
                    .starts_with("already")
            );
            assert!(more.calls.is_empty());
        }
    }

    #[test]
    fn r17h_reissue_refuses_before_any_call() {
        type Edit = Box<dyn Fn(&mut Records, &mut Records, &RouteBinding)>;
        let edits: Vec<(&str, Edit, &str)> = vec![
            (
                "no fence proof",
                Box::new(|_, f, _| *f = Records::default()),
                "refused",
            ),
            (
                "original accepted",
                Box::new(|r, _, b| {
                    r.assign.get_mut(&b.key()).unwrap().phase = ActionPhase::Accepted {
                        operation: "op-1".to_string(),
                    }
                }),
                "blocked",
            ),
            (
                "original refused",
                Box::new(|r, _, b| {
                    r.assign.get_mut(&b.key()).unwrap().phase = ActionPhase::Refused {
                        failure: ApiFailure::PreconditionFailed,
                    }
                }),
                "blocked",
            ),
            (
                "original intent only",
                Box::new(|r, _, b| r.assign.get_mut(&b.key()).unwrap().phase = ActionPhase::Intent),
                "blocked",
            ),
            (
                "original malformed answer",
                Box::new(|r, _, b| {
                    r.assign.get_mut(&b.key()).unwrap().phase = ActionPhase::OutcomeUnknown {
                        failure: ApiFailure::Malformed("x".to_string()),
                    }
                }),
                "blocked",
            ),
            (
                "no original",
                Box::new(|r, _, b| {
                    r.assign.remove(&b.key());
                }),
                "blocked",
            ),
            (
                "no base",
                Box::new(|r, _, b| r.assign.get_mut(&b.key()).unwrap().base = None),
                "blocked",
            ),
            (
                "another request id",
                Box::new(|r, _, b| {
                    r.assign.get_mut(&b.key()).unwrap().request_id =
                        "22222222-2222-4222-8222-222222222222".to_string()
                }),
                "blocked",
            ),
            (
                "a newer route record",
                Box::new(|r, _, _| r.newer = Some(true)),
                "blocked",
            ),
            (
                "newer check fails",
                Box::new(|r, _, _| r.newer = None),
                "blocked",
            ),
            (
                "no observation",
                Box::new(|r, _, b| {
                    r.observation.remove(&b.key());
                }),
                "blocked",
            ),
            (
                "fingerprint changed",
                Box::new(|r, _, b| {
                    r.observation.get_mut(&b.key()).unwrap().fingerprint = "fp-2".to_string()
                }),
                "blocked",
            ),
            (
                "entries changed",
                Box::new(|r, _, b| {
                    r.observation.get_mut(&b.key()).unwrap().alias_entries =
                        vec![json!({"ipCidrRange": "10.0.7.0/24"})]
                }),
                "blocked",
            ),
            (
                "range already present",
                Box::new(|r, _, b| {
                    let o = r.observation.get_mut(&b.key()).unwrap();
                    o.alias_entries = vec![json!({"ipCidrRange": VIP})];
                    o.coverage = "all".to_string();
                }),
                "blocked",
            ),
            (
                "body digest differs",
                Box::new(|r, _, b| {
                    r.assign
                        .get_mut(&b.key())
                        .unwrap()
                        .base
                        .as_mut()
                        .unwrap()
                        .body_sha256 = "00".to_string()
                }),
                "blocked",
            ),
            (
                "re-issue intent not durable",
                Box::new(|r, _, _| r.fail_reissue_save = true),
                "blocked",
            ),
        ];
        for (name, edit, expected) in edits {
            let (plan, binding, mut fence, mut records, _, _) = after_timeout(vec![]);
            edit(&mut records, &mut fence, &binding);
            let mut api = Api::new(vec![]);
            assert_eq!(
                route_reissue(&mut api, &plan, &binding, &mut fence, &mut records),
                expected,
                "{name}"
            );
            assert!(api.calls.is_empty(), "{name}: nothing sent");
            if name != "re-issue intent not durable" {
                assert!(!records.reissue.contains_key(&binding.key()), "{name}");
            }
        }
    }
}
