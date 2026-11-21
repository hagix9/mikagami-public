//! Phase 1-J25 (J25-B/C/D): tests of the GCE fencing backend candidate (`gce_fence_backend`)
//! against a scripted in-memory model of the Compute API, and of its hand-off to the existing
//! Stage 14 fencing model (`fencing`, `NodeMutationStore`).
//!
//! The model below is not GCE. A pass here shows that the decision core classifies the scripted
//! answers as `FENCING_STATE_MACHINE.md` requires; whether real GCE answers as scripted is the
//! G25-1 / G25-2 question (`GCE_STOP_BACKEND.md`, `GCE_ALIAS_IP_BACKEND.md`).
//!
//! Test-only: everything is inside `mod tests`, so the architecture guards see no production code.

#[cfg(test)]
mod tests {
    use crate::gce_fence_backend::*;
    use serde_json::{Value, json};
    use std::collections::{BTreeMap, VecDeque};

    const INCIDENT_1: &str = "11111111-2222-4333-8444-555555555555";
    const INCIDENT_2: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    const TARGET_ID: &str = "7000000000000000011";
    const VIP: &str = "192.0.2.50/32";
    const OTHER_RANGE: &str = "192.0.2.60/32";

    // ------------------------------------------------------------------------------------------
    // A scripted model of the Compute API
    // ------------------------------------------------------------------------------------------

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum StopEffect {
        Terminate,
        StaysRunning,
        Fails,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum AliasEffect {
        Apply,
        Partial,
        Fails,
    }

    #[derive(Debug, Clone)]
    struct FakeNic {
        name: String,
        fingerprint: u64,
        ranges: Vec<String>,
    }

    #[derive(Debug, Clone)]
    struct FakeInstance {
        id: String,
        status: String,
        nics: Vec<FakeNic>,
    }

    #[derive(Debug, Clone)]
    enum Pending {
        Stop(String),
        Alias {
            instance: String,
            nic: String,
            ranges: Vec<String>,
        },
    }

    #[derive(Debug, Clone)]
    struct FakeOperation {
        kind: &'static str,
        target_id: String,
        gets_until_done: u32,
        done: bool,
        error: bool,
        effect: Option<Pending>,
    }

    struct FakeGce {
        instances: BTreeMap<String, FakeInstance>,
        operations: BTreeMap<String, FakeOperation>,
        next_op: u64,
        stop_effect: StopEffect,
        alias_effect: AliasEffect,
        op_delay: u32,
        /// Forced answers by call kind ("stop", "patch", "get-instance", "get-op"), consumed first.
        forced: VecDeque<(&'static str, HttpOutcome)>,
        /// A concurrent writer changes the NIC between our describe and our update.
        race_fingerprint: bool,
        calls: Vec<(HttpMethod, String)>,
        /// Request ids already seen (a repeated id must never happen in this backend).
        request_ids: Vec<String>,
        /// `subnetworkRangeName` reported for a range (J25 audit N-5).
        range_names: BTreeMap<String, String>,
        last_patch: Option<Value>,
        /// Shared test clock advanced by every call (a slow API, J25 audit B-1b).
        slow_clock: Option<std::rc::Rc<std::cell::Cell<u64>>>,
    }

    impl FakeGce {
        fn new() -> Self {
            let mut instances = BTreeMap::new();
            instances.insert(
                "sim-node-a".to_string(),
                FakeInstance {
                    id: TARGET_ID.to_string(),
                    status: "RUNNING".to_string(),
                    nics: vec![FakeNic {
                        name: "nic0".to_string(),
                        fingerprint: 1,
                        ranges: vec![VIP.to_string()],
                    }],
                },
            );
            instances.insert(
                "sim-node-b".to_string(),
                FakeInstance {
                    id: "7000000000000000012".to_string(),
                    status: "RUNNING".to_string(),
                    nics: vec![FakeNic {
                        name: "nic0".to_string(),
                        fingerprint: 1,
                        ranges: vec![],
                    }],
                },
            );
            Self {
                instances,
                operations: BTreeMap::new(),
                next_op: 1,
                stop_effect: StopEffect::Terminate,
                alias_effect: AliasEffect::Apply,
                op_delay: 1,
                forced: VecDeque::new(),
                race_fingerprint: false,
                calls: Vec::new(),
                request_ids: Vec::new(),
                range_names: BTreeMap::new(),
                last_patch: None,
                slow_clock: None,
            }
        }

        fn mutations(&self, kind: &str) -> usize {
            self.calls
                .iter()
                .filter(|(method, path)| *method != HttpMethod::Get && path.contains(kind))
                .count()
        }

        fn target(&mut self) -> &mut FakeInstance {
            self.instances.get_mut("sim-node-a").unwrap()
        }

        fn instance_json(
            instance: &FakeInstance,
            name: &str,
            range_names: &BTreeMap<String, String>,
        ) -> String {
            let entry = |range: &String| match range_names.get(range) {
                Some(subnet) => json!({"ipCidrRange": range, "subnetworkRangeName": subnet}),
                None => json!({"ipCidrRange": range}),
            };
            json!({
                "id": instance.id,
                "name": name,
                "status": instance.status,
                "networkInterfaces": instance.nics.iter().map(|nic| json!({
                    "name": nic.name,
                    "fingerprint": format!("fp-{}", nic.fingerprint),
                    "aliasIpRanges": nic.ranges.iter().map(entry).collect::<Vec<_>>(),
                })).collect::<Vec<_>>(),
            })
            .to_string()
        }

        fn op_json(name: &str, op: &FakeOperation) -> String {
            let mut value = json!({
                "name": name,
                "operationType": op.kind,
                "targetId": op.target_id,
                "status": if op.done { "DONE" } else { "RUNNING" },
            });
            if op.done && op.error {
                value["error"] = json!({"errors": [{"code": "RESOURCE_OPERATION_FAILED"}]});
                value["httpErrorStatusCode"] = json!(400);
            }
            value.to_string()
        }

        fn new_op(
            &mut self,
            kind: &'static str,
            target_id: String,
            effect: Pending,
            error: bool,
        ) -> String {
            let name = format!("operation-{}", self.next_op);
            self.next_op += 1;
            self.operations.insert(
                name.clone(),
                FakeOperation {
                    kind,
                    target_id,
                    gets_until_done: self.op_delay,
                    done: false,
                    error,
                    effect: Some(effect),
                },
            );
            name
        }

        fn complete(&mut self, name: &str) {
            let op = self.operations.get_mut(name).unwrap();
            op.done = true;
            let effect = op.effect.take();
            let error = op.error;
            match effect {
                Some(Pending::Stop(instance)) if !error => {
                    // A deleted instance stays deleted.
                    if self.stop_effect == StopEffect::Terminate
                        && let Some(instance) = self.instances.get_mut(&instance)
                    {
                        instance.status = "TERMINATED".into();
                    }
                }
                Some(Pending::Alias {
                    instance,
                    nic,
                    ranges,
                }) if !error => {
                    let alias_effect = self.alias_effect;
                    let Some(target) = self.instances.get_mut(&instance) else {
                        return;
                    };
                    let nic = target
                        .nics
                        .iter_mut()
                        .find(|candidate| candidate.name == nic)
                        .unwrap();
                    match alias_effect {
                        AliasEffect::Apply => nic.ranges = ranges,
                        AliasEffect::Partial => {
                            // Only the first removed range goes away.
                            if let Some(index) =
                                nic.ranges.iter().position(|range| !ranges.contains(range))
                            {
                                nic.ranges.remove(index);
                            }
                        }
                        AliasEffect::Fails => {}
                    }
                    nic.fingerprint += 1;
                }
                _ => {}
            }
        }
    }

    impl ComputeTransport for FakeGce {
        fn call(&mut self, method: HttpMethod, path: &str, body: Option<&str>) -> HttpOutcome {
            self.calls.push((method, path.to_string()));
            if let Some(clock) = &self.slow_clock {
                clock.set(clock.get() + 20_000);
            }
            let (route, query) = path.split_once('?').unwrap_or((path, ""));
            let segments: Vec<&str> = route.split('/').collect();
            let kind = match (method, segments.as_slice()) {
                (HttpMethod::Get, [_, _, _, _, "instances", _]) => "get-instance",
                (HttpMethod::Get, [_, _, _, _, "operations", _]) => "get-op",
                (HttpMethod::Post, [.., "stop"]) => "stop",
                (HttpMethod::Patch, [.., "updateNetworkInterface"]) => "patch",
                _ => "other",
            };
            if let Some(position) = self.forced.iter().position(|(forced, _)| *forced == kind) {
                return self.forced.remove(position).unwrap().1;
            }
            let query: BTreeMap<&str, &str> = query
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .collect();
            if let Some(id) = query.get("requestId") {
                assert!(
                    !self.request_ids.contains(&id.to_string()),
                    "a request id was reused"
                );
                self.request_ids.push(id.to_string());
            }
            let not_found = || HttpOutcome::Response {
                status: 404,
                body: "{}".into(),
            };
            match kind {
                "get-instance" => match self.instances.get(segments[5]) {
                    Some(instance) => HttpOutcome::Response {
                        status: 200,
                        body: Self::instance_json(instance, segments[5], &self.range_names),
                    },
                    None => not_found(),
                },
                "get-op" => {
                    let name = segments[5].to_string();
                    let Some(op) = self.operations.get_mut(&name) else {
                        return not_found();
                    };
                    if !op.done {
                        if op.gets_until_done == 0 {
                            self.complete(&name);
                        } else {
                            op.gets_until_done -= 1;
                        }
                    }
                    let op = self.operations.get(&name).unwrap();
                    HttpOutcome::Response {
                        status: 200,
                        body: Self::op_json(&name, op),
                    }
                }
                "stop" => {
                    let name = segments[5].to_string();
                    let Some(instance) = self.instances.get_mut(&name) else {
                        return not_found();
                    };
                    let id = instance.id.clone();
                    if self.stop_effect == StopEffect::Terminate && instance.status == "RUNNING" {
                        instance.status = "STOPPING".into();
                    }
                    let error = self.stop_effect == StopEffect::Fails;
                    let op = self.new_op("stop", id, Pending::Stop(name), error);
                    HttpOutcome::Response {
                        status: 200,
                        body: Self::op_json(&op, &self.operations[&op]),
                    }
                }
                "patch" => {
                    let name = segments[5].to_string();
                    let nic_name = query
                        .get("networkInterface")
                        .copied()
                        .unwrap_or("")
                        .to_string();
                    let race = self.race_fingerprint;
                    let alias_error = self.alias_effect == AliasEffect::Fails;
                    let Some(instance) = self.instances.get_mut(&name) else {
                        return not_found();
                    };
                    let id = instance.id.clone();
                    let Some(nic) = instance.nics.iter_mut().find(|nic| nic.name == nic_name)
                    else {
                        return HttpOutcome::Response {
                            status: 400,
                            body: "{}".into(),
                        };
                    };
                    if race {
                        nic.fingerprint += 1;
                    }
                    let body: Value = serde_json::from_str(body.unwrap()).unwrap();
                    self.last_patch = Some(body.clone());
                    if body["fingerprint"] != json!(format!("fp-{}", nic.fingerprint)) {
                        return HttpOutcome::Response {
                            status: 412,
                            body: "{}".into(),
                        };
                    }
                    let ranges: Vec<String> = body["aliasIpRanges"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|range| range["ipCidrRange"].as_str().unwrap().to_string())
                        .collect();
                    // GCE refuses a range that another NIC still holds.
                    let added: Vec<&String> = ranges
                        .iter()
                        .filter(|range| !nic.ranges.contains(range))
                        .collect();
                    let in_use = self.instances.iter().any(|(other, instance)| {
                        other != &name
                            && instance
                                .nics
                                .iter()
                                .any(|nic| added.iter().any(|range| nic.ranges.contains(range)))
                    });
                    if in_use {
                        return HttpOutcome::Response {
                            status: 400,
                            body: "{}".into(),
                        };
                    }
                    let op = self.new_op(
                        "updateNetworkInterface",
                        id,
                        Pending::Alias {
                            instance: name,
                            nic: nic_name,
                            ranges,
                        },
                        alias_error,
                    );
                    HttpOutcome::Response {
                        status: 200,
                        body: Self::op_json(&op, &self.operations[&op]),
                    }
                }
                _ => not_found(),
            }
        }
    }

    // ------------------------------------------------------------------------------------------
    // Store, hooks and probe
    // ------------------------------------------------------------------------------------------

    #[derive(Default)]
    struct MemStore {
        records: BTreeMap<(String, u64, &'static str), ActionRecord>,
        /// Save calls (1-based) that fail.
        fail_saves: Vec<usize>,
        saves: usize,
    }

    impl RecordStore for MemStore {
        fn load(
            &mut self,
            binding: &AttemptBinding,
            method: FenceMethod,
        ) -> Result<Option<ActionRecord>, StoreError> {
            Ok(self
                .records
                .get(&(
                    binding.incident_id.clone(),
                    binding.attempt_token,
                    method.as_str(),
                ))
                .cloned())
        }

        fn save(&mut self, record: &ActionRecord) -> Result<(), StoreError> {
            self.saves += 1;
            if self.fail_saves.contains(&self.saves) {
                return Err(StoreError::Io("injected write failure".into()));
            }
            self.records.insert(
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

    /// Simulates a process crash at one point: the hook panics there.
    struct CrashAt(Option<FencePoint>);

    impl FaultHook for CrashAt {
        fn at(&mut self, point: FencePoint) {
            if self.0 == Some(point) {
                panic!("J25 simulated crash at {}", point.as_str());
            }
        }
    }

    struct FixedProbe(ProbeResult);

    impl DataPlaneProbe for FixedProbe {
        fn probe(&mut self, _range: &str) -> ProbeResult {
            self.0
        }
    }

    fn target() -> InstanceIdentity {
        InstanceIdentity {
            project: "j25-sim-project".into(),
            zone: "sim-zone-a".into(),
            name: "sim-node-a".into(),
            instance_id: TARGET_ID.into(),
        }
    }

    fn plan(methods: &[FenceMethod], combine: Combine, inventory_complete: bool) -> FencePlan {
        let alias = methods
            .contains(&FenceMethod::AliasIp)
            .then(|| AliasPolicy {
                nic: "nic0".into(),
                ranges: vec![VIP.into()],
                inventory_complete,
                propagation_hold_ms: 60_000,
                // The unit tests jump the clock by up to one hold between polls.
                max_observation_gap_ms: 60_000,
                probe_required: true,
                short_hold_for_test: false,
            });
        let plan = FencePlan {
            cluster: "j25-test".into(),
            target_node: "node-a".into(),
            target: target(),
            methods: methods.to_vec(),
            combine,
            alias,
        };
        plan.validate().unwrap();
        plan
    }

    fn stop_plan() -> FencePlan {
        plan(&[FenceMethod::Stop], Combine::AnySufficient, false)
    }

    fn binding(incident: &str, token: u64) -> AttemptBinding {
        AttemptBinding::from_step(
            &stop_plan(),
            Some("j25-test"),
            Some("node-a"),
            Some(incident),
            Some(&token.to_string()),
        )
        .unwrap()
    }

    struct World {
        gce: FakeGce,
        store: MemStore,
        probe: FixedProbe,
        now_ms: u64,
    }

    impl World {
        fn new() -> Self {
            Self {
                gce: FakeGce::new(),
                store: MemStore::default(),
                probe: FixedProbe(ProbeResult::Absent),
                now_ms: 1_000,
            }
        }

        fn fence(
            &mut self,
            plan: &FencePlan,
            binding: &AttemptBinding,
        ) -> Vec<(FenceMethod, ActionReport)> {
            fence(&mut ActionContext {
                plan,
                binding,
                api: &mut self.gce,
                store: &mut self.store,
                hooks: &mut NoFaults,
            })
        }

        fn verify(
            &mut self,
            plan: &FencePlan,
            binding: &AttemptBinding,
        ) -> (Vec<(FenceMethod, MethodVerdict)>, FinalVerdict) {
            let now = self.now_ms;
            verify(&mut VerifyContext {
                plan,
                binding,
                api: &mut self.gce,
                store: &mut self.store,
                hooks: &mut NoFaults,
                probe: &mut self.probe,
                clock: &mut || Some(now),
            })
        }

        /// Verify polls until a non-Unknown verdict or `polls` are used.
        fn verify_until(
            &mut self,
            plan: &FencePlan,
            binding: &AttemptBinding,
            polls: u32,
        ) -> FinalVerdict {
            let mut last = FinalVerdict::Unknown("no poll".into());
            for _ in 0..polls {
                last = self.verify(plan, binding).1;
                if !matches!(last, FinalVerdict::Unknown(_)) {
                    break;
                }
                self.now_ms += 10_000;
            }
            last
        }

        fn record(&self, binding: &AttemptBinding, method: FenceMethod) -> Option<&ActionRecord> {
            self.store.records.get(&(
                binding.incident_id.clone(),
                binding.attempt_token,
                method.as_str(),
            ))
        }
    }

    fn unknown(verdict: &FinalVerdict) -> bool {
        matches!(verdict, FinalVerdict::Unknown(_))
    }

    // ------------------------------------------------------------------------------------------
    // Binding and plan
    // ------------------------------------------------------------------------------------------

    #[test]
    fn j25_binding_is_validated_before_anything_is_read_or_sent() {
        let plan = stop_plan();
        let step = |cluster, target, incident, attempt| {
            AttemptBinding::from_step(&plan, cluster, target, incident, attempt)
        };
        assert!(
            step(
                Some("j25-test"),
                Some("node-a"),
                Some(INCIDENT_1),
                Some("1")
            )
            .is_ok()
        );
        assert_eq!(
            step(None, Some("node-a"), Some(INCIDENT_1), Some("1")),
            Err(BindingError::Missing("MIKAGAMI_CLUSTER"))
        );
        assert_eq!(
            step(Some("other"), Some("node-a"), Some(INCIDENT_1), Some("1")),
            Err(BindingError::ClusterMismatch)
        );
        assert_eq!(
            step(
                Some("j25-test"),
                Some("node-b"),
                Some(INCIDENT_1),
                Some("1")
            ),
            Err(BindingError::TargetMismatch)
        );
        for bad in [
            "11111111-2222-1333-8444-555555555555",
            "11111111-2222-4333-8444-55555555555X",
            "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE",
            "",
        ] {
            assert_eq!(
                step(Some("j25-test"), Some("node-a"), Some(bad), Some("1")),
                Err(BindingError::MalformedIncident),
                "{bad}"
            );
        }
        for bad in ["0", "-1", "01", "x", "", "18446744073709551616"] {
            assert_eq!(
                step(
                    Some("j25-test"),
                    Some("node-a"),
                    Some(INCIDENT_1),
                    Some(bad)
                ),
                Err(BindingError::MalformedAttempt),
                "{bad}"
            );
        }
        // One request id per attempt and method; every part of the binding changes it.
        let base = binding(INCIDENT_1, 1);
        let id = request_id(&base, FenceMethod::Stop);
        assert!(is_canonical_uuid_v4(&id));
        assert_eq!(id, request_id(&base, FenceMethod::Stop));
        assert_ne!(id, request_id(&base, FenceMethod::AliasIp));
        assert_ne!(id, request_id(&binding(INCIDENT_1, 2), FenceMethod::Stop));
        assert_ne!(id, request_id(&binding(INCIDENT_2, 1), FenceMethod::Stop));
    }

    #[test]
    fn j25_plan_validation_refuses_plans_that_could_never_be_safe() {
        let mut plan = stop_plan();
        plan.target.instance_id = "sim-node-a".into();
        assert!(plan.validate().is_err(), "the id must be the numeric id");
        let mut plan = stop_plan();
        plan.methods = vec![FenceMethod::Stop, FenceMethod::Stop];
        assert!(plan.validate().is_err());
        let mut plan = stop_plan();
        plan.methods = vec![];
        assert!(plan.validate().is_err());
        let mut plan = stop_plan();
        plan.target.zone = "a/b".into();
        assert!(plan.validate().is_err(), "no path injection");
        // J25 SA-2: no query injection through any name that reaches the URL.
        for bad in [
            "nic0&requestId=x",
            "nic0?x",
            "nic 0",
            "nic0#x",
            "nic%30",
            "",
        ] {
            let mut alias_plan = plan_unchecked(&[FenceMethod::AliasIp], true);
            alias_plan.alias.as_mut().unwrap().nic = bad.into();
            assert!(alias_plan.validate().is_err(), "{bad}");
            let mut stop = stop_plan();
            stop.target.name = bad.into();
            assert!(stop.validate().is_err(), "{bad}");
        }
        let mut alias_only = plan_unchecked(&[FenceMethod::AliasIp], false);
        assert!(
            alias_only.validate().is_err(),
            "F-4 alone needs a complete inventory"
        );
        alias_only.alias.as_mut().unwrap().inventory_complete = true;
        assert!(alias_only.validate().is_ok());
        for bad in [
            "192.0.2.50",
            "192.0.2.51/24",
            "192.0.2.50/033",
            "192.0.2.50/33",
            "x/32",
        ] {
            alias_only.alias.as_mut().unwrap().ranges = vec![bad.into()];
            assert!(
                alias_only.validate().is_err(),
                "{bad}: a canonical CIDR (audit B-1c)"
            );
        }
        alias_only.alias.as_mut().unwrap().ranges = vec![VIP.into()];
        alias_only.alias.as_mut().unwrap().probe_required = false;
        assert!(
            alias_only.validate().is_err(),
            "the alias method needs the probe (audit N-6)"
        );
        let mut stop_with_alias = stop_plan();
        stop_with_alias.alias = plan_unchecked(&[FenceMethod::AliasIp], true).alias;
        assert!(stop_with_alias.validate().is_err());
    }

    fn plan_unchecked(methods: &[FenceMethod], inventory_complete: bool) -> FencePlan {
        FencePlan {
            cluster: "j25-test".into(),
            target_node: "node-a".into(),
            target: target(),
            methods: methods.to_vec(),
            combine: Combine::AnySufficient,
            alias: Some(AliasPolicy {
                nic: "nic0".into(),
                ranges: vec![VIP.into()],
                inventory_complete,
                propagation_hold_ms: 0,
                max_observation_gap_ms: 1,
                probe_required: true,
                short_hold_for_test: true,
            }),
        }
    }

    #[test]
    fn j25_api_results_are_classified_and_only_refusals_count_as_not_applied() {
        let response = |status| HttpOutcome::Response {
            status,
            body: "{}".into(),
        };
        assert_eq!(classify(response(401)), Err(ApiFailure::Unauthenticated));
        assert_eq!(classify(response(403)), Err(ApiFailure::PermissionDenied));
        assert_eq!(classify(response(412)), Err(ApiFailure::PreconditionFailed));
        assert_eq!(classify(response(429)), Err(ApiFailure::RateLimited));
        assert_eq!(classify(response(503)), Err(ApiFailure::ServerError(503)));
        // J25 audit N-4: only the listed refusals are "not applied".
        for maybe in [201u16, 204, 302, 307, 408, 418, 499] {
            let failure = classify(response(maybe)).unwrap_err();
            assert!(failure.may_have_been_applied(), "{maybe}");
        }
        assert!(!classify(response(400)).unwrap_err().may_have_been_applied());
        // J25 audit N-2: an operation name that is not a resource name is malformed.
        for bad in ["op/../x", "op?x", "op x", ""] {
            let value =
                json!({"name": bad, "operationType": "stop", "targetId": "1", "status": "DONE"});
            assert!(Operation::parse(&value).is_err(), "{bad}");
        }
        assert!(matches!(
            classify(HttpOutcome::Response {
                status: 200,
                body: "not json".into()
            }),
            Err(ApiFailure::Malformed(_))
        ));
        for applied in [
            ApiFailure::Timeout,
            ApiFailure::ServerError(500),
            ApiFailure::Transport("reset".into()),
            ApiFailure::Malformed("x".into()),
        ] {
            assert!(applied.may_have_been_applied(), "{applied}");
        }
        for refused in [
            ApiFailure::Unauthenticated,
            ApiFailure::PermissionDenied,
            ApiFailure::RateLimited,
            ApiFailure::PreconditionFailed,
            ApiFailure::NotFound,
            ApiFailure::NotSent("refused".into()),
        ] {
            assert!(!refused.may_have_been_applied(), "{refused}");
        }
        // An operation is a success only when DONE without any error indication.
        let op = |extra: Value| {
            let mut value = json!({"name": "op", "operationType": "stop", "targetId": TARGET_ID, "status": "DONE"});
            for (key, item) in extra.as_object().unwrap() {
                value[key] = item.clone();
            }
            Operation::parse(&value).unwrap()
        };
        assert!(op(json!({})).succeeded());
        assert!(op(json!({"error": {"errors": [{"code": "X"}]}})).failed());
        assert!(
            op(json!({"error": {}})).failed(),
            "an error object without codes is an error"
        );
        assert!(op(json!({"httpErrorStatusCode": 409})).failed());
        assert!(!op(json!({"status": "RUNNING"})).succeeded());
        assert!(
            Operation::parse(&json!({"name": "op", "status": "DONE"})).is_err(),
            "required fields"
        );
        assert!(Operation::parse(&json!({"name": "op", "operationType": "stop", "targetId": "1", "status": "ABORTING"})).is_err());
    }

    // ------------------------------------------------------------------------------------------
    // F-2: stop
    // ------------------------------------------------------------------------------------------

    /// I-1, I-2: request, acceptance and a running operation are not proof; only DONE without error
    /// and a fresh TERMINATED of the same numeric id are, and the evidence is persisted first.
    #[test]
    fn j25_f2_only_done_and_terminated_of_the_identified_target_isolates() {
        let mut world = World::new();
        world.gce.op_delay = 2;
        let plan = stop_plan();
        let attempt = binding(INCIDENT_1, 1);
        let report = world.fence(&plan, &attempt);
        assert!(matches!(report[0].1, ActionReport::Sent { .. }));
        assert!(matches!(
            world.record(&attempt, FenceMethod::Stop).unwrap().phase,
            ActionPhase::Accepted { .. }
        ));
        // Accepted, operation running, instance STOPPING: not proof.
        let (verdicts, verdict) = world.verify(&plan, &attempt);
        assert!(unknown(&verdict), "{verdicts:?}");
        let (_, verdict) = world.verify(&plan, &attempt);
        assert!(unknown(&verdict));
        assert!(
            world
                .record(&attempt, FenceMethod::Stop)
                .unwrap()
                .confirmed
                .is_none()
        );
        let (_, verdict) = world.verify(&plan, &attempt);
        assert!(matches!(verdict, FinalVerdict::Isolated(_)), "{verdict:?}");
        assert_eq!(verify_output(&verdict), (0, "isolated\n"));
        assert!(
            world
                .record(&attempt, FenceMethod::Stop)
                .unwrap()
                .confirmed
                .is_some()
        );
        assert_eq!(world.gce.mutations("/stop"), 1);
    }

    /// The fence action describes the target first: a VM recreated under the name (another numeric
    /// id) or an undescribable target is never stopped.
    #[test]
    fn j25_f2_identity_mismatch_or_undescribable_target_sends_nothing() {
        let mut world = World::new();
        world.gce.target().id = "7000000000000000099".into();
        let report = world.fence(&stop_plan(), &binding(INCIDENT_1, 1));
        assert!(
            matches!(report[0].1, ActionReport::Blocked(_)),
            "{report:?}"
        );
        assert_eq!(world.gce.mutations("/stop"), 0);
        assert!(
            world
                .record(&binding(INCIDENT_1, 1), FenceMethod::Stop)
                .is_none()
        );
        let mut world = World::new();
        world
            .gce
            .forced
            .push_back(("get-instance", HttpOutcome::Timeout));
        let report = world.fence(&stop_plan(), &binding(INCIDENT_1, 1));
        assert!(matches!(report[0].1, ActionReport::Blocked(_)));
        assert_eq!(world.gce.mutations("/stop"), 0);
        // Nothing recorded, so a verify of this attempt is Unknown.
        assert!(unknown(
            &world.verify(&stop_plan(), &binding(INCIDENT_1, 1)).1
        ));
    }

    /// API timeout, 5xx and a transport reset may have been applied: recorded as outcome-unknown,
    /// never resent for the attempt, and never isolating, even if the instance reads TERMINATED.
    #[test]
    fn j25_f2_timeout_5xx_and_transport_failures_are_unknown_and_never_resent() {
        for failure in [
            HttpOutcome::Timeout,
            HttpOutcome::Response {
                status: 503,
                body: "{}".into(),
            },
            HttpOutcome::Transport("reset".into()),
        ] {
            let mut world = World::new();
            world.gce.forced.push_back(("stop", failure.clone()));
            let plan = stop_plan();
            let attempt = binding(INCIDENT_1, 1);
            assert!(
                matches!(world.fence(&plan, &attempt)[0].1, ActionReport::Unknown(_)),
                "{failure:?}"
            );
            assert!(matches!(
                world.record(&attempt, FenceMethod::Stop).unwrap().phase,
                ActionPhase::OutcomeUnknown { .. }
            ));
            // The request may have stopped the VM anyway.
            world.gce.target().status = "TERMINATED".into();
            assert!(
                unknown(&world.verify_until(&plan, &attempt, 3)),
                "{failure:?}"
            );
            // A second action for the same attempt sends nothing (I-6).
            assert_eq!(
                world.fence(&plan, &attempt)[0].1,
                ActionReport::AlreadyRecorded("outcome-unknown")
            );
            assert_eq!(
                world
                    .gce
                    .calls
                    .iter()
                    .filter(|(_, path)| path.contains("/stop"))
                    .count(),
                1
            );
        }
    }

    /// 429, 401 and 403 are refusals: nothing was applied. A refusal is definitive (FAILED) only
    /// when the instance is seen running; an undescribable instance stays Unknown.
    #[test]
    fn j25_f2_rate_limit_and_auth_refusals_are_not_isolated() {
        for status in [429u16, 401, 403] {
            let mut world = World::new();
            world.gce.forced.push_back((
                "stop",
                HttpOutcome::Response {
                    status,
                    body: "{}".into(),
                },
            ));
            let plan = stop_plan();
            let attempt = binding(INCIDENT_1, 1);
            assert!(matches!(
                world.fence(&plan, &attempt)[0].1,
                ActionReport::Refused(_)
            ));
            let verdict = world.verify(&plan, &attempt).1;
            assert!(
                matches!(verdict, FinalVerdict::NotIsolated(_)),
                "{status}: {verdict:?}"
            );
            assert_eq!(verify_output(&verdict), (0, "not-isolated\n"));
            let mut world = World::new();
            world.gce.forced.push_back((
                "stop",
                HttpOutcome::Response {
                    status,
                    body: "{}".into(),
                },
            ));
            world.fence(&plan, &attempt);
            world.gce.forced.push_back((
                "get-instance",
                HttpOutcome::Response {
                    status: 401,
                    body: "{}".into(),
                },
            ));
            assert!(unknown(&world.verify(&plan, &attempt).1));
        }
    }

    /// Operation DONE with an error, or DONE while the instance runs, is a definitive failure.
    #[test]
    fn j25_f2_done_with_error_or_done_but_running_is_not_isolated() {
        for effect in [StopEffect::Fails, StopEffect::StaysRunning] {
            let mut world = World::new();
            world.gce.stop_effect = effect;
            let plan = stop_plan();
            let attempt = binding(INCIDENT_1, 1);
            world.fence(&plan, &attempt);
            let verdict = world.verify_until(&plan, &attempt, 4);
            assert!(
                matches!(verdict, FinalVerdict::NotIsolated(_)),
                "{effect:?}: {verdict:?}"
            );
        }
        // DONE with an error while the VM reads TERMINATED (somebody else stopped it): not proof.
        let mut world = World::new();
        world.gce.stop_effect = StopEffect::Fails;
        let plan = stop_plan();
        let attempt = binding(INCIDENT_1, 1);
        world.fence(&plan, &attempt);
        world.gce.target().status = "TERMINATED".into();
        assert!(unknown(&world.verify_until(&plan, &attempt, 4)));
    }

    /// Deleted or deleted-and-recreated between the action and the verify; a stale or foreign
    /// operation; SUSPENDED and STOPPING: never isolated.
    #[test]
    fn j25_f2_deleted_recreated_stale_operation_and_suspended_are_unknown() {
        let plan = stop_plan();
        let attempt = binding(INCIDENT_1, 1);
        let mut world = World::new();
        world.fence(&plan, &attempt);
        world.gce.instances.remove("sim-node-a");
        assert!(unknown(&world.verify_until(&plan, &attempt, 4)), "deleted");
        let mut world = World::new();
        world.fence(&plan, &attempt);
        world.gce.verify_until_done();
        let recreated = world.gce.target();
        recreated.id = "7000000000000000099".into();
        recreated.status = "TERMINATED".into();
        assert!(
            unknown(&world.verify_until(&plan, &attempt, 4)),
            "recreated"
        );
        // The recorded operation now answers for another target.
        let mut world = World::new();
        world.fence(&plan, &attempt);
        let name = match &world.record(&attempt, FenceMethod::Stop).unwrap().phase {
            ActionPhase::Accepted { operation } => operation.clone(),
            other => panic!("{other:?}"),
        };
        world.gce.operations.get_mut(&name).unwrap().target_id = "7000000000000000012".into();
        assert!(
            unknown(&world.verify_until(&plan, &attempt, 4)),
            "foreign operation"
        );
        for status in ["SUSPENDED", "SUSPENDING", "STOPPING", "PENDING_STOP"] {
            let mut world = World::new();
            world.gce.stop_effect = StopEffect::StaysRunning;
            world.fence(&plan, &attempt);
            world.gce.verify_until_done();
            world.gce.target().status = status.into();
            assert!(unknown(&world.verify_until(&plan, &attempt, 2)), "{status}");
        }
    }

    impl FakeGce {
        fn verify_until_done(&mut self) {
            let names: Vec<String> = self.operations.keys().cloned().collect();
            for name in names {
                if !self.operations[&name].done {
                    self.complete(&name);
                }
            }
        }
    }

    /// I-4: the evidence of one attempt (incident, token) is never read for another: a new token of
    /// the same incident, or another incident, finds no record and stays Unknown.
    #[test]
    fn j25_f2_evidence_of_another_attempt_or_incident_is_never_used() {
        let plan = stop_plan();
        let first = binding(INCIDENT_1, 1);
        let mut world = World::new();
        world.fence(&plan, &first);
        assert!(matches!(
            world.verify_until(&plan, &first, 4),
            FinalVerdict::Isolated(_)
        ));
        for other in [binding(INCIDENT_1, 2), binding(INCIDENT_2, 1)] {
            assert!(unknown(&world.verify(&plan, &other).1), "{other:?}");
        }
        // A record whose content names another attempt is foreign even under this attempt's key.
        let mut forged = world.record(&first, FenceMethod::Stop).unwrap().clone();
        forged.binding = binding(INCIDENT_2, 1);
        world
            .store
            .records
            .insert((INCIDENT_1.into(), 1, "stop"), forged);
        assert!(unknown(&world.verify(&plan, &first).1));
        assert!(matches!(
            world.fence(&plan, &first)[0].1,
            ActionReport::Blocked(_)
        ));
    }

    /// I-9: the intent is durable before the request; a failed intent write sends nothing; a failed
    /// result write leaves the intent, which every verify reads as Unknown; a failed evidence write
    /// turns Isolated into Unknown.
    #[test]
    fn j25_f2_record_write_failures_fail_closed() {
        let plan = stop_plan();
        let attempt = binding(INCIDENT_1, 1);
        let mut world = World::new();
        world.store.fail_saves = vec![1];
        assert!(matches!(
            world.fence(&plan, &attempt)[0].1,
            ActionReport::Blocked(_)
        ));
        assert_eq!(world.gce.mutations("/stop"), 0);
        let mut world = World::new();
        world.store.fail_saves = vec![2];
        assert!(matches!(
            world.fence(&plan, &attempt)[0].1,
            ActionReport::Unknown(_)
        ));
        assert_eq!(world.gce.mutations("/stop"), 1);
        assert_eq!(
            world.record(&attempt, FenceMethod::Stop).unwrap().phase,
            ActionPhase::Intent
        );
        world.gce.verify_until_done();
        assert!(unknown(&world.verify_until(&plan, &attempt, 3)));
        let mut world = World::new();
        world.fence(&plan, &attempt);
        world.gce.verify_until_done();
        world.store.fail_saves = vec![world.store.saves + 1];
        let verdict = world.verify(&plan, &attempt).1;
        assert!(unknown(&verdict), "{verdict:?}");
        assert!(
            world
                .record(&attempt, FenceMethod::Stop)
                .unwrap()
                .confirmed
                .is_none()
        );
    }

    /// J25 §10 points 1, 3, 4, 5 (helper side): a crash at each point leaves a durable state from
    /// which the crashed attempt never isolates, and the restarted node's new incident needs its
    /// own action and its own observation. The stop is idempotent on GCE's side (`STOPPING` or
    /// `TERMINATED` stay so), so the new incident's stop is a new request with a new request id.
    #[test]
    fn j25_f2_crash_at_each_helper_point_never_reuses_the_crashed_attempt() {
        let plan = stop_plan();
        for point in [
            FencePoint::BeforeRequest,
            FencePoint::AfterAccept,
            FencePoint::AfterOperationDone,
            FencePoint::AfterInstanceObserved,
        ] {
            let mut world = World::new();
            let crashed = binding(INCIDENT_1, 1);
            let action_point = matches!(point, FencePoint::BeforeRequest | FencePoint::AfterAccept);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                fence(&mut ActionContext {
                    plan: &plan,
                    binding: &crashed,
                    api: &mut world.gce,
                    store: &mut world.store,
                    hooks: &mut CrashAt(action_point.then_some(point)),
                });
                world.gce.verify_until_done();
                verify(&mut VerifyContext {
                    plan: &plan,
                    binding: &crashed,
                    api: &mut world.gce,
                    store: &mut world.store,
                    hooks: &mut CrashAt((!action_point).then_some(point)),
                    probe: &mut NoProbe,
                    clock: &mut || Some(5_000),
                })
            }));
            assert!(result.is_err(), "{point:?} must have crashed");
            let record = world.record(&crashed, FenceMethod::Stop).unwrap().clone();
            assert!(
                record.confirmed.is_none(),
                "{point:?}: no evidence is persisted before the report"
            );
            match point {
                FencePoint::BeforeRequest | FencePoint::AfterAccept => {
                    assert_eq!(record.phase, ActionPhase::Intent, "{point:?}");
                    // The crashed attempt (if its verify ever ran) stays Unknown.
                    world.gce.verify_until_done();
                    assert!(unknown(&world.verify(&plan, &crashed).1), "{point:?}");
                }
                _ => assert!(matches!(record.phase, ActionPhase::Accepted { .. })),
            }
            let stops_before = world.gce.mutations("/stop");
            // The restarted node: a new session retires the incident (R2); a new incident follows.
            let restarted = binding(INCIDENT_2, 1);
            assert!(
                unknown(&world.verify(&plan, &restarted).1),
                "{point:?}: nothing reused"
            );
            world.fence(&plan, &restarted);
            assert_eq!(world.gce.mutations("/stop"), stops_before + 1);
            let verdict = world.verify_until(&plan, &restarted, 4);
            assert!(
                matches!(verdict, FinalVerdict::Isolated(_)),
                "{point:?}: {verdict:?}"
            );
            assert!(
                world
                    .record(&crashed, FenceMethod::Stop)
                    .unwrap()
                    .confirmed
                    .is_none()
            );
        }
    }

    /// Concurrent requests (two incidents fencing the same target), a double execution of one
    /// attempt, and the target restarting (or being started again) during fencing.
    #[test]
    fn j25_f2_concurrent_double_execution_and_target_restart() {
        let plan = stop_plan();
        let one = binding(INCIDENT_1, 1);
        let two = binding(INCIDENT_2, 1);
        let mut world = World::new();
        world.fence(&plan, &one);
        world.fence(&plan, &two);
        assert_eq!(world.gce.mutations("/stop"), 2);
        assert!(matches!(
            world.verify_until(&plan, &one, 4),
            FinalVerdict::Isolated(_)
        ));
        assert!(matches!(
            world.verify_until(&plan, &two, 4),
            FinalVerdict::Isolated(_)
        ));
        // Double execution of one attempt: the second action sends nothing.
        assert_eq!(
            world.fence(&plan, &one)[0].1,
            ActionReport::AlreadyRecorded("accepted")
        );
        assert_eq!(world.gce.mutations("/stop"), 2);
        // The target is started again after it was TERMINATED: a later poll of a new attempt
        // whose stop is still running sees it running, not isolated.
        let mut world = World::new();
        world.fence(&plan, &one);
        assert!(matches!(
            world.verify_until(&plan, &one, 4),
            FinalVerdict::Isolated(_)
        ));
        world.gce.target().status = "RUNNING".into();
        let verdict = world.verify(&plan, &one).1;
        assert!(
            matches!(verdict, FinalVerdict::NotIsolated(_)),
            "a re-started VM is not isolated: {verdict:?}"
        );
    }

    // ------------------------------------------------------------------------------------------
    // F-4: alias IP
    // ------------------------------------------------------------------------------------------

    /// F-4 alone with a complete inventory (the probe is always required, J25 audit N-6).
    fn alias_plan(_probe: bool) -> FencePlan {
        plan(&[FenceMethod::AliasIp], Combine::AnySufficient, true)
    }

    /// The removal is proof only after it is seen absent for the propagation hold and the
    /// data-plane probe finds no host on the protected path; the API answer itself is not.
    #[test]
    fn j25_f4_removal_needs_the_propagation_hold_and_the_probe() {
        let plan = alias_plan(true);
        let attempt = binding(INCIDENT_1, 1);
        let mut world = World::new();
        assert!(matches!(
            world.fence(&plan, &attempt)[0].1,
            ActionReport::Sent { .. }
        ));
        let body = world
            .gce
            .calls
            .iter()
            .find(|(method, _)| *method == HttpMethod::Patch)
            .unwrap();
        assert!(body.1.contains("networkInterface=nic0"));
        assert!(
            unknown(&world.verify(&plan, &attempt).1),
            "operation running, range present"
        );
        world.gce.verify_until_done();
        assert!(world.gce.target().nics[0].ranges.is_empty());
        let (_, verdict) = world.verify(&plan, &attempt);
        assert!(
            unknown(&verdict),
            "first observation of the removal: hold not elapsed"
        );
        let first_seen = world
            .record(&attempt, FenceMethod::AliasIp)
            .unwrap()
            .removal_first_seen_ms;
        assert_eq!(first_seen, Some(world.now_ms));
        world.now_ms += 59_999;
        assert!(unknown(&world.verify(&plan, &attempt).1));
        world.now_ms += 1;
        world.probe = FixedProbe(ProbeResult::Present);
        assert!(
            unknown(&world.verify(&plan, &attempt).1),
            "the probe still sees the path"
        );
        // J26 audit N-1: a probe that still sees the path (or is inconclusive) restarts the hold.
        assert_eq!(
            world
                .record(&attempt, FenceMethod::AliasIp)
                .unwrap()
                .removal_first_seen_ms,
            None
        );
        world.probe = FixedProbe(ProbeResult::Unknown);
        assert!(unknown(&world.verify(&plan, &attempt).1));
        world.probe = FixedProbe(ProbeResult::Absent);
        let restart = world.now_ms;
        assert!(
            unknown(&world.verify(&plan, &attempt).1),
            "a new hold after the probe"
        );
        world.now_ms += 60_000;
        assert!(matches!(
            world.verify(&plan, &attempt).1,
            FinalVerdict::Isolated(_)
        ));
        let first_seen = Some(restart);
        // The first observation is durable: a crashed verify process does not restart the hold.
        assert_eq!(
            world
                .record(&attempt, FenceMethod::AliasIp)
                .unwrap()
                .removal_first_seen_ms,
            first_seen
        );
    }

    /// Partial removal, an update DONE with an error, a fingerprint race (412), a range already
    /// absent, a range re-added to the old NIC, and a missing NIC.
    #[test]
    fn j25_f4_partial_failed_raced_absent_readded_and_missing_nic() {
        let attempt = binding(INCIDENT_1, 1);
        // Partial: two protected ranges, only one removed.
        let mut plan = alias_plan(false);
        plan.alias.as_mut().unwrap().ranges = vec![VIP.into(), OTHER_RANGE.into()];
        let mut world = World::new();
        world.gce.target().nics[0].ranges.push(OTHER_RANGE.into());
        world.gce.alias_effect = AliasEffect::Partial;
        world.fence(&plan, &attempt);
        world.gce.verify_until_done();
        world.now_ms += 120_000;
        assert!(
            matches!(
                world.verify(&plan, &attempt).1,
                FinalVerdict::NotIsolated(_)
            ),
            "partial removal"
        );
        // DONE with an error and the range still present.
        let plan = alias_plan(false);
        let mut world = World::new();
        world.gce.alias_effect = AliasEffect::Fails;
        world.fence(&plan, &attempt);
        world.gce.verify_until_done();
        assert!(matches!(
            world.verify(&plan, &attempt).1,
            FinalVerdict::NotIsolated(_)
        ));
        // A concurrent writer changed the NIC: 412, nothing applied by us.
        let mut world = World::new();
        world.gce.race_fingerprint = true;
        assert_eq!(
            world.fence(&plan, &attempt)[0].1,
            ActionReport::Refused(ApiFailure::PreconditionFailed)
        );
        assert!(
            matches!(
                world.verify(&plan, &attempt).1,
                FinalVerdict::NotIsolated(_)
            ),
            "range still there after a refusal"
        );
        // Already absent: nothing sent, state-based proof after the hold.
        let mut world = World::new();
        world.gce.target().nics[0].ranges.clear();
        assert_eq!(world.fence(&plan, &attempt)[0].1, ActionReport::NotNeeded);
        assert_eq!(world.gce.mutations("updateNetworkInterface"), 0);
        world.verify(&plan, &attempt);
        world.now_ms += 60_000;
        assert!(matches!(
            world.verify(&plan, &attempt).1,
            FinalVerdict::Isolated(_)
        ));
        // Re-added to the old NIC after the removal: not isolated.
        world.gce.target().nics[0].ranges.push(VIP.into());
        assert!(matches!(
            world.verify(&plan, &attempt).1,
            FinalVerdict::Unknown(_) | FinalVerdict::NotIsolated(_)
        ));
        // Missing NIC.
        let mut world = World::new();
        world.gce.target().nics[0].name = "nic1".into();
        assert!(matches!(
            world.fence(&plan, &attempt)[0].1,
            ActionReport::Blocked(_)
        ));
        assert!(unknown(&world.verify(&plan, &attempt).1));
    }

    /// The new node's assignment is refused while the old NIC holds the range and succeeds after
    /// the removal: the control plane keeps one holder at a time. Not part of the fencing proof.
    #[test]
    fn j25_f4_new_node_assignment_is_exclusive_and_comes_after_the_removal() {
        let new_node = InstanceIdentity {
            name: "sim-node-b".into(),
            instance_id: "7000000000000000012".into(),
            ..target()
        };
        let ranges = vec![VIP.to_string()];
        let mut world = World::new();
        let early = assign_alias(
            &mut world.gce,
            &new_node,
            "nic0",
            &ranges,
            "00000000-0000-4000-8000-000000000001",
        );
        assert!(
            matches!(early, ActionReport::Refused(ApiFailure::OtherStatus(400))),
            "{early:?}"
        );
        let plan = alias_plan(false);
        world.fence(&plan, &binding(INCIDENT_1, 1));
        world.gce.verify_until_done();
        let late = assign_alias(
            &mut world.gce,
            &new_node,
            "nic0",
            &ranges,
            "00000000-0000-4000-8000-000000000002",
        );
        assert!(matches!(late, ActionReport::Sent { .. }));
        world.gce.verify_until_done();
        assert_eq!(world.gce.instances["sim-node-b"].nics[0].ranges, ranges);
        assert!(world.gce.target().nics[0].ranges.is_empty());
        let wrong = InstanceIdentity {
            instance_id: "1".into(),
            ..new_node
        };
        assert!(matches!(
            assign_alias(
                &mut world.gce,
                &wrong,
                "nic0",
                &ranges,
                "00000000-0000-4000-8000-000000000003"
            ),
            ActionReport::Blocked(_)
        ));
    }

    /// J25 audit B-1a: the hold is a continuous absence. A range that comes back (for example an
    /// operator's rollback) restarts it; t=0 removed, t=30 s back, t=59 s removed again: the hold
    /// is measured from t=59 s.
    #[test]
    fn j25_f4_hold_restarts_when_a_range_comes_back() {
        let plan = alias_plan(true);
        let attempt = binding(INCIDENT_1, 1);
        let mut world = World::new();
        world.fence(&plan, &attempt);
        world.gce.verify_until_done();
        world.now_ms = 0;
        assert!(unknown(&world.verify(&plan, &attempt).1));
        assert_eq!(
            world
                .record(&attempt, FenceMethod::AliasIp)
                .unwrap()
                .removal_first_seen_ms,
            Some(0)
        );
        world.now_ms = 30_000;
        world.gce.target().nics[0].ranges.push(VIP.into());
        assert!(!matches!(
            world.verify(&plan, &attempt).1,
            FinalVerdict::Isolated(_)
        ));
        assert_eq!(
            world
                .record(&attempt, FenceMethod::AliasIp)
                .unwrap()
                .removal_first_seen_ms,
            None,
            "a range seen again restarts the hold"
        );
        world.now_ms = 59_000;
        world.gce.target().nics[0].ranges.clear();
        assert!(unknown(&world.verify(&plan, &attempt).1));
        world.now_ms = 61_000;
        assert!(
            unknown(&world.verify(&plan, &attempt).1),
            "2 s after the last removal"
        );
        world.now_ms = 119_000;
        assert!(matches!(
            world.verify(&plan, &attempt).1,
            FinalVerdict::Isolated(_)
        ));
    }

    /// J25 audit B-1b: the first observation is stamped after the describe that showed the
    /// absence, not before the API calls (here every call takes 20 s).
    #[test]
    fn j25_f4_hold_starts_after_the_observation_not_before_the_calls() {
        let plan = alias_plan(true);
        let attempt = binding(INCIDENT_1, 1);
        let mut world = World::new();
        world.fence(&plan, &attempt);
        world.gce.verify_until_done();
        let time = std::rc::Rc::new(std::cell::Cell::new(1_000u64));
        world.gce.slow_clock = Some(time.clone());
        let read = time.clone();
        let mut clock = move || Some(read.get());
        let verdict = verify(&mut VerifyContext {
            plan: &plan,
            binding: &attempt,
            api: &mut world.gce,
            store: &mut world.store,
            hooks: &mut NoFaults,
            probe: &mut world.probe,
            clock: &mut clock,
        })
        .1;
        assert!(unknown(&verdict));
        // The operation GET and the describe each took 20 s before the absence was seen.
        assert_eq!(
            world
                .record(&attempt, FenceMethod::AliasIp)
                .unwrap()
                .removal_first_seen_ms,
            Some(41_000)
        );
        // A clock failure is Unknown, never a time.
        let verdict = verify(&mut VerifyContext {
            plan: &plan,
            binding: &attempt,
            api: &mut world.gce,
            store: &mut world.store,
            hooks: &mut NoFaults,
            probe: &mut world.probe,
            clock: &mut || None,
        })
        .1;
        assert!(unknown(&verdict));
    }

    /// J25 audit B-1c: ranges are compared by address on every NIC of the old instance: a wider
    /// range holding the VIP, the VIP on another NIC, or an unparseable range is "present"; the
    /// action changes nothing it does not own.
    #[test]
    fn j25_f4_overlapping_ranges_on_any_nic_are_present() {
        let plan = alias_plan(true);
        let attempt = binding(INCIDENT_1, 1);
        // A /28 that contains the protected /32 on the configured NIC.
        let mut world = World::new();
        world.gce.target().nics[0].ranges = vec!["192.0.2.48/28".into()];
        assert!(matches!(
            world.fence(&plan, &attempt)[0].1,
            ActionReport::Blocked(_)
        ));
        assert_eq!(world.gce.mutations("updateNetworkInterface"), 0);
        // Even with a record, the overlap is present and the hold never starts.
        let mut world = World::new();
        world.fence(&plan, &attempt);
        world.gce.verify_until_done();
        world.gce.target().nics[0].ranges = vec!["192.0.2.48/28".into()];
        world.now_ms += 120_000;
        assert!(matches!(
            world.verify(&plan, &attempt).1,
            FinalVerdict::NotIsolated(_)
        ));
        assert_eq!(
            world
                .record(&attempt, FenceMethod::AliasIp)
                .unwrap()
                .removal_first_seen_ms,
            None
        );
        // The VIP on another NIC of the old instance.
        let mut world = World::new();
        world.gce.target().nics.push(FakeNic {
            name: "nic1".into(),
            fingerprint: 1,
            ranges: vec![VIP.into()],
        });
        assert!(matches!(
            world.fence(&plan, &attempt)[0].1,
            ActionReport::Blocked(_)
        ));
        let mut world = World::new();
        world.fence(&plan, &attempt);
        world.gce.verify_until_done();
        world.gce.target().nics.push(FakeNic {
            name: "nic1".into(),
            fingerprint: 1,
            ranges: vec![VIP.into()],
        });
        world.now_ms += 120_000;
        assert!(!matches!(
            world.verify(&plan, &attempt).1,
            FinalVerdict::Isolated(_)
        ));
        // An unparseable observed range counts as overlapping.
        let mut world = World::new();
        world.fence(&plan, &attempt);
        world.gce.verify_until_done();
        world.gce.target().nics[0].ranges = vec!["not-a-range".into()];
        world.now_ms += 120_000;
        assert!(!matches!(
            world.verify(&plan, &attempt).1,
            FinalVerdict::Isolated(_)
        ));
        // Unrelated ranges do not count.
        let cidr = |text: &str| parse_cidr(text).unwrap();
        assert!(cidr("192.0.2.48/28").overlaps(&cidr(VIP)));
        assert!(cidr(VIP).overlaps(&cidr("192.0.2.0/24")));
        assert!(!cidr(OTHER_RANGE).overlaps(&cidr(VIP)));
        assert_eq!(cidr("192.0.2.50").to_string(), VIP);
    }

    /// J25 audit N-5: the update keeps every other range exactly as GCE reported it
    /// (`subnetworkRangeName` included) and drops only the protected one.
    #[test]
    fn j25_f4_update_keeps_the_other_ranges_unchanged() {
        let plan = alias_plan(true);
        let mut world = World::new();
        world.gce.target().nics[0].ranges.push(OTHER_RANGE.into());
        world
            .gce
            .range_names
            .insert(OTHER_RANGE.into(), "secondary-a".into());
        world.fence(&plan, &binding(INCIDENT_1, 1));
        let body = world.gce.last_patch.clone().unwrap();
        assert_eq!(
            body["aliasIpRanges"],
            json!([{"ipCidrRange": OTHER_RANGE, "subnetworkRangeName": "secondary-a"}])
        );
    }

    // ------------------------------------------------------------------------------------------
    // F-5: combination
    // ------------------------------------------------------------------------------------------

    #[test]
    fn j25_f5_combination_table() {
        use MethodVerdict::{Isolated as I, NotIsolated as N, Unknown as U};
        let i = || I("i".into());
        let n = || N("n".into());
        let u = || U("u".into());
        let both = [FenceMethod::Stop, FenceMethod::AliasIp];
        let any_partial = plan(&both, Combine::AnySufficient, false);
        let any_complete = plan(&both, Combine::AnySufficient, true);
        let all = plan(&both, Combine::All, false);
        let rows: Vec<(&FencePlan, MethodVerdict, MethodVerdict, &str)> = vec![
            // F-2 alone is sufficient.
            (&any_partial, i(), u(), "I"),
            (&any_partial, i(), n(), "I"),
            // F-4 alone is sufficient only for a complete alias-only inventory.
            (&any_partial, u(), i(), "U"),
            (&any_complete, u(), i(), "I"),
            (&any_complete, n(), i(), "I"),
            // One UNKNOWN and nothing sufficient: Unknown.
            (&any_partial, u(), u(), "U"),
            (&any_complete, n(), u(), "U"),
            // Everything that matters definitively failed: NotIsolated.
            (&any_partial, n(), u(), "N"),
            (&any_complete, n(), n(), "N"),
            // All: both must isolate; any definitive failure fails.
            (&all, i(), i(), "I"),
            (&all, i(), u(), "U"),
            (&all, i(), n(), "N"),
            (&all, u(), n(), "N"),
        ];
        for (plan, stop, alias, expected) in rows {
            let verdict = combine(
                plan,
                &[
                    (FenceMethod::Stop, stop.clone()),
                    (FenceMethod::AliasIp, alias.clone()),
                ],
            );
            let got = match verdict {
                FinalVerdict::Isolated(_) => "I",
                FinalVerdict::NotIsolated(_) => "N",
                FinalVerdict::Unknown(_) => "U",
            };
            assert_eq!(
                got, expected,
                "{:?} stop={stop:?} alias={alias:?}",
                plan.combine
            );
        }
        // A configured method without a verdict is Unknown.
        assert!(unknown(&combine(
            &any_complete,
            &[(FenceMethod::AliasIp, i())]
        )));
    }

    /// Both methods end to end; the alias evidence of another generation (attempt) does not count.
    #[test]
    fn j25_f5_both_methods_end_to_end_and_mixed_generations() {
        let plan = plan(
            &[FenceMethod::Stop, FenceMethod::AliasIp],
            Combine::All,
            false,
        );
        let attempt = binding(INCIDENT_1, 1);
        let mut world = World::new();
        let reports = world.fence(&plan, &attempt);
        assert_eq!(
            reports[0].0,
            FenceMethod::AliasIp,
            "the alias is revoked first"
        );
        assert!(
            reports.iter().all(|(_, report)| report.is_success()),
            "{reports:?}"
        );
        world.gce.verify_until_done();
        assert!(
            unknown(&world.verify(&plan, &attempt).1),
            "hold not elapsed"
        );
        world.now_ms += 60_000;
        assert!(matches!(
            world.verify(&plan, &attempt).1,
            FinalVerdict::Isolated(_)
        ));
        // The alias record of attempt 1 moved under attempt 2's key is foreign; attempt 2's stop
        // is isolated, but All needs its own alias evidence.
        let next = binding(INCIDENT_1, 2);
        world.fence(&plan_unchecked_stop_only(), &next);
        world.gce.verify_until_done();
        let alias_record = world
            .record(&attempt, FenceMethod::AliasIp)
            .unwrap()
            .clone();
        world
            .store
            .records
            .insert((INCIDENT_1.into(), 2, "alias-ip"), alias_record);
        let (verdicts, verdict) = world.verify(&plan, &next);
        assert!(
            matches!(verdicts[1].1, MethodVerdict::Unknown(_)),
            "{verdicts:?}"
        );
        assert!(unknown(&verdict));
    }

    fn plan_unchecked_stop_only() -> FencePlan {
        stop_plan()
    }

    // ------------------------------------------------------------------------------------------
    // J26-A: re-audit of the J25 B-1 remediation, one test per counterexample of J26 §4
    // ------------------------------------------------------------------------------------------

    mod j26_b1 {
        use super::*;

        fn removed(world: &mut World, plan: &FencePlan, attempt: &AttemptBinding) {
            world.fence(plan, attempt);
            world.gce.verify_until_done();
        }

        /// CE-1: the range reappears during the hold - on the configured NIC, on another NIC, or as
        /// a wider range - and each time the hold starts again from the next continuous absence.
        #[test]
        fn j26_ce1_reappearance_in_any_form_restarts_the_hold() {
            let plan = alias_plan(true);
            let attempt = binding(INCIDENT_1, 1);
            for (form, nic) in [
                (VIP, 0usize),
                (VIP, 1),
                ("192.0.2.48/29", 0),
                ("192.0.2.50", 0),
            ] {
                let mut world = World::new();
                world.gce.target().nics.push(FakeNic {
                    name: "nic1".into(),
                    fingerprint: 1,
                    ranges: vec![],
                });
                removed(&mut world, &plan, &attempt);
                world.now_ms = 0;
                assert!(unknown(&world.verify(&plan, &attempt).1));
                world.now_ms = 40_000;
                world.gce.target().nics[nic].ranges.push(form.into());
                assert!(
                    !matches!(world.verify(&plan, &attempt).1, FinalVerdict::Isolated(_)),
                    "{form} on nic{nic}"
                );
                assert_eq!(
                    world
                        .record(&attempt, FenceMethod::AliasIp)
                        .unwrap()
                        .removal_first_seen_ms,
                    None,
                    "{form}"
                );
                world.gce.target().nics[nic].ranges.clear();
                world.now_ms = 50_000;
                assert!(unknown(&world.verify(&plan, &attempt).1));
                world.now_ms = 109_999;
                assert!(
                    unknown(&world.verify(&plan, &attempt).1),
                    "{form}: 59.999 s after the last removal"
                );
                world.now_ms = 110_000;
                assert!(
                    matches!(world.verify(&plan, &attempt).1, FinalVerdict::Isolated(_)),
                    "{form}"
                );
            }
        }

        /// CE-2: a clock read before the describe would start the hold early. The stamp is the
        /// time after the observation; a crash after the read but before the save restarts it.
        #[test]
        fn j26_ce2_hold_start_is_the_time_after_the_describe() {
            let plan = alias_plan(true);
            let attempt = binding(INCIDENT_1, 1);
            let mut world = World::new();
            removed(&mut world, &plan, &attempt);
            let time = std::rc::Rc::new(std::cell::Cell::new(0u64));
            world.gce.slow_clock = Some(time.clone());
            let reads = std::rc::Rc::new(std::cell::Cell::new(Vec::<u64>::new()));
            let (read, log) = (time.clone(), reads.clone());
            let mut clock = move || {
                let mut seen = log.take();
                seen.push(read.get());
                log.set(seen);
                Some(read.get())
            };
            verify(&mut VerifyContext {
                plan: &plan,
                binding: &attempt,
                api: &mut world.gce,
                store: &mut world.store,
                hooks: &mut NoFaults,
                probe: &mut world.probe,
                clock: &mut clock,
            });
            let seen = reads.take();
            assert_eq!(seen.len(), 1, "one clock read per poll, after the calls");
            // operation GET + describe = 2 calls x 20 s before the read.
            assert_eq!(seen[0], 40_000);
            assert_eq!(
                world
                    .record(&attempt, FenceMethod::AliasIp)
                    .unwrap()
                    .removal_first_seen_ms,
                Some(40_000)
            );
            // A save failure of the first observation is Unknown and leaves no stamp.
            let mut world = World::new();
            removed(&mut world, &plan, &attempt);
            world.store.fail_saves = vec![world.store.saves + 1];
            assert!(unknown(&world.verify(&plan, &attempt).1));
            assert_eq!(
                world
                    .record(&attempt, FenceMethod::AliasIp)
                    .unwrap()
                    .removal_first_seen_ms,
                None
            );
        }

        /// CE-3: notation differences are the same address range: a bare address, a /32, a range
        /// written with host bits on the NIC, and the configuration's canonical form.
        #[test]
        fn j26_ce3_notation_differences_are_the_same_range() {
            let same = |a: &str, b: &str| parse_cidr(a).unwrap() == parse_cidr(b).unwrap();
            assert!(same("192.0.2.50", "192.0.2.50/32"));
            assert!(same("192.0.2.51/24", "192.0.2.0/24"));
            assert!(
                parse_cidr("192.0.2.051/32").is_none(),
                "leading zeros are not an address"
            );
            assert!(parse_cidr("192.0.2.50/").is_none());
            let plan = alias_plan(true);
            let attempt = binding(INCIDENT_1, 1);
            for observed in ["192.0.2.50", "192.0.2.51/24", "192.0.2.50/31"] {
                // The fence never removes a differently written entry it does not own exactly...
                let mut world = World::new();
                world.gce.target().nics[0].ranges = vec![observed.into()];
                let report = world.fence(&plan, &attempt);
                if observed == "192.0.2.50" {
                    // ...except the bare form, which is exactly the protected /32.
                    assert!(
                        matches!(report[0].1, ActionReport::Sent { .. }),
                        "{observed}: {report:?}"
                    );
                } else {
                    assert!(
                        matches!(report[0].1, ActionReport::Blocked(_)),
                        "{observed}: {report:?}"
                    );
                }
                // ...and the verify sees it as present whatever the notation.
                let mut world = World::new();
                removed(&mut world, &plan, &attempt);
                world.gce.target().nics[0].ranges = vec![observed.into()];
                world.now_ms += 120_000;
                assert!(
                    !matches!(world.verify(&plan, &attempt).1, FinalVerdict::Isolated(_)),
                    "{observed}"
                );
            }
            // The new node's assignment treats the notations as the same range too.
            let new_node = InstanceIdentity {
                name: "sim-node-b".into(),
                instance_id: "7000000000000000012".into(),
                ..target()
            };
            let mut world = World::new();
            world.gce.target().nics[0].ranges.clear();
            world.gce.instances.get_mut("sim-node-b").unwrap().nics[0].ranges =
                vec!["192.0.2.50".into()];
            assert_eq!(
                assign_alias(
                    &mut world.gce,
                    &new_node,
                    "nic0",
                    &[VIP.to_string()],
                    "00000000-0000-4000-8000-000000000009"
                ),
                ActionReport::NotNeeded
            );
        }

        /// CE-4: every NIC of the old instance is examined, and a describe without the configured
        /// NIC (or without any network interface) is never an absence.
        #[test]
        fn j26_ce4_every_nic_is_examined_and_a_missing_nic_is_unknown() {
            let plan = alias_plan(true);
            let attempt = binding(INCIDENT_1, 1);
            let mut world = World::new();
            removed(&mut world, &plan, &attempt);
            for extra in ["nic1", "nic2", "nic3"] {
                world.gce.target().nics.push(FakeNic {
                    name: extra.into(),
                    fingerprint: 1,
                    ranges: vec![],
                });
            }
            world.gce.target().nics[3].ranges = vec![VIP.into()];
            world.now_ms += 120_000;
            assert!(
                !matches!(world.verify(&plan, &attempt).1, FinalVerdict::Isolated(_)),
                "the VIP on the 4th NIC"
            );
            world.gce.target().nics.clear();
            world.now_ms += 120_000;
            assert!(
                unknown(&world.verify(&plan, &attempt).1),
                "no network interface at all"
            );
        }

        /// CE-5: only `absent` is absent. `present`, `unknown` and a probe that cannot run all keep
        /// the verdict Unknown even after the hold.
        #[test]
        fn j26_ce5_only_absent_is_absent() {
            let plan = alias_plan(true);
            let attempt = binding(INCIDENT_1, 1);
            for result in [ProbeResult::Present, ProbeResult::Unknown] {
                let mut world = World::new();
                world.probe = FixedProbe(result);
                removed(&mut world, &plan, &attempt);
                world.verify(&plan, &attempt);
                world.now_ms += 600_000;
                for _ in 0..3 {
                    assert!(unknown(&world.verify(&plan, &attempt).1), "{result:?}");
                }
            }
            // NoProbe (a probe that cannot run) reads Unknown.
            assert_eq!(NoProbe.probe(VIP), ProbeResult::Unknown);
        }

        /// CE-6: observations of different generations never combine: attempt 2 does not inherit
        /// attempt 1's hold, and an `all` plan needs both methods' evidence of the same attempt.
        #[test]
        fn j26_ce6_observations_of_different_generations_never_combine() {
            let plan = alias_plan(true);
            let first = binding(INCIDENT_1, 1);
            let second = binding(INCIDENT_1, 2);
            let mut world = World::new();
            removed(&mut world, &plan, &first);
            world.now_ms = 0;
            world.verify(&plan, &first);
            world.now_ms = 50_000;
            world.verify(&plan, &first);
            world.now_ms = 100_000;
            assert!(matches!(
                world.verify(&plan, &first).1,
                FinalVerdict::Isolated(_)
            ));
            // Attempt 2: the range is already absent, so its action is not-needed; its hold starts
            // at its own first observation.
            assert_eq!(world.fence(&plan, &second)[0].1, ActionReport::NotNeeded);
            assert!(
                unknown(&world.verify(&plan, &second).1),
                "attempt 2 does not inherit the hold"
            );
            assert_eq!(
                world
                    .record(&second, FenceMethod::AliasIp)
                    .unwrap()
                    .removal_first_seen_ms,
                Some(100_000)
            );
            // A record of attempt 1 placed under attempt 2's key is foreign.
            let mut world = World::new();
            removed(&mut world, &plan, &first);
            world.now_ms = 0;
            world.verify(&plan, &first);
            let transplanted = world.record(&first, FenceMethod::AliasIp).unwrap().clone();
            world
                .store
                .records
                .insert((INCIDENT_1.into(), 2, "alias-ip"), transplanted);
            world.now_ms = 100_000;
            assert!(unknown(&world.verify(&plan, &second).1));
        }

        /// CE-7: with an incomplete inventory, F-4 alone never promotes: the plan is refused, and
        /// in any-sufficient an Isolated alias next to a non-isolated stop is not enough.
        #[test]
        fn j26_ce7_incomplete_inventory_never_lets_f4_alone_promote() {
            let mut alias_only = plan_unchecked(&[FenceMethod::AliasIp], false);
            assert!(alias_only.validate().is_err());
            alias_only.combine = Combine::All;
            assert!(
                alias_only.validate().is_err(),
                "all with alias alone is still F-4 alone"
            );
            let both = plan(
                &[FenceMethod::Stop, FenceMethod::AliasIp],
                Combine::AnySufficient,
                false,
            );
            let attempt = binding(INCIDENT_1, 1);
            let mut world = World::new();
            world.gce.stop_effect = StopEffect::StaysRunning;
            removed(&mut world, &both, &attempt);
            world.verify(&both, &attempt);
            world.now_ms += 60_000;
            let (verdicts, verdict) = world.verify(&both, &attempt);
            assert!(
                matches!(verdicts[1].1, MethodVerdict::Isolated(_)),
                "{verdicts:?}"
            );
            assert!(
                !matches!(verdict, FinalVerdict::Isolated(_)),
                "F-4 alone with an incomplete inventory"
            );
        }

        /// J26 audit N-1: a poll that cannot observe the absence (429 describe, an unobservable
        /// operation, a missing NIC, an unreadable clock) restarts the hold, so an unseen re-add
        /// during such a poll cannot be bridged.
        #[test]
        fn j26_n1_unobservable_polls_restart_the_hold() {
            let plan = alias_plan(true);
            let attempt = binding(INCIDENT_1, 1);
            type Break = fn(&mut World);
            let breaks: [(&str, Break); 3] = [
                ("describe 429", |w| {
                    w.gce.forced.push_back((
                        "get-instance",
                        HttpOutcome::Response {
                            status: 429,
                            body: "{}".into(),
                        },
                    ))
                }),
                ("operation unobservable", |w| {
                    w.gce.forced.push_back(("get-op", HttpOutcome::Timeout))
                }),
                ("NIC missing", |w| {
                    w.gce.target().nics[0].name = "nic9".into()
                }),
            ];
            for (name, broken) in breaks {
                let mut world = World::new();
                removed(&mut world, &plan, &attempt);
                world.now_ms = 0;
                world.verify(&plan, &attempt);
                world.now_ms = 30_000;
                broken(&mut world);
                assert!(unknown(&world.verify(&plan, &attempt).1), "{name}");
                assert_eq!(
                    world
                        .record(&attempt, FenceMethod::AliasIp)
                        .unwrap()
                        .removal_first_seen_ms,
                    None,
                    "{name}"
                );
                world.gce.target().nics[0].name = "nic0".into();
                world.now_ms = 59_000;
                world.verify(&plan, &attempt);
                world.now_ms = 61_000;
                assert!(
                    unknown(&world.verify(&plan, &attempt).1),
                    "{name}: 2 s of continuous absence"
                );
                world.now_ms = 119_000;
                assert!(
                    matches!(world.verify(&plan, &attempt).1, FinalVerdict::Isolated(_)),
                    "{name}"
                );
            }
            // An unreadable clock restarts it too.
            let mut world = World::new();
            removed(&mut world, &plan, &attempt);
            world.verify(&plan, &attempt);
            verify(&mut VerifyContext {
                plan: &plan,
                binding: &attempt,
                api: &mut world.gce,
                store: &mut world.store,
                hooks: &mut NoFaults,
                probe: &mut world.probe,
                clock: &mut || None,
            });
            assert_eq!(
                world
                    .record(&attempt, FenceMethod::AliasIp)
                    .unwrap()
                    .removal_first_seen_ms,
                None
            );
        }

        /// J26 audit N-1: two absent observations further apart than the gap are not one absence.
        #[test]
        fn j26_n1_an_observation_gap_restarts_the_hold() {
            let mut plan = alias_plan(true);
            plan.alias.as_mut().unwrap().max_observation_gap_ms = 15_000;
            plan.validate().unwrap();
            let attempt = binding(INCIDENT_1, 1);
            let mut world = World::new();
            removed(&mut world, &plan, &attempt);
            world.now_ms = 0;
            world.verify(&plan, &attempt);
            for t in [15_000, 30_000, 45_000] {
                world.now_ms = t;
                world.verify(&plan, &attempt);
            }
            world.now_ms = 61_000; // 16 s since the last observation: restart
            let verdict = world.verify(&plan, &attempt).1;
            assert!(unknown(&verdict), "{verdict:?}");
            assert_eq!(
                world
                    .record(&attempt, FenceMethod::AliasIp)
                    .unwrap()
                    .removal_first_seen_ms,
                Some(61_000)
            );
            for t in [75_000, 90_000, 105_000, 120_000] {
                world.now_ms = t;
                world.verify(&plan, &attempt);
            }
            world.now_ms = 121_000;
            assert!(matches!(
                world.verify(&plan, &attempt).1,
                FinalVerdict::Isolated(_)
            ));
        }

        /// J26 audit N-2: the production hold has a floor; a shorter hold is a test-build setting.
        #[test]
        fn j26_n2_the_propagation_hold_has_a_floor() {
            let mut plan = alias_plan(true);
            let alias = plan.alias.as_mut().unwrap();
            alias.propagation_hold_ms = MIN_PROPAGATION_HOLD_MS - 1;
            alias.max_observation_gap_ms = 1_000;
            assert!(plan.validate().is_err());
            plan.alias.as_mut().unwrap().short_hold_for_test = true;
            assert!(plan.validate().is_ok());
            plan.alias.as_mut().unwrap().max_observation_gap_ms = 0;
            assert!(plan.validate().is_err(), "a zero gap");
            let alias = plan.alias.as_mut().unwrap();
            alias.max_observation_gap_ms = alias.propagation_hold_ms + 1;
            assert!(plan.validate().is_err(), "a gap longer than the hold");
        }

        /// J26 audit N-4: every protected range is probed; one range still answering is enough to
        /// keep the verdict Unknown.
        #[test]
        fn j26_n4_every_protected_range_is_probed() {
            struct PerRange(Vec<String>, &'static str);
            impl DataPlaneProbe for PerRange {
                fn probe(&mut self, range: &str) -> ProbeResult {
                    self.0.push(range.to_string());
                    if range == self.1 {
                        ProbeResult::Present
                    } else {
                        ProbeResult::Absent
                    }
                }
            }
            let mut plan = alias_plan(true);
            plan.alias.as_mut().unwrap().ranges = vec![VIP.into(), OTHER_RANGE.into()];
            let attempt = binding(INCIDENT_1, 1);
            for (present, expected) in [(OTHER_RANGE, false), ("none", true)] {
                let mut world = World::new();
                world.gce.target().nics[0].ranges.push(OTHER_RANGE.into());
                world.fence(&plan, &attempt);
                world.gce.verify_until_done();
                let mut probe = PerRange(Vec::new(), present);
                let poll = |world: &mut World, probe: &mut PerRange, now: u64| {
                    verify(&mut VerifyContext {
                        plan: &plan,
                        binding: &attempt,
                        api: &mut world.gce,
                        store: &mut world.store,
                        hooks: &mut NoFaults,
                        probe,
                        clock: &mut || Some(now),
                    })
                    .1
                };
                poll(&mut world, &mut probe, 0);
                let verdict = poll(&mut world, &mut probe, 60_000);
                assert_eq!(
                    matches!(verdict, FinalVerdict::Isolated(_)),
                    expected,
                    "{present}: {verdict:?}"
                );
                assert!(
                    probe.0.contains(&VIP.to_string()),
                    "{present}: {:?}",
                    probe.0
                );
                if expected {
                    assert!(probe.0.contains(&OTHER_RANGE.to_string()));
                }
            }
        }

        fn stamps(world: &World, attempt: &AttemptBinding) -> (Option<u64>, Option<u64>, bool) {
            let r = world.record(attempt, FenceMethod::AliasIp).unwrap();
            (
                r.removal_first_seen_ms,
                r.removal_last_seen_ms,
                r.alias_poll_open,
            )
        }

        /// J26 re-audit NB-1: a protected range seen by any describe of the poll - here only the
        /// stop method's - restarts the alias hold, although the alias method's own describe
        /// shows it absent.
        #[test]
        fn j26_nb1_a_range_seen_by_the_stop_describe_restarts_the_alias_hold() {
            let plan = plan(
                &[FenceMethod::Stop, FenceMethod::AliasIp],
                Combine::All,
                false,
            );
            let attempt = binding(INCIDENT_1, 1);
            let mut world = World::new();
            world.fence(&plan, &attempt);
            world.gce.verify_until_done();
            world.now_ms = 0;
            world.verify(&plan, &attempt);
            assert_eq!(stamps(&world, &attempt).0, Some(0));
            // The stop method's describe (the first of the poll) sees the range; the alias
            // method's own describe sees the real, absent state.
            let mut readded = world.gce.instances["sim-node-a"].clone();
            readded.nics[0].ranges = vec![VIP.into()];
            let body = FakeGce::instance_json(&readded, "sim-node-a", &BTreeMap::new());
            world
                .gce
                .forced
                .push_back(("get-instance", HttpOutcome::Response { status: 200, body }));
            world.now_ms = 30_000;
            let (verdicts, verdict) = world.verify(&plan, &attempt);
            assert!(!matches!(verdict, FinalVerdict::Isolated(_)));
            assert!(
                !matches!(verdicts[1].1, MethodVerdict::Isolated(_)),
                "{verdicts:?}"
            );
            assert_eq!(
                stamps(&world, &attempt),
                (None, None, false),
                "the hold restarted"
            );
            world.now_ms = 60_000;
            assert!(
                unknown(&world.verify(&plan, &attempt).1),
                "a new hold from 60 s"
            );
            world.now_ms = 120_000;
            assert!(matches!(
                world.verify(&plan, &attempt).1,
                FinalVerdict::Isolated(_)
            ));
        }

        /// J26 re-audit NB-2: when the restart of the hold cannot be saved, the poll marker
        /// written before the API calls stays set, and the next poll restarts the hold - after an
        /// unobservable describe and after a probe that still sees the path.
        #[test]
        fn j26_nb2_an_unsaved_restart_still_restarts_at_the_next_poll() {
            let plan = alias_plan(true);
            let attempt = binding(INCIDENT_1, 1);
            for case in ["describe-429", "probe-present"] {
                let mut world = World::new();
                removed(&mut world, &plan, &attempt);
                world.now_ms = 0;
                world.verify(&plan, &attempt);
                if case == "describe-429" {
                    world.now_ms = 10_000;
                    world.gce.forced.push_back((
                        "get-instance",
                        HttpOutcome::Response {
                            status: 429,
                            body: "{}".into(),
                        },
                    ));
                } else {
                    world.now_ms = 60_000;
                    world.probe = FixedProbe(ProbeResult::Present);
                }
                // describe-429: save 1 = the marker, save 2 = the restart. probe-present: save 1 =
                // the marker, save 2 = the stamps (the hold has elapsed, so the marker stays
                // open), save 3 = the restart after the probe. Fail the restart.
                let restart_save = if case == "describe-429" { 2 } else { 3 };
                world.store.fail_saves = vec![world.store.saves + restart_save];
                assert!(unknown(&world.verify(&plan, &attempt).1), "{case}");
                let (first, _, open) = stamps(&world, &attempt);
                assert!(
                    open,
                    "{case}: the marker of the unrecorded poll is still set"
                );
                assert_eq!(first, Some(0), "{case}: the old stamp is still on disk");
                if case == "probe-present" {
                    assert!(
                        world
                            .record(&attempt, FenceMethod::AliasIp)
                            .unwrap()
                            .confirmed
                            .is_none()
                    );
                }
                world.probe = FixedProbe(ProbeResult::Absent);
                world.now_ms += 5_000;
                let now = world.now_ms;
                let verdict = world.verify(&plan, &attempt).1;
                assert!(
                    unknown(&verdict),
                    "{case}: never Isolated on the old stamp: {verdict:?}"
                );
                assert_eq!(
                    stamps(&world, &attempt),
                    (Some(now), Some(now), false),
                    "{case}"
                );
            }
        }

        /// J26 re-audit NB-3: a clock behind the last observation, and an older record with a
        /// first observation but no last one, restart the hold.
        #[test]
        fn j26_nb3_a_backward_clock_and_an_older_record_restart_the_hold() {
            let plan = alias_plan(true);
            let attempt = binding(INCIDENT_1, 1);
            let mut world = World::new();
            removed(&mut world, &plan, &attempt);
            world.now_ms = 50_000;
            world.verify(&plan, &attempt);
            world.now_ms = 40_000;
            assert!(unknown(&world.verify(&plan, &attempt).1));
            assert_eq!(
                stamps(&world, &attempt).0,
                Some(40_000),
                "backward clock: a new hold"
            );
            // An older (J25) record: first_seen without last_seen.
            let mut record = world
                .record(&attempt, FenceMethod::AliasIp)
                .unwrap()
                .clone();
            record.removal_first_seen_ms = Some(0);
            record.removal_last_seen_ms = None;
            world
                .store
                .records
                .insert((INCIDENT_1.into(), 1, "alias-ip"), record);
            world.now_ms = 100_000;
            assert!(unknown(&world.verify(&plan, &attempt).1));
            assert_eq!(
                stamps(&world, &attempt).0,
                Some(100_000),
                "an older record: a new hold"
            );
        }

        /// J26 re-audit NB-6: the remaining restart branches - a renumbered instance, an
        /// operation that is not this attempt's alias update, an inconclusive probe - clear both
        /// stamps and close the marker.
        #[test]
        fn j26_nb6_every_restart_branch_clears_both_stamps() {
            let plan = alias_plan(true);
            let attempt = binding(INCIDENT_1, 1);
            type Break = fn(&mut World);
            let breaks: [(&str, Break); 3] = [
                ("renumbered instance", |w| {
                    w.gce.target().id = "7000000000000000099".into()
                }),
                ("foreign operation", |w| {
                    let name = w.gce.operations.keys().next().unwrap().clone();
                    w.gce.operations.get_mut(&name).unwrap().kind = "stop";
                }),
                ("probe unknown", |w| {
                    w.now_ms = 60_000;
                    w.probe = FixedProbe(ProbeResult::Unknown);
                }),
            ];
            for (name, broken) in breaks {
                let mut world = World::new();
                removed(&mut world, &plan, &attempt);
                world.now_ms = 0;
                world.verify(&plan, &attempt);
                assert_eq!(
                    stamps(&world, &attempt),
                    (Some(0), Some(0), false),
                    "{name}"
                );
                broken(&mut world);
                assert!(unknown(&world.verify(&plan, &attempt).1), "{name}");
                assert_eq!(stamps(&world, &attempt), (None, None, false), "{name}");
            }
        }
    }

    // ------------------------------------------------------------------------------------------
    // J26-D: F-5 `combine = all` (the GCE standard candidate), one test per case of J26 §8
    // ------------------------------------------------------------------------------------------

    mod j26_f5 {
        use super::*;

        fn all_plan() -> FencePlan {
            plan(
                &[FenceMethod::Stop, FenceMethod::AliasIp],
                Combine::All,
                false,
            )
        }

        /// Runs the action and polls until the hold has elapsed; returns the final verdict.
        fn run(world: &mut World, attempt: &AttemptBinding) -> FinalVerdict {
            let plan = all_plan();
            world.fence(&plan, attempt);
            world.gce.verify_until_done();
            world.verify(&plan, attempt);
            world.now_ms += 60_000;
            world.verify(&plan, attempt).1
        }

        fn kind(verdict: &FinalVerdict) -> &'static str {
            match verdict {
                FinalVerdict::Isolated(_) => "I",
                FinalVerdict::NotIsolated(_) => "N",
                FinalVerdict::Unknown(_) => "U",
            }
        }

        /// Cases 1-6: success / failure / UNKNOWN of each method, end to end.
        #[test]
        fn j26_f5_all_needs_both_methods_isolated() {
            let attempt = binding(INCIDENT_1, 1);
            type Setup = fn(&mut World);
            let cases: [(&str, Setup, &str); 6] = [
                ("F-2 ok, F-4 ok", |_| {}, "I"),
                (
                    "F-2 ok, F-4 failed",
                    |w| w.gce.alias_effect = AliasEffect::Fails,
                    "N",
                ),
                (
                    "F-2 failed, F-4 ok",
                    |w| w.gce.stop_effect = StopEffect::StaysRunning,
                    "N",
                ),
                (
                    "F-2 ok, F-4 UNKNOWN",
                    |w| w.probe = FixedProbe(ProbeResult::Unknown),
                    "U",
                ),
                (
                    "F-2 UNKNOWN, F-4 ok",
                    |w| w.gce.forced.push_back(("stop", HttpOutcome::Timeout)),
                    "U",
                ),
                (
                    "both UNKNOWN",
                    |w| {
                        w.gce.forced.push_back(("stop", HttpOutcome::Timeout));
                        w.probe = FixedProbe(ProbeResult::Present);
                    },
                    "U",
                ),
            ];
            for (name, setup, expected) in cases {
                let mut world = World::new();
                setup(&mut world);
                let verdict = run(&mut world, &attempt);
                assert_eq!(kind(&verdict), expected, "{name}: {verdict:?}");
                if expected != "I" {
                    assert_ne!(verify_output(&verdict), (0, "isolated\n"), "{name}");
                }
            }
        }

        /// Case 7: success evidence of different generations (stop of token 1, alias of token 2).
        #[test]
        fn j26_f5_evidence_of_different_generations_does_not_combine() {
            let plan = all_plan();
            let one = binding(INCIDENT_1, 1);
            let two = binding(INCIDENT_1, 2);
            let mut world = World::new();
            assert_eq!(kind(&run(&mut world, &one)), "I");
            // Token 2: only the alias action runs (its stop record is absent).
            let alias_only = plan_unchecked(&[FenceMethod::AliasIp], true);
            world.fence(&alias_only, &two);
            world.now_ms += 60_000;
            world.verify(&plan, &two);
            world.now_ms += 60_000;
            let (verdicts, verdict) = world.verify(&plan, &two);
            assert!(
                matches!(verdicts[0].1, MethodVerdict::Unknown(_)),
                "token 1's stop is not token 2's"
            );
            assert_eq!(kind(&verdict), "U");
        }

        /// Cases 8-10: an old operation's success answer, evidence of another instance id, and the
        /// same instance name with a new numeric id.
        #[test]
        fn j26_f5_old_operation_other_instance_and_renumbered_name_never_isolate() {
            let attempt = binding(INCIDENT_1, 1);
            // 8: the recorded stop operation now answers as another (old) operation.
            let mut world = World::new();
            let plan = all_plan();
            world.fence(&plan, &attempt);
            world.gce.verify_until_done();
            let name = match &world.record(&attempt, FenceMethod::Stop).unwrap().phase {
                ActionPhase::Accepted { operation } => operation.clone(),
                other => panic!("{other:?}"),
            };
            world.gce.operations.get_mut(&name).unwrap().kind = "start";
            world.now_ms += 120_000;
            world.verify(&plan, &attempt);
            world.now_ms += 60_000;
            assert_eq!(
                kind(&world.verify(&plan, &attempt).1),
                "U",
                "an operation of another kind"
            );
            // 9: the alias operation names another target.
            let mut world = World::new();
            world.fence(&plan, &attempt);
            let alias_op = match &world.record(&attempt, FenceMethod::AliasIp).unwrap().phase {
                ActionPhase::Accepted { operation } => operation.clone(),
                other => panic!("{other:?}"),
            };
            world.gce.verify_until_done();
            world.gce.operations.get_mut(&alias_op).unwrap().target_id =
                "7000000000000000012".into();
            world.now_ms += 120_000;
            world.verify(&plan, &attempt);
            world.now_ms += 60_000;
            assert_eq!(
                kind(&world.verify(&plan, &attempt).1),
                "U",
                "evidence of another instance id"
            );
            // 10: the same name with a new numeric id after the action.
            let mut world = World::new();
            world.fence(&plan, &attempt);
            world.gce.verify_until_done();
            world.gce.target().id = "7000000000000000099".into();
            world.now_ms += 120_000;
            world.verify(&plan, &attempt);
            world.now_ms += 60_000;
            assert_eq!(
                kind(&world.verify(&plan, &attempt).1),
                "U",
                "renumbered instance name"
            );
        }

        /// Case 11: only one method's evidence is durable (the other record is missing or its
        /// evidence write fails): never Isolated, and no partial `isolated` is printed.
        #[test]
        fn j26_f5_one_durable_record_is_not_enough() {
            let plan = all_plan();
            let attempt = binding(INCIDENT_1, 1);
            let mut world = World::new();
            world.fence(&plan, &attempt);
            world.gce.verify_until_done();
            world
                .store
                .records
                .remove(&(INCIDENT_1.to_string(), 1, "alias-ip"));
            world.now_ms += 120_000;
            assert_eq!(
                kind(&world.verify(&plan, &attempt).1),
                "U",
                "the alias record is missing"
            );
            // Both records present, but the evidence write of the second method fails.
            let mut world = World::new();
            world.fence(&plan, &attempt);
            world.gce.verify_until_done();
            world.verify(&plan, &attempt);
            world.now_ms += 60_000;
            // The next poll saves the stop evidence, then the alias evidence: fail the alias one.
            world.store.fail_saves = vec![world.store.saves + 2];
            let verdict = world.verify(&plan, &attempt).1;
            assert_eq!(
                kind(&verdict),
                "U",
                "an evidence write failure: {verdict:?}"
            );
            assert_eq!(verify_output(&verdict).0, VERIFY_INCONCLUSIVE_EXIT);
        }
    }

    // ------------------------------------------------------------------------------------------
    // J25-D: hand-off to the Stage 14 fencing model and promotion gate
    // ------------------------------------------------------------------------------------------

    mod gate {
        use super::*;
        use crate::failure_assessment::LocalLossEvidence;
        use crate::fencing::{
            ActionOutcome, ClearanceRefusal, ContinuityContext, ContinuityViolation,
            FencingBackend, FencingEventOutcome, FencingIncident, FencingState, FencingTransition,
            IncidentOpening, InconclusiveKind,
        };
        use crate::node_mutation::{NodeMutationError, NodeMutationStore};
        use crate::protocol::{ClusterId, NodeId, SessionId, Term};
        use std::path::PathBuf;
        use std::time::Instant;

        const OBSERVER: &str = "0123456789abcdef";
        const RESTARTED: &str = "fedcba9876543210";
        const ANCHOR: Term = Term(41);
        const LOSS: u64 = 3;

        fn path(name: &str) -> PathBuf {
            std::env::temp_dir().join(format!(
                "mikagami-j25-gate-{name}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ))
        }

        fn store(path: &PathBuf) -> NodeMutationStore {
            let store =
                NodeMutationStore::new(path, ClusterId::new("j25-test"), NodeId::new("node-b"));
            store.initialize_new().unwrap();
            store
        }

        struct Facts {
            peer: NodeId,
            session: SessionId,
            episode: Option<LocalLossEvidence>,
        }

        impl Facts {
            fn new(session: &str) -> Self {
                Self {
                    peer: NodeId::new("node-a"),
                    session: SessionId::new(session),
                    episode: Some(LocalLossEvidence::new_for_test(LOSS, Instant::now())),
                }
            }

            fn context(&self) -> ContinuityContext<'_> {
                ContinuityContext {
                    configured_peer: &self.peer,
                    current_session: &self.session,
                    live_episode: self.episode.as_ref(),
                }
            }
        }

        fn open(store: &NodeMutationStore, session: &str) -> FencingIncident {
            store
                .open_fencing_incident(IncidentOpening {
                    target_node_id: NodeId::new("node-a"),
                    anchor_term: ANCHOR,
                    observer_session_id: SessionId::new(session),
                    observer_loss_generation: LOSS,
                    backend: FencingBackend::Command,
                })
                .unwrap()
        }

        fn applied(outcome: FencingEventOutcome) -> FencingTransition {
            match outcome {
                FencingEventOutcome::Transition(transition) => transition,
                FencingEventOutcome::NoOp => panic!("expected a transition"),
            }
        }

        /// The helper's step binding is exactly the incident and token the store gave the step.
        fn step_binding(incident: &FencingIncident, token: u64) -> AttemptBinding {
            binding(incident.incident_id.as_str(), token)
        }

        /// What the command backend's verify grammar makes of the helper's output, and the Stage 14
        /// event it drives (`drive_fencing_step`): only `isolated` reaches T5.
        fn poll(
            incident: &FencingIncident,
            token: u64,
            verdict: &FinalVerdict,
            budget_exhausted: bool,
        ) -> FencingEventOutcome {
            match verify_output(verdict) {
                (0, "isolated\n") => incident.confirm_by_verification(token).unwrap(),
                (0, "not-isolated\n") => incident.verification_not_isolated(token).unwrap(),
                (code, "") => {
                    assert_ne!(code, 0);
                    incident
                        .verification_inconclusive(
                            token,
                            InconclusiveKind::NonzeroExit,
                            budget_exhausted,
                        )
                        .unwrap()
                }
                other => panic!("unexpected output {other:?}"),
            }
        }

        fn refusal(
            store: &NodeMutationStore,
            incident: &FencingIncident,
            facts: &Facts,
            view: Term,
        ) -> Option<NodeMutationError> {
            store
                .mint_fencing_clearance(&incident.incident_ref(), &facts.context(), view)
                .err()
        }

        /// §9: no clearance before the action, while it runs, while the verify is Unknown; the
        /// clearance comes only from the CONFIRMED written for this incident's own verify, and is
        /// still only fencing evidence for the existing authorization path (the anchor term, the
        /// session and the episode must hold; the grant must be anchor + 1 later).
        #[test]
        fn j25_gate_clearance_only_from_this_incidents_confirmed_verify() {
            let file = path("confirmed");
            let store = store(&file);
            let facts = Facts::new(OBSERVER);
            let plan = stop_plan();
            let mut world = World::new();
            world.gce.op_delay = 2;
            let requested = open(&store, OBSERVER);
            assert_eq!(
                requested.state,
                FencingState::Requested { attempt_token: 1 }
            );
            assert_eq!(
                refusal(&store, &requested, &facts, ANCHOR),
                Some(NodeMutationError::FencingClearanceRefused(
                    ClearanceRefusal::NotConfirmed
                ))
            );
            // The gate's fence action: the helper's report is provenance only (T4).
            let attempt = step_binding(&requested, 1);
            assert!(world.fence(&plan, &attempt)[0].1.is_success());
            let verifying = store
                .apply_fencing_transition(
                    requested
                        .action_returned(1, ActionOutcome::ReportedSuccess)
                        .unwrap(),
                )
                .unwrap();
            assert_eq!(
                refusal(&store, &verifying, &facts, ANCHOR),
                Some(NodeMutationError::FencingClearanceRefused(
                    ClearanceRefusal::NotConfirmed
                ))
            );
            // Unknown polls with budget left change nothing.
            let verdict = world.verify(&plan, &attempt).1;
            assert!(unknown(&verdict));
            assert!(matches!(
                poll(&verifying, 1, &verdict, false),
                FencingEventOutcome::NoOp
            ));
            let verdict = world.verify(&plan, &attempt).1;
            assert!(unknown(&verdict));
            let verdict = world.verify(&plan, &attempt).1;
            assert!(matches!(verdict, FinalVerdict::Isolated(_)));
            let confirmed = store
                .apply_fencing_transition(applied(poll(&verifying, 1, &verdict, false)))
                .unwrap();
            assert!(matches!(confirmed.state, FencingState::Confirmed(_)));
            let clearance = store
                .mint_fencing_clearance(&confirmed.incident_ref(), &facts.context(), ANCHOR)
                .unwrap();
            assert_eq!(clearance.anchor_term(), ANCHOR);
            assert_eq!(clearance.target_node_id().as_str(), "node-a");
            // The Witness term moved: the same evidence no longer clears.
            assert_eq!(
                refusal(&store, &confirmed, &facts, Term(42)),
                Some(NodeMutationError::FencingClearanceRefused(
                    ClearanceRefusal::Continuity(ContinuityViolation::WitnessEpoch)
                ))
            );
            let _ = std::fs::remove_file(&file);
        }

        /// §9: NotIsolated gives FAILED, an exhausted Unknown gives UNKNOWN; neither clears, and the
        /// next attempt (T3, token 2) cannot use attempt 1's helper evidence.
        #[test]
        fn j25_gate_failed_unknown_and_the_next_token_never_clear_from_old_evidence() {
            let file = path("failed");
            let store = store(&file);
            let facts = Facts::new(OBSERVER);
            let plan = stop_plan();
            let mut world = World::new();
            world.gce.stop_effect = StopEffect::StaysRunning;
            let requested = open(&store, OBSERVER);
            let first = step_binding(&requested, 1);
            world.fence(&plan, &first);
            let verifying = store
                .apply_fencing_transition(
                    requested
                        .action_returned(1, ActionOutcome::ReportedSuccess)
                        .unwrap(),
                )
                .unwrap();
            let verdict = world.verify_until(&plan, &first, 4);
            assert!(matches!(verdict, FinalVerdict::NotIsolated(_)));
            let failed = store
                .apply_fencing_transition(applied(poll(&verifying, 1, &verdict, false)))
                .unwrap();
            assert_eq!(failed.state, FencingState::Failed { attempt_token: 1 });
            assert!(refusal(&store, &failed, &facts, ANCHOR).is_some());
            // T3: a new operator action, token 2. The VM gets stopped by someone else meanwhile.
            let requested2 = store
                .apply_fencing_transition(failed.request_again(FencingBackend::Command).unwrap())
                .unwrap();
            assert_eq!(
                requested2.state,
                FencingState::Requested { attempt_token: 2 }
            );
            world.gce.target().status = "TERMINATED".into();
            let second = step_binding(&requested2, 2);
            // Before its own action, attempt 2 has no evidence (attempt 1's record is not read).
            let verdict = world.verify(&plan, &second).1;
            assert!(unknown(&verdict));
            let verifying2 = store
                .apply_fencing_transition(
                    requested2
                        .action_returned(2, ActionOutcome::ReportedFailure)
                        .unwrap(),
                )
                .unwrap();
            let unknown_state = store
                .apply_fencing_transition(applied(poll(&verifying2, 2, &verdict, true)))
                .unwrap();
            assert!(matches!(unknown_state.state, FencingState::Unknown(_)));
            assert!(refusal(&store, &unknown_state, &facts, ANCHOR).is_some());
            // A stale token's isolated result is refused by the model itself.
            assert!(verifying2.confirm_by_verification(1).is_err());
            let _ = std::fs::remove_file(&file);
        }

        /// §9 / §10 points 7, 8: a node restart after CONFIRMED (or just before the lease request)
        /// leaves a CONFIRMED of the old session, which never clears again (R2); the new incident
        /// has a new id, so the helper's old records are not its records either.
        #[test]
        fn j25_gate_restart_after_confirmed_reuses_nothing() {
            let file = path("restart");
            let store = store(&file);
            let plan = stop_plan();
            let mut world = World::new();
            let requested = open(&store, OBSERVER);
            let first = step_binding(&requested, 1);
            world.fence(&plan, &first);
            let verifying = store
                .apply_fencing_transition(
                    requested
                        .action_returned(1, ActionOutcome::ReportedSuccess)
                        .unwrap(),
                )
                .unwrap();
            let verdict = world.verify_until(&plan, &first, 4);
            let confirmed = store
                .apply_fencing_transition(applied(poll(&verifying, 1, &verdict, false)))
                .unwrap();
            // The process restarts: a new session.
            let restarted = Facts::new(RESTARTED);
            assert_eq!(
                refusal(&store, &confirmed, &restarted, ANCHOR),
                Some(NodeMutationError::FencingClearanceRefused(
                    ClearanceRefusal::Continuity(ContinuityViolation::ObserverSession)
                ))
            );
            store
                .retire_fencing_incident(&confirmed.incident_ref())
                .unwrap();
            let fresh = open(&store, RESTARTED);
            assert_ne!(fresh.incident_id, confirmed.incident_id);
            assert!(fresh.incident_seq > confirmed.incident_seq);
            let fresh_attempt = step_binding(&fresh, 1);
            assert!(
                unknown(&world.verify(&plan, &fresh_attempt).1),
                "the old incident's evidence is not the new one's"
            );
            assert!(refusal(&store, &fresh, &restarted, ANCHOR).is_some());
            let _ = std::fs::remove_file(&file);
        }
    }

    // ------------------------------------------------------------------------------------------
    // Two-node runtime -> GCE helper binding (TWO_NODE_FENCING_INTEGRATION_REPORT.md)
    //
    // The two-node runtime builds the step request itself (`CommandFenceRunner::request`), the
    // command backend turns it into the helper's environment (`SpawnPlan`), and the helper binds
    // its records to that environment (`AttemptBinding::from_step`). These tests run that exact
    // chain against the scripted Compute model.
    // ------------------------------------------------------------------------------------------

    mod two_node_binding {
        use super::*;
        use crate::fencing_backend::{SpawnPlan, StepKind, StepOutcome, VerifyOutcome};
        use crate::two_node::controller::{FenceAction, Verdict};
        use crate::two_node::runtime::{CommandFenceRunner, action_outcome, verify_verdict};

        fn runner(cluster: &str, target: &str) -> CommandFenceRunner {
            let argv = |command: &str| {
                Some(vec![
                    "/usr/lib/mikagami/mikagami-gce-fence".to_string(),
                    command.to_string(),
                    "--config".to_string(),
                    "/etc/mikagami/gce-fence.toml".to_string(),
                ])
            };
            let section = crate::config::FencingConfig {
                backend: crate::config::FencingBackendKind::Command,
                fence: argv("fence"),
                verify: argv("verify"),
                fence_timeout_sec: Some(30),
                verify_timeout_sec: Some(10),
                verify_polls: Some(60),
            };
            let settings = crate::fencing_backend::FencingSettings::from_config(Some(&section))
                .unwrap()
                .command()
                .unwrap()
                .clone();
            CommandFenceRunner::new(settings, cluster, target)
        }

        /// The helper's binding exactly as the helper would build it from the environment the
        /// command backend gives the spawned process for this step.
        fn helper_binding(
            runner: &CommandFenceRunner,
            kind: StepKind,
            attempt: u32,
            op_id: &str,
        ) -> (Vec<String>, Result<AttemptBinding, BindingError>) {
            let request = runner.request(kind, 7, attempt, op_id);
            let spawn = SpawnPlan::new(&request);
            let env = |name: &str| {
                spawn
                    .environment
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| value.clone())
            };
            (
                spawn.argv.to_vec(),
                AttemptBinding::from_step(
                    &stop_plan(),
                    env("MIKAGAMI_CLUSTER").as_deref(),
                    env("MIKAGAMI_FENCE_TARGET").as_deref(),
                    env("MIKAGAMI_FENCE_INCIDENT").as_deref(),
                    env("MIKAGAMI_FENCE_ATTEMPT").as_deref(),
                ),
            )
        }

        fn op_id() -> String {
            crate::node_mutation::generate_uuid().unwrap()
        }

        #[test]
        fn fence_and_verify_of_one_attempt_carry_the_same_helper_binding() {
            let runner = runner("j25-test", "node-a");
            for attempt in [1, 2, 3] {
                let op = op_id();
                let (fence_argv, fence) = helper_binding(&runner, StepKind::Action, attempt, &op);
                let (verify_argv, verify) = helper_binding(&runner, StepKind::Verify, attempt, &op);
                let fence = fence.expect("the helper accepts the two-node operation id");
                assert_eq!(Ok(&fence), verify.as_ref());
                assert_eq!(fence.incident_id, op);
                assert_eq!(fence.attempt_token, u64::from(attempt));
                assert_eq!(fence_argv[1], "fence");
                assert_eq!(verify_argv[1], "verify");
                assert!(is_canonical_uuid_v4(&request_id(&fence, FenceMethod::Stop)));
            }
            // Every attempt has a fresh operation id, so no two attempts share a request id.
            let (_, a) = helper_binding(&runner, StepKind::Action, 1, &op_id());
            let (_, b) = helper_binding(&runner, StepKind::Action, 2, &op_id());
            assert_ne!(
                request_id(&a.unwrap(), FenceMethod::Stop),
                request_id(&b.unwrap(), FenceMethod::Stop)
            );
        }

        #[test]
        fn a_confirmed_stop_is_evidence_for_its_own_operation_only() {
            let runner = runner("j25-test", "node-a");
            let mut world = World::new();
            let plan = stop_plan();
            let op = op_id();
            let (_, fence) = helper_binding(&runner, StepKind::Action, 1, &op);
            let fence = fence.unwrap();
            let reports = world.fence(&plan, &fence);
            assert!(
                reports.iter().all(|(_, report)| report.is_success()),
                "{reports:?}"
            );
            let (_, verify_binding) = helper_binding(&runner, StepKind::Verify, 1, &op);
            let verdict = world.verify_until(&plan, &verify_binding.unwrap(), 5);
            assert!(matches!(verdict, FinalVerdict::Isolated(_)), "{verdict:?}");

            // Another operation id (a later attempt, a stale or foreign result): no record of
            // its own action, so never isolated, whatever the instance state is.
            for (attempt, other) in [(2, op_id()), (1, op_id())] {
                let (_, binding) = helper_binding(&runner, StepKind::Verify, attempt, &other);
                let (_, verdict) = world.verify(&plan, &binding.unwrap());
                assert!(unknown(&verdict), "{verdict:?}");
            }
            // The same operation id with another attempt token is another binding as well.
            let (_, same_op_other_attempt) = helper_binding(&runner, StepKind::Verify, 2, &op);
            let (_, verdict) = world.verify(&plan, &same_op_other_attempt.unwrap());
            assert!(unknown(&verdict), "{verdict:?}");
        }

        #[test]
        fn accepted_but_running_or_unobservable_is_never_isolated() {
            let runner = runner("j25-test", "node-a");
            let plan = stop_plan();
            for effect in [StopEffect::StaysRunning, StopEffect::Fails] {
                let mut world = World::new();
                world.gce.stop_effect = effect;
                let op = op_id();
                let (_, binding) = helper_binding(&runner, StepKind::Action, 1, &op);
                let binding = binding.unwrap();
                world.fence(&plan, &binding);
                let verdict = world.verify_until(&plan, &binding, 5);
                assert!(
                    !matches!(verdict, FinalVerdict::Isolated(_)),
                    "{effect:?}: {verdict:?}"
                );
            }
        }

        #[test]
        fn a_corrupt_or_foreign_helper_record_blocks_fence_and_verify() {
            let runner = runner("j25-test", "node-a");
            let plan = stop_plan();
            let mut world = World::new();
            let op = op_id();
            let (_, binding) = helper_binding(&runner, StepKind::Action, 1, &op);
            let binding = binding.unwrap();
            world.fence(&plan, &binding);
            let key = (binding.incident_id.clone(), binding.attempt_token, "stop");
            let mut record = world.store.records.get(&key).cloned().unwrap();
            record.request_id = "00000000-0000-4000-8000-000000000000".into();
            world.store.records.insert(key, record);
            let (_, verdict) = world.verify(&plan, &binding);
            assert!(unknown(&verdict), "{verdict:?}");
            let reports = world.fence(&plan, &binding);
            assert!(
                reports
                    .iter()
                    .all(|(_, report)| matches!(report, ActionReport::Blocked(_))),
                "{reports:?}"
            );
        }

        #[test]
        fn a_wrong_target_or_cluster_is_refused_by_the_helper() {
            let op = op_id();
            for (cluster, target, expected) in [
                ("j25-test", "node-b", BindingError::TargetMismatch),
                ("other", "node-a", BindingError::ClusterMismatch),
            ] {
                let runner = runner(cluster, target);
                let (_, binding) = helper_binding(&runner, StepKind::Action, 1, &op);
                assert_eq!(binding, Err(expected));
            }
        }

        #[test]
        fn step_outcomes_map_to_the_controller_conservatively() {
            use crate::fencing::{ActionOutcome, InconclusiveKind};
            assert_eq!(
                verify_verdict(Some(StepOutcome::Verify(VerifyOutcome::Isolated))),
                Verdict::Isolated
            );
            assert_eq!(
                verify_verdict(Some(StepOutcome::Verify(VerifyOutcome::NotIsolated))),
                Verdict::NotIsolated
            );
            for outcome in [
                Some(StepOutcome::Verify(VerifyOutcome::Inconclusive(
                    InconclusiveKind::Timeout,
                ))),
                Some(StepOutcome::Verify(VerifyOutcome::Inconclusive(
                    InconclusiveKind::SpawnFailed,
                ))),
                Some(StepOutcome::Action(ActionOutcome::ReportedSuccess)),
                None,
            ] {
                assert_eq!(
                    verify_verdict(outcome.clone()),
                    Verdict::Inconclusive,
                    "{outcome:?}"
                );
            }
            assert_eq!(
                action_outcome(Some(StepOutcome::Action(ActionOutcome::ReportedSuccess))),
                FenceAction::ReportedSuccess
            );
            assert_eq!(
                action_outcome(Some(StepOutcome::Verify(VerifyOutcome::Isolated))),
                FenceAction::SpawnFailed,
                "a verify outcome is never an action report"
            );
            assert_eq!(action_outcome(None), FenceAction::SpawnFailed);
        }

        #[test]
        fn a_malformed_operation_identity_never_reaches_a_helper() {
            let mut runner = runner("j25-test", "node-a");
            use crate::two_node::runtime::FenceRunner;
            assert_eq!(runner.fence(1, 1, "not-a-uuid"), FenceAction::SpawnFailed);
            assert_eq!(runner.verify(1, 0, &op_id()), Verdict::Inconclusive);
        }
    }
}
