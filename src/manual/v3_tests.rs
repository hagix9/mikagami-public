//! Prototype v0.3 regression tests (audit B of R7 and the v0.3 work).
//!
//! Each test names the finding it pins. Mutants of the code they cover are in
//! `prototype/v0.3/MUTATION_RESULTS.md`.

mod rollback_texts {
    //! Audit B LOW-1: every rollback arm that is not "verified" says what is
    //! known about the restarts of chronyd (CLI_REFERENCE promise RA-D-02).
    use crate::manual::Failure;
    use crate::manual::chrony_agent::PRE_SWAP;
    use crate::manual::chrony_ctl;
    use crate::manual::fakes::{Fault, World};
    use crate::manual::proto::op;
    use crate::manual::r6_tests::chrony_displaced::{Hooks, NEW, THIRD};
    use std::fs;
    use std::path::PathBuf;
    use std::rc::Rc;

    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            PRE_SWAP.with(|h| *h.borrow_mut() = None);
            crate::manual::fsutil::EXCHANGE_FAIL_AT.with(|c| c.set(None));
        }
    }

    fn unknown_text(r: Result<chrony_ctl::ApplyReport, Failure>) -> String {
        match r {
            Err(Failure::Unknown(m)) => m,
            other => panic!("expected UNKNOWN, got {other:?}"),
        }
    }

    /// The first verification fails (tracking is down); `heal_at` decides
    /// whether a later restart makes it pass.
    fn failing_world(label: &str, heal_on_second_restart: bool) -> World {
        let w = World::new(label);
        let sys = w.remote.host("node-a").sys.clone();
        sys.fail_tracking(true);
        if heal_on_second_restart {
            let healed = sys.clone();
            w.remote.inject_when(
                "node-a",
                op::SERVICE_CONTROL,
                Some("\"action\":\"restart\""),
                1,
                1,
                Fault::Hook(Rc::new(move || healed.fail_tracking(false))),
            );
        }
        w
    }

    fn restarts(w: &World) -> usize {
        w.count_agent_calls("node-a", op::SERVICE_CONTROL)
    }

    #[test]
    fn l1_a_restore_that_could_not_put_back_says_a_restart_was_requested() {
        // The put-back exchange of the restore fails after somebody else wrote
        // a third version: the answer is "kept", the class UNKNOWN. The first
        // restart WAS requested, so the text must say chronyd may run the
        // candidate (it used to say nothing about the restart).
        let _r = Reset;
        let w = failing_world("v3-l1-kept", true);
        let conf: PathBuf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        let calls = Rc::new(std::cell::Cell::new(0));
        let seen = Rc::clone(&calls);
        PRE_SWAP.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                seen.set(seen.get() + 1);
                if seen.get() == 2 {
                    fs::write(&conf, THIRD).unwrap();
                }
            }));
        });
        crate::manual::fsutil::EXCHANGE_CALLS.with(|c| c.set(0));
        crate::manual::fsutil::EXCHANGE_FAIL_AT.with(|c| c.set(Some(3)));
        let m = unknown_text(chrony_ctl::apply(&w.ctx(), "node-a", NEW, false));
        assert_eq!(restarts(&w), 1, "only the first restart ran");
        assert!(m.contains("A restart WAS requested"), "{m}");
        assert!(m.contains("CANDIDATE"), "{m}");
        assert!(
            m.contains("did not get as far as a restart of its own"),
            "{m}"
        );
    }

    #[test]
    fn l1_a_rollback_whose_own_restart_fails_says_chronyd_was_restarted_twice() {
        // The previous file is back, the rollback's restart is requested, and
        // the verification after it fails as well.
        let w = failing_world("v3-l1-twice", false);
        let m = unknown_text(chrony_ctl::apply(&w.ctx(), "node-a", NEW, false));
        assert_eq!(restarts(&w), 2, "publish restart and rollback restart");
        assert!(m.contains("ROLLBACK FAILED"), "{m}");
        assert!(m.contains("at least twice"), "{m}");
        assert!(m.contains("A restart WAS requested"), "{m}");
    }

    #[test]
    fn l1_a_failed_restore_after_a_refused_first_restart_says_nothing_was_restarted() {
        // The first restart is refused (the exclusion is lost), so chronyd was
        // not restarted; then the restore itself fails. The rollback-failed
        // text must carry the 'not restarted' statement.
        let w = World::new("v3-l1-refused");
        w.remote.inject_when(
            "node-a",
            op::SERVICE_CONTROL,
            Some("\"action\":\"restart\""),
            0,
            1,
            Fault::RefuseBefore("exclusion from the HA daemon is not proven".into()),
        );
        w.remote.inject_when(
            "node-a",
            op::CHRONY_RESTORE,
            None,
            0,
            1,
            Fault::FailBefore("disk full".into()),
        );
        let m = unknown_text(chrony_ctl::apply(&w.ctx(), "node-a", NEW, false));
        assert!(m.contains("ROLLBACK FAILED"), "{m}");
        assert!(m.contains("did not restart chronyd"), "{m}");
        // The one restart call is the refused one; nothing ran after it.
        assert_eq!(restarts(&w), 1);
    }

    #[test]
    fn m1_no_restart_is_claimed_when_the_state_read_before_it_cannot_be_made() {
        // Audit v0.3 MEDIUM-1: the status read that comes before a restart fails
        // twice (publish, rollback). No restart request is ever sent, so the report
        // must not say that one was, nor that chronyd was restarted twice.
        let w = World::new("v3-m1-not-requested");
        w.remote
            .inject_when("node-a", op::SERVICE_STATUS, None, 0, 2, Fault::DropBefore);
        let m = unknown_text(chrony_ctl::apply(&w.ctx(), "node-a", NEW, false));
        assert_eq!(restarts(&w), 0, "no restart request was sent");
        assert!(m.contains("No restart was requested"), "{m}");
        assert!(m.contains("did not request a restart of its own"), "{m}");
        assert!(!m.contains("A restart WAS requested"), "{m}");
        assert!(!m.contains("at least twice"), "{m}");
        assert!(!m.contains("CANDIDATE"), "{m}");
    }

    #[test]
    fn m1_a_restart_request_that_fails_is_reported_as_not_known_not_as_done() {
        // The restart requests (publish, rollback) never reach the agent: they were
        // sent, nothing is known about the outcome.
        let w = World::new("v3-m1-unconfirmed");
        w.remote.inject_when(
            "node-a",
            op::SERVICE_CONTROL,
            Some("\"action\":\"restart\""),
            0,
            2,
            Fault::DropBefore,
        );
        let m = unknown_text(chrony_ctl::apply(&w.ctx(), "node-a", NEW, false));
        assert!(m.contains("REQUESTED after the publish"), "{m}");
        assert!(m.contains("not known whether chronyd was restarted"), "{m}");
        assert!(
            m.contains("not known whether chronyd was restarted a second time"),
            "{m}"
        );
        assert!(!m.contains("A restart WAS requested"), "{m}");
        assert!(!m.contains("at least twice"), "{m}");
    }

    #[test]
    fn m1_the_kept_version_text_does_not_contradict_a_refused_first_restart() {
        // The first restart is refused, so chronyd was not restarted; the rollback's
        // restore then meets an edit of somebody else and its answer is lost. The
        // text of the kept version used to say that the first restart "may have been
        // carried out" in the same breath as "this command did not restart chronyd".
        let _r = Reset;
        let w = World::new("v3-m1-refused-kept");
        w.remote.inject_when(
            "node-a",
            op::SERVICE_CONTROL,
            Some("\"action\":\"restart\""),
            0,
            1,
            Fault::RefuseBefore("exclusion from the HA daemon is not proven".into()),
        );
        let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        let _hooks = Hooks::arm(conf, 2, 3);
        w.remote
            .inject_when("node-a", op::CHRONY_RESTORE, None, 0, 1, Fault::DropAfter);
        let m = unknown_text(chrony_ctl::apply(&w.ctx(), "node-a", NEW, false));
        assert!(m.contains("kept version"), "{m}");
        assert!(m.contains("did not restart chronyd"), "{m}");
        assert!(!m.contains("may have been carried out"), "{m}");
        assert!(!m.contains("CANDIDATE"), "{m}");
    }

    #[test]
    fn l1_a_failed_restore_after_a_requested_restart_says_chronyd_may_run_the_candidate() {
        let w = failing_world("v3-l1-requested", true);
        w.remote.inject_when(
            "node-a",
            op::CHRONY_RESTORE,
            None,
            0,
            1,
            Fault::FailBefore("disk full".into()),
        );
        let m = unknown_text(chrony_ctl::apply(&w.ctx(), "node-a", NEW, false));
        assert!(m.contains("ROLLBACK FAILED"), "{m}");
        assert!(m.contains("A restart WAS requested"), "{m}");
        assert!(
            m.contains("The rollback itself did not restart chronyd"),
            "{m}"
        );
    }
}

mod agent_gaps {
    //! Audit B LOW-3: test gaps found by the independent auditor's surviving
    //! mutants A15, A5 and A8 (`prototype/v0.3/MUTATION_RESULTS.md`).
    use crate::manual::fakes::World;
    use crate::manual::fsutil;
    use crate::manual::proto::op;
    use crate::manual::r6_tests::chrony_displaced::{Hooks, NEW, OLD, conf_dir, named};
    use crate::manual::{agent, testkit};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn sha(text: &str) -> String {
        fsutil::sha256_hex(text.as_bytes())
    }

    #[test]
    fn l1_the_agents_put_back_failure_text_names_the_content_being_put_in() {
        // Audit B LOW-1: in a restore the live file holds the backup, not 'the
        // new content'. The same text serves publish and restore, so it says
        // what is true of both. Tested at the agent, where the controller does
        // not shorten the message.
        let w = World::new("v3-l1-agent-text");
        let host = w.remote.host("node-a");
        let staged = agent::handle(
            &host.env,
            &testkit::req(
                op::CHRONY_STAGE,
                serde_json::json!({"content": NEW, "sha256": sha(NEW)}),
            ),
        );
        let id = staged.data["stage_id"].as_str().unwrap().to_string();
        let conf = host.env.cfg.chrony_conf.clone();
        let _hooks = Hooks::arm(conf, 1, 99);
        crate::manual::fsutil::EXCHANGE_CALLS.with(|c| c.set(0));
        crate::manual::fsutil::EXCHANGE_FAIL_AT.with(|c| c.set(Some(2)));
        let r = agent::handle(
            &host.env,
            &testkit::req(
                op::CHRONY_PUBLISH,
                serde_json::json!({
                    "stage_id": id,
                    "expect_current": sha(OLD),
                    "expect_new": sha(NEW),
                }),
            ),
        );
        crate::manual::fsutil::EXCHANGE_FAIL_AT.with(|c| c.set(None));
        let text = format!("{r:?}");
        assert!(text.contains("content being put in"), "{text}");
        assert!(!text.contains("holds the new content"), "{text}");
    }

    #[test]
    fn a15_a_configuration_directory_that_cannot_be_listed_is_not_reported_as_readable() {
        // The agent half of the 'unreadable listing' rule: a failed `read_dir`
        // must answer `readable: false`, never `readable: true, count: 0`
        // (which the next apply would take for "nothing is kept").
        let w = World::new("v3-a15");
        let dir = conf_dir(&w);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o300)).unwrap();
        let listable = fs::read_dir(&dir).is_ok();
        let host = w.remote.host("node-a");
        let r = agent::handle(
            &host.env,
            &testkit::req(op::CHRONY_STATE, serde_json::json!({})),
        );
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        if listable {
            // Running as root: directory permissions do not stop the listing,
            // so this test cannot make the failure (LINUX_TEST_RESULTS.md).
            eprintln!("a15: skipped, the directory stays listable for this user");
            return;
        }
        assert_eq!(
            r.data["displaced"]["readable"],
            serde_json::json!(false),
            "{:?}",
            r.data
        );
    }

    #[test]
    fn a5_the_staged_name_is_gone_once_the_displaced_version_has_its_other_name() {
        // 'The staged name is removed as soon as the data has another name'
        // (LIMITATIONS 58). The ordinary path makes the second name right after
        // the exchange. Here that first attempt fails once (a transient error)
        // and the put-back fails as well: the later attempt (`protect_displaced`)
        // does make the name, and then exactly one name is left to look at.
        let w = World::new("v3-a5");
        let host = w.remote.host("node-a");
        let staged = agent::handle(
            &host.env,
            &testkit::req(
                op::CHRONY_STAGE,
                serde_json::json!({"content": NEW, "sha256": sha(NEW)}),
            ),
        );
        let id = staged.data["stage_id"].as_str().unwrap().to_string();
        let conf = host.env.cfg.chrony_conf.clone();
        let _hooks = Hooks::arm(conf, 1, 99);
        crate::manual::fsutil::EXCHANGE_CALLS.with(|c| c.set(0));
        crate::manual::fsutil::EXCHANGE_FAIL_AT.with(|c| c.set(Some(2)));
        crate::manual::fsutil::LINK_FAIL_ONCE.with(|c| c.set(Some(1)));
        let r = agent::handle(
            &host.env,
            &testkit::req(
                op::CHRONY_PUBLISH,
                serde_json::json!({
                    "stage_id": id,
                    "expect_current": sha(OLD),
                    "expect_new": sha(NEW),
                }),
            ),
        );
        crate::manual::fsutil::EXCHANGE_FAIL_AT.with(|c| c.set(None));
        crate::manual::fsutil::LINK_FAIL_ONCE.with(|c| c.set(None));
        assert_eq!(
            r.error.as_ref().map(|e| e.code.as_str()),
            Some(crate::manual::proto::code::DISPLACED_KEPT),
            "{r:?}"
        );
        assert_eq!(
            named(&w, ".mkg-displaced-").len(),
            1,
            "their version is kept under one protected name"
        );
        assert!(
            named(&w, ".mkg-stage-").is_empty(),
            "the staged name must not remain beside the protected name: {:?}",
            named(&w, ".mkg-stage-")
        );
    }

    #[test]
    fn a8_a_staged_name_that_is_not_a_regular_file_is_left_exactly_as_it_is() {
        // Only root can plant such a name; the clean-up must neither remove it
        // nor move it to a protected name (a directory has no content hash).
        let w = World::new("v3-a8");
        let dir = conf_dir(&w);
        let stage_id = "0123456789abcdeffedcba9876543210";
        let planted = dir.join(format!(".mkg-stage-{stage_id}.conf"));
        fs::create_dir(&planted).unwrap();
        fs::write(planted.join("inside"), "x").unwrap();
        let host = w.remote.host("node-a");
        let r = agent::handle(
            &host.env,
            &testkit::req(
                op::CHRONY_CLEANUP,
                serde_json::json!({"stage_id": stage_id}),
            ),
        );
        assert_eq!(r.data["removed"], serde_json::json!(false), "{:?}", r.data);
        assert!(
            r.data["note"]
                .as_str()
                .is_some_and(|n| n.contains("not a regular file")),
            "{:?}",
            r.data
        );
        assert!(
            planted.join("inside").is_file(),
            "the directory is untouched"
        );
        assert!(
            named(&w, ".mkg-displaced-").is_empty(),
            "nothing was moved to a protected name"
        );
    }
}

mod status_guidance {
    //! v0.3: `resource status` says what may be done next and what must not be,
    //! as a function of the observed verdict, in the text and in the JSON.
    use crate::manual::fakes::{Fault, World};
    use crate::manual::proto::op;
    use crate::manual::vip::{MoveRequest, move_vip, vip_status};

    fn mv(w: &World, to: &str) {
        let _ = move_vip(
            &w.ctx(),
            &MoveRequest {
                target: to.to_string(),
                confirm_fenced: None,
            },
        );
    }

    #[test]
    fn a_consistent_vip_offers_the_move_to_the_other_node_in_text_and_json() {
        let w = World::new("v3-guidance-consistent");
        let status = vip_status(&w.ctx());
        assert_eq!(status.verdict, "consistent", "{:?}", status.problems);
        let allowed = status.guidance.allowed.join("\n");
        assert!(allowed.contains("move vip --to node-b"), "{allowed}");
        assert!(!allowed.contains("--to node-a"), "{allowed}");
        // the quiet state carries the warnings against hand edits (audit MEDIUM-2e)
        let forbidden = status.guidance.forbidden.join("\n");
        assert!(forbidden.contains("gcloud"), "{forbidden}");
        let json = serde_json::to_value(&status).unwrap();
        assert!(json["guidance"]["allowed"].is_array(), "{json}");
    }

    #[test]
    fn an_unresolved_operation_names_the_operation_to_abandon_and_forbids_a_move() {
        // The commit never reaches the Witness: the move ends UNKNOWN with the
        // operation recorded. The guidance names that very operation.
        let w = World::new("v3-guidance-unresolved");
        w.remote
            .inject("witness", op::LEASE_COMMIT, Fault::DropBefore);
        mv(&w, "node-b");
        let op_id = w.lease().op.unwrap().op_id;
        let status = vip_status(&w.ctx());
        assert_eq!(status.verdict, "unresolved_operation");
        let allowed = status.guidance.allowed.join("\n");
        let forbidden = status.guidance.forbidden.join("\n");
        assert!(
            allowed.contains(&format!("--abandon-op {op_id}")),
            "the guidance names the recorded operation: {allowed}"
        );
        assert!(forbidden.contains("mkg resource move vip"), "{forbidden}");
        assert!(forbidden.contains("gcloud"), "{forbidden}");
        assert!(
            !allowed.contains("move vip --to"),
            "no move is offered while an operation is unresolved: {allowed}"
        );
    }

    #[test]
    fn an_unreachable_witness_offers_no_move_and_no_abandon() {
        let w = World::new("v3-guidance-unknown");
        w.remote.host("witness").reachable.set(false);
        let status = vip_status(&w.ctx());
        assert_eq!(status.verdict, "unknown");
        let allowed = status.guidance.allowed.join("\n");
        assert!(
            !allowed.contains("move vip") && !allowed.contains("abandon"),
            "{allowed}"
        );
        assert!(status.guidance.forbidden.join("\n").contains("move vip"));
    }

    #[test]
    fn the_overview_prints_and_serialises_the_guidance_of_both_resources() {
        let w = World::new("v3-guidance-overview");
        let out = crate::manual::run::status_overview_in(&w.ctx()).unwrap();
        assert!(out.text.contains("next (allowed):"), "{}", out.text);
        assert!(
            out.text.contains("move vip --to node-b"),
            "the VIP part of the overview carries its own advice: {}",
            out.text
        );
        assert!(
            out.json["vip"]["guidance"]["allowed"].is_array(),
            "{}",
            out.json
        );
        assert!(
            out.json["chronyd"]["guidance"]["allowed"].is_array(),
            "{}",
            out.json
        );
        // A node that cannot be observed turns the chronyd advice from
        // 'apply' into 'make the node reachable'.
        w.remote.host("node-b").reachable.set(false);
        let out = crate::manual::run::status_overview_in(&w.ctx()).unwrap();
        assert!(
            out.text.contains("node-b: make the node reachable"),
            "{}",
            out.text
        );
        assert!(out.text.contains("next (forbidden):"), "{}", out.text);
        assert_ne!(out.exit, 0);
    }

    // --- audit v0.3 MEDIUM-2: the advice follows the observed state ------------------------

    fn execute_status(
        w: &World,
        resource: crate::manual::cli_def::ResourceName,
    ) -> crate::manual::run::Output {
        use crate::manual::cli_def::{Common, ResourceCommands};
        crate::manual::run::execute_resource(
            &w.ctx(),
            ResourceCommands::Status {
                resource,
                node: None,
                common: Common {
                    config: None,
                    json: false,
                },
            },
        )
        .unwrap()
    }

    #[test]
    fn a_kept_version_on_a_healthy_node_is_advised_in_text_and_json() {
        // (a) `healthy` is true, the guidance still says what the kept version means
        let w = World::new("v3-guidance-kept");
        let dir = crate::manual::r6_tests::chrony_displaced::conf_dir(&w);
        std::fs::write(
            dir.join(".mkg-displaced-mkg-stage-0123456789abcdeffedcba9876543210.conf"),
            "x\n",
        )
        .unwrap();
        let out = execute_status(&w, crate::manual::cli_def::ResourceName::Chronyd);
        assert!(
            out.text.contains("node-a: compare the kept file(s)"),
            "{}",
            out.text
        );
        assert!(
            out.text.contains("next (forbidden):")
                && out.text.contains("chronyd apply --node node-a"),
            "{}",
            out.text
        );
        // B4 / B5: the JSON carries the same lists
        let allowed = out.json["guidance"]["allowed"].to_string();
        let forbidden = out.json["guidance"]["forbidden"].to_string();
        assert!(allowed.contains("compare the kept file"), "{allowed}");
        assert!(
            forbidden.contains("chronyd apply --node node-a"),
            "{forbidden}"
        );
        assert!(!allowed.contains("mkg chronyd apply"), "{allowed}");
    }

    #[test]
    fn a_node_that_fails_its_tracking_has_the_apply_forbidden() {
        // B2
        let w = World::new("v3-guidance-tracking");
        w.remote.host("node-b").sys.fail_tracking(true);
        let out = execute_status(&w, crate::manual::cli_def::ResourceName::Chronyd);
        let forbidden = out.json["guidance"]["forbidden"].to_string();
        assert!(
            forbidden.contains("chronyd apply --node node-b"),
            "{forbidden}"
        );
        assert!(forbidden.contains("deleting .mkg-* files"), "{forbidden}");
        assert!(!forbidden.contains("--node node-a"), "{forbidden}");
        assert_ne!(out.exit, 0);
    }

    #[test]
    fn a_terminated_peer_is_not_offered_as_the_target_of_a_move() {
        // (b) after a fenced move the old source is TERMINATED and the verdict is consistent
        let w = World::new("v3-guidance-terminated");
        w.gce.set_status("inst-b", "TERMINATED");
        w.remote.host("node-b").reachable.set(false);
        let status = vip_status(&w.ctx());
        let allowed = status.guidance.allowed.join("\n");
        assert!(
            !allowed.contains("move vip --to node-b"),
            "{} / {:?}",
            allowed,
            status.problems
        );
    }

    #[test]
    fn an_uninitialised_store_is_advised_init_and_not_reconcile() {
        // (c) the first state of every installation
        let w = World::build("v3-guidance-uninitialised", false);
        let status = vip_status(&w.ctx());
        assert_eq!(status.verdict, "mismatch", "{:?}", status.problems);
        let allowed = status.guidance.allowed.join("\n");
        assert!(allowed.contains("init vip --owner node-a"), "{allowed}");
        assert!(!allowed.contains("reconcile vip"), "{allowed}");
    }

    #[test]
    fn a_host_with_a_running_ha_unit_has_the_chronyd_apply_forbidden_in_the_overview() {
        // (d) the VIP part says ha_conflict; the chronyd part must not offer the apply
        let w = World::new("v3-guidance-ha");
        w.remote.host("node-b").sys.unmask("mikagami.service");
        assert!(
            w.ha_start("node-b", "mikagami.service"),
            "an unmasked unit starts"
        );
        let out = crate::manual::run::status_overview_in(&w.ctx()).unwrap();
        assert_eq!(out.json["vip"]["verdict"], "ha_conflict", "{}", out.json);
        let forbidden = out.json["chronyd"]["guidance"]["forbidden"].to_string();
        assert!(
            forbidden.contains("chronyd apply --node node-b"),
            "{forbidden}"
        );
        assert!(
            forbidden.contains("exclusion from the HA daemon is not proven"),
            "{forbidden}"
        );
    }

    #[test]
    fn a_host_with_an_unmasked_but_stopped_ha_unit_has_the_chronyd_apply_forbidden_too() {
        // (d) not only a running daemon: "unmasked" is not a proof of the exclusion either
        let w = World::new("v3-guidance-unmasked");
        w.remote.host("node-b").sys.unmask("mikagami.service");
        let out = crate::manual::run::status_overview_in(&w.ctx()).unwrap();
        assert_ne!(out.json["vip"]["verdict"], "consistent", "{}", out.json);
        let forbidden = out.json["chronyd"]["guidance"]["forbidden"].to_string();
        assert!(
            forbidden.contains("chronyd apply --node node-b"),
            "{forbidden}"
        );
        assert!(!forbidden.contains("--node node-a"), "{forbidden}");
    }

    #[test]
    fn a_state_that_cannot_be_observed_keeps_the_prohibitions_of_an_unresolved_operation() {
        // (e) an operation is recorded and one describe fails: the verdict is `unknown`
        let w = World::new("v3-guidance-unknown-op");
        w.remote
            .inject("witness", op::LEASE_COMMIT, Fault::DropBefore);
        mv(&w, "node-b");
        w.gce.fail_describe("inst-b", true);
        let status = vip_status(&w.ctx());
        assert_eq!(status.verdict, "unknown", "{:?}", status.problems);
        let forbidden = status.guidance.forbidden.join("\n");
        assert!(forbidden.contains("install.sh --ha-mode"), "{forbidden}");
        assert!(forbidden.contains("gcloud"), "{forbidden}");
        assert!(forbidden.contains("by hand"), "{forbidden}");
        assert!(
            forbidden.contains("deleting or editing files"),
            "{forbidden}"
        );
        assert!(forbidden.contains("--abandon-op"), "{forbidden}");
    }

    #[test]
    fn the_status_text_summarises_the_recorded_operation_in_one_line() {
        let w = World::new("v3-op-summary");
        w.remote
            .inject("witness", op::LEASE_COMMIT, Fault::DropBefore);
        mv(&w, "node-b");
        let op_id = w.lease().op.unwrap().op_id;
        let out = crate::manual::run::status_overview_in(&w.ctx()).unwrap();
        let line = out
            .text
            .lines()
            .find(|l| l.starts_with("operation:"))
            .expect("an operation line");
        assert!(line.contains(&op_id), "{line}");
        assert!(line.contains("node-a -> node-b"), "{line}");
        assert!(line.contains("phase "), "{line}");
        assert!(!line.contains('{'), "no raw JSON in the text form: {line}");
        // the JSON keeps the whole record
        assert_eq!(out.json["vip"]["operation"]["op_id"], op_id.as_str());
    }

    #[test]
    fn the_summary_names_the_cloud_changes_that_were_sent_and_never_invents_fields() {
        let rec = serde_json::json!({
            "op_id": "move-1", "source": "node-a", "target": "node-b",
            "phase": "source_released", "controller": "mkg",
            "evidence": {"cloud_changes": [{"action": "detach", "node": "node-a"}]}
        });
        let line = crate::manual::run::operation_summary(&rec);
        assert_eq!(
            line,
            "move-1 node-a -> node-b, phase source_released, controller mkg; \
             cloud change(s) sent: detach on node-a"
        );
        let empty = crate::manual::run::operation_summary(&serde_json::json!({}));
        assert_eq!(empty, "? ? -> ?, phase ?, controller ?");
    }
}

mod abandon_rule {
    //! v0.3 audit LOW-2: the 15-minute silence of `--abandon-op` was only ever tested with
    //! values derived from the constant itself, so a shorter constant passed every test.
    use crate::manual::Failure;
    use crate::manual::fakes::{Fault, World};
    use crate::manual::lease::ABANDON_QUIET_SECS;
    use crate::manual::proto::op;
    use crate::manual::vip::{MoveRequest, move_vip, reconcile_vip};

    #[test]
    fn the_silence_that_an_abandon_needs_is_fifteen_minutes() {
        assert_eq!(ABANDON_QUIET_SECS, 900);
    }

    #[test]
    fn an_abandon_is_refused_ten_minutes_after_the_last_record_and_accepted_after_fifteen() {
        let w = World::new("v3-abandon-window");
        w.remote
            .inject("witness", op::LEASE_COMMIT, Fault::DropBefore);
        let _ = move_vip(
            &w.ctx(),
            &MoveRequest {
                target: "node-b".to_string(),
                confirm_fenced: None,
            },
        );
        let op_id = w.lease().op.unwrap().op_id;
        w.clock.advance_secs(600);
        let early = reconcile_vip(&w.ctx(), Some(&op_id), false);
        assert!(
            matches!(&early, Err(Failure::Refused(m)) if m.contains("may still be running")),
            "{early:?}"
        );
        assert!(w.lease().op.is_some(), "nothing was adopted");
        w.clock.advance_secs(310);
        let report = reconcile_vip(&w.ctx(), Some(&op_id), false).unwrap();
        assert_eq!(report.owner, "node-b");
    }
}
