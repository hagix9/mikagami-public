//! Tests of the final R7 round: R-3 (a displaced version always gets a
//! protected name, or the text says that it has none), R-4 (the order of the
//! steps, with a simulated death of the agent at each point), R-10 (a third
//! version written inside the window), and what an operator and the next
//! apply see of a kept version.

mod kept_versions {
    use crate::manual::chrony_agent::{CRASH_AT, MID_SWAP};
    use crate::manual::chrony_ctl;
    use crate::manual::fakes::{Fault, World};
    use crate::manual::fsutil;
    use crate::manual::proto::{Response, code, op};
    use crate::manual::r6_tests::chrony_displaced::{
        FailLinks, Hooks, NEW, OLD, THIRD, conf_dir, kept_copies, live, named,
    };
    use crate::manual::{Failure, agent, testkit};
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;
    use std::rc::Rc;

    const FOURTH: &str = "server second-admin-edit.example.invalid\n";

    fn sha(text: &str) -> String {
        fsutil::sha256_hex(text.as_bytes())
    }

    fn stage(w: &World) -> (String, PathBuf) {
        let host = w.remote.host("node-a");
        let r = agent::handle(
            &host.env,
            &testkit::req(
                op::CHRONY_STAGE,
                serde_json::json!({"content": NEW, "sha256": sha(NEW)}),
            ),
        );
        let id = r.data["stage_id"].as_str().unwrap().to_string();
        let staged = conf_dir(w).join(format!(".mkg-stage-{id}.conf"));
        (id, staged)
    }

    fn publish(w: &World, id: &str) -> Response {
        let host = w.remote.host("node-a");
        agent::handle(
            &host.env,
            &testkit::req(
                op::CHRONY_PUBLISH,
                serde_json::json!({
                    "stage_id": id,
                    "expect_current": sha(OLD),
                    "expect_new": sha(NEW),
                }),
            ),
        )
    }

    fn cleanup(w: &World, id: &str) -> Response {
        let host = w.remote.host("node-a");
        agent::handle(
            &host.env,
            &testkit::req(op::CHRONY_CLEANUP, serde_json::json!({"stage_id": id})),
        )
    }

    /// Age every temporary and run the sweep (it runs inside `backup`).
    fn sweep_everything(w: &World) {
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(7200);
        for path in named(w, ".mkg-") {
            if let Ok(file) = fs::OpenOptions::new().append(true).open(&path) {
                let _ = file.set_modified(old);
            }
        }
        let host = w.remote.host("node-a");
        let backup = agent::handle(
            &host.env,
            &testkit::req(
                op::CHRONY_BACKUP,
                serde_json::json!({"expect_sha256": sha(&live(w))}),
            ),
        );
        assert!(backup.ok, "{backup:?}");
    }

    fn message(r: &Response) -> String {
        r.error.as_ref().unwrap().message.clone()
    }

    fn assert_displaced_kept(r: &Response, what: &str) {
        assert!(!r.ok, "{what}: {r:?}");
        assert_eq!(
            r.error.as_ref().unwrap().code,
            code::DISPLACED_KEPT,
            "{what}: {r:?}"
        );
    }

    /// The other party's edit is kept under exactly one protected name that
    /// neither the clean-up of the stage id nor the sweep removes.
    fn assert_survives_cleanup_and_sweep(w: &World, id: &str, keep: &PathBuf, what: &str) {
        assert_eq!(fs::read_to_string(keep).unwrap(), THIRD, "{what}");
        let cleaned = cleanup(w, id);
        assert!(cleaned.ok, "{what}: {cleaned:?}");
        sweep_everything(w);
        assert_eq!(
            fs::read_to_string(keep).unwrap(),
            THIRD,
            "{what}: the kept version survived clean-up and sweep"
        );
    }

    // ------------------------------------------------------------ R-3

    #[test]
    fn r3_a_taken_second_name_moves_on_to_the_next_free_one() {
        for occupant in ["file", "directory", "dangling link"] {
            let w = World::new("r7-name-taken");
            let (id, _staged) = {
                let (id, staged) = stage(&w);
                (id, staged)
            };
            let dir = conf_dir(&w);
            let taken = dir.join(format!(".mkg-displaced-mkg-stage-{id}.conf"));
            match occupant {
                "file" => fs::write(&taken, "an earlier kept version\n").unwrap(),
                "directory" => fs::create_dir(&taken).unwrap(),
                _ => std::os::unix::fs::symlink("/nonexistent-target", &taken).unwrap(),
            }
            let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
            let _hooks = Hooks::arm(conf, 1, 2);
            let r = publish(&w, &id);
            assert_displaced_kept(&r, occupant);
            let next = dir.join(format!(".mkg-displaced-mkg-stage-{id}.conf-1"));
            assert!(
                message(&r).contains(&next.display().to_string()),
                "{occupant}: {}",
                message(&r)
            );
            assert!(message(&r).contains("nothing deletes it"), "{occupant}");
            assert_survives_cleanup_and_sweep(&w, &id, &next, occupant);
            // Whatever held the first name is exactly as it was.
            match occupant {
                "file" => assert_eq!(
                    fs::read_to_string(&taken).unwrap(),
                    "an earlier kept version\n"
                ),
                "directory" => assert!(taken.is_dir()),
                _ => assert!(fs::symlink_metadata(&taken).unwrap().is_symlink()),
            }
        }
    }

    #[test]
    fn r3_when_links_are_refused_the_file_is_moved_without_replacing_anything() {
        let w = World::new("r7-moved");
        let (id, staged) = stage(&w);
        let dir = conf_dir(&w);
        let taken = dir.join(format!(".mkg-displaced-mkg-stage-{id}.conf"));
        fs::write(&taken, "an earlier kept version\n").unwrap();
        let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        let _hooks = Hooks::arm(conf, 1, 2);
        fsutil::LINK_FAIL.with(|c| c.set(Some(1)));
        let r = publish(&w, &id);
        fsutil::LINK_FAIL.with(|c| c.set(None));
        assert_displaced_kept(&r, "links refused");
        let next = dir.join(format!(".mkg-displaced-mkg-stage-{id}.conf-1"));
        assert!(message(&r).contains(&next.display().to_string()));
        assert!(message(&r).contains("MOVED"), "{}", message(&r));
        assert!(!staged.exists(), "the staged name was moved, not copied");
        assert_survives_cleanup_and_sweep(&w, &id, &next, "links refused");
        assert_eq!(
            fs::read_to_string(&taken).unwrap(),
            "an earlier kept version\n",
            "the earlier file was not replaced"
        );
    }

    #[test]
    fn r3_a_kernel_without_a_no_replace_rename_still_keeps_the_file() {
        let w = World::new("r7-plain-rename");
        let (id, staged) = stage(&w);
        let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        let _hooks = Hooks::arm(conf, 1, 2);
        fsutil::LINK_FAIL.with(|c| c.set(Some(1)));
        fsutil::NOREPLACE_FAIL.with(|c| c.set(Some(None)));
        let r = publish(&w, &id);
        fsutil::LINK_FAIL.with(|c| c.set(None));
        fsutil::NOREPLACE_FAIL.with(|c| c.set(None));
        assert_displaced_kept(&r, "no no-replace rename");
        let keep = conf_dir(&w).join(format!(".mkg-displaced-mkg-stage-{id}.conf"));
        assert!(!staged.exists());
        assert_survives_cleanup_and_sweep(&w, &id, &keep, "plain rename");
    }

    #[test]
    fn r3_only_when_every_way_fails_the_file_stays_unprotected_and_the_text_says_so() {
        let w = World::new("r7-unprotected");
        let (id, staged) = stage(&w);
        let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        let _hooks = Hooks::arm(conf, 1, 2);
        let _refused = FailLinks::arm();
        fsutil::NOREPLACE_FAIL.with(|c| c.set(Some(None)));
        fsutil::PLAIN_RENAME_FAIL.with(|c| c.set(Some(5)));
        let r = publish(&w, &id);
        assert_displaced_kept(&r, "every way fails");
        let text = message(&r);
        assert!(text.contains("NO protected name"), "{text}");
        assert!(text.contains("copy it away NOW"), "{text}");
        assert!(!text.contains("deletes it at once"), "{text}");
        assert!(text.contains(&staged.display().to_string()), "{text}");
        assert_eq!(fs::read_to_string(&staged).unwrap(), THIRD);
        // What the text says is true: the clean-up and the sweep leave a file
        // whose content is not the staged content (audit H-2); nothing else
        // protects it.
        assert!(cleanup(&w, &id).ok);
        assert_eq!(fs::read_to_string(&staged).unwrap(), THIRD);
        sweep_everything(&w);
        assert_eq!(fs::read_to_string(&staged).unwrap(), THIRD);
    }

    #[test]
    fn r3_all_sixteen_names_taken_is_the_unprotected_case_and_nothing_is_replaced() {
        let w = World::new("r7-all-taken");
        let (id, staged) = stage(&w);
        let dir = conf_dir(&w);
        for n in 0..16u32 {
            let name = if n == 0 {
                format!(".mkg-displaced-mkg-stage-{id}.conf")
            } else {
                format!(".mkg-displaced-mkg-stage-{id}.conf-{n}")
            };
            fs::write(dir.join(name), format!("earlier {n}\n")).unwrap();
        }
        let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        let _hooks = Hooks::arm(conf, 1, 2);
        let r = publish(&w, &id);
        assert_displaced_kept(&r, "all names taken");
        assert!(message(&r).contains("NO protected name"));
        assert_eq!(fs::read_to_string(&staged).unwrap(), THIRD);
        for n in 0..16u32 {
            let name = if n == 0 {
                format!(".mkg-displaced-mkg-stage-{id}.conf")
            } else {
                format!(".mkg-displaced-mkg-stage-{id}.conf-{n}")
            };
            assert_eq!(
                fs::read_to_string(dir.join(name)).unwrap(),
                format!("earlier {n}\n"),
                "name {n} was replaced"
            );
        }
    }

    #[test]
    fn r3_a_publish_without_a_foreign_edit_works_when_links_are_refused() {
        // The second name is made BEFORE the displaced file is judged; when it
        // cannot be made, the ordinary case (nothing foreign) still succeeds.
        let w = World::new("r7-no-links-ordinary");
        let (id, _staged) = stage(&w);
        fsutil::LINK_FAIL.with(|c| c.set(Some(1)));
        let r = publish(&w, &id);
        fsutil::LINK_FAIL.with(|c| c.set(None));
        assert!(r.ok, "{r:?}");
        assert_eq!(live(&w), NEW);
        assert!(named(&w, ".mkg-displaced-").is_empty());
    }

    #[test]
    fn r3_an_ordinary_publish_leaves_no_second_name_behind() {
        let w = World::new("r7-ordinary");
        let (id, staged) = stage(&w);
        let r = publish(&w, &id);
        assert!(r.ok, "{r:?}");
        assert_eq!(live(&w), NEW);
        assert!(named(&w, ".mkg-displaced-").is_empty());
        assert!(!staged.exists());
    }

    // ------------------------------------------------------------ R-4

    #[test]
    fn r4_the_agent_dying_at_any_point_does_not_lose_the_other_version() {
        for point in 1u8..=3 {
            let w = World::new("r7-crash");
            let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
            let (id, staged) = stage(&w);
            let _hooks = Hooks::arm(conf, 1, 99);
            CRASH_AT.with(|c| c.set(point));
            let died = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| publish(&w, &id)));
            CRASH_AT.with(|c| c.set(0));
            assert!(died.is_err(), "point {point}: the agent was meant to die");
            let displaced = named(&w, ".mkg-displaced-");
            match point {
                1 => {
                    // Between the exchange and the second name: their version
                    // is only under the staged name. The agent's clean-up and
                    // sweep no longer delete such a name: they see that the
                    // content is not what the name promises and keep it.
                    assert_eq!(fs::read_to_string(&staged).unwrap(), THIRD);
                    assert!(displaced.is_empty());
                    let cleaned = cleanup(&w, &id);
                    assert!(cleaned.ok, "{cleaned:?}");
                    sweep_everything(&w);
                    assert_eq!(
                        kept_copies(&w).len(),
                        1,
                        "point 1: their version survived clean-up and sweep under a protected name"
                    );
                    assert!(!staged.exists(), "it does not stay under the staged name");
                }
                2 => {
                    // The second name exists before anything else is decided.
                    assert_eq!(live(&w), NEW, "the candidate is live");
                    assert_eq!(kept_copies(&w).len(), 1, "their version has its name");
                    assert_survives_cleanup_and_sweep(&w, &id, &kept_copies(&w)[0], "point 2");
                }
                _ => {
                    // After the put-back: their version is live again and the
                    // second name is a stale name of that same file.
                    assert_eq!(live(&w), THIRD);
                    assert_eq!(kept_copies(&w).len(), 1);
                    assert_survives_cleanup_and_sweep(&w, &id, &kept_copies(&w)[0], "point 3");
                }
            }
        }
    }

    #[test]
    fn r4_a_death_after_the_first_exchange_with_the_first_name_taken_still_leaves_a_second_name() {
        // The second name is a hard link made BEFORE the file is read; with the
        // first free name taken it must be the next one (a link that gave up
        // would leave the file to the move ladder, and a death at this point
        // would then leave it under the staged name only).
        let w = World::new("r7-crash-taken");
        let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        let (id, staged) = stage(&w);
        let dir = conf_dir(&w);
        fs::write(
            dir.join(format!(".mkg-displaced-mkg-stage-{id}.conf")),
            "an earlier kept version\n",
        )
        .unwrap();
        let _hooks = Hooks::arm(conf, 1, 99);
        CRASH_AT.with(|c| c.set(2));
        let died = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| publish(&w, &id)));
        CRASH_AT.with(|c| c.set(0));
        assert!(died.is_err());
        let next = dir.join(format!(".mkg-displaced-mkg-stage-{id}.conf-1"));
        assert_eq!(
            fs::read_to_string(&next).unwrap(),
            THIRD,
            "a link under the next free name"
        );
        assert_eq!(
            fs::read_to_string(&staged).unwrap(),
            THIRD,
            "still linked to the staged name"
        );
        assert_eq!(
            fs::metadata(&next).unwrap().nlink(),
            2,
            "it is a hard link (one inode, two names), not a move"
        );
    }

    // ------------------------------------------------------------ R-10

    #[test]
    fn r10_a_third_version_written_inside_the_window_is_kept_not_deleted() {
        let w = World::new("r7-fourth");
        let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        let (id, _staged) = stage(&w);
        let _hooks = Hooks::arm(conf.clone(), 1, 99);
        let mid_conf = conf.clone();
        MID_SWAP.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                // After the first exchange the live path holds the candidate;
                // a third party overwrites it before it is put back.
                fs::write(&mid_conf, FOURTH).unwrap();
            }));
        });
        let r = publish(&w, &id);
        MID_SWAP.with(|h| *h.borrow_mut() = None);
        assert_displaced_kept(&r, "third version");
        assert!(message(&r).contains("newest"), "{}", message(&r));
        // The first foreign version is live again; the newest is kept.
        assert_eq!(live(&w), THIRD);
        let kept: Vec<PathBuf> = named(&w, ".mkg-displaced-")
            .into_iter()
            .filter(|p| fs::read_to_string(p).is_ok_and(|t| t == FOURTH))
            .collect();
        assert_eq!(kept.len(), 1, "the newest version has one protected name");
        assert_eq!(
            named(&w, ".mkg-displaced-").len(),
            1,
            "no stale name of the first version is left"
        );
        let keep = kept[0].clone();
        let cleaned = cleanup(&w, &id);
        assert!(cleaned.ok);
        sweep_everything(&w);
        assert_eq!(fs::read_to_string(&keep).unwrap(), FOURTH);
    }

    #[test]
    fn r10_the_ordinary_put_back_is_still_a_refusal_with_nothing_kept() {
        let w = World::new("r7-put-back");
        let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        let (id, _staged) = stage(&w);
        let _hooks = Hooks::arm(conf, 1, 99);
        let r = publish(&w, &id);
        assert!(!r.ok);
        assert_eq!(r.error.as_ref().unwrap().code, code::REFUSED, "{r:?}");
        assert_eq!(live(&w), THIRD);
        assert!(named(&w, ".mkg-displaced-").is_empty());
    }

    // ------------------------------------------------- operator view, apply

    #[test]
    fn r3_a_kept_version_is_listed_by_state_and_show_and_stops_the_next_apply() {
        let w = World::new("r7-visible");
        let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        {
            let _hooks = Hooks::arm(conf, 1, 2);
            let r = chrony_ctl::apply(&w.ctx(), "node-a", NEW, false);
            assert!(matches!(r, Err(Failure::Unknown(_))), "{r:?}");
        }
        let kept = kept_copies(&w);
        assert_eq!(kept.len(), 1);
        let host = w.remote.host("node-a");
        let state = agent::handle(
            &host.env,
            &testkit::req(op::CHRONY_STATE, serde_json::json!({})),
        );
        assert_eq!(state.data["displaced"]["count"], 1);
        let listed = state.data["displaced"]["names"][0]
            .as_str()
            .unwrap()
            .to_string();
        assert!(listed.starts_with(".mkg-displaced-"), "{listed}");
        // `show` carries it as a problem.
        let shown = chrony_ctl::show(&w.ctx(), "node-a").unwrap();
        assert!(
            shown.problems.iter().any(|p| p.contains("kept version")),
            "{:?}",
            shown.problems
        );
        // The next apply is refused before anything is sent that changes the node.
        let stages_before = w.count_agent_calls("node-a", op::CHRONY_STAGE);
        let r = chrony_ctl::apply(
            &w.ctx(),
            "node-a",
            "pool other.example.invalid iburst\n",
            false,
        );
        let Err(Failure::Refused(text)) = &r else {
            panic!("expected a refusal, got {r:?}");
        };
        assert!(
            text.contains("kept version") && text.contains("nothing is changed"),
            "{text}"
        );
        assert_eq!(
            w.count_agent_calls("node-a", op::CHRONY_STAGE),
            stages_before
        );
        // A dry run is read-only and is not stopped by it.
        let dry = chrony_ctl::apply(
            &w.ctx(),
            "node-a",
            "pool other.example.invalid iburst\n",
            true,
        );
        assert!(
            !matches!(&dry, Err(Failure::Refused(t)) if t.contains("kept version")),
            "{dry:?}"
        );
        // The operator decides and deletes the file; the next apply goes on.
        fs::remove_file(&kept[0]).unwrap();
        for stale in named(&w, ".mkg-displaced-") {
            fs::remove_file(stale).unwrap();
        }
        let r = chrony_ctl::apply(
            &w.ctx(),
            "node-a",
            "pool other.example.invalid iburst\n",
            false,
        );
        assert!(
            !matches!(&r, Err(Failure::Refused(t)) if t.contains("kept version")),
            "{r:?}"
        );
    }

    #[test]
    fn l4_a_listing_that_cannot_be_trusted_stops_the_next_apply() {
        // The field is there but says "not readable", or the count is not a
        // number: nobody can say that no kept version exists (audit L-4).
        for (what, rewritten) in [
            (
                "unreadable",
                serde_json::json!({"count": 0, "names": [], "readable": false}),
            ),
            (
                "count not a number",
                serde_json::json!({"count": "none", "names": []}),
            ),
        ] {
            let w = World::new("r7-l4");
            let stages_before = w.count_agent_calls("node-a", op::CHRONY_STAGE);
            let data = rewritten.clone();
            w.remote.inject_when(
                "node-a",
                op::CHRONY_STATE,
                None,
                0,
                100,
                Fault::Rewrite(Rc::new(move |d| d["displaced"] = data.clone())),
            );
            let r = chrony_ctl::apply(&w.ctx(), "node-a", "pool x.example.invalid iburst\n", false);
            let Err(Failure::Refused(text)) = &r else {
                panic!("{what}: expected a refusal, got {r:?}");
            };
            assert!(text.contains("cannot say"), "{what}: {text}");
            assert_eq!(
                w.count_agent_calls("node-a", op::CHRONY_STAGE),
                stages_before,
                "{what}: nothing was staged"
            );
            let shown = chrony_ctl::show(&w.ctx(), "node-a").unwrap();
            assert!(
                shown.problems.iter().any(|p| p.contains("cannot say")),
                "{what}: {:?}",
                shown.problems
            );
        }
    }

    #[test]
    fn a2_an_agent_without_the_field_is_too_old_and_the_next_apply_refuses() {
        // An agent older than this controller neither protects a displaced
        // version nor reports one: nothing can be said, so the apply refuses
        // (audit A2 LOW-2; both sides are upgraded together).
        let w = World::new("r7-old-agent");
        w.remote.inject_when(
            "node-a",
            op::CHRONY_STATE,
            None,
            0,
            100,
            Fault::Rewrite(Rc::new(|d| {
                d.as_object_mut().unwrap().remove("displaced");
            })),
        );
        let stages_before = w.count_agent_calls("node-a", op::CHRONY_STAGE);
        let r = chrony_ctl::apply(&w.ctx(), "node-a", "pool x.example.invalid iburst\n", false);
        let Err(Failure::Refused(text)) = &r else {
            panic!("expected a refusal, got {r:?}");
        };
        assert!(text.contains("cannot say"), "{text}");
        assert_eq!(
            w.count_agent_calls("node-a", op::CHRONY_STAGE),
            stages_before
        );
        let shown = chrony_ctl::show(&w.ctx(), "node-a").unwrap();
        assert!(
            shown
                .problems
                .iter()
                .any(|p| p.contains("older than this controller"))
        );
    }
}

/// The primitives under the kept-version design, on whatever file system the
/// test runs on. On Linux they are the real `renameat2` calls; elsewhere the
/// emulations of `fsutil`. The Linux run of these tests is part of the R7 real-host evidence.
mod kernel_primitives {
    use crate::manual::fsutil;
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    fn dir(label: &str) -> std::path::PathBuf {
        crate::manual::fsutil::tests::temp_dir(label)
    }

    #[test]
    fn rename_noreplace_moves_only_onto_an_absent_name() {
        let d = dir("r7-noreplace");
        let (from, to) = (d.join("from"), d.join("to"));
        fs::write(&from, "one").unwrap();
        // Absent target: moved, same inode, old name gone.
        let ino = fs::metadata(&from).unwrap().ino();
        fsutil::rename_noreplace(&from, &to).unwrap();
        assert!(!from.exists());
        assert_eq!(fs::metadata(&to).unwrap().ino(), ino);
        // Taken by a file, a directory, a link: AlreadyExists, nothing moved.
        for (name, kind) in [("f", "file"), ("d", "directory"), ("l", "link")] {
            let src = d.join(format!("src-{name}"));
            fs::write(&src, "two").unwrap();
            let taken = d.join(format!("taken-{name}"));
            match kind {
                "file" => fs::write(&taken, "keep").unwrap(),
                "directory" => fs::create_dir(&taken).unwrap(),
                _ => std::os::unix::fs::symlink("/nonexistent", &taken).unwrap(),
            }
            let e = fsutil::rename_noreplace(&src, &taken).unwrap_err();
            assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists, "{kind}: {e}");
            assert_eq!(
                fs::read_to_string(&src).unwrap(),
                "two",
                "{kind}: not moved"
            );
        }
        assert_eq!(fs::read_to_string(d.join("taken-f")).unwrap(), "keep");
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn link_new_never_replaces_and_shares_the_inode() {
        let d = dir("r7-link");
        let (a, b) = (d.join("a"), d.join("b"));
        fs::write(&a, "x").unwrap();
        fsutil::link_new(&a, &b).unwrap();
        assert_eq!(
            fs::metadata(&a).unwrap().ino(),
            fs::metadata(&b).unwrap().ino()
        );
        assert_eq!(fs::metadata(&a).unwrap().nlink(), 2);
        let e = fsutil::link_new(&a, &b).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn exchange_swaps_two_files_atomically_and_keeps_each_inode() {
        let d = dir("r7-exchange");
        let (a, b) = (d.join("a"), d.join("b"));
        fs::write(&a, "A").unwrap();
        fs::write(&b, "B").unwrap();
        let (ia, ib) = (
            fs::metadata(&a).unwrap().ino(),
            fs::metadata(&b).unwrap().ino(),
        );
        fsutil::exchange(&a, &b).unwrap();
        assert_eq!(fs::read_to_string(&a).unwrap(), "B");
        assert_eq!(fs::read_to_string(&b).unwrap(), "A");
        assert_eq!(fs::metadata(&a).unwrap().ino(), ib);
        assert_eq!(fs::metadata(&b).unwrap().ino(), ia);
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn rename_to_absent_name_refuses_a_taken_name() {
        let d = dir("r7-absent");
        let (a, b) = (d.join("a"), d.join("b"));
        fs::write(&a, "A").unwrap();
        fs::write(&b, "B").unwrap();
        let e = fsutil::rename_to_absent_name(&a, &b).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read_to_string(&b).unwrap(), "B");
        fs::remove_file(&b).unwrap();
        fsutil::rename_to_absent_name(&a, &b).unwrap();
        assert_eq!(fs::read_to_string(&b).unwrap(), "A");
        fs::remove_dir_all(d).unwrap();
    }
}

/// What the controller does after a displacement when it does not get a clean
/// answer: the answer is lost, or the agent dies at a point of `swap_in`
/// (independent audit phase A, H-1 and H-2). Nothing may be reported as a
/// success, chronyd is not restarted, and the other party's text survives.
mod controller_after_loss {
    use crate::manual::Failure;
    use crate::manual::chrony_agent::{CRASH_AT, MID_SWAP};
    use crate::manual::chrony_ctl;
    use crate::manual::fakes::{AgentMayDie, Fault, World};
    use crate::manual::proto::op;
    use crate::manual::r6_tests::chrony_displaced::{
        FailLinks, Hooks, NEW, OLD, THIRD, kept_copies, live, named,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::rc::Rc;

    const FOURTH: &str = "server second-admin-edit.example.invalid\n";

    fn restarts(w: &World) -> usize {
        w.count_agent_calls("node-a", op::SERVICE_CONTROL)
    }

    fn any_copy_with(w: &World, text: &str) -> Vec<PathBuf> {
        named(w, ".mkg-")
            .into_iter()
            .filter(|p| fs::read_to_string(p).is_ok_and(|t| t == text))
            .collect()
    }

    fn assert_unknown_and_untouched(
        r: &Result<crate::manual::chrony_ctl::ApplyReport, Failure>,
        w: &World,
        what: &str,
    ) {
        let Err(Failure::Unknown(message)) = r else {
            panic!("{what}: expected UNKNOWN, got {r:?}");
        };
        assert!(
            message.contains("kept") || message.contains("version"),
            "{what}: {message}"
        );
        assert_eq!(restarts(w), 0, "{what}: chronyd was not restarted");
        assert_eq!(
            w.count_agent_calls("node-a", op::CHRONY_RESTORE),
            0,
            "{what}: nothing was restored"
        );
    }

    #[test]
    fn h1_a_lost_publish_answer_after_a_displacement_is_unknown_not_success() {
        let w = World::new("r7-h1-lost-answer");
        let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        let _hooks = Hooks::arm(conf, 1, 2);
        w.remote
            .inject_when("node-a", op::CHRONY_PUBLISH, None, 0, 1, Fault::DropAfter);
        let r = chrony_ctl::apply(&w.ctx(), "node-a", NEW, false);
        assert_unknown_and_untouched(&r, &w, "lost answer");
        assert_eq!(kept_copies(&w).len(), 1, "their version is kept");
        assert_eq!(live(&w), NEW);
    }

    #[test]
    fn h1_an_agent_death_after_the_second_name_is_unknown_not_success() {
        let w = World::new("r7-h1-death-2");
        let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        let _hooks = Hooks::arm(conf, 1, 99);
        let _die = AgentMayDie::arm();
        CRASH_AT.with(|c| c.set(2));
        let r = chrony_ctl::apply(&w.ctx(), "node-a", NEW, false);
        CRASH_AT.with(|c| c.set(0));
        assert_unknown_and_untouched(&r, &w, "death at point 2");
        assert_eq!(kept_copies(&w).len(), 1, "their version has its name");
        // The data has two names at this point (the staged one and the
        // protected one); the state counts the file once.
        let host = w.remote.host("node-a");
        let state = crate::manual::agent::handle(
            &host.env,
            &crate::manual::testkit::req(op::CHRONY_STATE, serde_json::json!({})),
        );
        assert_eq!(
            state.data["displaced"]["count"], 1,
            "{:?}",
            state.data["displaced"]
        );
    }

    #[test]
    fn h2_an_agent_death_before_the_second_name_does_not_lose_their_version_to_the_fence() {
        // The agent dies right after the first exchange: their version is only
        // under the staged name. The controller's fence (clean-up of the stage
        // id) used to delete it. Now the agent sees that the content is not the
        // staged content and keeps it.
        let w = World::new("r7-h2-death-1");
        let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        let _hooks = Hooks::arm(conf, 1, 99);
        let _die = AgentMayDie::arm();
        CRASH_AT.with(|c| c.set(1));
        let r = chrony_ctl::apply(&w.ctx(), "node-a", NEW, false);
        CRASH_AT.with(|c| c.set(0));
        assert_unknown_and_untouched(&r, &w, "death at point 1");
        assert_eq!(
            any_copy_with(&w, THIRD).len(),
            1,
            "their version survived the fence: {:?}",
            named(&w, ".mkg-")
        );
        assert!(
            !named(&w, ".mkg-stage-")
                .iter()
                .any(|p| fs::read_to_string(p).is_ok_and(|t| t == THIRD)),
            "it is not left under the staged name"
        );
        assert_eq!(kept_copies(&w).len(), 1, "it has a protected name");
    }

    #[test]
    fn h2_a_third_version_and_an_agent_death_after_the_put_back_do_not_lose_the_third_version() {
        let w = World::new("r7-h2-death-3");
        let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        let _hooks = Hooks::arm(conf.clone(), 1, 99);
        let mid = conf.clone();
        MID_SWAP.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                fs::write(&mid, FOURTH).unwrap();
            }));
        });
        let _die = AgentMayDie::arm();
        CRASH_AT.with(|c| c.set(3));
        let r = chrony_ctl::apply(&w.ctx(), "node-a", NEW, false);
        CRASH_AT.with(|c| c.set(0));
        MID_SWAP.with(|h| *h.borrow_mut() = None);
        assert_unknown_and_untouched(&r, &w, "death at point 3");
        assert_eq!(
            any_copy_with(&w, FOURTH).len(),
            1,
            "the third version survived"
        );
        assert_eq!(live(&w), THIRD, "the first foreign version is live again");
    }

    #[test]
    fn h1_a_lost_restore_answer_after_a_displacement_is_unknown_not_a_verified_rollback() {
        // The first verification fails (the tracking cannot be read), so the
        // apply rolls back. Inside the restore's window somebody edits the
        // file, the put-back fails, and the restore's answer is lost. The live
        // hash is the old one: by the hash alone the rollback looks done, and
        // the restart that follows would "verify" it (the tracking works again
        // by then). The kept version must make it UNKNOWN before any restart
        // (audit H-1, restore variant).
        let w = World::new("r7-h1-restore-lost");
        let sys = w.remote.host("node-a").sys.clone();
        sys.fail_tracking(true);
        let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        let _hooks = Hooks::arm(conf, 2, 3);
        w.remote
            .inject_when("node-a", op::CHRONY_RESTORE, None, 0, 1, Fault::DropAfter);
        let healed = sys.clone();
        w.remote.inject_when(
            "node-a",
            op::SERVICE_CONTROL,
            Some("\"action\":\"restart\""),
            1,
            1,
            Fault::Hook(Rc::new(move || healed.fail_tracking(false))),
        );
        let r = chrony_ctl::apply(&w.ctx(), "node-a", NEW, false);
        let Err(Failure::Unknown(message)) = &r else {
            panic!("expected UNKNOWN, got {r:?}");
        };
        assert!(message.contains("kept version"), "{message}");
        assert!(
            message.contains("may be running the CANDIDATE"),
            "{message}"
        );
        assert!(!message.contains("NOT restarted"), "{message}");
        assert!(!message.contains("verified"), "{message}");
        assert_eq!(restarts(&w), 1, "only the first restart happened");
        assert_eq!(kept_copies(&w).len(), 1);
        assert_eq!(live(&w), OLD);
    }

    #[test]
    fn h1_a_lost_publish_answer_when_the_file_was_moved_is_unknown_not_success() {
        // Links are refused, so their version was MOVED to its protected name:
        // the staged name is gone, the fence finds nothing to look at, and only
        // the list of kept versions says that something happened (audit H-1).
        let w = World::new("r7-h1-moved");
        let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        let _hooks = Hooks::arm(conf, 1, 2);
        crate::manual::fsutil::LINK_FAIL.with(|c| c.set(Some(1)));
        w.remote
            .inject_when("node-a", op::CHRONY_PUBLISH, None, 0, 1, Fault::DropAfter);
        let r = chrony_ctl::apply(&w.ctx(), "node-a", NEW, false);
        crate::manual::fsutil::LINK_FAIL.with(|c| c.set(None));
        assert_unknown_and_untouched(&r, &w, "moved, answer lost");
        assert_eq!(kept_copies(&w).len(), 1);
        assert_eq!(live(&w), NEW);
        assert!(
            named(&w, ".mkg-stage-").is_empty(),
            "the staged name is gone"
        );
    }

    #[test]
    fn h1_a_failed_publish_while_a_kept_version_appears_is_unknown() {
        // Defence in depth: a publish that answers FAILED (the first exchange
        // failed) normally leaves the node unchanged. If a kept version exists
        // after it, the controller does not call that "nothing changed".
        let w = World::new("r7-h1-failed");
        let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        let _hooks = Hooks::arm(conf, 99, 1);
        let dir = crate::manual::r6_tests::chrony_displaced::conf_dir(&w);
        w.remote.inject_when(
            "node-a",
            op::CHRONY_PUBLISH,
            None,
            0,
            1,
            Fault::Hook(Rc::new(move || {
                fs::write(dir.join(".mkg-displaced-planted.conf"), "x\n").unwrap();
            })),
        );
        let r = chrony_ctl::apply(&w.ctx(), "node-a", NEW, false);
        let Err(Failure::Unknown(message)) = &r else {
            panic!("expected UNKNOWN, got {r:?}");
        };
        assert!(message.contains("kept version"), "{message}");
        assert_eq!(restarts(&w), 0);
    }

    #[test]
    fn a8_a_restore_that_cannot_protect_their_version_does_not_delete_it() {
        // The unprotected last resort in a restore: neither a link nor a move
        // works, so the version stays under the restore name - and the restore
        // path must not remove that name (audit A8).
        let w = World::new("r7-a8");
        w.remote
            .host("node-a")
            .sys
            .restart_does_nothing("chrony.service");
        let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        let _hooks = Hooks::arm(conf, 2, 3);
        let _refused = FailLinks::arm();
        let r = chrony_ctl::apply(&w.ctx(), "node-a", NEW, false);
        assert!(matches!(r, Err(Failure::Unknown(_))), "{r:?}");
        let left: Vec<PathBuf> = named(&w, ".mkg-restore-")
            .into_iter()
            .filter(|p| fs::read_to_string(p).is_ok_and(|t| t == THIRD))
            .collect();
        assert_eq!(
            left.len(),
            1,
            "their version is still under the restore name"
        );
    }

    #[test]
    fn h2_the_sweep_keeps_a_stale_file_whose_content_is_not_what_its_name_promises() {
        use crate::manual::agent;
        use crate::manual::fsutil;
        use crate::manual::testkit;
        let w = World::new("r7-h2-sweep");
        let host = w.remote.host("node-a");
        let dir = host_conf_dir(&w);
        // A leftover of ours (content as promised) and a foreign one under a
        // name of the same kind; both are old.
        let ours = "pool ours.example.invalid iburst\n";
        let ours16 = &fsutil::sha256_hex(ours.as_bytes())[..16];
        let ours_path = dir.join(format!(".mkg-stage-aaaaaaaaaaaaaaaa{ours16}.conf"));
        fs::write(&ours_path, ours).unwrap();
        let theirs_path = dir.join(format!(".mkg-stage-bbbbbbbbbbbbbbbb{ours16}.conf"));
        fs::write(&theirs_path, THIRD).unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(7200);
        for p in [&ours_path, &theirs_path] {
            let f = fs::OpenOptions::new().append(true).open(p).unwrap();
            f.set_modified(old).unwrap();
        }
        let backup = agent::handle(
            &host.env,
            &testkit::req(
                op::CHRONY_BACKUP,
                serde_json::json!({"expect_sha256": fsutil::sha256_hex(OLD.as_bytes())}),
            ),
        );
        assert!(backup.ok, "{backup:?}");
        assert!(!ours_path.exists(), "our own stale leftover was swept");
        assert!(
            !theirs_path.exists(),
            "their file no longer sits under a swept name"
        );
        assert_eq!(
            any_copy_with(&w, THIRD).len(),
            1,
            "their file was kept under a protected name"
        );
        assert_eq!(kept_copies(&w).len(), 1);
    }

    /// Resets what the restore-death test sets, also on a panic.
    struct HookReset;
    impl Drop for HookReset {
        fn drop(&mut self) {
            crate::manual::chrony_agent::PRE_SWAP.with(|h| *h.borrow_mut() = None);
            CRASH_AT.with(|c| c.set(0));
        }
    }

    #[test]
    fn m1_a_restore_that_dies_inside_the_swap_is_unknown_and_its_leftover_is_listed() {
        // The rollback's restore: the agent dies right after the first exchange
        // while somebody's edit was in the window. Their version is only under
        // the restore name; the live file is the backup. By the hash alone the
        // rollback looks done and verified. The leftover's content is not what
        // its name promises, so the state lists it, and the outcome is UNKNOWN
        // (audit A2 MEDIUM-1).
        let w = World::new("r7-m1-restore-death");
        let sys = w.remote.host("node-a").sys.clone();
        sys.fail_tracking(true);
        let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        let calls = Rc::new(std::cell::Cell::new(0));
        let (seen, target) = (Rc::clone(&calls), conf.clone());
        crate::manual::chrony_agent::PRE_SWAP.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                seen.set(seen.get() + 1);
                if seen.get() == 2 {
                    fs::write(&target, THIRD).unwrap();
                    CRASH_AT.with(|c| c.set(1));
                }
            }));
        });
        let _reset = HookReset;
        let healed = sys.clone();
        w.remote.inject_when(
            "node-a",
            op::SERVICE_CONTROL,
            Some("\"action\":\"restart\""),
            1,
            1,
            Fault::Hook(Rc::new(move || healed.fail_tracking(false))),
        );
        let _die = AgentMayDie::arm();
        let r = chrony_ctl::apply(&w.ctx(), "node-a", NEW, false);
        let Err(Failure::Unknown(message)) = &r else {
            panic!("expected UNKNOWN, got {r:?}");
        };
        assert!(message.contains("kept version"), "{message}");
        assert!(
            message.contains("may be running the CANDIDATE"),
            "{message}"
        );
        assert!(!message.contains("NOT restarted"), "{message}");
        assert!(!message.contains("verified"), "{message}");
        assert_eq!(restarts(&w), 1, "only the first restart happened");
        let left: Vec<PathBuf> = named(&w, ".mkg-restore-")
            .into_iter()
            .filter(|p| fs::read_to_string(p).is_ok_and(|t| t == THIRD))
            .collect();
        assert_eq!(left.len(), 1, "their version is still there");
        // The next apply is refused: the leftover is listed.
        drop(_die);
        let again = chrony_ctl::apply(&w.ctx(), "node-a", NEW, false);
        assert!(
            matches!(&again, Err(Failure::Refused(t)) if t.contains("kept version")),
            "{again:?}"
        );
        let shown = chrony_ctl::show(&w.ctx(), "node-a").unwrap();
        assert!(
            shown.problems.iter().any(|p| p.contains("kept version")),
            "{:?}",
            shown.problems
        );
    }

    #[test]
    fn m3_a_lost_answer_when_nothing_could_protect_their_version_keeps_the_whole_warning() {
        // Neither a link nor a move works; the answer is lost. The fence finds
        // their version under the staged name and reports it; the warning is
        // not cut (audit A2 MEDIUM-3 / LOW-4).
        let w = World::new("r7-m3-unprotected-lost");
        let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        let _hooks = Hooks::arm(conf, 1, 2);
        let _refused = FailLinks::arm();
        crate::manual::fsutil::NOREPLACE_FAIL.with(|c| c.set(Some(None)));
        crate::manual::fsutil::PLAIN_RENAME_FAIL.with(|c| c.set(Some(5)));
        w.remote
            .inject_when("node-a", op::CHRONY_PUBLISH, None, 0, 1, Fault::DropAfter);
        let r = chrony_ctl::apply(&w.ctx(), "node-a", NEW, false);
        let Err(Failure::Unknown(message)) = &r else {
            panic!("expected UNKNOWN, got {r:?}");
        };
        assert!(message.contains("copy it away NOW"), "{message}");
        assert_eq!(restarts(&w), 0);
        let staged: Vec<PathBuf> = named(&w, ".mkg-stage-")
            .into_iter()
            .filter(|p| fs::read_to_string(p).is_ok_and(|t| t == THIRD))
            .collect();
        assert_eq!(
            staged.len(),
            1,
            "their version is still under the staged name"
        );
    }

    #[test]
    fn m3_the_sweep_keeps_a_stale_restore_file_whose_content_is_not_what_its_name_promises() {
        use crate::manual::{agent, fsutil, testkit};
        let w = World::new("r7-m3-restore-sweep");
        let host = w.remote.host("node-a");
        let dir = host_conf_dir(&w);
        let ours = "pool ours.example.invalid iburst\n";
        let hash16 = &fsutil::sha256_hex(ours.as_bytes())[..16];
        let theirs = dir.join(format!(".mkg-restore-aaaaaaaaaaaaaaaa{hash16}.conf"));
        let mine = dir.join(format!(".mkg-restore-bbbbbbbbbbbbbbbb{hash16}.conf"));
        fs::write(&theirs, THIRD).unwrap();
        fs::write(&mine, ours).unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(7200);
        for p in [&theirs, &mine] {
            let f = fs::OpenOptions::new().append(true).open(p).unwrap();
            f.set_modified(old).unwrap();
        }
        let backup = agent::handle(
            &host.env,
            &testkit::req(
                op::CHRONY_BACKUP,
                serde_json::json!({"expect_sha256": fsutil::sha256_hex(OLD.as_bytes())}),
            ),
        );
        assert!(backup.ok, "{backup:?}");
        assert!(!mine.exists(), "our own stale restore copy was swept");
        assert!(!theirs.exists(), "theirs no longer sits under a swept name");
        assert_eq!(any_copy_with(&w, THIRD).len(), 1, "theirs was kept");
        assert_eq!(
            backup.data["quarantined"].as_array().map(Vec::len),
            Some(1),
            "the backup answer reports what the sweep kept (audit A2 LOW-1)"
        );
    }

    #[test]
    fn m3_a_leftover_that_the_sweep_keeps_during_an_apply_stops_the_apply_before_staging() {
        let w = World::new("r7-m3-sweep-in-apply");
        let dir = host_conf_dir(&w);
        let ours16 = &crate::manual::fsutil::sha256_hex(b"x")[..16];
        let planted = dir.join(format!(".mkg-restore-cccccccccccccccc{ours16}.conf"));
        let target = planted.clone();
        // After the gate, before the backup: a stale leftover with somebody's text.
        w.remote.inject_when(
            "node-a",
            op::CHRONY_BACKUP,
            None,
            0,
            1,
            Fault::Hook(Rc::new(move || {
                fs::write(&target, THIRD).unwrap();
                let f = fs::OpenOptions::new().append(true).open(&target).unwrap();
                f.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(7200))
                    .unwrap();
            })),
        );
        let r = chrony_ctl::apply(&w.ctx(), "node-a", NEW, false);
        let Err(Failure::Refused(text)) = &r else {
            panic!("expected a refusal, got {r:?}");
        };
        assert!(
            text.contains("sweep") && text.contains("configuration was not changed"),
            "{text}"
        );
        assert_eq!(
            w.count_agent_calls("node-a", op::CHRONY_STAGE),
            0,
            "nothing was staged"
        );
        assert_eq!(live(&w), OLD);
        assert_eq!(any_copy_with(&w, THIRD).len(), 1, "their text was kept");
    }

    #[test]
    fn m3_the_state_lists_leftovers_that_break_their_name_and_not_those_that_keep_it() {
        use crate::manual::{agent, fsutil, testkit};
        let w = World::new("r7-m3-state-list");
        let host = w.remote.host("node-a");
        let dir = host_conf_dir(&w);
        let ours = "pool ours.example.invalid iburst\n";
        let hash16 = &fsutil::sha256_hex(ours.as_bytes())[..16];
        fs::write(
            dir.join(format!(".mkg-stage-dddddddddddddddd{hash16}.conf")),
            ours,
        )
        .unwrap();
        fs::write(
            dir.join(format!(".mkg-stage-eeeeeeeeeeeeeeee{hash16}.conf")),
            THIRD,
        )
        .unwrap();
        fs::write(dir.join(".mkg-stage-ffffffffffffffff.conf"), THIRD).unwrap();
        let state = agent::handle(
            &host.env,
            &testkit::req(op::CHRONY_STATE, serde_json::json!({})),
        );
        assert_eq!(
            state.data["displaced"]["count"], 1,
            "{:?}",
            state.data["displaced"]
        );
        let listed = state.data["displaced"]["names"][0].as_str().unwrap();
        assert!(listed.contains("eeeeeeeeeeeeeeee"), "{listed}");
        // A file that has two names - the leftover name and a protected name -
        // is one kept version, not two.
        let pair = dir.join(format!(".mkg-restore-1111111111111111{hash16}.conf"));
        fs::write(&pair, THIRD).unwrap();
        fs::hard_link(&pair, dir.join(".mkg-displaced-pair.conf")).unwrap();
        let state = agent::handle(
            &host.env,
            &testkit::req(op::CHRONY_STATE, serde_json::json!({})),
        );
        assert_eq!(
            state.data["displaced"]["count"], 2,
            "{:?}",
            state.data["displaced"]
        );
    }

    #[test]
    fn m3_an_unreadable_listing_after_a_lost_answer_is_unknown_not_success() {
        // The re-read after a lost publish answer sees a listing it cannot trust.
        let w = World::new("r7-m3-reread-unknown");
        let flag = Rc::new(std::cell::Cell::new(false));
        w.remote
            .inject_when("node-a", op::CHRONY_PUBLISH, None, 0, 1, Fault::DropAfter);
        let on = Rc::clone(&flag);
        w.remote.inject_when(
            "node-a",
            op::CHRONY_CLEANUP,
            None,
            0,
            1,
            Fault::Hook(Rc::new(move || on.set(true))),
        );
        let seen = Rc::clone(&flag);
        w.remote.inject_when(
            "node-a",
            op::CHRONY_STATE,
            None,
            0,
            100,
            Fault::Rewrite(Rc::new(move |d| {
                if seen.get() {
                    d["displaced"] =
                        serde_json::json!({"count": 0, "names": [], "readable": false});
                }
            })),
        );
        let r = chrony_ctl::apply(&w.ctx(), "node-a", NEW, false);
        let Err(Failure::Unknown(_)) = &r else {
            panic!("expected UNKNOWN, got {r:?}");
        };
        assert_eq!(restarts(&w), 0);
    }

    fn host_conf_dir(w: &World) -> PathBuf {
        crate::manual::r6_tests::chrony_displaced::conf_dir(w)
    }
}
