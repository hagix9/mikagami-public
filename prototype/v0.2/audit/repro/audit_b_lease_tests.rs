#[cfg(test)]
mod audit_b {
    use super::tests::store;
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// B-L1: the lock file is unlinked while a critical section holds it.
    #[test]
    fn b_l1_unlinked_lock_file_admits_a_second_holder() {
        let (store, dir) = store("b-l1");
        store.init("node-a", 1).unwrap();
        let held = store.lock().unwrap(); // critical section of process A
        fs::remove_file(dir.join("lease.json.lock")).unwrap(); // operator "cleans up stale lock"
        let second = store.lock(); // process B
        eprintln!("second lock while first still held: ok={}", second.is_ok());
        assert!(second.is_err(), "two holders in the critical section");
        drop(held);
    }

    /// B-L2: restoring an old copy of the lease file is not detected; an
    /// operation that already entered a mutating phase disappears and a
    /// second operation is admitted; epochs are granted twice.
    #[test]
    fn b_l2_restored_old_backup_double_grants_epoch_and_erases_the_mutating_op() {
        let (store, dir) = store("b-l2");
        let path = dir.join("lease.json");
        store.init("node-a", 1).unwrap();
        let backup = fs::read(&path).unwrap(); // `cp -a` backup / snapshot, epoch 1, no op
        store.acquire("move-op1aaaaa", "node-a", "node-b", 60, "c1", 1, 10).unwrap();
        store.phase("move-op1aaaaa", Phase::SourceQuiescing, None, 11).unwrap();
        // snapshot restore of the Witness disk
        fs::write(&path, &backup).unwrap();
        let st = store.status().unwrap();
        eprintln!("after restore: owner={:?} epoch={} op={:?}", st.owner, st.epoch, st.op.is_some());
        // second controller is admitted although op1 is mutating in the real world
        let r = store.acquire("move-op2bbbbb", "node-a", "node-b", 60, "c2", 1, 12);
        eprintln!("second acquire: {:?}", r.as_ref().map(|s| s.op.as_ref().map(|o| o.op_id.clone())));
        assert!(r.is_err(), "rollback of the record was not detected");
        // and the first controller's next phase now fails with a confusing message only
        let r1 = store.phase("move-op1aaaaa", Phase::SourceReleased, None, 13);
        eprintln!("op1 continues: {r1:?}");
    }

    /// B-L3: a state file without the "op" key is accepted as "no operation".
    #[test]
    fn b_l3_missing_op_key_is_read_as_no_operation() {
        let (store, dir) = store("b-l3");
        let path = dir.join("lease.json");
        store.init("node-a", 1).unwrap();
        store.acquire("move-op1aaaaa", "node-a", "node-b", 60, "c1", 1, 10).unwrap();
        store.phase("move-op1aaaaa", Phase::SourceQuiescing, None, 11).unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        v.as_object_mut().unwrap().remove("op");
        fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
        let st = store.status();
        eprintln!("status without op key: {:?}", st.as_ref().map(|s| s.op.is_some()));
        assert!(st.is_err(), "a damaged record (op key missing) must not read as 'no op'");
    }

    /// B-L4: a missing lease file (unmounted data disk / deleted / new path) is a
    /// fresh start: `init` re-grants epoch 1.
    #[test]
    fn b_l4_missing_file_is_a_fresh_start_and_epoch_restarts() {
        let (store, dir) = store("b-l4");
        let path = dir.join("lease.json");
        store.init("node-a", 1).unwrap();
        store.acquire("move-op1aaaaa", "node-a", "node-b", 60, "c1", 1, 10).unwrap();
        store.phase("move-op1aaaaa", Phase::TargetStarted, None, 11).unwrap();
        store.commit("move-op1aaaaa", "node-b", Value::Null, 12).unwrap();
        assert_eq!(store.status().unwrap().epoch, 2);
        fs::remove_file(&path).unwrap();
        let r = store.init("node-a", 20);
        eprintln!("init after loss: {:?}", r.as_ref().map(|s| (s.owner.clone(), s.epoch)));
        assert!(r.is_err(), "init must not silently restart the epoch of a used store");
    }

    /// B-L5: no ownership / mode check of the state directory or file.
    #[test]
    fn b_l5_world_writable_dir_and_state_are_accepted() {
        let (store, dir) = store("b-l5");
        store.init("node-a", 1).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        fs::set_permissions(dir.join("lease.json"), fs::Permissions::from_mode(0o666)).unwrap();
        let r = store.status();
        eprintln!("status with 0777 dir / 0666 file: ok={}", r.is_ok());
        assert!(r.is_err());
    }

    /// B-L6: commit/phase/abort do not check epoch_at_start against the epoch.
    #[test]
    fn b_l6_epoch_at_start_is_never_compared() {
        let (store, dir) = store("b-l6");
        let path = dir.join("lease.json");
        store.init("node-a", 1).unwrap();
        store.acquire("move-op1aaaaa", "node-a", "node-b", 60, "c1", 1, 10).unwrap();
        store.phase("move-op1aaaaa", Phase::TargetStarted, None, 11).unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        v["epoch"] = serde_json::json!(7);
        fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
        let r = store.commit("move-op1aaaaa", "node-b", Value::Null, 12);
        eprintln!("commit with epoch 7 vs epoch_at_start 1: {:?}", r.as_ref().map(|s| s.epoch));
        assert!(r.is_err());
    }

    /// B-L7: wall-clock steps. Forward step during Acquired = takeover, the old
    /// holder is then refused (safe). Backward step keeps a dead Acquired lock
    /// alive for the size of the step (liveness only).
    #[test]
    fn b_l7_clock_steps() {
        let (store, _dir) = store("b-l7");
        store.init("node-a", 1000).unwrap();
        store.acquire("move-op1aaaaa", "node-a", "node-b", 300, "c1", 1, 200_000).unwrap();
        // forward step of 400 s
        store.acquire("move-op2bbbbb", "node-a", "node-b", 300, "c2", 1, 200_400).unwrap();
        let r = store.phase("move-op1aaaaa", Phase::SourceQuiescing, None, 200_401);
        eprintln!("op1 after takeover: {r:?}");
        assert!(r.is_err());
        // backward step of one day: op2 (crashed controller) blocks for a day
        let r = store.acquire("move-op3ccccc", "node-a", "node-b", 300, "c3", 1, 200_400 - 86_400 + 5000);
        eprintln!("acquire after backward step: {:?}", r.as_ref().map(|_| ()));
        // forward step then mutating op, then 100 years: never expires
        store.phase("move-op2bbbbb", Phase::SourceQuiescing, None, 200_500).unwrap();
        let r = store.acquire("move-op4ddddd", "node-a", "node-b", 300, "c4", 1, u64::MAX / 2);
        eprintln!("mutating op after enormous forward step: {:?}", r.as_ref().map(|_| ()));
        assert!(r.is_err());
    }

    /// B-L8: leftover temp files / tmp write failure keeps the old state.
    #[test]
    fn b_l8_rename_failure_keeps_old_state_and_cleans_tmp() {
        let (store, dir) = store("b-l8");
        store.init("node-a", 1).unwrap();
        let before = fs::read(dir.join("lease.json")).unwrap();
        // make rename impossible: replace lease.json by a non-empty directory? (load would fail) -
        // instead make the directory read-only after lock creation.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
        let r = store.acquire("move-op1aaaaa", "node-a", "node-b", 60, "c", 1, 5);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        eprintln!("acquire on read-only dir: {r:?}");
        assert!(matches!(r, Err(LeaseError::Storage(_))));
        assert_eq!(fs::read(dir.join("lease.json")).unwrap(), before);
        let tmps: Vec<_> = fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()).filter(|e| e.file_name().to_string_lossy().ends_with(".tmp")).collect();
        assert!(tmps.is_empty());
    }

    /// B-L9: evidence size can brick the store (4 MiB read cap vs 1 MiB x 50 history).
    #[test]
    fn b_l9_large_evidence_bricks_the_store() {
        let (store, _dir) = store("b-l9");
        store.init("node-a", 1).unwrap();
        let big = serde_json::json!({"x": "a".repeat(900_000)});
        let mut owner = "node-a";
        let mut epoch = 1;
        let mut broke_at = None;
        for i in 0..8 {
            let target = if owner == "node-a" { "node-b" } else { "node-a" };
            let op = format!("move-op{i:08}");
            if store.acquire(&op, owner, target, 60, "c", epoch, 10).is_err() { broke_at = Some(i); break; }
            store.phase(&op, Phase::TargetStarted, None, 11).unwrap();
            if store.commit(&op, target, big.clone(), 12).is_err() { broke_at = Some(i); break; }
            owner = target; epoch += 1;
        }
        eprintln!("store unusable after {broke_at:?} large commits; status = {:?}", store.status().map(|_| ()));
        assert!(store.status().is_ok());
    }
}
