//! Phase 1-J24 (N-6): the Witness side of the C-F generation fence, tested against the unchanged
//! Witness (`witness_authority`, `witness_journal`, `witness_state`).
//!
//! Every fence here is the exact message the node sends: `generation_fence_of` applied to a
//! retained LeaseRequest, converted with `to_protocol_message`. The tests pin the Witness
//! behaviour C-F relies on, so that a future Witness change that breaks it fails here:
//! - the fence commits only a PolicyReject: term, holder, lease id, lease state, TTL and deadline
//!   stay as they were; the journal gains exactly that one record and the sender's watermark
//!   becomes the fence's generation (W-1, W-6, W-9);
//! - it never releases the sender's own active lease, nor another holder's;
//! - a duplicate, also after a Witness restart, is answered the same way and commits nothing;
//! - the request it fences can no longer obtain a grant afterwards;
//! - the grants the Witness can produce never carry term 0 or the fence's lease id (W-7, W-8),
//!   which is why the fence can match no lease.
//! One test characterises the accepted residual RR-2 (N-6): the Witness does not reject the
//! reserved lease id itself, so a hand-written state that W-7 / W-8 make unreachable lets the fence
//! release it.
//!
//! Test-only: everything is inside `mod tests`, so the architecture guards (which read a module up
//! to its `mod tests`) see no production code here.

#[cfg(test)]
mod tests {
    use crate::linux_node_runtime::{GENERATION_FENCE_LEASE_ID, generation_fence_of};
    use crate::node_mutation::{DurableWitnessMutation, OutstandingWitnessMutation};
    use crate::protocol::{
        ClusterId, CommonFields, DurationMs, LeaseId, NodeId, PROTOCOL_VERSION, ProtocolMessage,
        RequestId, Sequence, SessionId, Term, UnsignedEnvelope, WitnessMutationOutcomeCode,
    };
    use crate::witness_authority::{
        PreparedLeaseResponse, expire_lease_if_needed, prepare_lease_release_authority,
        prepare_lease_request_authority,
    };
    use crate::witness_journal::CommittedSemanticResult;
    use crate::witness_runtime::WitnessRequestObservation;
    use crate::witness_state::{
        BootId, BootIdProvider, LeaseState, MonotonicClock, WitnessPersistentState,
        WitnessReadiness, WitnessStateError, WitnessStateStore,
    };
    use std::fs;
    use std::path::{Path, PathBuf};

    #[derive(Clone)]
    struct Boot;
    impl BootIdProvider for Boot {
        fn current_boot_id(&self) -> Result<BootId, WitnessStateError> {
            Ok(BootId::new("boot-a"))
        }
    }

    #[derive(Clone, Copy)]
    struct Clock(u64);
    impl MonotonicClock for Clock {
        fn now_ms(&self) -> Result<u64, WitnessStateError> {
            Ok(self.0)
        }
    }

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "mikagami-j24-n6-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn store(path: &Path, now: u64) -> WitnessStateStore<Boot, Clock> {
        WitnessStateStore::with_providers(path, ClusterId::new("cluster"), Boot, Clock(now))
    }

    fn fresh(name: &str) -> PathBuf {
        let file = path(name);
        store(&file, 1_000)
            .save(&WitnessPersistentState::new(
                ClusterId::new("cluster"),
                BootId::new("boot-a"),
            ))
            .unwrap();
        file
    }

    /// The envelope and the observation of `message` from `sender` (what the Witness runtime hands to
    /// the authority after authentication).
    fn envelope(
        sender: &str,
        request_id: &RequestId,
        message: ProtocolMessage,
    ) -> (UnsignedEnvelope, WitnessRequestObservation) {
        let sender_node_id = NodeId::new(sender);
        let observation = match &message {
            ProtocolMessage::LeaseRequest(payload) => WitnessRequestObservation::LeaseRequest {
                request_id: request_id.clone(),
                sender_node_id: sender_node_id.clone(),
                term: Term(0),
                lease_id: None,
                payload: payload.clone(),
            },
            ProtocolMessage::LeaseRelease(payload) => WitnessRequestObservation::LeaseRelease {
                request_id: request_id.clone(),
                sender_node_id: sender_node_id.clone(),
                term: Term(0),
                lease_id: None,
                payload: payload.clone(),
            },
            other => panic!("unexpected message {other:?}"),
        };
        let request = UnsignedEnvelope {
            common: CommonFields {
                protocol_version: PROTOCOL_VERSION,
                cluster_id: ClusterId::new("cluster"),
                sender_node_id,
                receiver_node_id: NodeId::new("witness"),
                session_id: SessionId::new("session-a"),
                sequence: Sequence(1),
                term: Term(0),
                lease_id: None,
                request_id: Some(request_id.clone()),
                operation_id: None,
            },
            message,
        };
        (request, observation)
    }

    /// A retained LeaseRequest M of `generation` (what the node keeps after a lost answer).
    fn retained_request(request_id: &str, generation: u64) -> OutstandingWitnessMutation {
        request_at(request_id, generation, Term(0))
    }

    fn request_at(request_id: &str, generation: u64, observed: Term) -> OutstandingWitnessMutation {
        OutstandingWitnessMutation {
            request_id: RequestId::new(request_id),
            mutation_generation: generation,
            mutation: DurableWitnessMutation::LeaseRequest {
                observed_term: observed,
                priority: 100,
                requested_ttl: DurationMs(10_000),
            },
        }
    }

    fn send_request(
        store: &WitnessStateStore<Boot, Clock>,
        sender: &str,
        mutation: &OutstandingWitnessMutation,
    ) -> PreparedLeaseResponse {
        let (request, observation) =
            envelope(sender, &mutation.request_id, mutation.to_protocol_message());
        prepare_lease_request_authority(store, &observation, &request).unwrap()
    }

    /// Sends the node's generation fence of `retained` from `sender`.
    fn send_fence(
        store: &WitnessStateStore<Boot, Clock>,
        sender: &str,
        retained: &OutstandingWitnessMutation,
    ) -> PreparedLeaseResponse {
        let fence = generation_fence_of(retained).unwrap();
        let ProtocolMessage::LeaseRelease(payload) = fence.to_protocol_message() else {
            panic!("a fence is a LeaseRelease");
        };
        assert_eq!(payload.term, Term(0));
        assert_eq!(payload.lease_id, LeaseId::new(GENERATION_FENCE_LEASE_ID));
        let (request, observation) = envelope(
            sender,
            &fence.request_id,
            ProtocolMessage::LeaseRelease(payload),
        );
        prepare_lease_release_authority(store, &observation, &request).unwrap()
    }

    fn state(store: &WitnessStateStore<Boot, Clock>) -> WitnessPersistentState {
        store.load().state.unwrap()
    }

    /// Everything except the journal and the generation watermarks: the authority part of the state.
    fn authority(state: &WitnessPersistentState) -> WitnessPersistentState {
        let mut rest = state.clone();
        rest.journal.clear();
        rest.generation_watermarks.clear();
        rest
    }

    fn reject_code(prepared: &PreparedLeaseResponse) -> Option<WitnessMutationOutcomeCode> {
        match &prepared.message {
            ProtocolMessage::LeaseReject(payload) => Some(payload.code),
            _ => None,
        }
    }

    /// The fence committed exactly one PolicyReject record and moved only the sender's watermark.
    fn assert_fence_commit(
        before: &WitnessPersistentState,
        after: &WitnessPersistentState,
        sender: &str,
        retained: &OutstandingWitnessMutation,
    ) {
        let fence = generation_fence_of(retained).unwrap();
        assert_eq!(
            authority(after),
            authority(before),
            "the fence changed the authority state"
        );
        assert_eq!(after.journal.len(), before.journal.len() + 1);
        let record = after.journal.last().unwrap();
        assert_eq!(record.request_id, fence.request_id);
        assert_eq!(record.requester_node_id, sender);
        assert_eq!(
            record.request_kind,
            crate::protocol::MessageType::LeaseRelease
        );
        assert_eq!(record.mutation_generation, retained.mutation_generation);
        assert!(matches!(
            &record.result,
            CommittedSemanticResult::LeaseReject(reject)
                if reject.code == WitnessMutationOutcomeCode::PolicyReject
        ));
        let mut expected_watermarks = before.generation_watermarks.clone();
        expected_watermarks.insert(sender.to_string(), retained.mutation_generation);
        assert_eq!(after.generation_watermarks, expected_watermarks);
    }

    #[test]
    fn j24_n6_fence_on_an_empty_witness_commits_only_a_policy_reject() {
        let file = fresh("empty");
        let witness = store(&file, 2_000);
        let m = retained_request("00000000-0000-4000-8000-000000024001", 1);
        let before = state(&witness);
        let answer = send_fence(&witness, "node-a", &m);
        assert_eq!(
            reject_code(&answer),
            Some(WitnessMutationOutcomeCode::PolicyReject)
        );
        let after = state(&witness);
        assert_fence_commit(&before, &after, "node-a", &m);
        assert_eq!(after.current_term, Term(0));
        assert_eq!(after.lease_state, LeaseState::None);

        // The fenced request can never obtain a grant afterwards, and its late copy commits nothing.
        let late = send_request(&witness, "node-a", &m);
        assert!(
            !matches!(late.message, ProtocolMessage::LeaseGrant(_)),
            "the fenced request was granted: {:?}",
            late.message
        );
        assert_eq!(state(&witness), after);
        let _ = fs::remove_file(file);
    }

    #[test]
    fn j24_n6_fence_never_releases_the_senders_own_active_lease() {
        let file = fresh("own");
        let witness = store(&file, 2_000);
        let grant_request = retained_request("00000000-0000-4000-8000-000000024011", 1);
        let ProtocolMessage::LeaseGrant(grant) =
            send_request(&witness, "node-a", &grant_request).message
        else {
            panic!("expected the first grant");
        };
        assert_eq!(grant.term, Term(1));
        // A later promotion attempt of the same node at generation 2 whose answer was lost.
        let m = retained_request("00000000-0000-4000-8000-000000024012", 2);
        let before = state(&witness);
        assert_eq!(before.lease_state, LeaseState::Active);
        let answer = send_fence(&witness, "node-a", &m);
        assert_eq!(
            reject_code(&answer),
            Some(WitnessMutationOutcomeCode::PolicyReject)
        );
        let after = state(&witness);
        assert_fence_commit(&before, &after, "node-a", &m);
        assert_eq!(after.lease_state, LeaseState::Active);
        assert_eq!(after.current_term, Term(1));
        assert_eq!(after.active_lease_id.as_ref(), Some(&grant.lease_id));
        assert_eq!(after.holder_node_id, Some(NodeId::new("node-a")));
        let _ = fs::remove_file(file);
    }

    #[test]
    fn j24_n6_fence_never_touches_another_holders_lease() {
        let file = fresh("other");
        let witness = store(&file, 2_000);
        let grant_request = retained_request("00000000-0000-4000-8000-000000024021", 1);
        let ProtocolMessage::LeaseGrant(grant) =
            send_request(&witness, "node-b", &grant_request).message
        else {
            panic!("expected node-b's grant");
        };
        let m = retained_request("00000000-0000-4000-8000-000000024022", 1);
        let before = state(&witness);
        let answer = send_fence(&witness, "node-a", &m);
        assert_eq!(
            reject_code(&answer),
            Some(WitnessMutationOutcomeCode::PolicyReject)
        );
        let after = state(&witness);
        assert_fence_commit(&before, &after, "node-a", &m);
        assert_eq!(after.holder_node_id, Some(NodeId::new("node-b")));
        assert_eq!(after.active_lease_id.as_ref(), Some(&grant.lease_id));
        let _ = fs::remove_file(file);
    }

    #[test]
    fn j24_n6_fence_duplicates_and_witness_restarts_commit_nothing_new() {
        let file = fresh("duplicate");
        let m = retained_request("00000000-0000-4000-8000-000000024031", 1);
        let first = send_fence(&store(&file, 2_000), "node-a", &m);
        assert_eq!(
            reject_code(&first),
            Some(WitnessMutationOutcomeCode::PolicyReject)
        );
        let bytes = fs::read(&file).unwrap();

        // The answer was lost: the same fence again, then after a Witness restart (a new store over
        // the same file, same boot) and later in time. Each is the same PolicyReject, and the file is
        // byte-for-byte unchanged.
        for now in [2_500, 60_000] {
            let restarted = store(&file, now);
            assert_eq!(restarted.load().readiness, WitnessReadiness::Ready);
            let again = send_fence(&restarted, "node-a", &m);
            assert_eq!(
                reject_code(&again),
                Some(WitnessMutationOutcomeCode::PolicyReject)
            );
            assert_eq!(
                fs::read(&file).unwrap(),
                bytes,
                "a duplicate fence wrote the state"
            );
        }
        let _ = fs::remove_file(file);
    }

    #[test]
    fn j24_n6_reachable_grants_never_carry_term_zero_or_the_fence_lease_id() {
        let file = fresh("grants");
        let mut now = 2_000;
        let mut generations = std::collections::BTreeMap::new();
        for round in 0..5u64 {
            let sender = if round % 2 == 0 { "node-a" } else { "node-b" };
            let generation = generations.entry(sender).or_insert(0u64);
            *generation += 1;
            let witness = store(&file, now);
            let request = request_at(
                &format!("00000000-0000-4000-8000-00000002405{round}"),
                *generation,
                state(&witness).current_term,
            );
            let ProtocolMessage::LeaseGrant(grant) =
                send_request(&witness, sender, &request).message
            else {
                panic!("expected a grant in round {round}");
            };
            assert!(grant.term.0 >= 1, "a grant carried term 0");
            assert_ne!(grant.lease_id.as_str(), GENERATION_FENCE_LEASE_ID);
            assert!(
                crate::protocol::is_valid_mutating_request_id(grant.lease_id.as_str()),
                "a grant's lease id is not a canonical UUIDv4: {}",
                grant.lease_id.as_str()
            );
            // Let the lease expire so that the other node can be granted next.
            now += 20_000;
            let expired = store(&file, now);
            expire_lease_if_needed(&expired).unwrap();
        }
        let _ = fs::remove_file(file);
    }

    /// RR-2 (N-6), accepted residual: the Witness does not reject the reserved lease id itself. A
    /// hand-written state with an Active lease of term 0 and the fence's lease id (unreachable through
    /// the Witness: see the test above) is loaded as Ready, and the fence releases it. The node treats
    /// such an answer as an error (J23 `j23_fence_answered_with_a_success_or_a_non_terminal_reject_…`).
    /// If a future Witness rejects the reserved id, this test must be updated together with RR-2.
    #[test]
    fn j24_n6_residual_a_hand_written_fence_lease_is_not_rejected_by_the_witness() {
        let file = path("residual");
        let mut corrupted =
            WitnessPersistentState::new(ClusterId::new("cluster"), BootId::new("boot-a"));
        corrupted.current_term = Term(0);
        corrupted.active_lease_id = Some(LeaseId::new(GENERATION_FENCE_LEASE_ID));
        corrupted.holder_node_id = Some(NodeId::new("node-a"));
        corrupted.lease_ttl_ms = Some(DurationMs(10_000));
        corrupted.lease_deadline_monotonic_ms = Some(50_000);
        corrupted.lease_state = LeaseState::Active;
        let witness = store(&file, 2_000);
        witness.save(&corrupted).unwrap();
        assert_eq!(witness.load().readiness, WitnessReadiness::Ready);
        let m = retained_request("00000000-0000-4000-8000-000000024061", 1);
        let answer = send_fence(&witness, "node-a", &m);
        assert!(matches!(answer.message, ProtocolMessage::LeaseReleased(_)));
        let _ = fs::remove_file(file);
    }
}
