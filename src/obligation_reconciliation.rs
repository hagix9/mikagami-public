//! Startup Obligation Reconciliation (SOR, contract A-4): the pure decision of
//! whether a node that restarted with a release obligation `O = (term_o,
//! lease_o)` may let it go, from one authoritative Witness `GET_TERM` view.
//!
//! No clock or name matching is used: the verdict (`decide`) follows from the
//! Witness term and holder classification only; `reconcile` applies it through
//! the existing store and exact-release machinery. A time-based guess ("the
//! lease must have expired by now") never clears anything.
//!
//! Clearing is further conditioned, by the caller, on a freshly observed
//! trusted ZeroResource, no outstanding mutation `M` and no fencing incident.

use crate::evidence_fusion::adapter::AuthorityViewCompatibility;
use crate::node_lease_authority::node_witness_runtime::{
    NodeWitnessMutationResult, NodeWitnessMutationRuntime, NodeWitnessRuntimeError,
};
use crate::node_mutation::{DurableWitnessMutation, NodeMutationError, NodeMutationStore};
use crate::protocol::{LeaseId, NodeId, Term};
use crate::witness_runtime::WitnessSession;

/// What the reconciliation does with `O`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SorAction {
    /// (i) The Witness still records this node's exact `(term_o, lease_o)`:
    /// the existing exact `LeaseRelease` path runs.
    ExactRelease,
    /// (ii)/(iii) `lease_o` can no longer be held: clear `O` atomically.
    ClearSuperseded(SupersededBy),
    /// Anything else leaves `O` in place (RecoveryBlocked), with the cause.
    Blocked(SorBlock),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SupersededBy {
    /// (ii) `current_term > term_o`.
    NewerTerm,
    /// (iii) `current_term == term_o` and the Witness records no holder.
    SameTermNoHolder,
    /// v0.6 A-4: the Witness deterministically rejected the exact release, so
    /// `(term_o, lease_o)` cannot be held or released by this node any more.
    WitnessRejectedRelease {
        /// The bounded Witness reason (never used as a decision input).
        reason: String,
    },
    /// C-l: the exact replay of `M` was answered RetiredStale and a new
    /// GET_TERM view shows `current_term > term_o`. Superseded, not released.
    RetiredThenNewerTerm,
    /// C-l: as above, with `current_term == term_o` and no holder.
    RetiredThenSameTermNoHolder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SorBlock {
    /// `current_term < term_o`: the Witness is behind this node's own record
    /// (a rollback or the wrong Witness). Never cleared.
    WitnessBehind,
    /// Same term with a holder that is not provably gone (another node, an
    /// expired-but-unprocessed lease, or a lease id that is not `lease_o`).
    HolderNotGone,
    /// C-l with CL-05s: a newer-term view still shows this node as an
    /// unexpired holder (`remaining > 0`), or as a holder the classifier
    /// could not reconcile. Never cleared, whatever the term.
    SelfStillHolder,
    /// C-l (CL-07): the view shows this node's exact `lease_o` unexpired.
    /// The slot is taken by `M`, which can never be NewEligible again, so no
    /// new Release is begun.
    RetiredExactRelease,
}

impl SorBlock {
    pub(crate) const fn reason(self) -> &'static str {
        match self {
            Self::WitnessBehind => {
                "the Witness term is older than the node's release obligation (Witness state rolled back or wrong Witness)"
            }
            Self::HolderNotGone => {
                "the Witness still records a lease holder for the obligation's term that is not this node's exact lease"
            }
            Self::SelfStillHolder => {
                "after the retired exact release, the Witness still shows this node as an unexpired lease holder"
            }
            Self::RetiredExactRelease => {
                "after the retired exact release, the Witness still shows this node's exact lease unexpired"
            }
        }
    }
}

/// C-l: the decision after the exact replay of `M` was answered RetiredStale,
/// from a new GET_TERM view classified like `decide`'s (this node, no expected
/// term, self lease = `lease_o`). The existing `decide` applies, with two
/// differences:
/// - CL-05s: at a newer term, a view that shows this node as a holder with
///   `remaining > 0` is Blocked. With no expected term the classifier yields
///   exactly `CompatibleSelfUnexpired` (lease id = `lease_o`) or
///   `InconsistentAuthorityView` (another or no lease id) for that holder; a
///   self holder with `remaining = 0` is `ExpiredButUnprocessed` and is not
///   blocked (F33-5).
/// - CL-07: `ExactRelease` is Blocked; no new Release is begun.
///
/// Only `ClearSuperseded` resolves `O`, under its own C-l label.
pub(crate) fn decide_retired(
    term_o: Term,
    witness_term: Term,
    compatibility: AuthorityViewCompatibility,
) -> SorAction {
    if witness_term.0 > term_o.0
        && matches!(
            compatibility,
            AuthorityViewCompatibility::CompatibleSelfUnexpired
                | AuthorityViewCompatibility::InconsistentAuthorityView
        )
    {
        return SorAction::Blocked(SorBlock::SelfStillHolder);
    }
    match decide(term_o, witness_term, compatibility) {
        SorAction::ClearSuperseded(SupersededBy::NewerTerm) => {
            SorAction::ClearSuperseded(SupersededBy::RetiredThenNewerTerm)
        }
        SorAction::ClearSuperseded(SupersededBy::SameTermNoHolder) => {
            SorAction::ClearSuperseded(SupersededBy::RetiredThenSameTermNoHolder)
        }
        SorAction::ClearSuperseded(_) | SorAction::ExactRelease => {
            SorAction::Blocked(SorBlock::RetiredExactRelease)
        }
        blocked @ SorAction::Blocked(_) => blocked,
    }
}

/// The SOR-2 decision. `compatibility` must have been classified by the
/// adapter against `(this node, expected_term = None, self_lease = lease_o)`.
pub(crate) fn decide(
    term_o: Term,
    witness_term: Term,
    compatibility: AuthorityViewCompatibility,
) -> SorAction {
    use std::cmp::Ordering;
    match witness_term.0.cmp(&term_o.0) {
        Ordering::Less => SorAction::Blocked(SorBlock::WitnessBehind),
        // The lease of term_o was overwritten by a later grant.
        Ordering::Greater => SorAction::ClearSuperseded(SupersededBy::NewerTerm),
        Ordering::Equal => match compatibility {
            AuthorityViewCompatibility::CompatibleNoHolder => {
                SorAction::ClearSuperseded(SupersededBy::SameTermNoHolder)
            }
            // This node is the holder with exactly lease_o (the classifier
            // compared the lease id): release it through the exact path.
            AuthorityViewCompatibility::CompatibleSelfUnexpired => SorAction::ExactRelease,
            AuthorityViewCompatibility::ConflictingHolder
            | AuthorityViewCompatibility::ExpiredButUnprocessed
            | AuthorityViewCompatibility::InconsistentAuthorityView => {
                SorAction::Blocked(SorBlock::HolderNotGone)
            }
        },
    }
}

/// The `O` a restarted node may resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SorCandidate {
    pub(crate) term: Term,
    pub(crate) lease_id: LeaseId,
    /// The owned `LeaseRelease(O)` is already durably outstanding (`M`).
    pub(crate) release_pending: bool,
}

/// The result of one Startup Obligation Reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SorOutcome {
    /// No resolvable obligation: nothing was done.
    NotApplicable,
    /// (i) The exact `LeaseRelease` was accepted; `O` is gone.
    Released { term: Term },
    /// (ii)/(iii) `O` was cleared because its lease can no longer be held.
    Cleared { term: Term, by: SupersededBy },
    /// `O` stays; the node stays RecoveryBlocked. The text names the cause.
    Blocked(String),
}

/// The release obligation SOR may resolve, if any. `Some` only for `O` with
/// no fencing incident and either no `M` or exactly the owned
/// `LeaseRelease(O)` as `M`; any other `M` is outside SOR and keeps the
/// existing recovery contract.
pub(crate) fn candidate(
    store: &NodeMutationStore,
) -> Result<Option<SorCandidate>, NodeMutationError> {
    let image = store.load_existing()?;
    let Some(obligation) = image.release_obligation else {
        return Ok(None);
    };
    if image.fencing_incident.is_some() {
        return Ok(None);
    }
    let release_pending = match &image.outstanding_mutation {
        None => false,
        Some(outstanding) => match &outstanding.mutation {
            DurableWitnessMutation::LeaseRelease { term, lease_id, .. }
                if *term == obligation.term && *lease_id == obligation.lease_id =>
            {
                true
            }
            _ => return Ok(None),
        },
    };
    Ok(Some(SorCandidate {
        term: obligation.term,
        lease_id: obligation.lease_id,
        release_pending,
    }))
}

/// Startup Obligation Reconciliation (SOR-1..SOR-5), after the caller has
/// freshly established whether the node's resources are provably absent
/// (`zero_resource`, the verified cleanup that mints trusted ZeroResource).
///
/// `view` is the authoritative `GET_TERM` result classified against
/// `(this node, no expected term, lease_o)`; it is only consulted when no
/// owned `LeaseRelease` is already pending. Without trusted ZeroResource
/// nothing is touched. Every uncertainty leaves `O` in place (`Blocked`). No
/// authority is installed here: SOR never grants anything (SOR-5).
///
/// Amendment C:
/// - C-m': `fresh_zero_resource` re-establishes trusted ZeroResource (the
///   guarded verified cleanup) immediately before each exceptional settle
///   (A-4d, C-l); `false` or an error leaves `O` and `M` in place.
/// - C-l: `retired_view` takes a new authoritative GET_TERM view on the same
///   session. It is called only after the exact replay of the pending `M`
///   was answered RetiredStale, never otherwise.
pub(crate) fn reconcile(
    store: &NodeMutationStore,
    node_id: &NodeId,
    session: &mut WitnessSession,
    zero_resource: bool,
    view: Option<(Term, AuthorityViewCompatibility)>,
    fresh_zero_resource: &mut dyn FnMut() -> bool,
    retired_view: &mut dyn FnMut(
        &mut WitnessSession,
    ) -> Result<(Term, AuthorityViewCompatibility), String>,
) -> Result<SorOutcome, NodeMutationError> {
    let Some(candidate) = candidate(store)? else {
        return Ok(SorOutcome::NotApplicable);
    };
    if !zero_resource {
        return Ok(SorOutcome::Blocked(
            "local resources could not be proven absent (no trusted ZeroResource)".into(),
        ));
    }
    let action = if candidate.release_pending {
        SorAction::ExactRelease
    } else {
        let Some((witness_term, compatibility)) = view else {
            return Ok(SorOutcome::Blocked(
                "no authoritative Witness view for the release obligation".into(),
            ));
        };
        decide(candidate.term, witness_term, compatibility)
    };
    match action {
        SorAction::Blocked(block) => Ok(SorOutcome::Blocked(block.reason().into())),
        SorAction::ClearSuperseded(by) => {
            match store.clear_superseded_obligation(candidate.term, &candidate.lease_id) {
                Ok(()) => Ok(SorOutcome::Cleared {
                    term: candidate.term,
                    by,
                }),
                Err(error) => Ok(SorOutcome::Blocked(format!(
                    "the superseded release obligation could not be cleared: {error}"
                ))),
            }
        }
        SorAction::ExactRelease => {
            let runtime = NodeWitnessMutationRuntime::new(store, node_id.clone());
            let result = if candidate.release_pending {
                runtime.execute_outstanding_once(session)
            } else {
                runtime.begin_and_execute_lease_release_once(
                    session,
                    candidate.term,
                    candidate.lease_id.clone(),
                    "startup obligation reconciliation".to_string(),
                )
            };
            match result {
                Ok(NodeWitnessMutationResult::AcceptedSuccess { .. }) => Ok(SorOutcome::Released {
                    term: candidate.term,
                }),
                // v0.6 A-4: a deterministic reject of the EXACT release is
                // itself proof that `(term_o, lease_o)` is not releasable by
                // this node any more: every reject reason the Witness can
                // produce here says the lease is absent, belongs to another
                // term, another lease id, or another holder. Keeping `O` would
                // block the node forever on a record that can never succeed
                // ("there is no active lease to release" is the common case
                // after the lease expired while the node was down).
                //
                // The runtime keeps the owned Release record `M` on a reject
                // (only `AcceptedSuccess` completes it), so `M` and `O` are
                // settled together below. `RetiredStale` is NOT used to clear
                // `O` (it is a generation statement, not a statement about
                // this lease); it only leads to the C-l view below.
                Ok(NodeWitnessMutationResult::DeterministicReject {
                    reason,
                    witness_term,
                    ..
                }) => {
                    // Only a Witness at or ahead of `term_o` can prove anything
                    // about this lease. A Witness behind it (persistence loss /
                    // rollback) denies a lease it no longer knows about; that is
                    // exactly the `WitnessBehind` case `decide` refuses to clear.
                    if witness_term.0 < candidate.term.0 {
                        return Ok(SorOutcome::Blocked(format!(
                            "the Witness rejected the release from an older term {} (obligation term {}); refusing to clear",
                            witness_term.0, candidate.term.0
                        )));
                    }
                    // The runtime deliberately keeps the owned Release record
                    // on a reject (only `AcceptedSuccess` proves release via
                    // that path). Here the reject itself proves the opposite
                    // direction - there is nothing this node can release - so
                    // both records are settled atomically. C-m': trusted
                    // ZeroResource is re-established immediately before, and
                    // the settle checks the fencing incident inside its guard.
                    let settled = match store.outstanding() {
                        Ok(Some(outstanding))
                            if matches!(
                                &outstanding.mutation,
                                DurableWitnessMutation::LeaseRelease { term, lease_id, .. }
                                    if *term == candidate.term && *lease_id == candidate.lease_id
                            ) =>
                        {
                            if !fresh_zero_resource() {
                                return Ok(SorOutcome::Blocked(
                                    "local resources could not be proven absent again before the settle"
                                        .into(),
                                ));
                            }
                            store.settle_rejected_owned_release(
                                &outstanding.request_id,
                                outstanding.mutation_generation,
                                candidate.term,
                                &candidate.lease_id,
                            )
                        }
                        // The owned release record is deliberately kept on a
                        // reject, so this arm is not expected. Never take the
                        // weaker clear path here: without the exact record the
                        // reject cannot be tied to `O`.
                        Ok(_) => {
                            return Ok(SorOutcome::Blocked(
                                "the rejected release has no matching outstanding record".into(),
                            ));
                        }
                        Err(error) => Err(error),
                    };
                    match settled {
                        Ok(()) => Ok(SorOutcome::Cleared {
                            term: candidate.term,
                            by: SupersededBy::WitnessRejectedRelease { reason },
                        }),
                        Err(error) => Ok(SorOutcome::Blocked(format!(
                            "the rejected release obligation could not be cleared: {error}"
                        ))),
                    }
                }
                // C-l: only the exact replay of the pending `M`, correlated on
                // the current session, can lead here.
                Ok(NodeWitnessMutationResult::RetiredStale { .. }) if candidate.release_pending => {
                    resolve_retired(store, session, &candidate, fresh_zero_resource, retired_view)
                }
                Ok(other) => Ok(SorOutcome::Blocked(format!(
                    "the Witness did not accept the exact release: {other:?}"
                ))),
                // OD-J31-4: an exhausted correlation is an unknown outcome, not
                // a correlation failure; `M` and `O` stay.
                Err(NodeWitnessRuntimeError::Witness(
                    crate::witness_runtime::WitnessRuntimeError::UncorrelatedResponsesExhausted,
                )) => Ok(SorOutcome::Blocked(
                    "the outcome of the exact release is unknown (only uncorrelated responses were read)"
                        .into(),
                )),
                Err(error) => Ok(SorOutcome::Blocked(format!(
                    "the exact release could not be completed: {error}"
                ))),
            }
        }
    }
}

/// C-l (AC-9..AC-11, CL-01..CL-15): after the exact replay of the pending `M`
/// was answered RetiredStale, take a new view on the same session and apply
/// `decide_retired`. RetiredStale alone never resolves anything (CL-01): every
/// failure, and every outcome other than `ClearSuperseded`, keeps `M` and `O`.
/// The resolution is one atomic settle of exactly `M` and `O`, after a fresh
/// trusted ZeroResource, with the incident check inside the store guard. It is
/// `Cleared`, never `Released`, and installs no authority.
fn resolve_retired(
    store: &NodeMutationStore,
    session: &mut WitnessSession,
    candidate: &SorCandidate,
    fresh_zero_resource: &mut dyn FnMut() -> bool,
    retired_view: &mut dyn FnMut(
        &mut WitnessSession,
    ) -> Result<(Term, AuthorityViewCompatibility), String>,
) -> Result<SorOutcome, NodeMutationError> {
    let Some(outstanding) = store.outstanding()?.filter(|outstanding| {
        matches!(
            &outstanding.mutation,
            DurableWitnessMutation::LeaseRelease { term, lease_id, .. }
                if *term == candidate.term && *lease_id == candidate.lease_id
        )
    }) else {
        return Ok(SorOutcome::Blocked(
            "the retired release has no matching outstanding record".into(),
        ));
    };
    let (witness_term, compatibility) = match retired_view(session) {
        Ok(view) => view,
        Err(reason) => {
            return Ok(SorOutcome::Blocked(format!(
                "the exact release was retired and no new Witness view was available: {reason}"
            )));
        }
    };
    let by = match decide_retired(candidate.term, witness_term, compatibility) {
        SorAction::ClearSuperseded(by) => by,
        SorAction::Blocked(block) => return Ok(SorOutcome::Blocked(block.reason().into())),
        SorAction::ExactRelease => {
            return Ok(SorOutcome::Blocked(
                SorBlock::RetiredExactRelease.reason().into(),
            ));
        }
    };
    if !fresh_zero_resource() {
        return Ok(SorOutcome::Blocked(
            "local resources could not be proven absent again before the settle".into(),
        ));
    }
    match store.settle_retired_owned_release(
        &outstanding.request_id,
        outstanding.mutation_generation,
        candidate.term,
        &candidate.lease_id,
    ) {
        Ok(()) => Ok(SorOutcome::Cleared {
            term: candidate.term,
            by,
        }),
        Err(error) => Ok(SorOutcome::Blocked(format!(
            "the retired release obligation could not be cleared: {error}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use AuthorityViewCompatibility as C;

    const T: Term = Term(7);

    #[test]
    fn newer_witness_term_clears_whatever_the_holder() {
        for compat in [
            C::CompatibleNoHolder,
            C::CompatibleSelfUnexpired,
            C::ConflictingHolder,
            C::ExpiredButUnprocessed,
            C::InconsistentAuthorityView,
        ] {
            assert_eq!(
                decide(T, Term(8), compat),
                SorAction::ClearSuperseded(SupersededBy::NewerTerm),
                "{compat:?}"
            );
        }
    }

    #[test]
    fn same_term_clears_only_without_holder_and_releases_only_the_exact_lease() {
        assert_eq!(
            decide(T, T, C::CompatibleNoHolder),
            SorAction::ClearSuperseded(SupersededBy::SameTermNoHolder)
        );
        assert_eq!(
            decide(T, T, C::CompatibleSelfUnexpired),
            SorAction::ExactRelease
        );
        for compat in [
            C::ConflictingHolder,
            C::ExpiredButUnprocessed,
            C::InconsistentAuthorityView,
        ] {
            assert_eq!(
                decide(T, T, compat),
                SorAction::Blocked(SorBlock::HolderNotGone),
                "{compat:?}"
            );
        }
    }

    #[test]
    fn older_witness_term_never_clears() {
        for compat in [
            C::CompatibleNoHolder,
            C::CompatibleSelfUnexpired,
            C::ConflictingHolder,
            C::ExpiredButUnprocessed,
            C::InconsistentAuthorityView,
        ] {
            assert_eq!(
                decide(T, Term(6), compat),
                SorAction::Blocked(SorBlock::WitnessBehind),
                "{compat:?}"
            );
        }
    }

    /// J35 C-l: `decide_retired` is `decide` with CL-05s (a newer-term
    /// unexpired self holder is Blocked) and CL-07 (ExactRelease is Blocked),
    /// under its own labels; it never returns ExactRelease.
    #[test]
    fn j35_decide_retired_adds_cl05s_and_cl07_to_decide() {
        let all = [
            C::CompatibleNoHolder,
            C::CompatibleSelfUnexpired,
            C::ConflictingHolder,
            C::ExpiredButUnprocessed,
            C::InconsistentAuthorityView,
        ];
        for compat in all {
            let newer = decide_retired(T, Term(8), compat);
            match compat {
                C::CompatibleSelfUnexpired | C::InconsistentAuthorityView => {
                    assert_eq!(
                        newer,
                        SorAction::Blocked(SorBlock::SelfStillHolder),
                        "{compat:?}"
                    )
                }
                _ => assert_eq!(
                    newer,
                    SorAction::ClearSuperseded(SupersededBy::RetiredThenNewerTerm),
                    "{compat:?}"
                ),
            }
            assert_eq!(
                decide_retired(T, Term(6), compat),
                SorAction::Blocked(SorBlock::WitnessBehind),
                "{compat:?}"
            );
            let same = decide_retired(T, T, compat);
            match compat {
                C::CompatibleNoHolder => assert_eq!(
                    same,
                    SorAction::ClearSuperseded(SupersededBy::RetiredThenSameTermNoHolder)
                ),
                C::CompatibleSelfUnexpired => {
                    assert_eq!(same, SorAction::Blocked(SorBlock::RetiredExactRelease))
                }
                _ => assert_eq!(
                    same,
                    SorAction::Blocked(SorBlock::HolderNotGone),
                    "{compat:?}"
                ),
            }
            for term in [Term(6), T, Term(8)] {
                assert_ne!(decide_retired(T, term, compat), SorAction::ExactRelease);
            }
        }
    }

    #[test]
    fn module_reads_no_clock_and_spawns_nothing() {
        let source = include_str!("obligation_reconciliation.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "Instant",
            "Duration",
            "SystemTime",
            "std::process",
            "thread::",
            "sleep",
            "AtomicBool",
        ] {
            assert!(!production.contains(forbidden), "{forbidden}");
        }
    }
}
