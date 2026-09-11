"""Unsupported legacy matches must be explicit, not canonical mismatches."""

from d810.backends.mba.ida import (
    IDAPatternAdapter, attach_selected_certified_catalogue_snapshot,
)
from d810.mba.rules.cst import CstSimplificationRule8
from d810.mba.rules.predicates import PredFFRule1


def test_legacy_only_observation_is_counted_outside_canonical_parity():
    eligible = IDAPatternAdapter(CstSimplificationRule8())
    excluded = IDAPatternAdapter(PredFFRule1())
    snapshot, ledger = attach_selected_certified_catalogue_snapshot(
        (eligible, excluded), runtime_mode='cython',
    )
    assert snapshot.structural_authorizable
    excluded._record_shadow_parity(legacy_match=True)
    assert ledger.observation_count == 0
    assert ledger.legacy_match_count == 0
    assert ledger.legacy_rule_mismatches == 0
    assert excluded.legacy_only_observation_count == 1
    assert excluded.legacy_only_match_count == 1
    # Calling the finalizer twice must not double-count one attempt.
    excluded._record_shadow_parity(legacy_match=True)
    assert excluded.legacy_only_observation_count == 1
    eligible._record_shadow_parity(legacy_match=False)
    assert ledger.observation_count == 1


def test_reattachment_resets_excluded_counts_with_new_ledger():
    excluded = IDAPatternAdapter(PredFFRule1())
    snapshot, first = attach_selected_certified_catalogue_snapshot(
        (excluded,), runtime_mode='cython',
    )
    excluded._record_shadow_parity(legacy_match=True)
    same_snapshot, second = attach_selected_certified_catalogue_snapshot(
        (excluded,), runtime_mode='cython',
    )
    assert snapshot is same_snapshot
    assert first is not second
    assert excluded.legacy_only_observation_count == 0
    assert excluded.legacy_only_match_count == 0
