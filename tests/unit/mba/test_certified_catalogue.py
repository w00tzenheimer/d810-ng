from __future__ import annotations

from d810.mba.certified_catalogue import (
    ShadowMatcherParityLedger,
    build_certified_catalogue_snapshot,
)
from d810.mba.dsl import Var


class _Rule:
    def __init__(self, name: str, pattern, family: str = "add") -> None:
        self.source_name = name
        self.pattern = pattern
        self.family = family


def test_snapshot_is_memoized_immutable_and_preserves_declaration_order() -> None:
    x, y = Var("x"), Var("y")
    first = _Rule("later_alphabetically", x + y)
    second = _Rule("earlier_alphabetically", x ^ y)

    snapshot = build_certified_catalogue_snapshot(
        (first, second), compiler_version="v1"
    )
    same = build_certified_catalogue_snapshot((first, second), compiler_version="v1")

    assert snapshot is same
    assert snapshot.rules_in_declaration_order == (first, second)
    assert snapshot.rule_ids_by_root_shape[("add", 32, 2)] == (0,)
    assert snapshot.rule_ids_by_root_shape[("xor", 32, 2)] == (1,)
    assert ("sub", 32, 2) not in snapshot.rule_ids_by_root_shape
    try:
        snapshot.rule_ids_by_root_shape[("sub", 32, 2)] = (0,)  # type: ignore[index]
    except TypeError:
        pass
    else:
        raise AssertionError("snapshot index must be immutable")


def test_snapshot_fingerprint_changes_with_content_version_or_enabled_families() -> (
    None
):
    x, y = Var("x"), Var("y")
    first = build_certified_catalogue_snapshot(
        (_Rule("one", x + y),), compiler_version="v1"
    )
    changed_rule = build_certified_catalogue_snapshot(
        (_Rule("two", x + y),), compiler_version="v1"
    )
    changed_version = build_certified_catalogue_snapshot(
        (_Rule("one", x + y),), compiler_version="v2"
    )
    changed_widths = build_certified_catalogue_snapshot(
        (_Rule("one", x + y),), compiler_version="v1", widths=(32,)
    )
    changed_families = build_certified_catalogue_snapshot(
        (_Rule("one", x + y),), compiler_version="v1", enabled_families=("add",)
    )

    assert first.fingerprint != changed_rule.fingerprint
    assert first.fingerprint != changed_version.fingerprint
    assert first.fingerprint != changed_widths.fingerprint
    assert first.fingerprint != changed_families.fingerprint


def test_enabled_families_filter_rules_before_root_bucket_indexing() -> None:
    x, y = Var("x"), Var("y")
    add_rule = _Rule("add", x + y, family="add")
    xor_rule = _Rule("xor", x ^ y, family="xor")

    snapshot = build_certified_catalogue_snapshot(
        (add_rule, xor_rule),
        compiler_version="v1",
        enabled_families=("add",),
    )

    assert snapshot.rules_in_declaration_order == (add_rule,)
    assert snapshot.rule_ids_by_root_shape == {
        ("add", 8, 2): (0,),
        ("add", 16, 2): (0,),
        ("add", 32, 2): (0,),
        ("add", 64, 2): (0,),
    }


def test_shadow_ledger_counts_only_evidence_backed_legacy_parity_mismatches() -> None:
    ledger = ShadowMatcherParityLedger()

    ledger.record(
        legacy_match=False, structural_match=True, same_rule=False, same_bindings=None
    )
    ledger.record(
        legacy_match=True, structural_match=True, same_rule=True, same_bindings=True
    )
    ledger.record(
        legacy_match=True, structural_match=True, same_rule=True, same_bindings=None
    )
    ledger.record(
        legacy_match=True, structural_match=False, same_rule=False, same_bindings=False
    )

    assert ledger.observation_count == 4
    assert ledger.legacy_match_count == 3
    assert ledger.legacy_rule_mismatches == 1
    assert ledger.legacy_binding_mismatches == 1
    assert ledger.legacy_binding_unknown == 1
