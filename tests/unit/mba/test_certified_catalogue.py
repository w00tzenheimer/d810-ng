from __future__ import annotations

from d810.mba.certified_catalogue import build_certified_catalogue_snapshot
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
