from __future__ import annotations

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.backends.mba.ida import (  # noqa: E402
    IDAPatternAdapter,
    attach_selected_certified_catalogue_snapshot,
)
from d810.hexrays.expr import ast as ast_dispatcher  # noqa: E402
from d810.hexrays.ir.mop_snapshot import MopSnapshot  # noqa: E402
from d810.mba.ac_matching import AcMatchStopReason  # noqa: E402
from d810.mba.dsl import Const, Var  # noqa: E402


def _leaf(name: str, register: int):
    leaf = ast_dispatcher.AstLeaf(name)
    leaf.mop = MopSnapshot(t=ida_hexrays.mop_r, size=4, reg=register)
    leaf.dest_size = 4
    return leaf


def _constant(value: int):
    constant = ast_dispatcher.AstConstant(str(value), value, 4)
    constant.mop = MopSnapshot(t=ida_hexrays.mop_n, size=4, value=value)
    constant.dest_size = 4
    return constant


def test_shadow_matcher_resolves_only_original_native_binding_paths() -> None:
    x = Var("x")

    class Rule:
        pattern = x + Const("one", 1)

    adapter = IDAPatternAdapter(Rule())
    adapter._attempt_destination_size = 4
    ast = ast_dispatcher.AstNode(ida_hexrays.m_add, _constant(1), _leaf("x", 1))
    ast.dest_size = 4

    report = adapter.observe_structural_match(ast)

    assert report is not None
    assert report.stop_reason is AcMatchStopReason.MATCHED
    assert report.bindings is not None
    assert report.bindings.candidate_path_by_name == {"x": (1,), "one": (0,)}


def test_shadow_matcher_never_claims_legacy_binding_parity() -> None:
    x = Var("x")

    class Rule:
        pattern = x + Const("one", 1)

    adapter = IDAPatternAdapter(Rule())
    adapter._attempt_destination_size = 4
    ast = ast_dispatcher.AstNode(ida_hexrays.m_add, _constant(1), _leaf("x", 1))
    ast.dest_size = 4

    assert adapter.observe_structural_match(ast) is not None

    metadata = adapter._shadow_metadata(legacy_match=True)

    assert metadata == {
        "legacy_match": True,
        "structural_match": True,
        "same_rule": True,
        "same_bindings": None,
    }


def test_shadow_matcher_compares_exact_legacy_native_paths_when_available() -> None:
    x = Var("x")

    class Rule:
        pattern = x + Const("one", 1)

    adapter = IDAPatternAdapter(Rule())
    adapter._attempt_destination_size = 4
    ast = ast_dispatcher.AstNode(ida_hexrays.m_add, _constant(1), _leaf("x", 1))
    ast.dest_size = 4

    assert adapter.observe_structural_match(ast) is not None
    legacy = ast_dispatcher.AstNode(
        ida_hexrays.m_add,
        ast_dispatcher.AstConstant("one", 1, 4),
        ast_dispatcher.AstLeaf("x"),
    )
    legacy.leafs_by_name = {"x": legacy.right, "one": legacy.left}
    adapter.record_legacy_match_bindings(legacy, ast)

    assert adapter._shadow_metadata(legacy_match=True)["same_bindings"] is True


def test_shadow_matcher_rejects_ambiguous_legacy_mop_paths() -> None:
    """Equal live mops in two slots cannot establish exact binding parity."""

    x, y = Var("x"), Var("y")

    class Rule:
        pattern = x + y

    adapter = IDAPatternAdapter(Rule())
    adapter._attempt_destination_size = 4
    ast = ast_dispatcher.AstNode(ida_hexrays.m_add, _leaf("left", 1), _leaf("right", 1))
    ast.dest_size = 4

    assert adapter.observe_structural_match(ast) is not None
    adapter.record_legacy_match_bindings(
        type(
            "LegacyCandidate", (), {"leafs_by_name": {"x": ast.left, "y": ast.right}}
        )()
    )

    assert adapter._shadow_metadata(legacy_match=True)["same_bindings"] is None


def test_shadow_matcher_accepts_a_structural_path_for_repeated_pattern_leaf() -> None:
    """A repeated declared leaf has several valid source slots, unlike aliases."""

    x = Var("x")

    class Rule:
        pattern = x + x

    adapter = IDAPatternAdapter(Rule())
    adapter._attempt_destination_size = 4
    ast = ast_dispatcher.AstNode(ida_hexrays.m_add, _leaf("left", 1), _leaf("right", 1))
    ast.dest_size = 4
    legacy = ast_dispatcher.AstNode(
        ida_hexrays.m_add,
        ast_dispatcher.AstLeaf("x"),
        ast_dispatcher.AstLeaf("x"),
    )
    legacy.leafs_by_name = {"x": legacy.right}

    assert adapter.observe_structural_match(ast) is not None
    adapter.record_legacy_match_bindings(legacy, ast)

    assert adapter._shadow_metadata(legacy_match=True)["same_bindings"] is True


def test_selected_snapshot_narrows_shadow_observation_without_compilation() -> None:
    x = Var("x")

    class AddRule:
        pattern = x + Const("one", 1)

    class XorRule:
        pattern = x ^ Const("one", 1)

    add_adapter = IDAPatternAdapter(AddRule())
    xor_adapter = IDAPatternAdapter(XorRule())
    snapshot, _ledger = attach_selected_certified_catalogue_snapshot(
        (add_adapter, xor_adapter)
    )
    assert snapshot.rules_in_declaration_order == (add_adapter.rule, xor_adapter.rule)

    xor_adapter._attempt_destination_size = 4
    ast = ast_dispatcher.AstNode(ida_hexrays.m_add, _constant(1), _leaf("x", 1))
    ast.dest_size = 4

    assert xor_adapter.observe_structural_match(ast) is None
