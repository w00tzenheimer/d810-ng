"""Packed native MBA matcher contracts independent of Hex-Rays runtime."""

from __future__ import annotations

from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue
from d810.backends.mba.egglog_add_rule_compiler import compile_add_rule_catalogue
from d810.backends.mba.native_mba_term_view import NativeMbaTermView
from d810.backends.mba.native_pod_matcher import (
    OP_ADD,
    PackedNativeMbaTerm,
    match_root_pod,
)


def _leaf(name: str) -> NativeMbaTermView:
    return NativeMbaTermView(
        None,
        32,
        leaf_key=("mop", "r", name),
        native_operand=object(),
    )


def _constant(value: int) -> NativeMbaTermView:
    return NativeMbaTermView(None, 32, constant_value=value)


def _node(name: str, *children: NativeMbaTermView) -> NativeMbaTermView:
    return NativeMbaTermView(name, 32, children=children)


def _rule(name: str):
    return compile_add_rule_catalogue().receipt_for(name).compiled_rule


def test_packed_view_separates_numeric_nodes_from_live_identity_sidecar() -> None:
    x, y = _leaf("x"), _leaf("y")
    packed = PackedNativeMbaTerm.from_view(_node("add", x, y))
    root = packed.nodes[packed.root_index]

    assert root.operation == OP_ADD
    assert all(type(node.literal_u64) is int for node in packed.nodes)
    assert packed.sidecar[root.left_index] is x
    assert packed.sidecar[root.right_index] is y


def test_packed_view_retains_associative_binary_structure_for_numeric_matching() -> (
    None
):
    x, y, z = _leaf("x"), _leaf("y"), _leaf("z")
    packed = PackedNativeMbaTerm.from_view(_node("add", _node("add", x, y), z))
    root = packed.nodes[packed.root_index]

    assert root.operation == OP_ADD
    assert packed.nodes[root.left_index].operation == OP_ADD
    assert len(packed.nodes) == 5


def test_packed_view_uses_ac_identity_for_repeated_operand_checks() -> None:
    a, b = _leaf("a"), _leaf("b")
    packed = PackedNativeMbaTerm.from_view(
        _node("xor", _node("add", a, b), _node("add", b, a))
    )
    root = packed.nodes[packed.root_index]
    rows = packed.numeric_rows()

    assert rows[root.left_index][7] == rows[root.right_index][7]


def test_pod_adapter_matches_portable_catalogue_exactly() -> None:
    rule = _rule("Add_HackersDelightRule_2")
    assert rule is not None
    catalogue = CompiledPatternCatalogue.from_rules((rule,))
    x, y = _leaf("x"), _leaf("y")
    candidate = _node(
        "add",
        _node("xor", y, x),
        _node("mul", _constant(2), _node("and", y, x)),
    )

    assert match_root_pod(catalogue, candidate, comparison_budget=64) == (
        catalogue.match_root(candidate, comparison_budget=64)
    )
