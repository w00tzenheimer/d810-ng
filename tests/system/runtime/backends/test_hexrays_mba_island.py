from __future__ import annotations

from types import MappingProxyType

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.backends.mba.hexrays_island import (  # noqa: E402
    lower_hexrays_island,
    rebuild_hexrays_island,
)
from d810.hexrays.expr import ast as ast_dispatcher  # noqa: E402
from d810.hexrays.ir.mop_snapshot import MopSnapshot  # noqa: E402
from d810.mba.island_profile import IslandBlocker, MbaIslandClass  # noqa: E402
from d810.mba.typed_term import TypedBvTerm, term_fingerprint  # noqa: E402


def _leaf(name: str, register: int, size: int = 4):
    leaf = ast_dispatcher.AstLeaf(name)
    leaf.mop = MopSnapshot(t=ida_hexrays.mop_r, size=size, reg=register)
    leaf.dest_size = size
    return leaf


def _constant(value: int, size: int = 4):
    wrapped = value & ((1 << (size * 8)) - 1)
    constant = ast_dispatcher.AstConstant(str(value), wrapped, size)
    constant.mop = MopSnapshot(t=ida_hexrays.mop_n, size=size, value=wrapped)
    constant.dest_size = size
    return constant


def _node(opcode: int, left, right=None, size: int = 4):
    node = ast_dispatcher.AstNode(opcode, left, right)
    node.dest_size = size
    return node


class _AstFactory:
    def xor_negative_coefficient(self, width_bytes: int = 4):
        x = _leaf("x", 1, width_bytes)
        y = _leaf("y", 2, width_bytes)
        return _node(
            ida_hexrays.m_add,
            _node(
                ida_hexrays.m_mul,
                _constant(-2, width_bytes),
                x,
                width_bytes,
            ),
            y,
            width_bytes,
        )


@pytest.fixture
def ast_factory():
    return _AstFactory()


def test_lowering_preserves_live_leafs_paths_and_rebuilds_supported_island():
    x = _leaf("x", 1)
    expression = _node(
        ida_hexrays.m_add,
        _node(ida_hexrays.m_and, x, _constant(7)),
        _node(ida_hexrays.m_bnot, x.clone()),
    )

    lowering = lower_hexrays_island(expression, destination_size=4)

    assert lowering.term is not None
    assert lowering.profile.island_class is MbaIslandClass.LINEAR_MBA
    assert lowering.profile.blockers == ()
    assert isinstance(lowering.leafs, MappingProxyType)
    assert () not in lowering.native_nodes_by_path
    assert lowering.native_nodes_by_path[(0, 0)].is_constant()
    assert lowering.native_nodes_by_path[(0, 0)].value == 7
    assert lowering.native_nodes_by_path[(0, 1)].mop == x.mop
    assert lowering.native_nodes_by_path[(1, 0)].mop == x.mop
    live_leaf_keys = []

    def collect_leaf_keys(term):
        if term.operation is None:
            if term.leaf_key is not None:
                live_leaf_keys.append(term.leaf_key)
            return
        for child in term.children:
            collect_leaf_keys(child)

    collect_leaf_keys(lowering.term)
    assert len(live_leaf_keys) == 2
    assert live_leaf_keys[0] == live_leaf_keys[1]

    rebuilt = rebuild_hexrays_island(
        lowering.term,
        lowering=lowering,
        destination_size=4,
    )

    assert isinstance(rebuilt, ast_dispatcher.AstNode)
    rebuilt_live_leafs = [
        leaf for leaf in rebuilt.get_leaf_list() if not leaf.is_constant()
    ]
    assert len(rebuilt_live_leafs) == 2
    assert all(leaf.mop == x.mop for leaf in rebuilt_live_leafs)


def test_lowering_retains_raw_source_order_term_and_paths_alongside_canonical_term():
    """Structural matching needs declared source order, not AC sort order."""

    b = _leaf("b", 2)
    a = _leaf("a", 1)
    expression = _node(ida_hexrays.m_xor, b, a)

    lowering = lower_hexrays_island(expression, destination_size=4)

    assert lowering.term is not None
    assert lowering.raw_term is not None
    assert lowering.canonical_view is not None
    assert lowering.raw_term == lowering.canonical_view.raw_term
    assert lowering.term == lowering.canonical_view.canonical_term
    assert lowering.profile.fingerprint == term_fingerprint(lowering.term)
    assert lowering.raw_term.children[0].leaf_key != lowering.term.children[0].leaf_key
    assert lowering.raw_native_nodes_by_path[(0,)] is b
    assert lowering.raw_native_nodes_by_path[(1,)] is a


def test_negative_coefficient_lowering_preserves_raw_native_provenance(ast_factory):
    source = ast_factory.xor_negative_coefficient(width_bytes=4)
    rendered_before = str(source)
    lowering = lower_hexrays_island(source, destination_size=4)

    assert lowering.canonical_view is not None
    assert lowering.raw_term == lowering.canonical_view.raw_term
    assert lowering.term == lowering.canonical_view.canonical_term
    assert lowering.term.operation == "sub"
    assert str(source) == rendered_before
    assert lowering.raw_native_nodes_by_path[()] is source
    assert () not in lowering.native_nodes_by_path
    assert len(lowering.leafs) == 2
    assert any(leaf is source.left.right for leaf in lowering.leafs.values())
    assert any(leaf is source.right for leaf in lowering.leafs.values())

    x_key, y_key = sorted(lowering.leafs, key=repr)
    replacement = TypedBvTerm(
        "xor",
        32,
        children=(
            TypedBvTerm(None, 32, leaf_key=x_key),
            TypedBvTerm(None, 32, leaf_key=y_key),
        ),
    )
    assert rebuild_hexrays_island(
        replacement, lowering=lowering, destination_size=4
    ) is not None


def test_ac_reordering_retains_a_moved_exact_raw_subtree():
    x = _leaf("x", 1)
    y = _leaf("y", 2)
    z = _leaf("z", 3)
    nested = _node(ida_hexrays.m_xor, x, y)
    source = _node(ida_hexrays.m_xor, z, nested)

    lowering = lower_hexrays_island(source, destination_size=4)

    assert lowering.term is not None
    assert lowering.term.operation == "xor"
    assert lowering.term.children[0].operation == "xor"
    assert lowering.native_nodes_by_path[(0,)] is nested
    assert lowering.raw_native_nodes_by_path[(1,)] is nested


def test_ac_rebracketing_leaves_a_new_internal_group_unmapped():
    x = _leaf("x", 1)
    y = _leaf("y", 2)
    z = _leaf("z", 3)
    nested = _node(ida_hexrays.m_xor, y, z)
    source = _node(ida_hexrays.m_xor, x, nested)

    lowering = lower_hexrays_island(source, destination_size=4)

    assert lowering.term is not None
    assert lowering.term.children[0].operation == "xor"
    assert lowering.term.children[0].children[0].leaf_key == (
        "mop",
        ida_hexrays.mop_r,
        4,
        1,
    )
    assert (0,) not in lowering.native_nodes_by_path
    assert lowering.raw_native_nodes_by_path[(1,)] is nested


@pytest.mark.parametrize(
    ("opcode_name", "has_right"),
    (
        ("m_add", True),
        ("m_sub", True),
        ("m_mul", True),
        ("m_and", True),
        ("m_or", True),
        ("m_xor", True),
        ("m_bnot", False),
        ("m_neg", False),
    ),
)
def test_lowering_accepts_each_catalogue_operation(opcode_name, has_right):
    expression = _node(
        getattr(ida_hexrays, opcode_name),
        _leaf("x", 1),
        _leaf("y", 2) if has_right else None,
    )

    lowering = lower_hexrays_island(expression, destination_size=4)

    assert lowering.term is not None
    assert lowering.profile.blockers == ()


@pytest.mark.parametrize(
    ("opcode_name", "blocker"),
    (
        ("m_xdu", IslandBlocker.CAST),
        ("m_xds", IslandBlocker.CAST),
        ("m_low", IslandBlocker.CAST),
        ("m_high", IslandBlocker.CAST),
        ("m_shl", IslandBlocker.AMBIGUOUS_SHIFT),
        ("m_shr", IslandBlocker.AMBIGUOUS_SHIFT),
        ("m_sar", IslandBlocker.AMBIGUOUS_SHIFT),
        ("m_ldx", IslandBlocker.LOAD),
        ("m_call", IslandBlocker.CALL),
        ("m_setz", IslandBlocker.PREDICATE),
        ("m_setg", IslandBlocker.PREDICATE),
    ),
)
def test_lowering_fail_closes_known_unsupported_native_operations(opcode_name, blocker):
    opcode = getattr(ida_hexrays, opcode_name)
    expression = _node(opcode, _leaf("x", 1), _leaf("y", 2))

    lowering = lower_hexrays_island(expression, destination_size=4)

    assert lowering.term is None
    assert lowering.profile.island_class is MbaIslandClass.UNSUPPORTED
    assert lowering.profile.blockers == (blocker,)


def test_lowering_rejects_mixed_width_and_missing_destination_size():
    expression = _node(ida_hexrays.m_add, _leaf("wide", 1, 4), _leaf("narrow", 2, 2))

    mixed = lower_hexrays_island(expression, destination_size=4)
    missing = lower_hexrays_island(expression, destination_size=0)

    assert mixed.term is None
    assert mixed.profile.blockers == (IslandBlocker.MIXED_WIDTH,)
    assert missing.term is None
    assert missing.profile.island_class is MbaIslandClass.UNSUPPORTED
