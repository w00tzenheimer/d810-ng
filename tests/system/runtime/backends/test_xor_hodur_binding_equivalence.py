"""Native experiment for the Xor_Hodur_1 AC-binding mismatch witness."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")

import d810.backends.mba.ida as ida_backend  # noqa: E402
from d810.backends.mba.ida import IDAPatternAdapter  # noqa: E402
from d810.backends.mba.native_z3 import prove_native_ast_equivalence  # noqa: E402
from d810.hexrays.expr import ast as ast_dispatcher  # noqa: E402
from d810.hexrays.ir.mop_snapshot import MopSnapshot  # noqa: E402
from d810.mba.rules.hodur import Xor_Hodur_1  # noqa: E402
from tests.system.runtime.backends.test_ida_ac_matching import (  # noqa: E402
    _raw_register,
)


WIDTH_BYTES = 8
WIDTH_BITS = WIDTH_BYTES * 8
WITNESS_EA = 0x18001EBBE
WITNESS_CONSTANT = 0x8654A2C4DA7F0260
CANONICAL_PATHS = {"x": (0, 0, 0), "y": (0, 0, 1), "z": (0, 1)}
LEGACY_PATHS = {
    "y": frozenset({(0, 0, 0)}),
    "z": frozenset({(0, 0, 1)}),
    "x": frozenset({(0, 1)}),
}


def _leaf(name: str, register: int):
    leaf = ast_dispatcher.AstLeaf(name)
    leaf.mop = MopSnapshot(t=ida_hexrays.mop_r, size=WIDTH_BYTES, reg=register)
    leaf.dest_size = WIDTH_BYTES
    leaf.proof_origin = ("xor-hodur-r1", name)
    return leaf


def _constant(value: int):
    constant = ast_dispatcher.AstConstant(str(value), value, WIDTH_BYTES)
    constant.mop = MopSnapshot(
        t=ida_hexrays.mop_n,
        size=WIDTH_BYTES,
        value=value,
    )
    constant.dest_size = WIDTH_BYTES
    constant.proof_origin = ("xor-hodur-r1", "constant")
    return constant


def _node(opcode: int, left, right=None):
    node = ast_dispatcher.AstNode(opcode, left, right)
    node.dest_size = WIDTH_BYTES
    return node


def _experiment():
    a = _leaf("a", 256)
    b = _leaf("b", 16)
    c = _constant(WITNESS_CONSTANT)
    source = _node(
        ida_hexrays.m_bnot,
        _node(ida_hexrays.m_xor, _node(ida_hexrays.m_xor, a, b), c),
    )
    source.ea = WITNESS_EA
    source.dst_mop = _raw_register(96, size=WIDTH_BYTES)

    adapter = IDAPatternAdapter(Xor_Hodur_1())
    adapter._attempt_destination_size = WIDTH_BYTES
    adapter._shadow_source_ast = source
    adapter._shadow_structural_native_paths = dict(CANONICAL_PATHS)
    adapter._legacy_binding_paths = dict(LEGACY_PATHS)

    return SimpleNamespace(
        adapter=adapter,
        source=source,
        a=a,
        b=b,
        c=c,
        aliases=(a, b, c),
        alias_state=tuple((id(leaf), leaf.mop, leaf.proof_origin) for leaf in (a, b, c)),
        source_repr=repr(source),
        source_state=(source.ea, source.dst_mop, source.dest_size),
        canonical_paths=adapter._shadow_structural_native_paths,
        legacy_paths=adapter._legacy_binding_paths,
    )


def _emit(adapter, source, *, x, y, z):
    candidate = ida_backend._ShadowBindingCandidate(
        {"x": x, "y": y, "z": z}, source
    )
    replacement_instruction = adapter._get_shadow_replacement(candidate)
    assert replacement_instruction is not None
    replacement = ida_backend.minsn_to_ast(replacement_instruction)
    assert replacement is not None
    return replacement


def _assert_source_and_adapter_unchanged(experiment) -> None:
    adapter = experiment.adapter
    assert repr(experiment.source) == experiment.source_repr
    assert (
        experiment.source.ea,
        experiment.source.dst_mop,
        experiment.source.dest_size,
    ) == experiment.source_state
    assert tuple(
        (id(leaf), leaf.mop, leaf.proof_origin) for leaf in experiment.aliases
    ) == experiment.alias_state
    assert adapter._shadow_source_ast is experiment.source
    assert adapter._shadow_structural_native_paths is experiment.canonical_paths
    assert adapter._shadow_structural_native_paths == CANONICAL_PATHS
    assert adapter._legacy_binding_paths is experiment.legacy_paths
    assert adapter._legacy_binding_paths == LEGACY_PATHS


@pytest.mark.usefixtures("ida_database")
class TestXorHodurBindingEquivalence:
    binary_name = "libobfuscated.dll"

    def test_canonical_binding_emits_equivalent_equal_cost_replacement(self):
        experiment = _experiment()
        adapter = experiment.adapter
        template = adapter.REPLACEMENT_PATTERN
        assert all(leaf.mop is None for leaf in template.get_leaf_list())

        replacement = _emit(
            adapter,
            experiment.source,
            x=experiment.a,
            y=experiment.b,
            z=experiment.c,
        )

        assert replacement.opcode == ida_hexrays.m_xor
        assert replacement.left.mop == experiment.a.mop
        assert replacement.right.opcode == ida_hexrays.m_xor
        assert replacement.right.left.mop == experiment.b.mop
        assert replacement.right.right.opcode == ida_hexrays.m_bnot
        assert replacement.right.right.left.value == WITNESS_CONSTANT
        assert adapter._ast_cost(experiment.source) == (3, 6)
        assert adapter._ast_cost(replacement) == (3, 6)
        assert prove_native_ast_equivalence(
            experiment.source,
            replacement,
            width=WIDTH_BITS,
        )
        assert experiment.adapter._shadow_native_equivalence_verdict is None
        assert all(leaf.mop is None for leaf in template.get_leaf_list())
        _assert_source_and_adapter_unchanged(experiment)

    def test_native_proof_rejects_same_cost_changed_constant(self):
        experiment = _experiment()
        replacement = _emit(
            experiment.adapter,
            experiment.source,
            x=experiment.a,
            y=experiment.b,
            z=_constant(WITNESS_CONSTANT ^ 1),
        )

        assert experiment.adapter._ast_cost(replacement) == (3, 6)
        assert not prove_native_ast_equivalence(
            experiment.source,
            replacement,
            width=WIDTH_BITS,
        )
        _assert_source_and_adapter_unchanged(experiment)

    def test_structural_only_gate_still_refuses_equal_cost_candidate(self):
        experiment = _experiment()
        replacement = _emit(
            experiment.adapter,
            experiment.source,
            x=experiment.a,
            y=experiment.b,
            z=experiment.c,
        )
        assert experiment.adapter._ast_cost(experiment.source) == (3, 6)
        assert experiment.adapter._ast_cost(replacement) == (3, 6)
        assert prove_native_ast_equivalence(
            experiment.source,
            replacement,
            width=WIDTH_BITS,
        )

        assert experiment.adapter._prove_structural_only_candidate() is False
        assert experiment.adapter._shadow_structural_refused is True
        assert experiment.adapter._shadow_native_equivalence_verdict is None
        _assert_source_and_adapter_unchanged(experiment)
