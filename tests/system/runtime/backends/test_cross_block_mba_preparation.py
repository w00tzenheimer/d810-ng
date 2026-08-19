"""Read-only cross-block constant preparation for bounded MBA exploration."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.backends.mba.cross_block_preparation import (  # noqa: E402
    constant_environment_before_instruction,
    prepare_ast_with_def_use_constants,
    prepare_ast_with_cross_block_constants,
    rewrite_ast_with_constant_resolver,
)
from d810.backends.mba.hexrays_island import lower_hexrays_island  # noqa: E402
from d810.backends.mba.native_z3 import prove_native_ast_equivalence  # noqa: E402
from d810.hexrays.expr import ast as ast_dispatcher  # noqa: E402
from d810.hexrays.ir.mop_snapshot import MopSnapshot  # noqa: E402
from d810.ir.lattice import Const  # noqa: E402


class _Insn:
    def __init__(self, opcode, *, left=None, right=None, dest=None) -> None:
        self.opcode = opcode
        self.l = left
        self.r = right
        self.d = dest
        self.next = None
        self.ea = 0x401000

    def has_side_effects(self) -> bool:
        return False


def _stack(name: str, size: int = 4):
    return SimpleNamespace(t=ida_hexrays.mop_S, size=size, name=name)


def _number(value: int, size: int = 4):
    return SimpleNamespace(
        t=ida_hexrays.mop_n,
        size=size,
        nnn=SimpleNamespace(value=value),
    )


@pytest.mark.usefixtures("configure_hexrays")
def test_constant_environment_is_exactly_before_target_instruction(monkeypatch):
    """The public FCP lattice supplies a read-only, pre-use constant value."""

    definition = _Insn(
        ida_hexrays.m_mov,
        left=_number(0xA0DE427),
        dest=_stack("carrier"),
    )
    target = _Insn(ida_hexrays.m_add, left=_stack("carrier"))
    definition.next = target
    block = SimpleNamespace(serial=0, head=definition, predset=(), succset=())
    mba = SimpleNamespace(qty=1, get_mblock=lambda serial: block)
    block.mba = mba

    monkeypatch.setattr(
        "d810.hexrays.ir.mop_utils.constant_propagation_var_name",
        lambda mop: mop.name,
    )

    environment = constant_environment_before_instruction(mba, block, target)

    assert environment is not None
    assert environment["carrier"] == Const(0xA0DE427, 4)


@pytest.mark.usefixtures("configure_hexrays")
def test_constant_environment_accepts_unique_callback_wrapper_anchor(monkeypatch):
    """A callback wrapper may lose minsn identity but retains one block-local anchor."""

    definition = _Insn(
        ida_hexrays.m_mov,
        left=_number(0xA0DE427),
        dest=_stack("carrier"),
    )
    target = _Insn(ida_hexrays.m_nop, dest=_stack("result"))
    target.ea = 0x401004
    definition.next = target
    block = SimpleNamespace(serial=0, head=definition, predset=(), succset=())
    mba = SimpleNamespace(qty=1, get_mblock=lambda serial: block)
    block.mba = mba
    # Hex-Rays supplies the nested MBA expression to the handler, while the
    # forward lattice is anchored to the containing linked-list instruction.
    callback_wrapper = _Insn(ida_hexrays.m_sub, dest=_stack("nested", size=8))
    callback_wrapper.ea = target.ea

    monkeypatch.setattr(
        "d810.hexrays.ir.mop_utils.constant_propagation_var_name",
        lambda mop: mop.name,
    )

    environment = constant_environment_before_instruction(
        mba, block, callback_wrapper
    )

    assert environment is not None
    assert environment["carrier"] == Const(0xA0DE427, 4)


@pytest.mark.usefixtures("configure_hexrays")
def test_constant_environment_refuses_ambiguous_callback_ea(monkeypatch):
    """A nested callback EA is usable only once within its supplied block."""

    definition = _Insn(
        ida_hexrays.m_mov,
        left=_number(0xA0DE427),
        dest=_stack("carrier"),
    )
    first = _Insn(ida_hexrays.m_nop, dest=_stack("first"))
    second = _Insn(ida_hexrays.m_nop, dest=_stack("second"))
    definition.ea = 0x400FFC
    second.ea = first.ea
    definition.next = first
    first.next = second
    block = SimpleNamespace(serial=0, head=definition, predset=(), succset=())
    mba = SimpleNamespace(qty=1, get_mblock=lambda serial: block)
    callback_wrapper = _Insn(ida_hexrays.m_sub, dest=_stack("nested", size=8))
    callback_wrapper.ea = first.ea

    monkeypatch.setattr(
        "d810.hexrays.ir.mop_utils.constant_propagation_var_name",
        lambda mop: mop.name,
    )

    assert constant_environment_before_instruction(mba, block, callback_wrapper) is None


@pytest.mark.usefixtures("configure_hexrays")
def test_rewrite_ast_constants_clones_and_never_changes_the_live_ast(monkeypatch):
    """Preparation may specialize only a disposable AST clone."""

    carrier = ast_dispatcher.AstLeaf("carrier")
    carrier.mop = MopSnapshot(t=ida_hexrays.mop_r, size=4, reg=3)
    carrier.dest_size = 4
    original = ast_dispatcher.AstNode(ida_hexrays.m_xor, carrier, carrier.clone())
    original.dest_size = 4
    monkeypatch.setattr(
        ast_dispatcher,
        "get_constant_mop",
        lambda value, size: MopSnapshot(
            t=ida_hexrays.mop_n,
            size=size,
            value=value & ((1 << (size * 8)) - 1),
        ),
    )

    prepared, substitutions = rewrite_ast_with_constant_resolver(
        original,
        resolve_constant=lambda leaf: (0xA0DE427, 4)
        if leaf.name == "carrier"
        else None,
    )

    assert prepared is not original
    assert substitutions == 2
    assert all(leaf.is_constant() for leaf in prepared.get_leaf_list())
    assert all(not leaf.is_constant() for leaf in original.get_leaf_list())
    assert all(leaf.value == 0xA0DE427 for leaf in prepared.get_leaf_list())


@pytest.mark.usefixtures("configure_hexrays")
def test_native_proof_requires_exact_cross_block_constant_assumption():
    """A prepared replacement cannot bypass the native proof's leaf identity."""

    carrier = ast_dispatcher.AstLeaf("carrier")
    carrier.mop = MopSnapshot(t=ida_hexrays.mop_r, size=4, reg=3)
    carrier.dest_size = 4
    replacement = ast_dispatcher.AstConstant("c", 0xA0DE427, 4)
    replacement.mop = MopSnapshot(
        t=ida_hexrays.mop_n,
        size=4,
        value=0xA0DE427,
    )
    replacement.dest_size = 4
    lowering = lower_hexrays_island(carrier, destination_size=4)
    assert lowering.term is not None
    assert lowering.term.leaf_key is not None

    assert not prove_native_ast_equivalence(carrier, replacement, width=32)
    assert prove_native_ast_equivalence(
        carrier,
        replacement,
        width=32,
        known_constants={lowering.term.leaf_key: 0xA0DE427},
    )


@pytest.mark.usefixtures("configure_hexrays")
def test_preparation_carries_only_exact_live_leaf_assumptions(monkeypatch):
    """The clone and proof constraints are tied to one live leaf identity."""

    import d810.backends.mba.cross_block_preparation as preparation

    class _StackMop:
        t = ida_hexrays.mop_S
        size = 4
        name = "carrier"

        @staticmethod
        def to_cache_key():
            return (ida_hexrays.mop_S, 4, 0x20)

    carrier = ast_dispatcher.AstLeaf("carrier")
    carrier.mop = _StackMop()
    carrier.dest_size = 4
    monkeypatch.setattr(
        preparation,
        "constant_environment_before_instruction",
        lambda *_args: {"carrier": Const(0xA0DE427, 4)},
    )
    monkeypatch.setattr(
        preparation,
        "constant_propagation_var_name",
        lambda mop: mop.name,
    )
    monkeypatch.setattr(
        ast_dispatcher,
        "get_constant_mop",
        lambda value, size: MopSnapshot(
            t=ida_hexrays.mop_n,
            size=size,
            value=value,
        ),
    )

    prepared = prepare_ast_with_cross_block_constants(
        object(),
        object(),
        object(),
        carrier,
    )

    assert prepared is not None
    assert prepared.ast.is_constant()
    assert prepared.known_constants == {
        ("mop", ida_hexrays.mop_S, 4, 0x20): 0xA0DE427
    }


@pytest.mark.usefixtures("configure_hexrays")
def test_def_use_preparation_specializes_only_a_resolved_literal(monkeypatch):
    """One bounded def-use edge may provide an exact literal for e-graph extraction only."""

    import d810.backends.mba.cross_block_preparation as preparation

    class _FakeSnapshot:
        def __init__(self, *, t, size, reg=None, value=None):
            self.t = t
            self.size = size
            self.reg = reg
            self.value = value

        def to_mop(self, *, mba=None):  # noqa: ARG002
            return SimpleNamespace(t=self.t, size=self.size, r=self.reg)

        def to_cache_key(self):
            return (
                (self.t, self.size, self.value)
                if self.t == ida_hexrays.mop_n
                else (self.t, self.size, self.reg)
            )

    monkeypatch.setattr(preparation, "MopSnapshot", _FakeSnapshot)
    carrier = ast_dispatcher.AstLeaf("carrier")
    carrier.mop = _FakeSnapshot(t=ida_hexrays.mop_r, size=4, reg=3)
    carrier.dest_size = 4
    resolved = ast_dispatcher.AstConstant("c", 0xA0DE427, 4)
    resolved.dest_size = 4
    monkeypatch.setattr(
        preparation,
        "resolve_mop_to_ast",
        lambda *args, **kwargs: resolved,
        raising=False,
    )
    monkeypatch.setattr(
        preparation,
        "_resolve_block_instruction",
        lambda block, instruction: instruction,
    )
    monkeypatch.setattr(
        ast_dispatcher,
        "get_constant_mop",
        lambda value, size: _FakeSnapshot(
            t=ida_hexrays.mop_n,
            size=size,
            value=value,
        ),
    )

    prepared = prepare_ast_with_def_use_constants(
        object(),
        object(),
        object(),
        carrier,
    )

    assert prepared is not None
    assert prepared.ast.is_constant()
    assert prepared.known_constants == {
        ("mop", ida_hexrays.mop_r, 4, 3): 0xA0DE427
    }
