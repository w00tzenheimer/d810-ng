"""Tests for equality-chain dispatcher row extraction."""
from __future__ import annotations

import inspect
from types import SimpleNamespace

import d810.analyses.control_flow.equality_chain_dispatcher as equality_chain_dispatcher
from d810.analyses.control_flow.equality_chain_dispatcher import (
    extract_state_dispatcher_map_from_mba,
)
from d810.ir.flowgraph import InsnKind, InsnSnapshot, MopSnapshot, OperandKind
from d810.ir.semantics import PredicateKind


def _mop_n(value: int):
    return MopSnapshot(kind=OperandKind.NUMBER, value=value, size=4)


# Canonical operand duck-types that carry only the portable ``MopSnapshot``
# surface the canonical projection reads (``kind`` / ``size`` / scalar identity
# + the ``sub_l`` / ``sub_r`` / ``args`` nested-operand fields the projection's
# address walk touches) and RAISE on any raw Hex-Rays accessor.  They prove the
# ported recon path reaches operand identity through ``operand_storages`` /
# ``project_instruction`` only, never the backend-shaped ``.nnn`` / ``.s`` /
# ``.l`` / ``.t`` operand fields.
class _CanonicalConstWithoutRawNnn:
    kind = OperandKind.NUMBER
    value = 0x44
    size = 4
    sub_l = None
    sub_r = None
    args = ()

    @property
    def nnn(self):  # pragma: no cover - test fails if accessed
        raise AssertionError("equality-chain dispatcher read raw .nnn")

    @property
    def nnn_value(self):  # pragma: no cover - test fails if accessed
        raise AssertionError("equality-chain dispatcher read raw .nnn_value")


class _CanonicalStackWithoutRawS:
    kind = OperandKind.STACK
    stkoff = 0x3C
    size = 4
    sub_l = None
    sub_r = None
    args = ()

    @property
    def s(self):  # pragma: no cover - test fails if accessed
        raise AssertionError("equality-chain dispatcher read raw .s")

    @property
    def t(self):  # pragma: no cover - test fails if accessed
        raise AssertionError("equality-chain dispatcher read raw .t")


class _CanonicalLvarWithoutRawL:
    kind = OperandKind.LVAR
    lvar_off = 5
    size = 4
    sub_l = None
    sub_r = None
    args = ()

    @property
    def l(self):  # pragma: no cover - test fails if accessed
        raise AssertionError("equality-chain dispatcher read raw .l")

    @property
    def t(self):  # pragma: no cover - test fails if accessed
        raise AssertionError("equality-chain dispatcher read raw .t")


def _mop_s(off: int):
    return MopSnapshot(kind=OperandKind.STACK, stkoff=off, size=4)


def _mop_l(idx: int):
    return MopSnapshot(kind=OperandKind.LVAR, lvar_off=idx, size=4)


def _mop_b(serial: int):
    return MopSnapshot(kind=OperandKind.BLOCK, block_ref=serial)


def _mov(src, dst):
    """A real MOV ``InsnSnapshot`` (state-var alias source ``l`` -> dest ``d``).

    The canonical state-var-alias reader consumes ``operand_storages`` slot
    ``l`` (source) / ``d`` (dest), so the move must be a real ``InsnSnapshot``
    with those operand slots populated (never a duck-typed namespace).
    """
    return InsnSnapshot(
        opcode=-1,
        ea=0,
        operands=(),
        kind=InsnKind.MOV,
        l=src,
        d=dst,
    )


def _eq_tail(*, predicate: PredicateKind, state_mop, const: int, jump_target: int):
    """A real equality/inequality-jump ``InsnSnapshot`` tail.

    ``kind=EQUALITY_JUMP`` + ``predicate_kind`` makes the canonical projection
    populate ``control.predicate`` and ``control.target`` (from the ``d`` BLOCK
    operand) the recon extractor reads; the compared operands are the ``l``
    state operand and the ``r`` numeric constant.
    """
    return InsnSnapshot(
        opcode=-1,
        ea=0,
        operands=(),
        kind=InsnKind.EQUALITY_JUMP,
        predicate_kind=predicate,
        l=state_mop if state_mop is not None else _mop_s(0x3C),
        r=_mop_n(const),
        d=_mop_b(jump_target),
    )


def _block(
    serial: int,
    *,
    predicate: PredicateKind = PredicateKind.EQ,
    state_mop=None,
    const: int = 0,
    jump_target: int = 0,
    succs: tuple[int, int] = (0, 0),
    insns: tuple[object, ...] = (),
    block_type: object = "BLT_2WAY",
    tail: object | None = None,
):
    if tail is None:
        tail = _eq_tail(
            predicate=predicate,
            state_mop=state_mop,
            const=const,
            jump_target=jump_target,
        )
    return SimpleNamespace(
        serial=serial,
        type=block_type,
        succset=succs,
        insns=insns,
        tail=tail,
    )


class _Mba:
    def __init__(self, blocks: dict[int, object]):
        self.blocks = blocks
        self.qty = max(blocks) + 1

    def get_mblock(self, serial: int):
        return self.blocks.get(int(serial))


def test_extracts_jz_exact_rows_from_linear_chain() -> None:
    mba = _Mba(
        {
            2: _block(2, const=0x10, jump_target=7, succs=(3, 7)),
            3: _block(3, const=0x20, jump_target=9, succs=(4, 9)),
        }
    )

    dispatch_map = extract_state_dispatcher_map_from_mba(
        mba,
        dispatcher_entry_block=2,
    )

    assert dispatch_map is not None
    assert dispatch_map.state_to_handler() == {0x10: 7, 0x20: 9}
    assert dispatch_map.dispatcher_blocks == frozenset({2, 3})
    assert dispatch_map.state_var_stkoff == 0x3C


def test_canonicalizes_direct_dispatcher_state_scratch_alias() -> None:
    state_var = _mop_s(0x364)
    scratch = _mop_s(0x350)
    mba = _Mba(
        {
            2: _block(
                2,
                predicate=PredicateKind.NE,
                state_mop=state_var,
                const=0x10,
                jump_target=3,
                succs=(7, 3),
                insns=(_mov(state_var, scratch),),
            ),
            3: _block(
                3,
                state_mop=scratch,
                const=0x20,
                jump_target=9,
                succs=(4, 9),
            ),
        }
    )

    dispatch_map = extract_state_dispatcher_map_from_mba(
        mba,
        dispatcher_entry_block=2,
    )

    assert dispatch_map is not None
    assert dispatch_map.state_to_handler() == {0x10: 7, 0x20: 9}
    assert dispatch_map.state_var_stkoff == 0x364


def test_extracts_snapshot_constants_from_canonical_value() -> None:
    tail = InsnSnapshot(
        opcode=-1,
        ea=0,
        operands=(),
        kind=InsnKind.EQUALITY_JUMP,
        predicate_kind=PredicateKind.EQ,
        l=_CanonicalStackWithoutRawS(),
        r=_CanonicalConstWithoutRawNnn(),
        d=_mop_b(7),
    )
    mba = _Mba(
        {
            2: _block(2, succs=(3, 7), tail=tail),
        }
    )

    dispatch_map = extract_state_dispatcher_map_from_mba(
        mba,
        dispatcher_entry_block=2,
    )

    assert dispatch_map is not None
    assert dispatch_map.state_to_handler() == {0x44: 7}


def test_backend_specific_numeric_names_belong_in_adapter_not_recon() -> None:
    # Recon consumes a normalized ``InsnSnapshot`` whose semantic predicate is
    # produced by the live adapter, never raw Hex-Rays opcode/mop-type numbers.
    # A tail carrying no portable predicate yields no rows -- recon does not
    # re-derive an equality compare from a raw opcode integer (``opcode=444``).
    tail = InsnSnapshot(
        opcode=444,
        ea=0,
        operands=(),
        kind=InsnKind.UNKNOWN,
        predicate_kind=None,
        l=_mop_s(0x3C),
        r=_mop_n(0x55),
        d=_mop_b(7),
    )
    mba = _Mba(
        {
            2: _block(2, succs=(3, 7), block_type=4, tail=tail),
        }
    )

    signature = inspect.signature(extract_state_dispatcher_map_from_mba)

    assert "opcode_names" not in signature.parameters
    assert "mop_type_names" not in signature.parameters
    assert (
        extract_state_dispatcher_map_from_mba(mba, dispatcher_entry_block=2)
        is None
    )


def test_hexrays_numeric_constants_require_adapter_normalization() -> None:
    # A raw Hex-Rays numeric constant (``nnn_value``) is meaningless to recon
    # until the adapter normalizes it onto a portable ``MopSnapshot`` and the
    # tail's portable predicate.  Absent that predicate, no row is extracted.
    tail = InsnSnapshot(
        opcode=44,
        ea=0,
        operands=(),
        kind=InsnKind.UNKNOWN,
        predicate_kind=None,
        l=_mop_s(0x3C),
        r=_mop_n(0x55),
        d=_mop_b(7),
    )
    mba = _Mba(
        {
            2: _block(2, succs=(3, 7), tail=tail),
        }
    )

    assert (
        extract_state_dispatcher_map_from_mba(mba, dispatcher_entry_block=2)
        is None
    )


def test_equality_chain_dispatcher_does_not_import_live_hexrays() -> None:
    assert "import ida_hexrays" not in inspect.getsource(equality_chain_dispatcher)


def test_extracts_jnz_exact_row_from_fallthrough() -> None:
    mba = _Mba(
        {
            2: _block(
                2,
                predicate=PredicateKind.NE,
                const=0x10,
                jump_target=3,
                succs=(7, 3),
            ),
            3: _block(3, const=0x20, jump_target=9, succs=(4, 9)),
        }
    )

    dispatch_map = extract_state_dispatcher_map_from_mba(
        mba,
        dispatcher_entry_block=2,
    )

    assert dispatch_map is not None
    assert dispatch_map.state_to_handler() == {0x10: 7, 0x20: 9}


def test_rejects_mixed_state_variables() -> None:
    mba = _Mba(
        {
            2: _block(2, state_mop=_mop_s(0x3C), const=0x10, jump_target=7, succs=(3, 7)),
            3: _block(3, state_mop=_mop_s(0x44), const=0x20, jump_target=9, succs=(4, 9)),
        }
    )

    assert (
        extract_state_dispatcher_map_from_mba(mba, dispatcher_entry_block=2)
        is None
    )


def test_rejects_conflicting_duplicate_constants() -> None:
    mba = _Mba(
        {
            2: _block(2, const=0x10, jump_target=7, succs=(3, 7)),
            3: _block(3, const=0x10, jump_target=9, succs=(4, 9)),
        }
    )

    assert (
        extract_state_dispatcher_map_from_mba(mba, dispatcher_entry_block=2)
        is None
    )


def test_supports_promoted_lvar_state() -> None:
    mba = _Mba(
        {
            2: _block(
                2,
                state_mop=_mop_l(5),
                const=0x10,
                jump_target=7,
                succs=(3, 7),
            ),
        }
    )

    dispatch_map = extract_state_dispatcher_map_from_mba(
        mba,
        dispatcher_entry_block=2,
    )

    assert dispatch_map is not None
    assert dispatch_map.state_var_lvar_idx == 5


def test_lvar_state_uses_canonical_identity_not_raw_lvar_shape() -> None:
    mba = _Mba(
        {
            2: _block(
                2,
                state_mop=_CanonicalLvarWithoutRawL(),
                const=0x10,
                jump_target=7,
                succs=(3, 7),
            ),
        }
    )

    dispatch_map = extract_state_dispatcher_map_from_mba(
        mba,
        dispatcher_entry_block=2,
    )

    assert dispatch_map is not None
    assert dispatch_map.state_var_lvar_idx == 5
