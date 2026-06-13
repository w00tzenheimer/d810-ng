"""Portable test helpers for the DEFFAI unit tests (no IDA).

Builds hand-crafted :class:`FlowGraph` snapshots and supplies a pure-Python
``BlockEvaluator`` so the set-valued transfer is exercised without the
registry-backed (IDA-dependent) scalar fold.  The evaluator reproduces the
``mov const -> dest`` strong-update + ``kill on unresolved write`` semantics of
``_transfer_snapshot_constant_block`` closely enough that the singleton fast-path
parity test is meaningful.
"""
from __future__ import annotations

from d810.ir.flowgraph import (
    BlockKind,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.ir.semantics import PredicateKind

_U64 = 0xFFFFFFFFFFFFFFFF


# -- operand / insn builders -----------------------------------------------
def num(value: int, size: int = 8) -> MopSnapshot:
    """A constant (NUMBER) operand."""
    return MopSnapshot(t=1, size=size, value=int(value), kind=OperandKind.NUMBER)


def stk(off: int, size: int = 8) -> MopSnapshot:
    """A stack-slot operand at frame ``off``."""
    return MopSnapshot(t=2, size=size, stkoff=int(off), kind=OperandKind.STACK)


def reg(rid: int, size: int = 8) -> MopSnapshot:
    """A register operand."""
    return MopSnapshot(t=3, size=size, reg=int(rid), kind=OperandKind.REGISTER)


def blockref(serial: int) -> MopSnapshot:
    """A block-reference operand (branch target)."""
    return MopSnapshot(t=4, size=0, block_ref=int(serial), kind=OperandKind.BLOCK)


def mov(src: MopSnapshot, dst: MopSnapshot, ea: int = 0x1000) -> InsnSnapshot:
    """A ``mov src, dst`` instruction (MOV kind)."""
    return InsnSnapshot(
        opcode=0x04, ea=ea, operands=(), l=src, d=dst, kind=InsnKind.MOV
    )


def goto(target: int, ea: int = 0x1000) -> InsnSnapshot:
    """An unconditional ``goto target`` tail."""
    return InsnSnapshot(
        opcode=0x37,
        ea=ea,
        operands=(),
        l=blockref(target),
        kind=InsnKind.GOTO,
    )


def jcc(
    cmp_l: MopSnapshot,
    cmp_r: MopSnapshot,
    taken: int,
    pred: PredicateKind = PredicateKind.EQ,
    ea: int = 0x1000,
) -> InsnSnapshot:
    """A 2-way conditional jump: ``if (l <pred> r) goto taken``.

    ``d.block_ref`` is the taken target (mirrors the real tail convention).
    """
    return InsnSnapshot(
        opcode=0x2C if pred is PredicateKind.EQ else 0x2B,
        ea=ea,
        operands=(),
        l=cmp_l,
        r=cmp_r,
        d=blockref(taken),
        kind=InsnKind.COND_JUMP,
        branch_predicate=pred,
        is_conditional_jump=True,
    )


def jtbl(cases: tuple, ea: int = 0x1000) -> InsnSnapshot:
    """A jump-table tail; ``cases`` is ``((case_values, target), ...)``.

    The case table is carried on the ``l`` operand's ``switch_cases``.
    """
    op = MopSnapshot(
        t=10, size=0, switch_cases=tuple(cases), kind=OperandKind.CASE_LIST
    )
    return InsnSnapshot(
        opcode=0x99, ea=ea, operands=(), l=op, kind=InsnKind.TABLE_JUMP
    )


def ret(ea: int = 0x1000) -> InsnSnapshot:
    """A return tail."""
    return InsnSnapshot(opcode=0x3A, ea=ea, operands=(), kind=InsnKind.RET)


def block(
    serial: int,
    insns: tuple[InsnSnapshot, ...],
    succs: tuple[int, ...],
    *,
    kind: BlockKind = BlockKind.UNKNOWN,
    start_ea: int = 0x1000,
) -> BlockSnapshot:
    """A :class:`BlockSnapshot` (preds recomputed by :func:`make_graph`)."""
    return BlockSnapshot(
        serial=int(serial),
        block_type=0,
        succs=tuple(int(s) for s in succs),
        preds=(),
        flags=0,
        start_ea=int(start_ea),
        insn_snapshots=tuple(insns),
        kind=kind,
    )


def make_graph(
    blocks: list[BlockSnapshot], *, entry: int = 0, func_ea: int = 0x1000
) -> FlowGraph:
    """Assemble a :class:`FlowGraph`, recomputing every block's ``preds``."""
    by_serial = {int(b.serial): b for b in blocks}
    preds: dict[int, list[int]] = {s: [] for s in by_serial}
    for serial, blk in by_serial.items():
        for succ in blk.succs:
            if succ in preds:
                preds[int(succ)].append(int(serial))
    rebuilt: dict[int, BlockSnapshot] = {}
    for serial, blk in by_serial.items():
        rebuilt[serial] = BlockSnapshot(
            serial=blk.serial,
            block_type=blk.block_type,
            succs=blk.succs,
            preds=tuple(sorted(preds[serial])),
            flags=blk.flags,
            start_ea=blk.start_ea,
            insn_snapshots=blk.insn_snapshots,
            kind=blk.kind,
        )
    return FlowGraph(blocks=rebuilt, entry_serial=int(entry), func_ea=int(func_ea))


# -- portable block evaluator (pure-Python mov-const fold) ------------------
def portable_block_evaluator(state_var_stkoff: int = 0):
    """A pure-Python ``BlockEvaluator`` reproducing the mov-const strong-update.

    Walks the block's instructions; a ``mov <const>, <stk/reg dest>`` strong-
    updates the corresponding map; a ``mov <stk/reg src>, <dest>`` copies the
    resolved source (or kills the dest when the source is unresolved); any other
    write to a stack/reg dest kills it.  Mirrors
    ``_transfer_snapshot_constant_block`` for the constant cases the DEFFAI core
    relies on.  Ignores ``state_var_stkoff`` (it folds every cell uniformly).
    """

    def _evaluate(block, in_stk, in_reg, _state_off):
        stk_map = dict(in_stk)
        reg_map = dict(in_reg)
        for insn in block.insn_snapshots:
            dest = getattr(insn, "d", None)
            src = getattr(insn, "l", None)
            if dest is None:
                continue
            # Resolve the source value.
            value = None
            if src is not None:
                if src.kind is OperandKind.NUMBER and src.value is not None:
                    value = int(src.value) & _U64
                elif src.stkoff is not None:
                    value = stk_map.get(int(src.stkoff))
                elif src.reg is not None:
                    value = reg_map.get(int(src.reg))
            # Apply to the destination cell.
            if dest.stkoff is not None:
                key = int(dest.stkoff)
                if value is not None:
                    stk_map[key] = value
                else:
                    stk_map.pop(key, None)
            elif dest.reg is not None:
                key = int(dest.reg)
                if value is not None:
                    reg_map[key] = value
                else:
                    reg_map.pop(key, None)
        return stk_map, reg_map

    return _evaluate
