"""Hex-Rays adapter that lifts mba/mblock structures into PortableCFG snapshots."""
from __future__ import annotations

from d810.core.logging import getLogger
from d810.core.typing import TYPE_CHECKING

from d810.cfg.portable_cfg import BlockSnapshot, InsnSnapshot, PortableCFG
from d810.hexrays.ir.block_helpers import get_pred_serials, get_succ_serials
from d810.hexrays.ir.mop_snapshot import MopSnapshot

if TYPE_CHECKING:
    import ida_hexrays

logger = getLogger(__name__)

try:
    import ida_hexrays

    _IDA_AVAILABLE = True
except ImportError:
    _IDA_AVAILABLE = False


def lift_block(blk: "ida_hexrays.mblock_t") -> BlockSnapshot:
    if not _IDA_AVAILABLE:
        raise RuntimeError("lift_block requires IDA Hexrays (ida_hexrays module not available)")

    serial = blk.serial
    block_type = blk.type
    flags = blk.flags
    start_ea = blk.start

    succs = get_succ_serials(blk)
    preds = get_pred_serials(blk)

    insn_snapshots = []
    insn = blk.head
    while insn:
        opcode = insn.opcode
        ea = insn.ea

        operands = tuple(
            MopSnapshot.from_mop(mop)
            for mop in (insn.l, insn.r, insn.d)
            if mop.t != ida_hexrays.mop_z  # type: ignore[attr-defined]
        )

        insn_snapshots.append(InsnSnapshot(opcode=opcode, ea=ea, operands=operands))
        insn = insn.next

    return BlockSnapshot(
        serial=serial,
        block_type=block_type,
        succs=succs,
        preds=preds,
        flags=flags,
        start_ea=start_ea,
        insn_snapshots=tuple(insn_snapshots),
    )


def lift(mba: "ida_hexrays.mba_t") -> PortableCFG:
    if not _IDA_AVAILABLE:
        raise RuntimeError("lift requires IDA Hexrays (ida_hexrays module not available)")

    blocks = {}
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        blocks[blk.serial] = lift_block(blk)

    return PortableCFG(
        blocks=blocks,
        entry_serial=0,
        func_ea=mba.entry_ea,
        metadata={"maturity": mba.maturity},
    )


__all__ = ["lift", "lift_block"]
