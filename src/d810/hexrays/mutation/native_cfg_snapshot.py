"""Owned, same-MBA snapshots for bounded native CFG rollback.

Unlike the analysis FlowGraph, these retain complete SDK instruction copies.
Restoration is restricted to a batch whose original blocks still exist in order;
removed/replaced originals and a changed MBA frame require regeneration.
"""
from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.ir.block_identity import MbaBlockHandle

BLOCK_FIELDS = ("type", "flags", "start", "end", "maxbsp", "minbstkref", "minbargref")
BLOCK_LISTS = ("dead_at_start", "mustbuse", "maybuse", "mustbdef", "maybdef", "dnu")
FRAME_FIELDS = ("maturity", "frsize", "inargoff", "tmpstk_size", "minstkref", "minargref", "spd_adjust")


def copy_native_list(original):
    result = ida_hexrays.mlist_t()
    result.add(original)
    return result


def instruction_fingerprint(block) -> tuple:
    result = []
    instruction = block.head
    while instruction is not None:
        result.append(instruction.serialize())
        instruction = instruction.next
    return tuple(result)


def frame_fingerprint(mba) -> tuple:
    return tuple(int(getattr(mba, name)) for name in FRAME_FIELDS) + (len(mba.vars),)


@dataclass(frozen=True)
class NativeBlockSnapshot:
    address: int
    handle: MbaBlockHandle
    metadata: tuple[int, ...]
    successors: tuple[int, ...]
    predecessors: tuple[int, ...]
    instructions: tuple[ida_hexrays.minsn_t, ...]
    fingerprint: tuple
    stop_lists: tuple[ida_hexrays.mlist_t, ...]


@dataclass(frozen=True)
class NativeCfgSnapshot:
    mba_address: int
    identity_index: object
    frame: tuple
    blocks: tuple[NativeBlockSnapshot, ...]

    @property
    def num_blocks(self) -> int:
        return len(self.blocks)

    @property
    def entry_serial(self) -> int:
        return 0


def capture_native_cfg_snapshot(mba, identity_index) -> NativeCfgSnapshot:
    """Capture only valid pre-lvar CFGs, without borrowing block/insn pointers."""
    if int(mba.maturity) >= int(ida_hexrays.MMAT_LVARS):
        raise ValueError("native CFG rollback does not restore allocated lvars")
    mba.verify(True)
    blocks = []
    for serial in range(mba.qty):
        block = mba.get_mblock(serial)
        handle = identity_index.handle_for_serial(serial)
        if handle is None:
            raise ValueError("native rollback requires tracked original block identities")
        instructions = []
        instruction = block.head
        while instruction is not None:
            instructions.append(ida_hexrays.minsn_t(instruction))
            instruction = instruction.next
        stop_lists = (
            tuple(copy_native_list(getattr(block, name)) for name in BLOCK_LISTS)
            if block.type == ida_hexrays.BLT_STOP else ()
        )
        blocks.append(NativeBlockSnapshot(
            address=int(block.this),
            handle=handle,
            metadata=tuple(int(getattr(block, name)) for name in BLOCK_FIELDS),
            successors=tuple(block.succset),
            predecessors=tuple(block.predset),
            instructions=tuple(instructions),
            fingerprint=instruction_fingerprint(block),
            stop_lists=stop_lists,
        ))
    return NativeCfgSnapshot(int(mba.this), identity_index, frame_fingerprint(mba), tuple(blocks))
