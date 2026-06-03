"""Live (IDA-verified) reaching-defs / liveness facts for the portable domains.

The Slice-1b backend half. Where ``analyses/value_flow/stack_value_flow`` reads
the *portable* FlowGraph operand snapshots (an approximation good enough for the
synthetic unit tests), this provider builds the per-block facts from **IDA's own
def/use lists** -- ``build_def_list`` / ``build_use_list`` per instruction and
``mustbdef`` per block, via the verified read-only wrappers in
``evaluator/hexrays_microcode/{def_search,liveness}`` -- so the
``ReachingDefsDomain`` / ``LivenessDomain`` run on facts that match IDA exactly.

A tracked location is a ``(stkoff, width)`` stack interval (the return-slot
carrier, the real carrier such as ``a5+0xD0``, and the dispatcher state var). A
location is *defined*/​*used* by an instruction iff IDA's def/use ``mlist_t``
``has_common`` its interval -- the same membership test ``liveness.py`` uses.
"""
from __future__ import annotations

import ida_hexrays

from d810.core.logging import getLogger
from d810.core.typing import Mapping
from d810.evaluator.hexrays_microcode.def_search import (
    instruction_defs,
    instruction_uses,
)
from d810.evaluator.hexrays_microcode.liveness import is_var_live_at_block_entry
from d810.analyses.value_flow.liveness import BlockLivenessFacts
from d810.analyses.value_flow.reaching_defs import BlockReachingFacts

logger = getLogger(__name__)

__all__ = [
    "build_live_liveness_facts",
    "build_live_reaching_facts",
    "is_state_var_live_at_entry",
]


def _loc_mlist(stkoff: int, width: int) -> "ida_hexrays.mlist_t":
    """Build an ``mlist_t`` covering the stack interval ``[stkoff, stkoff+width)``."""
    ml = ida_hexrays.mlist_t()
    ml.mem.add(ida_hexrays.ivl_t(int(stkoff), int(width)))
    return ml


def _iter_insns(blk: "ida_hexrays.mblock_t"):
    ins = blk.head
    while ins is not None:
        yield ins
        ins = ins.next


def build_live_reaching_facts(
    mba: object, flow_graph: object, tracked: Mapping[int, int]
) -> dict[int, BlockReachingFacts]:
    """Per-block reaching-def gen from IDA's per-instruction ``build_def_list``.

    ``tracked`` maps each watched stack offset to its width in bytes.
    """
    locs = [(int(off), int(width)) for off, width in tracked.items()]
    facts: dict[int, BlockReachingFacts] = {}
    for serial in flow_graph.blocks:
        blk = mba.get_mblock(int(serial))
        if blk is None:
            continue
        blk.make_lists_ready()
        gen: dict[int, set] = {}
        for ins in _iter_insns(blk):
            def_list = instruction_defs(blk, ins)
            for off, width in locs:
                if def_list.has_common(_loc_mlist(off, width)):
                    gen.setdefault(off, set()).add((int(serial), int(ins.ea)))
        if gen:
            facts[int(serial)] = BlockReachingFacts(
                gen={loc: frozenset(sites) for loc, sites in gen.items()}
            )
    return facts


def build_live_liveness_facts(
    mba: object, flow_graph: object, tracked: Mapping[int, int]
) -> dict[int, BlockLivenessFacts]:
    """Per-block use/def from IDA's def/use lists (``used`` upward-exposed)."""
    locs = [(int(off), int(width)) for off, width in tracked.items()]
    facts: dict[int, BlockLivenessFacts] = {}
    for serial in flow_graph.blocks:
        blk = mba.get_mblock(int(serial))
        if blk is None:
            continue
        blk.make_lists_ready()
        used: set[int] = set()
        defined: set[int] = set()
        for ins in _iter_insns(blk):
            use_list = instruction_uses(blk, ins)
            def_list = instruction_defs(blk, ins)
            for off, width in locs:
                ml = _loc_mlist(off, width)
                if use_list.has_common(ml) and off not in defined:
                    used.add(off)
                if def_list.has_common(ml):
                    defined.add(off)
        if used or defined:
            facts[int(serial)] = BlockLivenessFacts(
                used=frozenset(used), defined=frozenset(defined)
            )
    return facts


def is_state_var_live_at_entry(
    mba: object, block_serial: int, state_stkoff: int, width: int
) -> bool:
    """Direct IDA-verified liveness check (``dead_at_start``) at a terminal.

    A cross-check on the backward-liveness fixpoint: IDA already computes
    block-entry liveness, so the state var being dead here is authoritative.
    """
    blk = mba.get_mblock(int(block_serial))
    if blk is None:
        return False
    return is_var_live_at_block_entry(blk, int(state_stkoff), int(width))
