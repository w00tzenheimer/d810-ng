"""Live (IDA-verified) reaching-defs / liveness facts for the portable domains.

The Slice-1b backend half. Where ``analyses/value_flow/stack_value_flow`` reads
the *portable* FlowGraph operand snapshots (an approximation good enough for the
synthetic unit tests), this provider folds the shared instruction facts built
from **IDA's own def/use lists** -- ``build_def_list`` / ``build_use_list`` per
instruction -- so the
``ReachingDefsDomain`` / ``LivenessDomain`` run on facts that match IDA exactly.

A tracked location is a ``(stkoff, width)`` stack interval (the return-slot
carrier, the real carrier such as ``a5+0xD0``, and the dispatcher state var). A
Uses and possible writes use ``has_common`` interval overlap. A full definition
additionally requires IDA's exact def list to ``include`` the whole interval.
"""

from __future__ import annotations

from d810.core.logging import getLogger
from d810.core.typing import Mapping
from d810.backends.hexrays.evidence.instruction_value_flow_live import (
    LiveInstructionFlow,
    build_live_instruction_flow,
)
from d810.evaluator.hexrays_microcode.liveness import is_var_live_at_block_entry
from d810.analyses.value_flow.liveness import BlockLivenessFacts
from d810.analyses.value_flow.reaching_defs import BlockReachingFacts
from d810.ir.locations import StackSlot

logger = getLogger(__name__)

__all__ = [
    "build_live_liveness_facts",
    "build_live_reaching_facts",
    "is_state_var_live_at_entry",
]


def _instruction_flow(
    mba: object, tracked: Mapping[int, int]
) -> tuple[LiveInstructionFlow, dict[StackSlot, int]]:
    offsets = {
        StackSlot(offset=int(offset), size=int(width)): int(offset)
        for offset, width in tracked.items()
    }
    return build_live_instruction_flow(mba, tuple(offsets)), offsets


def build_live_reaching_facts(
    mba: object, flow_graph: object, tracked: Mapping[int, int]
) -> dict[int, BlockReachingFacts]:
    """Per-block reaching-def gen from IDA's per-instruction ``build_def_list``.

    ``tracked`` maps each watched stack offset to its width in bytes.
    """
    instruction_flow, offsets = _instruction_flow(mba, tracked)
    allowed_blocks = {int(serial) for serial in flow_graph.blocks}
    facts: dict[int, BlockReachingFacts] = {}
    generated: dict[int, dict[int, set[tuple[int, int]]]] = {}
    for handle in instruction_flow.graph.nodes:
        coordinate = instruction_flow.coordinate(handle)
        serial = int(coordinate.block_serial)
        if serial not in allowed_blocks:
            continue
        gen = generated.setdefault(serial, {})
        access = instruction_flow.graph.facts_by_node[handle]
        for location in access.must_defs:
            if location in offsets:
                gen.setdefault(offsets[location], set()).add(
                    (serial, int(coordinate.insn_ea))
                )
    for serial, gen in generated.items():
        if gen:
            facts[serial] = BlockReachingFacts(
                gen={loc: frozenset(sites) for loc, sites in gen.items()}
            )
    return facts


def build_live_liveness_facts(
    mba: object, flow_graph: object, tracked: Mapping[int, int]
) -> dict[int, BlockLivenessFacts]:
    """Per-block use/def from IDA's def/use lists (``used`` upward-exposed)."""
    instruction_flow, offsets = _instruction_flow(mba, tracked)
    allowed_blocks = {int(serial) for serial in flow_graph.blocks}
    facts: dict[int, BlockLivenessFacts] = {}
    by_block: dict[int, list] = {}
    for handle in instruction_flow.graph.nodes:
        serial = int(instruction_flow.coordinate(handle).block_serial)
        if serial in allowed_blocks:
            by_block.setdefault(serial, []).append(
                instruction_flow.graph.facts_by_node[handle]
            )
    for serial, instruction_facts in by_block.items():
        used: set[int] = set()
        defined: set[int] = set()
        for access in instruction_facts:
            for location in access.uses | access.partial_defs:
                offset = offsets.get(location)
                if offset is not None and offset not in defined:
                    used.add(offset)
            for location in access.must_defs:
                offset = offsets.get(location)
                if offset is not None:
                    defined.add(offset)
        if used or defined:
            facts[serial] = BlockLivenessFacts(
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
