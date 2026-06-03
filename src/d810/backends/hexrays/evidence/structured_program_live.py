"""Live (IDA) end-to-end goto-free structured program from a live ``mba``.

Composes the portable structurer pipeline against IDA-authoritative inputs:

* FlowGraph via ``ir_translator.lift(mba)``;
* block statement text via ``pseudocode_render.render_block`` (the same
  ``_build_block_payload_by_serial`` the dumper uses);
* branch conditions via ``pseudocode_render.render_branch_condition``;
* reaching-defs of the return slot over IDA's ``build_def_list``
  (``stack_value_flow_live``) + IDA-verified block-entry liveness
  (``dead_at_start``) for the dispatcher state var;
* the carrier-delivery decision (``carrier_terminal_returns``) ->
  ``structure_recovered_program``.

Result: structured, goto-free pseudocode with the aligned-terminal carrier leak
(e.g. ``return 0x298372CC``) repaired to the real carrier (``a5+0xD0``). A
terminal is repaired only when its return slot reaches ONLY the entry-default
state write and the state var is dead there -- the dataflow proof of the leak.

This module is IDA-dependent (unit tests cannot exercise it); validate via the
docker §1a dump behind the ``D810_USE_STRUCTURER`` flag.
"""
from __future__ import annotations

import ida_hexrays  # noqa: F401  (import guard: this module requires Hex-Rays)

from d810.core.logging import getLogger
from d810.hexrays.mutation.ir_translator import lift as lift_flow_graph
from d810.hexrays.utils.pseudocode_render import render_branch_condition
from d810.backends.hexrays.evidence.microcode_dump import (
    _build_block_payload_by_serial,
)
from d810.analyses.control_flow.linearized_state_dag import (
    _prune_terminal_control_lines,
)
from d810.analyses.control_flow.recovered_graph_capture import (
    get_recovered_flow_graph,
)
from d810.backends.hexrays.evidence.stack_value_flow_live import (
    build_live_reaching_facts,
    is_state_var_live_at_entry,
)
from d810.analyses.data_flow.configuration import Direction, FixpointConfiguration
from d810.analyses.data_flow.worklist import run_fixpoint
from d810.analyses.value_flow.reaching_defs import ReachingDefsDomain, reaching_defs_of
from d810.analyses.value_flow.stack_value_flow import CarrierVerdict
from d810.analyses.control_flow.structurer import structure_recovered_program

logger = getLogger(__name__)

__all__ = ["structure_recovered_program_live"]


def structure_recovered_program_live(
    mba: object,
    *,
    state_var_stkoff: int,
    return_slot_stkoff: int,
    slot_width: int = 8,
    carrier_expr: str = "a5 + 0xD0",
) -> str:
    """Render the recovered function as goto-free pseudocode with the leak fixed.

    Args:
        mba: The live ``mba_t`` at the recovery maturity.
        state_var_stkoff: The dispatcher state variable's stack offset (from the
            §1a recovery's ``state_var_stkoff``).
        return_slot_stkoff: The return-slot carrier's stack offset.
        slot_width: Width in bytes of the tracked slots (default 8).
        carrier_expr: The real carrier expression to deliver at leaking aligned
            terminals (default ``"a5 + 0xD0"``, the byte_offset pointer).
    """
    # Prefer the §1a recovered (projected post-edit) FlowGraph — the dispatcher
    # is gone there. Fall back to lifting the raw mba only if the §1a run did not
    # stash one (then the structure would be the flattened dispatcher).
    flow_graph = get_recovered_flow_graph()
    if flow_graph is None:
        flow_graph = lift_flow_graph(mba)
    block_payload = _build_block_payload_by_serial(mba)

    branch_cond: dict[int, str] = {}
    for serial in flow_graph.blocks:
        blk = mba.get_mblock(int(serial))
        if blk is not None:
            branch_cond[int(serial)] = render_branch_condition(blk)

    tracked = {int(return_slot_stkoff): int(slot_width)}
    reaching_facts = build_live_reaching_facts(mba, flow_graph, tracked)
    reaching = run_fixpoint(
        ReachingDefsDomain(reaching_facts),
        nodes=list(flow_graph.blocks),
        entry_nodes=[int(flow_graph.entry_serial)],
        successors_of=flow_graph.successors,
        predecessors_of=flow_graph.predecessors,
        config=FixpointConfiguration(direction=Direction.FORWARD),
        raise_on_nonconvergence=False,
    )

    # The leak set: the entry-default definition(s) of the return slot (the
    # OLLVM ``result = (unsigned int)state`` write that dominates the function).
    entry = int(flow_graph.entry_serial)
    entry_facts = reaching_facts.get(entry)
    leak_def_sites = (
        tuple(entry_facts.gen.get(int(return_slot_stkoff), ())) if entry_facts else ()
    )

    terminals = [s for s in flow_graph.blocks if not tuple(flow_graph.successors(s))]
    verdicts: dict[int, CarrierVerdict] = {}
    for terminal in terminals:
        return_reaching = reaching_defs_of(
            reaching.in_states.get(terminal, frozenset()), int(return_slot_stkoff)
        )
        state_dead = not is_state_var_live_at_entry(
            mba, terminal, int(state_var_stkoff), int(slot_width)
        )
        # ``a5 + const`` is always computable, so carrier_dominates is True; the
        # leak gate is return_reaching ⊆ leak_def_sites AND state_dead.
        verdicts[terminal] = CarrierVerdict(
            return_reaching=return_reaching,
            carrier_dominates=True,
            state_dead=state_dead,
        )

    def _render_block(block: object) -> tuple:
        # Strip the block's control-flow tail (goto/jcc/ret): those are carried
        # by the region structure, not emitted as statements.
        return _prune_terminal_control_lines(
            tuple(block_payload.get(int(getattr(block, "serial", -1)), ()))
        )

    def _render_condition(block: object) -> str:
        return branch_cond.get(int(getattr(block, "serial", -1)), "cond")

    return structure_recovered_program(
        flow_graph,
        render_block=_render_block,
        render_condition=_render_condition,
        carrier_verdicts=verdicts,
        carrier_expr=carrier_expr,
        leak_def_sites=leak_def_sites,
    )
