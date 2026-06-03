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
    _build_live_linearized_state_dag,
)
from d810.analyses.control_flow.linearized_state_dag import (
    _prune_terminal_control_lines,
)
from d810.analyses.control_flow.recovered_graph_capture import (
    get_recovered_flow_graph,
    get_recovered_state_dag,
)
from d810.analyses.control_flow.state_dag_cfg_adapter import build_state_dag_cfg
from d810.analyses.control_flow.state_write_dse import (
    infer_state_var_name as _infer_state_var_name,
    prune_dead_state_writes as _prune_dead_state_writes,
)
from d810.backends.hexrays.evidence.stack_value_flow_live import (
    build_live_reaching_facts,
    is_state_var_live_at_entry,
)
from d810.analyses.data_flow.configuration import Direction, FixpointConfiguration
from d810.analyses.data_flow.worklist import run_fixpoint
from d810.analyses.value_flow.reaching_defs import ReachingDefsDomain, reaching_defs_of
from d810.analyses.value_flow.stack_value_flow import (
    CarrierVerdict,
    carrier_terminal_returns,
)
from d810.analyses.control_flow.structurer import build_region_tree
from d810.ir.structured_region import render_region

logger = getLogger(__name__)

__all__ = ["structure_recovered_program_live"]


def structure_recovered_program_live(
    mba: object,
    *,
    state_var_stkoff: int,
    return_slot_stkoff: int,
    slot_width: int = 8,
    carrier_expr: str = "a5 + 0xD0",
    dispatcher_entry_serial: int | None = None,
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
        dispatcher_entry_serial: When provided, the **enriched** state-DAG is
            rebuilt live (``_build_live_linearized_state_dag``) -- the same DAG
            the reference-like linearized renderer uses, with the full
            conditional-transition chain. Preferred over the shallow §1a stash.
    """
    # The structurer must run on the recovered state graph (dispatcher-free), not
    # the lifted/projected FlowGraph (which retains the BST comparison blocks).
    # Prefer the ENRICHED DAG rebuilt live (full conditional-transition chain,
    # same as the linearized renderer); fall back to the §1a shallow stash.
    base_graph = get_recovered_flow_graph()
    if base_graph is None:
        base_graph = lift_flow_graph(mba)
    base_successors = {
        int(serial): tuple(int(s) for s in getattr(blk, "succs", ()))
        for serial, blk in base_graph.blocks.items()
    }

    state_dag = None
    if dispatcher_entry_serial is not None:
        try:
            state_dag = _build_live_linearized_state_dag(
                mba,
                int(dispatcher_entry_serial),
                state_var_stkoff=int(state_var_stkoff),
            )
        except Exception as exc:  # noqa: BLE001 — diagnostics; fall back to stash
            logger.info("structurer: enriched DAG rebuild failed (%s); using stash", exc)
    if state_dag is None:
        state_dag = get_recovered_state_dag()

    if state_dag is not None:
        flow_graph = build_state_dag_cfg(state_dag, base_successors=base_successors)
        logger.info(
            "structurer: using recovered state-DAG (%d handler blocks, entry=%d)",
            len(flow_graph.blocks),
            flow_graph.entry_serial,
        )
    else:
        flow_graph = base_graph
        logger.info(
            "structurer: no state-DAG available; structuring FlowGraph (%d blocks)",
            len(getattr(flow_graph, "blocks", {})),
        )
    block_payload = _build_block_payload_by_serial(mba)

    # Dead dispatcher-state writes (``var_64 = 0x<state_const>``) are noise after
    # unflattening -- the state var is dead. Collect the recovered state
    # constants so the renderer can DSE those assignment lines (this also removes
    # the cosmetic ``0x298372CC`` state-write occurrences). Computed state writes
    # are dropped too once we know the state var's rendered name.
    state_consts: set[int] = set()
    for node in getattr(state_dag, "nodes", ()) or ():
        key = getattr(node, "key", None)
        sc = getattr(key, "state_const", None) if key is not None else None
        if sc is not None:
            state_consts.add(int(sc) & 0xFFFFFFFF)
    state_var_name = _infer_state_var_name(block_payload, state_consts)

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
    logger.info(
        "structurer: %d terminal(s)=%s return_terminals=%s",
        len(terminals),
        sorted(terminals)[:20],
        sorted(getattr(flow_graph, "return_terminals", frozenset()))[:20],
    )
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
        # by the region structure, not emitted as statements. Then DSE the dead
        # dispatcher-state writes (the state var is dead after unflattening).
        lines = _prune_terminal_control_lines(
            tuple(block_payload.get(int(getattr(block, "serial", -1)), ()))
        )
        return _prune_dead_state_writes(lines, state_var_name, state_consts)

    def _render_condition(block: object) -> str:
        return branch_cond.get(int(getattr(block, "serial", -1)), "cond")

    # Terminal returns: deliver the carrier at every genuine function return (the
    # EXIT_ROUTINE corridor tails the adapter marked) AND at any leak terminal
    # the carrier verdict flagged. Dead-end blocks at recovery gaps stay
    # return-less (the structurer simply ends the block).
    fixes = carrier_terminal_returns(
        verdicts, carrier_expr=carrier_expr, leak_def_sites=leak_def_sites
    )
    return_terminals = getattr(flow_graph, "return_terminals", frozenset())

    def _terminal_return(serial: int) -> str | None:
        s = int(serial)
        if s in fixes:
            return fixes[s]
        if s in return_terminals:
            return carrier_expr
        return None

    tree = build_region_tree(
        flow_graph,
        render_block=_render_block,
        render_condition=_render_condition,
        terminal_return=_terminal_return,
    )
    return render_region(tree)
