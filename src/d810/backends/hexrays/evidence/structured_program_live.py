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

import os

import ida_hexrays  # noqa: F401  (import guard: this module requires Hex-Rays)

from d810.core.logging import getLogger
from d810.hexrays.mutation.ir_translator import lift as lift_flow_graph
from d810.hexrays.utils.pseudocode_render import render_branch_condition
from d810.backends.hexrays.evidence.bst_analysis import _detect_state_var_stkoff
from d810.backends.hexrays.evidence.microcode_dump import (
    _build_block_payload_by_serial,
    _build_live_linearized_state_dag,
)
from d810.analyses.control_flow.linearized_state_dag import (
    _prune_terminal_control_lines,
)
from d810.analyses.control_flow.explore import Resolution
from d810.analyses.control_flow.recovered_graph_capture import (
    get_explore_materialize_blocks,
    get_explore_resolved_edges,
    get_recovered_flow_graph,
    get_recovered_state_dag,
)
from d810.analyses.control_flow.state_transition_graph import (
    augment_state_transition_graph,
    build_state_transition_graph,
)
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
from d810.analyses.control_flow.dominator import compute_dom_tree
from d810.ir.structured_region import render_region

logger = getLogger(__name__)

__all__ = ["structure_recovered_program_live"]


def structure_recovered_program_live(
    mba: object,
    *,
    state_var_stkoff: int | None = None,
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
    # Resolve the dispatcher state variable's stack offset. Prefer the value the
    # caller hands in (recon's Hodur detector); when absent, SELF-DETECT on this
    # mba at its own maturity via the same ``_detect_state_var_stkoff`` the recon
    # path uses. Detection is authoritative -- never fall back to a hardcoded slot
    # (a prior diagnostic env override silently fed the WRONG variable, e.g. 0x64
    # instead of the real 0x3C, producing a graph keyed on a non-state slot).
    if state_var_stkoff is None:
        if dispatcher_entry_serial is None:
            raise ValueError(
                "structure_recovered_program_live: state_var_stkoff not provided "
                "and dispatcher_entry_serial is None -- cannot self-detect the "
                "dispatcher state variable"
            )
        detected_stkoff, detected_lvar_idx = _detect_state_var_stkoff(
            mba, int(dispatcher_entry_serial), diag=False
        )
        if detected_stkoff is None:
            raise ValueError(
                "structure_recovered_program_live: state-var auto-detection failed "
                f"at dispatcher entry {dispatcher_entry_serial}"
            )
        state_var_stkoff = int(detected_stkoff)
        logger.info(
            "structurer: auto-detected state_var_stkoff=0x%X (lvar_idx=%s)",
            state_var_stkoff,
            detected_lvar_idx,
        )
    else:
        state_var_stkoff = int(state_var_stkoff)
        logger.info(
            "structurer: using caller-supplied state_var_stkoff=0x%X", state_var_stkoff
        )

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
        use_explore = os.environ.get("D810_USE_EXPLORE", "0").strip() == "1"
        # mba-decided dispatcher-region routed state-write blocks (e.g. blk57):
        # build materialises them as nodes so their resolved edges attach below.
        # Empty when explore is off -> the projection (hence golden) is identical.
        materialize_blocks = get_explore_materialize_blocks() if use_explore else ()
        flow_graph = build_state_transition_graph(
            state_dag,
            base_successors=base_successors,
            materialize_blocks=materialize_blocks,
        )
        logger.info(
            "structurer: using recovered state-DAG (%d handler blocks, entry=%d)",
            len(flow_graph.blocks),
            flow_graph.entry_serial,
        )
        # S5e (gated): re-attach explore()'s resolved transitions at the block-CFG
        # level. The dag-level injection (microcode_dump) can only wire edges
        # between LinearizedStateDag handler nodes (~78), so transitions targeting
        # adapter-only blocks -- range-backed / producer blocks such as 152 / 195,
        # pulled into this projected CFG but absent from the dag -- were dropped.
        # Those blocks exist in flow_graph.blocks, so attach the edges here, where
        # both endpoints are present. Flag OFF -> the stash is never read and the
        # CFG (hence the golden output) is byte-identical.
        if use_explore:
            resolved_edges = get_explore_resolved_edges()
            pairs = [
                (int(edge.from_serial), int(edge.to_serial))
                for edge in resolved_edges
                if getattr(edge, "resolution", None) == Resolution.RESOLVED
                and int(getattr(edge, "to_serial", -1)) >= 0
            ]
            flow_graph, added = augment_state_transition_graph(flow_graph, pairs)
            if added:
                if logger.info_on:
                    # Standing rule: a serialized block number carries its EA.
                    def _blk_ea(serial: int) -> str:
                        try:
                            blk = mba.get_mblock(int(serial))
                            return f"0x{int(blk.start) & 0xFFFFFFFFFFFFFFFF:016x}"
                        except Exception:
                            return "?"

                    for _src, _dst in added:
                        logger.info(
                            "structurer: attach explore edge blk[%d]@%s -> blk[%d]@%s",
                            _src,
                            _blk_ea(_src),
                            _dst,
                            _blk_ea(_dst),
                        )
                logger.info(
                    "structurer: augmented adapter CFG with %d explore edge(s) "
                    "(%d blocks, entry=%d)",
                    len(added),
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

    # Dump the adapter graph topology to JSON so the portable structurer can be
    # reproduced/debugged offline (no IDA / docker cycle). Diagnostic-only; cwd
    # inside the container is the mounted worktree, so this lands in .tmp/.
    try:
        import json as _json

        def _ea_hex(serial: int) -> str | None:
            # Standing rule: a serialized block number always carries its EA.
            try:
                _blk = mba.get_mblock(int(serial))
                return f"0x{int(_blk.start) & 0xFFFFFFFFFFFFFFFF:016x}"
            except Exception:
                return None

        _topo = {
            "entry_serial": int(flow_graph.entry_serial),
            "entry_ea": _ea_hex(int(flow_graph.entry_serial)),
            "return_terminals": sorted(
                int(s) for s in getattr(flow_graph, "return_terminals", ())
            ),
            "succ": {
                str(int(s)): [int(x) for x in flow_graph.successors(s)]
                for s in flow_graph.blocks
            },
            # serial -> block start EA, so the dump is self-describing offline
            # without a separate diag-DB cross-reference.
            "ea": {str(int(s)): _ea_hex(s) for s in flow_graph.blocks},
        }
        _dump_path = os.path.join(".tmp", "structurer_graph.json")
        with open(_dump_path, "w") as _fh:
            _json.dump(_topo, _fh)
        logger.info("structurer: dumped adapter graph to %s", _dump_path)
    except Exception as _exc:  # noqa: BLE001 — diagnostics only
        logger.info("structurer: graph dump failed (%s)", _exc)

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

    # Diagnostic: dump the adapter graph's back-edges (loop signals) so we can
    # tell genuine handler loops from spurious 2-cycles / self-edges.
    if logger.info_on:
        _succ = {
            int(s): tuple(int(x) for x in flow_graph.successors(s))
            for s in flow_graph.blocks
        }
        _entry = int(flow_graph.entry_serial)
        _dom = compute_dom_tree(_succ, _entry)
        _back = [
            (u, v) for u, vs in _succ.items() for v in vs if _dom.dominates(v, u)
        ]
        _self = [(u, v) for (u, v) in _back if u == v]
        logger.info(
            "structurer: %d back-edge(s) (%d self-loops); sample=%s",
            len(_back),
            len(_self),
            sorted(_back)[:20],
        )
        # Reachability BFS from entry over the adapter graph: distinguishes
        # "reachable but structurer didn't visit" (traversal gap) from
        # "unreachable in the graph" (edge gap).
        _seen_bfs = {_entry}
        _stack = [_entry]
        while _stack:
            _n = _stack.pop()
            for _s in _succ.get(_n, ()):
                if _s not in _seen_bfs:
                    _seen_bfs.add(_s)
                    _stack.append(_s)
        _term = [s for s in flow_graph.blocks if not _succ.get(s)]
        _unreach_term = sorted(t for t in _term if t not in _seen_bfs)
        logger.info(
            "structurer: BFS-reachable=%d/%d blocks; terminals=%s unreachable-terminals=%s",
            len(_seen_bfs),
            len(_succ),
            sorted(_term),
            _unreach_term,
        )

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

    # Terminal returns: every forward-degree-0 block in the recovered handler
    # graph is a chain end -- a genuine function return (or a recovery dead-end).
    # Deliver the recovered carrier there. EXIT_ROUTINE corridor tails and the
    # carrier-leak verdict (return reaches only a leaked state-constant write)
    # are the principled core; the broader terminal set guarantees the recovered
    # return value is delivered rather than a leaked dispatcher state.
    fixes = carrier_terminal_returns(
        verdicts, carrier_expr=carrier_expr, leak_def_sites=leak_def_sites
    )
    return_terminals = getattr(flow_graph, "return_terminals", frozenset())
    terminal_set = set(terminals)
    _reached: set[int] = set()

    def _terminal_return(serial: int) -> str | None:
        s = int(serial)
        _reached.add(s)
        if s in fixes:
            return fixes[s]
        if s in return_terminals or s in terminal_set:
            return carrier_expr
        return None

    tree = build_region_tree(
        flow_graph,
        render_block=_render_block,
        render_condition=_render_condition,
        terminal_return=_terminal_return,
    )
    if logger.info_on:
        missed = sorted(terminal_set - _reached)
        logger.info(
            "structurer: terminal_return reached %s; UNREACHED terminals=%s",
            sorted(t for t in _reached if t in terminal_set),
            missed,
        )
    return render_region(tree)
