"""Structural analysis: CFG -> goto-free region tree (Slice B).

The angr-style structurer's core. Conditionals use recursive **post-dominator
follow-node** structuring (the Engel / hammock method, also angr's
``RegionIdentifier`` conditional method): a 2-way block becomes a
:class:`ConditionRegion` whose join is the block's immediate post-dominator;
straight-line edges fold into a :class:`SequenceRegion`; terminals are leaf
:class:`BlockRegion`.

Natural loops are recovered from back-edges (``succ`` dominates ``node``). A
header that is itself the 2-way loop condition becomes a ``while``; a loop whose
single latch carries the condition becomes a ``do_while``; otherwise ``while
(1)``. Only **single-exit** loops are structured as loops here (the exit becomes
the continuation after the ``LoopRegion``); multi-exit / irreducible loops fall
back to acyclic structuring, which still terminates (back-edges are excluded and
a ``seen`` set guards re-entry) -- it under-structures rather than mis-structures
them. Mid-body breaks/continues and switch recovery are the next slice.

Block bodies and branch conditions come from injected renderers so this stays
portable and unit-testable; the Hex-Rays backend supplies the real statement
text. ``terminal_return`` is the Layer-1 -> Layer-2 seam (carrier delivery).
"""
from __future__ import annotations

from d810.core.typing import Callable, Iterable, Mapping, Optional
from d810.analyses.control_flow.dominator import compute_dom_tree
from d810.analyses.control_flow.sese_hammock import compute_postdominator_tree
from d810.analyses.value_flow.stack_value_flow import (
    CarrierVerdict,
    carrier_terminal_returns,
)
from d810.ir.structured_region import (
    BlockRegion,
    BreakRegion,
    ConditionRegion,
    LoopRegion,
    Region,
    ReturnRegion,
    SequenceRegion,
    render_region,
)

__all__ = ["build_region_tree", "structure_recovered_program"]


def _as_region(parts: list) -> "Region":
    if not parts:
        return SequenceRegion(())
    if len(parts) == 1:
        return parts[0]
    return SequenceRegion(tuple(parts))


def build_region_tree(
    flow_graph: object,
    *,
    render_block: Optional[Callable[[object], tuple]] = None,
    render_condition: Optional[Callable[[object], str]] = None,
    terminal_return: Optional[Callable[[int], Optional[str]]] = None,
) -> "Region":
    """Recover a goto-free region tree for ``flow_graph``."""
    block_lines = render_block or (lambda blk: ())
    condition_of = render_condition or (lambda blk: "cond")
    return_of = terminal_return or (lambda serial: None)

    blocks = flow_graph.blocks
    succ_map = {
        int(serial): tuple(int(s) for s in blk.succs)
        for serial, blk in blocks.items()
    }
    entry = int(flow_graph.entry_serial)
    dom = compute_dom_tree(succ_map, entry)
    back_edges = {
        (u, v)
        for u, succs in succ_map.items()
        for v in succs
        if dom.dominates(v, u)
    }
    pred_map: dict[int, set] = {}
    for u, succs in succ_map.items():
        for v in succs:
            pred_map.setdefault(v, set()).add(u)
    latches_by_header: dict[int, set] = {}
    for u, v in back_edges:
        latches_by_header.setdefault(v, set()).add(u)
    headers = set(latches_by_header)

    postdom = compute_postdominator_tree(flow_graph)
    pidom = dict(getattr(postdom, "idom", {}) or {})

    def _join(node: int) -> Optional[int]:
        follow = pidom.get(node)
        return follow if follow in blocks else None

    def _natural_loop(header: int) -> set:
        loop = {header}
        stack = list(latches_by_header.get(header, ()))
        while stack:
            node = stack.pop()
            if node not in loop:
                loop.add(node)
                stack.extend(pred_map.get(node, ()))
        return loop

    def _loop_exits(loop: set) -> set:
        return {s for n in loop for s in succ_map.get(n, ()) if s not in loop}

    def _structure_loop(
        header: int, exit_block: Optional[int], seen: frozenset, active: frozenset
    ) -> "Region":
        header_block = flow_graph.get_block(header)
        forward = [s for s in succ_map.get(header, ()) if (header, s) not in back_edges]
        latches = latches_by_header.get(header, set())

        # while: header is the 2-way loop condition, one arm leaves the loop.
        if len(forward) == 2 and exit_block is not None and exit_block in forward:
            in_loop = forward[0] if forward[1] == exit_block else forward[1]
            body = _region_from(in_loop, exit_block, seen | {header}, active)
            return LoopRegion(body=body, kind="while", condition=condition_of(header_block))

        # do_while: a single latch carries the loop condition at the bottom.
        if len(latches) == 1:
            latch = next(iter(latches))
            if exit_block is not None and exit_block in succ_map.get(latch, ()):
                body = _region_from(header, exit_block, seen, active)
                return LoopRegion(
                    body=body,
                    kind="do_while",
                    condition=condition_of(flow_graph.get_block(latch)),
                )

        # infinite / odd loop: structure internals under while (1). The loop's
        # single exit is mid-body (neither header nor latch carries the
        # condition), so transfers to ``exit_block`` inside the body become
        # ``break`` (else the rendered while(1) would be inescapable).
        body = _region_from(header, exit_block, seen, active, loop_exit=exit_block)
        return LoopRegion(body=body, kind="while", condition="1")

    def _region_from(
        node: Optional[int],
        stop: Optional[int],
        seen: frozenset,
        active: frozenset = frozenset(),
        loop_exit: Optional[int] = None,
    ) -> "Region":
        parts: list = []
        cur = node
        while cur is not None and cur != stop and cur in blocks and cur not in seen:
            if cur in headers and cur not in active:
                loop = _natural_loop(cur)
                exits = _loop_exits(loop)
                if len(exits) <= 1:
                    exit_block = next(iter(exits)) if exits else None
                    parts.append(
                        _structure_loop(cur, exit_block, seen, active | {cur})
                    )
                    cur = exit_block if exit_block in blocks else None
                    continue
                # multi-exit / irreducible: fall through to acyclic handling.

            seen = seen | {cur}
            blk = flow_graph.get_block(cur)
            forward = tuple(
                s for s in succ_map.get(cur, ()) if (cur, s) not in back_edges
            )
            if len(forward) <= 1:
                parts.append(BlockRegion(int(cur), tuple(block_lines(blk))))
                if forward and loop_exit is not None and forward[0] == loop_exit:
                    parts.append(BreakRegion())  # exit the enclosing while(1)
                    cur = None
                elif forward:
                    cur = forward[0]
                else:
                    returned = return_of(int(cur))
                    if returned is not None:
                        parts.append(ReturnRegion(returned))
                    cur = None
            elif len(forward) == 2:
                parts.append(BlockRegion(int(cur), tuple(block_lines(blk))))
                follow = _join(cur)
                taken, fallback = forward

                def _arm(target: int) -> Optional["Region"]:
                    if loop_exit is not None and target == loop_exit:
                        return BreakRegion()  # this arm leaves the loop
                    if target != follow:
                        return _region_from(target, follow, seen, active, loop_exit)
                    return None

                parts.append(
                    ConditionRegion(
                        condition=condition_of(blk),
                        then_region=_arm(taken),
                        else_region=_arm(fallback),
                    )
                )
                # If the conditional reconverges at the loop exit, both paths
                # leave the loop -> stop here (the arms already broke / fell out).
                if loop_exit is not None and follow == loop_exit:
                    cur = None
                else:
                    cur = follow
            else:  # n-way (switch); leaf for now.
                # Recursing every arm re-renders each arm's subtree once per visit,
                # and these residual state-dispatch blocks are reached dozens of
                # times -> a goto-free duplication explosion (observed: one block
                # rendered 45x, 848->3037 lines). Clean full coverage needs
                # DREAM/SAILR-style de-duplicating region structuring (a later
                # slice); these unrecovered dispatch blocks are recovery
                # incompleteness, so leaf is the honest, compact render.
                parts.append(BlockRegion(int(cur), tuple(block_lines(blk))))
                cur = None
        return _as_region(parts)

    return _region_from(entry, None, frozenset())


def structure_recovered_program(
    flow_graph: object,
    *,
    render_block: Callable[[object], tuple],
    render_condition: Callable[[object], str],
    carrier_verdicts: Mapping[int, CarrierVerdict],
    carrier_expr: str,
    leak_def_sites: Iterable,
) -> str:
    """End-to-end L1 -> L2 -> L3: recovered CFG + dataflow verdicts -> goto-free text.

    The carrier verdicts decide which terminals get the real carrier delivered
    (``carrier_terminal_returns``); the structurer builds the goto-free region
    tree (``build_region_tree``); ``render_region`` serializes it. In production
    ``render_block`` is ``hexrays.utils.pseudocode_render.render_block`` and
    ``render_condition`` the jcc-condition helper; the verdicts come from
    ``stack_value_flow_live`` + ``analyze_return_carrier`` over the live mba.
    """
    fixes = carrier_terminal_returns(
        carrier_verdicts, carrier_expr=carrier_expr, leak_def_sites=leak_def_sites
    )
    tree = build_region_tree(
        flow_graph,
        render_block=render_block,
        render_condition=render_condition,
        terminal_return=fixes.get,
    )
    return render_region(tree)
