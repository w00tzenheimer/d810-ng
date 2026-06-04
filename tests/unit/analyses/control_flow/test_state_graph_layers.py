"""Tests for the two-layer state-graph types: NodeKind + SCC condensation."""
from __future__ import annotations

from d810.analyses.control_flow.state_graph_layers import (
    NodeKind,
    classify_nodes,
    condense_sccs,
)
from d810.analyses.control_flow.state_transition_graph import (
    StateTransitionGraph,
    StateTransitionGraphBlock,
)


def _cfg(succ_map, entry):
    serials = set(succ_map) | {d for v in succ_map.values() for d in v}
    preds = {s: [] for s in serials}
    for s, dsts in succ_map.items():
        for d in dsts:
            preds[d].append(s)
    blocks = {
        s: StateTransitionGraphBlock(
            serial=s, succs=tuple(succ_map.get(s, ())), preds=tuple(preds[s])
        )
        for s in serials
    }
    return StateTransitionGraph(blocks=blocks, entry_serial=entry)


def test_classify_node_kinds():
    cfg = _cfg({78: (2,), 2: (55,), 55: (57, 56), 57: (186,), 56: (), 186: ()}, entry=78)
    kinds = classify_nodes(
        cfg, comparison_blocks={2, 55}, state_write_blocks={57}, entry=78
    )
    assert kinds[78] == NodeKind.ENTRY
    assert kinds[2] == NodeKind.DISPATCHER_TEST
    assert kinds[55] == NodeKind.DISPATCHER_TEST
    assert kinds[57] == NodeKind.STATE_WRITE
    assert kinds[56] == NodeKind.HANDLER
    assert kinds[186] == NodeKind.HANDLER


def test_condense_acyclic_is_all_singletons():
    cfg = _cfg({1: (2, 3), 2: (4,), 3: (4,), 4: ()}, entry=1)
    cond = condense_sccs(cfg)
    assert len(cond.components) == 4
    assert all(len(c) == 1 for c in cond.components)
    assert not any(cond.is_loop(i) for i in range(len(cond.components)))


def test_condense_collapses_a_cycle_into_one_loop_component():
    # 2 -> 3 -> 2 is a loop; condensed it must be a single non-trivial component
    # and the quotient must be acyclic.
    cfg = _cfg({1: (2,), 2: (3, 4), 3: (2,), 4: ()}, entry=1)
    cond = condense_sccs(cfg)
    c2 = cond.component_of[2]
    assert cond.components[c2] == frozenset({2, 3})
    assert cond.component_of[3] == c2
    assert cond.is_loop(c2)
    # the condensed graph is acyclic: no component reaches itself.
    for i in range(len(cond.components)):
        seen, stack = set(), list(cond.succs.get(i, ()))
        while stack:
            x = stack.pop()
            assert x != i, "condensed graph is not acyclic"
            if x not in seen:
                seen.add(x)
                stack.extend(cond.succs.get(x, ()))
