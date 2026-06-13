"""Unit tests for the Context-to-CFG Map -- DEFFAI Algorithm 1 (Step 6).

Covers: per-context partial CFG excludes the dispatcher region; keeps only
feasible arms under the context; block count per context <= original; an
infeasible arm is dropped from the edge set.  No IDA.
"""
from __future__ import annotations

import pytest

from d810.ir.semantics import PredicateKind
from d810.analyses.control_flow.state_transition_domain import StateValue
from d810.analyses.data_flow.concolic.refs import LocationRef

from d810.analyses.control_flow.deffai.analysis import analyze_kswitch
from d810.analyses.control_flow.deffai.ccm import build_ccm
from d810.analyses.control_flow.deffai.context import ContextPolicy, KContext

from tests.unit.analyses.control_flow.deffai._helpers import (
    block,
    goto,
    jcc,
    make_graph,
    mov,
    num,
    portable_block_evaluator,
    ret,
    stk,
)

STATE_OFF = 0x10
STATE = LocationRef.stack(STATE_OFF, 8)
EVAL = portable_block_evaluator(STATE_OFF)


def _analyze(graph, *, k=2, initial=None):
    return analyze_kswitch(
        graph,
        policy=ContextPolicy(k=k),
        state_cell=STATE,
        initial_state=initial,
        block_evaluator=EVAL,
        state_var_stkoff=STATE_OFF,
    )


def _linear_graph():
    # 0: state=10 -> 1 ; 1: handler body -> 2 ; 2: ret
    b0 = block(0, (mov(num(10), stk(STATE_OFF)), goto(1)), (1,))
    b1 = block(1, (goto(2),), (2,))
    b2 = block(2, (ret(),), ())
    return make_graph([b0, b1, b2])


def test_ccm_block_count_le_original():
    graph = _linear_graph()
    result = _analyze(graph, initial=10)
    ccm = build_ccm(result, graph, state_cell=STATE)
    for ctx in result.reachable_contexts:
        assert ccm.get(ctx).num_blocks <= graph.num_blocks


def test_ccm_excludes_dispatcher_region():
    graph = _linear_graph()
    result = _analyze(graph, initial=10)
    ccm = build_ccm(
        result, graph, state_cell=STATE, dispatcher_region=frozenset({0})
    )
    for ctx in result.reachable_contexts:
        assert 0 not in ccm.get(ctx).blocks  # dispatcher excluded


def test_ccm_keeps_reachable_blocks_only():
    # Block 3 is unreachable (no edge to it) -> never in any partial CFG.
    b0 = block(0, (mov(num(10), stk(STATE_OFF)), goto(1)), (1,))
    b1 = block(1, (ret(),), ())
    b2 = block(2, (ret(),), ())  # unreachable
    graph = make_graph([b0, b1, b2])
    result = _analyze(graph, initial=10)
    ccm = build_ccm(result, graph, state_cell=STATE)
    for ctx in result.reachable_contexts:
        assert 2 not in ccm.get(ctx).blocks


def test_ccm_drops_infeasible_arm_under_context():
    # Diamond where the context fixes state=10, so the (state==20) arm is dead.
    #   0: state=10 ; if (state==10) goto 1 else 2     [block 0 = dispatcher]
    #   1: ret  ;  2: ret
    b0 = block(
        0,
        (
            mov(num(10), stk(STATE_OFF)),
            jcc(stk(STATE_OFF), num(10), taken=1, pred=PredicateKind.EQ),
        ),
        (1, 2),
    )
    b1 = block(1, (ret(),), ())
    b2 = block(2, (ret(),), ())
    graph = make_graph([b0, b1, b2])
    result = _analyze(graph, initial=10)
    ccm = build_ccm(result, graph, state_cell=STATE)
    # In every context, the edge 0->2 (the state!=10 arm) is infeasible (state is
    # exactly {10}); only 0->1 survives.
    for ctx in result.reachable_contexts:
        partial = ccm.get(ctx)
        if 0 in partial.blocks and 2 in partial.blocks:
            assert (0, 2) not in partial.edges
            assert (0, 1) in partial.edges


def test_ccm_edges_restricted_to_context_blocks():
    graph = _linear_graph()
    result = _analyze(graph, initial=10)
    ccm = build_ccm(result, graph, state_cell=STATE)
    for ctx in result.reachable_contexts:
        partial = ccm.get(ctx)
        for u, v in partial.edges:
            assert u in partial.blocks
            assert v in partial.blocks


def test_ccm_empty_for_unreached_context():
    graph = _linear_graph()
    result = _analyze(graph, initial=10)
    ccm = build_ccm(result, graph, state_cell=STATE)
    bogus = KContext((0xDEAD,))
    assert ccm.get(bogus).num_blocks == 0
    assert ccm.get(bogus).edges == frozenset()
