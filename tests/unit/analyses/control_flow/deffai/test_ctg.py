"""Unit tests for the Context Transition Graph -- DEFFAI Algorithm 2 (Step 7).

Covers: ``POSSIBLE_SUCCESSORS`` growing the window while ``len(ctx) < k`` and
sliding once full; a forked next-state set producing multiple successor contexts;
an unroutable next-state marking the context ``unresolved`` (no fabricated edge);
a ``top`` next-state marking ``unresolved``; finiteness.  No IDA.
"""
from __future__ import annotations

import pytest

from d810.ir.semantics import PredicateKind
from d810.analyses.control_flow.state_transition_domain import StateValue
from d810.analyses.data_flow.concolic.refs import LocationRef

from d810.analyses.control_flow.deffai.analysis import analyze_kswitch
from d810.analyses.control_flow.deffai.ccm import build_ccm
from d810.analyses.control_flow.deffai.context import ContextPolicy, KContext
from d810.analyses.control_flow.deffai.ctg import build_ctg, possible_successors

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


def _ctg(graph, *, k=2, initial=None, route=None):
    result = _analyze(graph, k=k, initial=initial)
    ccm = build_ccm(result, graph, state_cell=STATE)
    return result, build_ctg(
        result, ccm, state_cell=STATE, graph=graph, k=k, route=route
    )


# -- POSSIBLE_SUCCESSORS gate ----------------------------------------------
def test_possible_successors_grows_while_not_full():
    ctx = KContext((1,))
    assert possible_successors(ctx, 2, k=3) == KContext((1, 2))  # grows


def test_possible_successors_slides_when_full():
    ctx = KContext((1, 2))
    assert possible_successors(ctx, 3, k=2) == KContext((2, 3))  # slides


def test_possible_successors_exact_ticket_fork_shape():
    # <1,2> with next-states {3,4} at k=2 -> {<2,3>, <2,4>}.
    ctx = KContext((1, 2))
    assert possible_successors(ctx, 3, k=2) == KContext((2, 3))
    assert possible_successors(ctx, 4, k=2) == KContext((2, 4))


# -- CTG over a real fixture -----------------------------------------------
def _forking_handler_graph():
    # A dispatcher loop whose single handler forks its next-state into {20, 30}:
    #   0: dispatcher: if (state==10) goto 1 else 4
    #   1: handler-10: if (cond==0) goto 2 else 3
    #   2: state=20 -> 0     (back-edge, next-state 20)
    #   3: state=30 -> 0     (back-edge, next-state 30)
    #   4: ret
    cond = stk(0x20)
    b0 = block(0, (jcc(stk(STATE_OFF), num(10), taken=1, pred=PredicateKind.EQ),), (1, 4))
    b1 = block(1, (jcc(cond, num(0), taken=2, pred=PredicateKind.EQ),), (2, 3))
    b2 = block(2, (mov(num(20), stk(STATE_OFF)), goto(0)), (0,))
    b3 = block(3, (mov(num(30), stk(STATE_OFF)), goto(0)), (0,))
    b4 = block(4, (ret(),), ())
    return make_graph([b0, b1, b2, b3, b4])


def test_ctg_fork_produces_multiple_successor_contexts():
    graph = _forking_handler_graph()
    result, ctg = _ctg(graph, k=2, initial=10)
    # Some context's next-state set is {20,30} -> two successor contexts.
    fork_found = False
    for ctx, succs in ctg.successors.items():
        cases_seen = {sc.last for sc in succs if sc.last is not None}
        if {20, 30} <= cases_seen:
            fork_found = True
    assert fork_found, f"expected a fork to {{20,30}}; got {ctg.successors}"


def test_ctg_successor_contexts_follow_possible_successors():
    graph = _forking_handler_graph()
    result, ctg = _ctg(graph, k=2, initial=10)
    # Every successor context is an extend() of its source by a next-state.
    for ctx, succs in ctg.successors.items():
        for sc in succs:
            assert sc.depth <= 2  # k=2 bound
            if sc.last is not None:
                assert sc == possible_successors(ctx, sc.last, k=2)


def test_ctg_unroutable_next_state_marks_unresolved():
    # route() returns None for state 30 -> the context with next-state 30 is
    # marked unresolved (no successor context fabricated for it).
    graph = _forking_handler_graph()

    def route(s):
        return None if s == 30 else 0  # 30 is unroutable

    result, ctg = _ctg(graph, k=2, initial=10, route=route)
    assert ctg.unresolved, "a context with the unroutable next-state 30 should be unresolved"
    # No successor context carries 30 as its last case.
    for succs in ctg.successors.values():
        assert all(sc.last != 30 for sc in succs)


def test_ctg_top_next_state_marks_unresolved():
    # Handler writes an unknown (register) next-state -> top -> unresolved.
    from tests.unit.analyses.control_flow.deffai._helpers import reg

    b0 = block(0, (jcc(stk(STATE_OFF), num(10), taken=1, pred=PredicateKind.EQ),), (1, 2))
    b1 = block(1, (mov(reg(9), stk(STATE_OFF)), goto(0)), (0,))  # unknown next-state
    b2 = block(2, (ret(),), ())
    graph = make_graph([b0, b1, b2])
    result, ctg = _ctg(graph, k=2, initial=10)
    assert ctg.unresolved


def test_ctg_no_fabricated_edge_for_bottom_next_state():
    # A clean linear (no back-edge writing state) -> no next-states, no successors.
    b0 = block(0, (mov(num(10), stk(STATE_OFF)), goto(1)), (1,))
    b1 = block(1, (ret(),), ())
    graph = make_graph([b0, b1])
    result, ctg = _ctg(graph, k=2, initial=10)
    for succs in ctg.successors.values():
        assert succs == frozenset()


def test_ctg_finiteness_no_infinite_context_growth():
    graph = _forking_handler_graph()
    result, ctg = _ctg(graph, k=2, initial=10)
    # All contexts (sources + successors) are bounded-depth k-tuples.
    all_ctxs = set(ctg.successors) | {
        sc for succs in ctg.successors.values() for sc in succs
    }
    assert all(c.depth <= 2 for c in all_ctxs)
    assert len(all_ctxs) <= ContextPolicy().max_contexts


def test_ctg_initial_contexts_present():
    graph = _forking_handler_graph()
    result, ctg = _ctg(graph, k=2, initial=10)
    assert ctg.initial_contexts  # non-empty
    assert KContext(()) in ctg.initial_contexts
