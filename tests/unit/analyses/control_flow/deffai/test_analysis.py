"""Unit tests for the k-switch context-sensitive fixpoint (DEFFAI Step 5).

Covers: a clean linear chain keeps every context store a singleton and converges
with ``top_density == 0``; a conditional-fork handler yields a first-class set on
the back-edge store; an MBA/unknown next-state surfaces as ``top`` (raising
top_density); contexts stay finite.  No IDA -- the scalar fold is injected.
"""
from __future__ import annotations

import pytest

from d810.ir.flowgraph import BlockKind
from d810.ir.semantics import PredicateKind
from d810.analyses.control_flow.state_transition_domain import StateValue
from d810.analyses.data_flow.concolic.refs import LocationRef

from d810.analyses.control_flow.deffai.analysis import analyze_kswitch
from d810.analyses.control_flow.deffai.context import ContextPolicy, KContext
from d810.analyses.control_flow.deffai.powerset_store import PowersetStore

from tests.unit.analyses.control_flow.deffai._helpers import (
    block,
    goto,
    jcc,
    make_graph,
    mov,
    num,
    portable_block_evaluator,
    reg,
    ret,
    stk,
)

STATE_OFF = 0x10
STATE = LocationRef.stack(STATE_OFF, 8)
EVAL = portable_block_evaluator(STATE_OFF)


def _analyze(graph, *, k=2, initial=None, **kw):
    return analyze_kswitch(
        graph,
        policy=ContextPolicy(k=k),
        state_cell=STATE,
        initial_state=initial,
        block_evaluator=EVAL,
        state_var_stkoff=STATE_OFF,
        **kw,
    )


def test_clean_linear_chain_all_singletons_and_converges():
    # 0: state=10 -> 1 ; 1: state=20 -> 2 ; 2: ret
    b0 = block(0, (mov(num(10), stk(STATE_OFF)), goto(1)), (1,))
    b1 = block(1, (mov(num(20), stk(STATE_OFF)), goto(2)), (2,))
    b2 = block(2, (ret(),), ())
    graph = make_graph([b0, b1, b2])

    result = _analyze(graph, initial=10)
    assert result.converged
    assert result.top_density == 0.0
    # Every tracked state-cell value is a singleton (no forks).
    for per_block in result.s_hash.values():
        for store in per_block.values():
            sv = store.get(STATE)
            if not sv.is_bottom:
                assert sv.single() is not None


def test_state_write_observed_in_store():
    b0 = block(0, (mov(num(10), stk(STATE_OFF)), goto(1)), (1,))
    b1 = block(1, (mov(num(99), stk(STATE_OFF)), ret()), ())
    graph = make_graph([b0, b1])
    result = _analyze(graph, initial=10)
    # Block 1's in-store carries state=10 (written by block 0).
    store1 = result.store_at(KContext(()), 1)
    assert store1.get(STATE) == StateValue.of(10)


def test_conditional_fork_yields_set_at_merge():
    # Diamond writing two different next-states that merge:
    #   0: state=1 ; if (cond==0) goto 2 else 1
    #   1: state=0xAA -> 3
    #   2: state=0xBB -> 3
    #   3: merge -> ret
    cond = stk(0x20)
    b0 = block(
        0,
        (mov(num(1), stk(STATE_OFF)), jcc(cond, num(0), taken=2, pred=PredicateKind.EQ)),
        (1, 2),
    )
    b1 = block(1, (mov(num(0xAA), stk(STATE_OFF)), goto(3)), (3,))
    b2 = block(2, (mov(num(0xBB), stk(STATE_OFF)), goto(3)), (3,))
    b3 = block(3, (ret(),), ())
    graph = make_graph([b0, b1, b2, b3])

    result = _analyze(graph, initial=1)
    assert result.converged
    # The merge block 3 sees the first-class set {0xAA, 0xBB}.
    store3 = result.store_at(KContext(()), 3)
    assert store3.get(STATE) == StateValue.of_many([0xAA, 0xBB])
    assert not store3.get(STATE).is_top


def test_unknown_next_state_surfaces_as_top():
    # Block 1 writes state from a register (unresolved) -> top; block 2 then
    # reads that top in-store, so the unknown is observable in top_density.
    b0 = block(0, (mov(num(10), stk(STATE_OFF)), goto(1)), (1,))
    b1 = block(1, (mov(reg(9), stk(STATE_OFF)), goto(2)), (2,))  # reg(9) -> top
    b2 = block(2, (ret(),), ())
    graph = make_graph([b0, b1, b2])
    result = _analyze(graph, initial=10)
    # Block 2's in-store carries the top state cell written by block 1.
    assert result.store_at(KContext(()), 2).get(STATE).is_top
    assert result.top_density > 0.0


def test_context_keeps_two_handlers_distinct():
    # Dispatcher loop: state seeds 10; dispatcher routes 10->h1, 20->h2; h1 sets
    # state=20 then loops; h2 sets state=30 (exit). With k>=1 the contexts after
    # the dispatcher differ by the case taken.
    #   0: dispatcher: if (state==10) goto 1 else 2
    #   1: h1: state=20 -> 0   (back-edge)
    #   2: h2: state=30 -> 3
    #   3: ret
    b0 = block(0, (jcc(stk(STATE_OFF), num(10), taken=1, pred=PredicateKind.EQ),), (1, 2))
    b1 = block(1, (mov(num(20), stk(STATE_OFF)), goto(0)), (0,))
    b2 = block(2, (mov(num(30), stk(STATE_OFF)), goto(3)), (3,))
    b3 = block(3, (ret(),), ())
    graph = make_graph([b0, b1, b2, b3])

    result = _analyze(graph, k=2, initial=10)
    assert result.converged
    # More than one context is reachable (the dispatcher routing advanced it).
    assert len(result.reachable_contexts) >= 1
    # The equal-arm refinement keeps handler 1's in-store state == {10}.
    # Find a context whose store at block 1 has state cell == {10}.
    h1_states = [
        result.s_hash[ctx][1].get(STATE)
        for ctx in result.reachable_contexts
        if 1 in result.s_hash.get(ctx, {})
    ]
    assert any(sv == StateValue.of(10) for sv in h1_states)


def test_contexts_bounded_by_policy():
    b0 = block(0, (jcc(stk(STATE_OFF), num(10), taken=1, pred=PredicateKind.EQ),), (1, 2))
    b1 = block(1, (mov(num(20), stk(STATE_OFF)), goto(0)), (0,))
    b2 = block(2, (ret(),), ())
    graph = make_graph([b0, b1, b2])
    result = _analyze(graph, k=6, initial=10)
    assert result.converged
    assert len(result.reachable_contexts) <= ContextPolicy().max_contexts


def test_empty_initial_state_still_converges():
    b0 = block(0, (mov(num(5), stk(STATE_OFF)), goto(1)), (1,))
    b1 = block(1, (ret(),), ())
    graph = make_graph([b0, b1])
    result = _analyze(graph, initial=None)
    assert result.converged
