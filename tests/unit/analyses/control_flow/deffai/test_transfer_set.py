"""Unit tests for the set-valued block transfer (DEFFAI Step 3).

Covers: singleton-fold parity with the scalar evaluator; the multi-value product
join; the 2-way ``select``/``cmov`` fork yielding ``{a,b}`` on the merge; per-arm
``assume`` pruning an infeasible value to ⊥; the ``switch_cases`` jtbl fan-out;
and ⊤-degradation past the product cap.  No IDA -- the scalar fold is injected.
"""
from __future__ import annotations

import pytest

from d810.ir.flowgraph import BlockKind
from d810.ir.semantics import PredicateKind
from d810.analyses.control_flow.state_transition_domain import StateValue
from d810.analyses.data_flow.concolic.refs import LocationRef

from d810.analyses.control_flow.deffai.powerset_store import PowersetStore
from d810.analyses.control_flow.deffai.transfer import (
    mop_cell,
    transfer_block_set,
)

from tests.unit.analyses.control_flow.deffai._helpers import (
    block,
    goto,
    jcc,
    jtbl,
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
COND = LocationRef.stack(0x20, 8)
EVAL = portable_block_evaluator(STATE_OFF)


def _transfer(blk, in_store, **kw):
    return transfer_block_set(
        blk,
        in_store,
        state_cell=STATE,
        block_evaluator=EVAL,
        state_var_stkoff=STATE_OFF,
        **kw,
    )


def test_mop_cell_maps_stack_and_reg():
    assert mop_cell(stk(0x10)) == LocationRef.stack(0x10, 8)
    assert mop_cell(reg(5)) == LocationRef.reg(5, 8)
    assert mop_cell(num(3)) is None  # a constant names no cell


def test_singleton_fold_writes_constant_to_state_cell():
    # block: mov 0x1234, state ; goto 1
    blk = block(0, (mov(num(0x1234), stk(STATE_OFF)), goto(1)), (1,))
    out = _transfer(blk, PowersetStore.bottom())
    assert out[1].get(STATE) == StateValue.of(0x1234)


def test_singleton_fold_parity_with_scalar_evaluator():
    # The singleton fast-path must equal the scalar evaluator run directly.
    blk = block(
        0,
        (mov(num(0xAA), stk(STATE_OFF)), mov(stk(STATE_OFF), reg(3)), goto(1)),
        (1,),
    )
    in_stk = {0x40: 7}
    in_reg = {}
    out_stk, out_reg = EVAL(blk, dict(in_stk), dict(in_reg), STATE_OFF)

    in_store = PowersetStore.of(
        {LocationRef.stack(0x40, 8): StateValue.of(7)}
    )
    out = _transfer(blk, in_store)[1]
    # Every scalar out-cell appears as a singleton in the set out-store.
    for off, val in out_stk.items():
        assert out.get(LocationRef.stack(off, 8)) == StateValue.of(val)
    for rid, val in out_reg.items():
        assert out.get(LocationRef.reg(rid, 8)) == StateValue.of(val)


def test_two_way_fork_select_yields_set_on_merge():
    # Diamond:
    #   0: if (cond == 0) goto 2 else 1
    #   1: mov 0xAA, state ; goto 3
    #   2: mov 0xBB, state ; goto 3
    #   3: merge (ret)
    b0 = block(0, (jcc(stk(0x20), num(0), taken=2, pred=PredicateKind.EQ),), (1, 2))
    b1 = block(1, (mov(num(0xAA), stk(STATE_OFF)), goto(3)), (3,))
    b2 = block(2, (mov(num(0xBB), stk(STATE_OFF)), goto(3)), (3,))
    b3 = block(3, (ret(),), ())
    graph = make_graph([b0, b1, b2, b3])

    # Fold each arm with a bottom state, join at the merge.
    s1 = _transfer(graph.blocks[1], PowersetStore.bottom())[3]
    s2 = _transfer(graph.blocks[2], PowersetStore.bottom())[3]
    merged = s1.join(s2)
    assert merged.get(STATE) == StateValue.of_many([0xAA, 0xBB])
    # First-class set, NOT collapsed to top.
    assert not merged.get(STATE).is_top


def test_two_way_eq_arm_refinement_prunes_infeasible_value():
    # in_store: state in {10, 20}. Branch: if (state == 10) goto taken=2 else 1.
    blk = block(
        0, (jcc(stk(STATE_OFF), num(10), taken=2, pred=PredicateKind.EQ),), (1, 2)
    )
    in_store = PowersetStore.of({STATE: StateValue.of_many([10, 20])})
    arms = _transfer(blk, in_store)
    # Equal arm (taken=2): state refined to {10}.
    assert arms[2].get(STATE) == StateValue.of(10)
    # Not-equal arm (fallthrough=1): {20} (10 excluded).
    assert arms[1].get(STATE) == StateValue.of_many([20])


def test_eq_arm_infeasible_value_becomes_bottom():
    # state == 99 but the incoming set is {10,20} -> equal arm is infeasible.
    blk = block(
        0, (jcc(stk(STATE_OFF), num(99), taken=2, pred=PredicateKind.EQ),), (1, 2)
    )
    in_store = PowersetStore.of({STATE: StateValue.of_many([10, 20])})
    arms = _transfer(blk, in_store)
    assert arms[2].get(STATE).is_bottom  # dead dispatcher edge surfaced, not guessed
    assert arms[1].get(STATE) == StateValue.of_many([10, 20])


def test_ne_arm_refinement():
    # if (state != 10) goto taken=2 else fallthrough=1 (the EQUAL arm).
    blk = block(
        0, (jcc(stk(STATE_OFF), num(10), taken=2, pred=PredicateKind.NE),), (1, 2)
    )
    in_store = PowersetStore.of({STATE: StateValue.of_many([10, 20, 30])})
    arms = _transfer(blk, in_store)
    # NE: the fallthrough (1) is the equal arm -> {10}; taken (2) excludes 10.
    assert arms[1].get(STATE) == StateValue.of(10)
    assert arms[2].get(STATE) == StateValue.of_many([20, 30])


def test_multi_value_product_joins_results():
    # in_store: src reg in {1, 2}; block copies src -> dest. Out dest = {1,2}.
    src = LocationRef.reg(7, 8)
    dest = LocationRef.stack(0x50, 8)
    blk = block(0, (mov(reg(7), stk(0x50)), goto(1)), (1,))
    in_store = PowersetStore.of({src: StateValue.of_many([1, 2])})
    out = _transfer(blk, in_store)[1]
    assert out.get(dest) == StateValue.of_many([1, 2])


def test_switch_cases_fan_out_refines_state_per_case():
    # jtbl on the state cell: case {10}->2, case {20}->3, default->4.
    cases = (((10,), 2), ((20,), 3), ((), 4))
    blk = block(0, (jtbl(cases),), (2, 3, 4), kind=BlockKind.N_WAY)
    in_store = PowersetStore.of({STATE: StateValue.of_many([10, 20, 30])})
    arms = _transfer(blk, in_store)
    assert arms[2].get(STATE) == StateValue.of(10)
    assert arms[3].get(STATE) == StateValue.of(20)
    # default arm carries the unrefined fold.
    assert arms[4].get(STATE) == StateValue.of_many([10, 20, 30])


def test_top_read_degrades_written_cell_to_top():
    # state is top going in; the block copies it to a dest -> dest stays top.
    dest = LocationRef.stack(0x60, 8)
    blk = block(0, (mov(stk(STATE_OFF), stk(0x60)), goto(1)), (1,))
    in_store = PowersetStore.of({STATE: StateValue.top()})
    out = _transfer(blk, in_store)[1]
    assert out.get(STATE).is_top


def test_product_cap_degrades_to_top():
    # A small max_product forces ⊤-degradation when the product exceeds it.
    src = LocationRef.reg(7, 8)
    dest = LocationRef.stack(0x70, 8)
    blk = block(0, (mov(reg(7), stk(0x70)), goto(1)), (1,))
    in_store = PowersetStore.of({src: StateValue.of_many([1, 2, 3, 4])})
    out = transfer_block_set(
        blk,
        in_store,
        state_cell=STATE,
        block_evaluator=EVAL,
        state_var_stkoff=STATE_OFF,
        max_product=2,  # 4 values > cap -> degrade
    )[1]
    assert out.get(dest).is_top


def test_one_way_passthrough_keeps_unrelated_cells():
    other = LocationRef.stack(0x80, 8)
    blk = block(0, (mov(num(5), stk(STATE_OFF)), goto(1)), (1,))
    in_store = PowersetStore.of({other: StateValue.of(42)})
    out = _transfer(blk, in_store)[1]
    assert out.get(other) == StateValue.of(42)  # untouched cell passes through
    assert out.get(STATE) == StateValue.of(5)


def test_terminal_block_has_no_successors():
    blk = block(0, (ret(),), ())
    out = _transfer(blk, PowersetStore.singleton(STATE, 1))
    assert out == {}
