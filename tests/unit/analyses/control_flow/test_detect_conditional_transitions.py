"""Unit tests for detect_conditional_transitions (llr-zfyi).

A two-way branch is only a *conditional state transition* when the diverging
arms reach DIFFERENT next states. When both arms converge on the same next
state, the branch is intra-handler work and the transition is unconditional --
the detector must not emit conditional transitions for it (sub_7FFD
STATE_37B42A40 / handler block 122 over-production).
"""
from __future__ import annotations

from d810.ir.flowgraph import BlockSnapshot, FlowGraph
from d810.analyses.control_flow.state_machine_analysis import (
    HandlerPathResult,
    detect_conditional_transitions,
)


def _blk(serial, succs, preds=()):
    return BlockSnapshot(serial, 0, tuple(succs), tuple(preds), 0, 0, ())


def test_both_arms_same_state_is_not_a_conditional_transition() -> None:
    """Handler 122 shape: 122 -2way-> {123,124}; 123 -> 124; 124 writes the
    single next state. Both arms reach 0x63D54755, so detect must emit NO
    conditional transitions."""
    state = 0x63D54755
    fg = FlowGraph(
        blocks={
            122: _blk(122, (123, 124)),
            123: _blk(123, (124,), (122,)),
            124: _blk(124, (3,), (122, 123)),
            3: _blk(3, (), (124,)),
        },
        entry_serial=122,
        func_ea=0x180014BE0,
    )
    paths = [
        HandlerPathResult(124, state, [(124, 0x180015000)], [122, 124]),
        HandlerPathResult(124, state, [(124, 0x180015000)], [122, 123, 124]),
    ]
    conds = detect_conditional_transitions(
        122, paths, {state}, fg, incoming_state=0x37B42A40
    )
    assert conds == [], conds


def test_arms_to_distinct_states_remain_conditional() -> None:
    """Guard against over-correction: when the two arms write DIFFERENT next
    states, both conditional transitions must still be emitted."""
    state_x = 0x11111111
    state_y = 0x22222222
    fg = FlowGraph(
        blocks={
            122: _blk(122, (123, 124)),
            123: _blk(123, (3,), (122,)),
            124: _blk(124, (3,), (122,)),
            3: _blk(3, (), (123, 124)),
        },
        entry_serial=122,
        func_ea=0x180014BE0,
    )
    paths = [
        HandlerPathResult(123, state_x, [(123, 0x180015000)], [122, 123]),
        HandlerPathResult(124, state_y, [(124, 0x180015010)], [122, 124]),
    ]
    conds = detect_conditional_transitions(
        122, paths, {state_x, state_y}, fg, incoming_state=0x37B42A40
    )
    assert {c.target_state for c in conds} == {state_x, state_y}, conds
    assert len(conds) == 2, conds
