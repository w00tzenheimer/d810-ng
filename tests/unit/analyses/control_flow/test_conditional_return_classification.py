"""Interval-map terminal classification: OLLVM sentinel-state terminals are CONDITIONAL_RETURN.

The DAG edge classifier marked CONDITIONAL_RETURN only for ``is_terminal_no_write`` (a direct return
that writes no state). OLLVM-flattened terminals instead write a *sentinel state* (e.g.
``state=0x1A2B3C4D``) that the dispatcher routes to its default fall-through (the shared return
block). The LiSA-sound test is an interval-map lookup: ``dispatcher.lookup(next_state)`` landing on
the dispatcher's default block (``default_block_serial``) — not a handler — is a CONDITIONAL_RETURN.
Without the dispatcher/default (portable/shallow path) only the no-write terminal is recognised,
byte-identical.
"""
from __future__ import annotations

from d810.analyses.control_flow.linearized_state_dag import _is_conditional_return


def test_no_write_terminal_is_return():
    # is_terminal_no_write: a direct return with no state write — always a return.
    assert _is_conditional_return(True, None, None, None) is True


def test_sentinel_state_routing_to_default_is_return():
    # target_state 0x1A2B3C4D resolves to no handler; dispatcher.lookup routes it to block 9,
    # which is the dispatcher's default (return) block -> CONDITIONAL_RETURN.
    assert _is_conditional_return(False, 0x1A2B3C4D, 9, 9) is True


def test_real_handler_transition_is_not_return():
    # target_state routes to a handler block (13 != default 9) -> CONDITIONAL_TRANSITION.
    assert _is_conditional_return(False, 0xB92456DE, 13, 9) is False


def test_unknown_default_is_conservative_not_return():
    # Without a known default block (portable/shallow path) a state write is never a return here.
    assert _is_conditional_return(False, 0x1A2B3C4D, 9, None) is False


def test_uncovered_state_is_not_return():
    # dispatcher.lookup returned None (state covered by no interval) -> not classified as return.
    assert _is_conditional_return(False, 0xDEADBEEF, None, 9) is False


def test_interval_dispatcher_default_target_is_max_coverage():
    # The fixture's table: 7 handler point-intervals + wide gap intervals all routing to block 9.
    # block 9 dominates coverage -> it is the recovered default (shared return) block.
    from d810.analyses.control_flow.interval_map import IntervalDispatcher, IntervalRow

    rows = [
        IntervalRow(lo=0x0, hi=0x2E7B9C30, target=9),
        IntervalRow(lo=0x2E7B9C30, hi=0x2E7B9C31, target=28),
        IntervalRow(lo=0x2E7B9C31, hi=0x3C8960A9, target=9),
        IntervalRow(lo=0x3C8960A9, hi=0x3C8960AA, target=16),
        IntervalRow(lo=0x3C8960AA, hi=0xC6685257, target=9),
        IntervalRow(lo=0xC6685257, hi=0xC6685258, target=10),
        IntervalRow(lo=0xC6685258, hi=0x100000000, target=9),
    ]
    disp = IntervalDispatcher(rows)
    assert disp.default_target == 9
    # And a handler point-state routes to its handler, not the default.
    assert disp.lookup(0xC6685257) == 10
    # The terminal sentinel (no handler) routes to the default -> return.
    assert disp.lookup(0x1A2B3C4D) == 9


def test_interval_dispatcher_empty_has_no_default():
    from d810.analyses.control_flow.interval_map import IntervalDispatcher

    assert IntervalDispatcher([]).default_target is None
