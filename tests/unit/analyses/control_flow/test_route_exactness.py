"""Unit tests for the shared BST route-exactness decision (ticket d81-8xhg).

A recovered comparison-tree (BST) dispatcher legitimately emits RANGE rows: a
leaf covers the whole interval its comparison chain carved out, not just the
single state constant the original switch case used.  Judging exactness by
interval WIDTH (``hi == lo + 1``) therefore refuses every range-backed leaf,
including the ones that are provably unambiguous because only one state value
the function ever writes falls inside the interval.

These tests pin the corrected predicate:

* a range row that contains exactly one written state constant is exact
  evidence for that state;
* a range row containing two or more written constants stays refused;
* a range row containing none stays refused;
* the pre-existing singleton path is untouched (and does not need the
  written-state set at all).
"""

from __future__ import annotations

import pytest

from d810.analyses.control_flow.interval_map import IntervalDispatcher, IntervalRow
from d810.analyses.control_flow.route_exactness import (
    dispatcher_written_state_constants,
    interval_isolates_state,
    is_exact_route_interval,
    normalize_written_state_constants,
    written_states_in_interval,
)

# Real values recovered from sub_7FFB0E398850 (ticket d81-yci2 evidence):
# the initial state falls inside a range leaf whose only written member is
# itself.
_STATE = 0x1CAFDDE5
_LO = 0x1B7B68FD
_HI = 0x208318D7
_TARGET = 143


def test_singleton_row_is_exact_without_written_states():
    assert is_exact_route_interval(
        lo=_STATE, hi=_STATE + 1, state=_STATE, written_states=frozenset()
    )
    assert is_exact_route_interval(
        lo=_STATE, hi=_STATE + 1, state=_STATE, written_states=None
    )


def test_singleton_row_not_covering_state_is_refused():
    assert not is_exact_route_interval(
        lo=_STATE + 1, hi=_STATE + 2, state=_STATE, written_states=None
    )


def test_range_row_with_single_written_member_is_exact():
    written = frozenset({_STATE, 0x76B1AD38, 0x3FCA366B})
    assert is_exact_route_interval(
        lo=_LO, hi=_HI, state=_STATE, written_states=written
    )
    assert interval_isolates_state(lo=_LO, hi=_HI, state=_STATE, written_states=written)


def test_range_row_with_two_written_members_is_refused():
    written = frozenset({_STATE, _LO + 1})
    assert not is_exact_route_interval(
        lo=_LO, hi=_HI, state=_STATE, written_states=written
    )
    assert not interval_isolates_state(
        lo=_LO, hi=_HI, state=_STATE, written_states=written
    )


def test_range_row_with_no_written_members_is_refused():
    # ``state`` itself is not in the written set -> the intersection is empty
    # for the queried value and the row proves nothing about it.
    assert not is_exact_route_interval(
        lo=_LO, hi=_HI, state=_STATE, written_states=frozenset({0x76B1AD38})
    )


def test_range_row_without_written_states_keeps_the_old_refusal():
    assert not is_exact_route_interval(
        lo=_LO, hi=_HI, state=_STATE, written_states=frozenset()
    )
    assert not is_exact_route_interval(
        lo=_LO, hi=_HI, state=_STATE, written_states=None
    )


def test_range_row_not_covering_state_is_refused():
    written = frozenset({_STATE})
    assert not is_exact_route_interval(
        lo=_HI, hi=_HI + 0x100, state=_STATE, written_states=written
    )


def test_written_states_in_interval_masks_to_u32():
    written = normalize_written_state_constants(
        [_STATE | (1 << 32), 0x76B1AD38, None]
    )
    assert written == frozenset({_STATE, 0x76B1AD38})
    assert written_states_in_interval(lo=_LO, hi=_HI, written_states=written) == (
        frozenset({_STATE})
    )


def test_dispatcher_carries_written_state_constants():
    rows = [IntervalRow(_LO, _HI, _TARGET)]
    plain = IntervalDispatcher(rows)
    assert dispatcher_written_state_constants(plain) == frozenset()

    bound = plain.with_written_state_constants({_STATE})
    assert dispatcher_written_state_constants(bound) == frozenset({_STATE})
    # copy-on-write: the original is untouched
    assert dispatcher_written_state_constants(plain) == frozenset()
    assert [(r.lo, r.hi, r.target) for r in bound._rows] == [(_LO, _HI, _TARGET)]
    assert bound.default_target == plain.default_target


def test_dispatcher_written_state_constants_tolerates_foreign_objects():
    assert dispatcher_written_state_constants(None) == frozenset()
    assert dispatcher_written_state_constants(object()) == frozenset()


def test_debug_log_names_state_range_and_target(caplog):
    """Every accepted range-backed route leaves one auditable DEBUG line."""
    import logging as _logging

    from d810.core.logging import LevelFlag, getLogger

    module_logger = getLogger("d810.analyses.control_flow.route_exactness")
    previous = module_logger.level
    module_logger.setLevel(_logging.DEBUG)
    # ``debug_on`` is a cached LevelFlag, not a live ``isEnabledFor`` call, so
    # the cache must be invalidated after changing the level.
    LevelFlag.bump_config_version()
    try:
        with caplog.at_level(
            _logging.DEBUG, logger="d810.analyses.control_flow.route_exactness"
        ):
            assert is_exact_route_interval(
                lo=_LO,
                hi=_HI,
                state=_STATE,
                written_states=frozenset({_STATE}),
                target=_TARGET,
            )
    finally:
        module_logger.setLevel(previous)
        LevelFlag.bump_config_version()
    joined = "\n".join(record.getMessage() for record in caplog.records)
    assert "1CAFDDE5" in joined
    assert "1B7B68FD" in joined
    assert "208318D7" in joined
    assert "143" in joined


@pytest.mark.parametrize("bad", [(10, 10), (10, 5)])
def test_degenerate_intervals_are_refused(bad):
    lo, hi = bad
    assert not is_exact_route_interval(
        lo=lo, hi=hi, state=lo, written_states=frozenset({lo})
    )
