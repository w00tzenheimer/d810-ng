"""Unit tests for d810.analyses.control_flow.interval_map."""

from __future__ import annotations

import pytest

from d810.analyses.control_flow.interval_map import (
    Interval,
    IntervalDispatcher,
    IntervalRow,
    Node,
    NodeKind,
    EmittedRange,
    emit_dispatch_intervals,
    sort_and_validate,
    coalesce_same_target,
    compute_gaps,
    interval_dispatcher_from_state_map,
    U32_MIN,
    U32_MAX_EXCL,
)


# ---------------------------------------------------------------------------
# TestInterval
# ---------------------------------------------------------------------------


class TestInterval:
    def test_empty(self) -> None:
        assert Interval(5, 5).empty() is True
        assert Interval(5, 3).empty() is True
        assert Interval(0, 1).empty() is False

    def test_contains(self) -> None:
        iv = Interval(10, 20)
        assert iv.contains(10) is True
        assert iv.contains(19) is True
        assert iv.contains(20) is False
        assert iv.contains(9) is False

    def test_intersect(self) -> None:
        a = Interval(0, 10)
        b = Interval(5, 15)
        result = a.intersect(b)
        assert result == Interval(5, 10)

        c = Interval(0, 5)
        d = Interval(5, 10)
        assert c.intersect(d) is None

    def test_subtract_point(self) -> None:
        iv = Interval(0, 10)
        # Remove middle point
        parts = iv.subtract_point(5)
        assert parts == [Interval(0, 5), Interval(6, 10)]

        # Remove lower bound
        parts = iv.subtract_point(0)
        assert parts == [Interval(1, 10)]

        # Remove upper-bound-adjacent point (9 is the last point in [0,10))
        parts = iv.subtract_point(9)
        assert parts == [Interval(0, 9)]

        # Remove point outside interval → returns [self] unchanged
        parts = iv.subtract_point(20)
        assert parts == [Interval(0, 10)]

    def test_ordering(self) -> None:
        # (0,5) < (0,10) because dataclass order compares (lo, hi) lexicographically
        assert Interval(0, 5) < Interval(0, 10)
        # (0,5) < (1,5)
        assert Interval(0, 5) < Interval(1, 5)


# ---------------------------------------------------------------------------
# TestEmitDispatchIntervals
# ---------------------------------------------------------------------------


def _target_node(target: int) -> Node:
    return Node(kind=NodeKind.TARGET, target=target)


class TestEmitDispatchIntervals:
    def test_single_jnz_leaf(self) -> None:
        # JNZ(imm=0x30, target=42): equality → target; no yes child
        # With INTERVAL_DEFAULT fix: remainder emitted as default intervals
        node = Node(kind=NodeKind.JNZ, imm=0x30, target=42, yes=None, block_serial=7)
        emitted = emit_dispatch_intervals(node)
        # 1 point (eq match) + 2 INTERVAL_DEFAULT (remainder before/after)
        assert len(emitted) == 3
        eq_entries = [e for e in emitted if e.reason == "JNZ/eq"]
        default_entries = [e for e in emitted if e.reason == "INTERVAL_DEFAULT"]
        assert len(eq_entries) == 1
        assert eq_entries[0].interval == Interval(0x30, 0x31)
        assert eq_entries[0].target == 42
        assert len(default_entries) == 2
        assert default_entries[0].interval == Interval(0, 0x30)
        assert default_entries[0].target == 7
        assert default_entries[1].interval == Interval(0x31, U32_MAX_EXCL)
        assert default_entries[1].target == 7

    def test_single_jz_leaf(self) -> None:
        # JZ(imm=0x50, target=99): equality → target; no no child
        # With INTERVAL_DEFAULT fix: remainder emitted as default intervals
        node = Node(kind=NodeKind.JZ, imm=0x50, target=99, no=None, block_serial=8)
        emitted = emit_dispatch_intervals(node)
        # 1 point (eq match) + 2 INTERVAL_DEFAULT (remainder before/after)
        assert len(emitted) == 3
        eq_entries = [e for e in emitted if e.reason == "JZ/eq"]
        default_entries = [e for e in emitted if e.reason == "INTERVAL_DEFAULT"]
        assert len(eq_entries) == 1
        assert eq_entries[0].interval == Interval(0x50, 0x51)
        assert eq_entries[0].target == 99
        assert len(default_entries) == 2
        assert default_entries[0].interval == Interval(0, 0x50)
        assert default_entries[0].target == 8
        assert default_entries[1].interval == Interval(0x51, U32_MAX_EXCL)
        assert default_entries[1].target == 8

    def test_jbe_split(self) -> None:
        # JBE(0x100): yes=[0, 0x101) → target 1; no=[0x101, 2^32) → target 2
        node = Node(
            kind=NodeKind.JBE,
            imm=0x100,
            yes=_target_node(1),
            no=_target_node(2),
        )
        emitted = emit_dispatch_intervals(node)
        assert len(emitted) == 2
        lows = {e.interval.lo: e for e in emitted}
        assert lows[0].interval == Interval(0, 0x101)
        assert lows[0].target == 1
        assert lows[0x101].interval == Interval(0x101, U32_MAX_EXCL)
        assert lows[0x101].target == 2

    def test_jb_split(self) -> None:
        # JB(0x80): yes=[0, 0x80) → target 1; no=[0x80, 2^32) → target 2
        node = Node(
            kind=NodeKind.JB,
            imm=0x80,
            yes=_target_node(1),
            no=_target_node(2),
        )
        emitted = emit_dispatch_intervals(node)
        assert len(emitted) == 2
        lows = {e.interval.lo: e for e in emitted}
        assert lows[0].interval == Interval(0, 0x80)
        assert lows[0].target == 1
        assert lows[0x80].interval == Interval(0x80, U32_MAX_EXCL)
        assert lows[0x80].target == 2

    def test_jae_split(self) -> None:
        # JAE(0x80): yes=[0x80, 2^32) taken→1; no=[0, 0x80) fall→2
        node = Node(
            kind=NodeKind.JAE,
            imm=0x80,
            yes=_target_node(1),
            no=_target_node(2),
        )
        emitted = emit_dispatch_intervals(node)
        assert len(emitted) == 2
        lows = {e.interval.lo: e for e in emitted}
        # fall (no) = [0, 0x80) → target 2
        assert lows[0].interval == Interval(0, 0x80)
        assert lows[0].target == 2
        # taken (yes) = [0x80, 2^32) → target 1
        assert lows[0x80].interval == Interval(0x80, U32_MAX_EXCL)
        assert lows[0x80].target == 1

    def test_chained_jnz(self) -> None:
        # Chain: jnz(0x10, t=1) → jnz(0x20, t=2) → jnz(0x30, t=3)
        # Each JNZ emits its own point interval for equality; yes child is next node
        # With INTERVAL_DEFAULT fix: last node (yes=None) emits remainder as defaults
        inner = Node(kind=NodeKind.JNZ, imm=0x30, target=3, yes=None, block_serial=9)
        mid = Node(kind=NodeKind.JNZ, imm=0x20, target=2, yes=inner)
        root = Node(kind=NodeKind.JNZ, imm=0x10, target=1, yes=mid)
        emitted = emit_dispatch_intervals(root)
        eq_entries = [e for e in emitted if e.reason == "JNZ/eq"]
        default_entries = [e for e in emitted if e.reason == "INTERVAL_DEFAULT"]
        # 3 point intervals for equalities
        assert len(eq_entries) == 3
        targets_by_lo = {e.interval.lo: e.target for e in eq_entries}
        assert targets_by_lo[0x10] == 1
        assert targets_by_lo[0x20] == 2
        assert targets_by_lo[0x30] == 3
        for e in eq_entries:
            assert e.interval.hi == e.interval.lo + 1
        # 4 INTERVAL_DEFAULT entries for remainder gaps between/around the 3 points
        assert len(default_entries) == 4
        for e in default_entries:
            assert e.target == 9

    def test_balanced_condition_chain(self) -> None:
        # JBE root with JNZ leaves → 2 point intervals + INTERVAL_DEFAULT remainders
        yes_leaf = Node(kind=NodeKind.JNZ, imm=0x10, target=10, yes=None, block_serial=5)
        no_leaf = Node(kind=NodeKind.JNZ, imm=0x50, target=50, yes=None, block_serial=6)
        root = Node(kind=NodeKind.JBE, imm=0x30, yes=yes_leaf, no=no_leaf)
        emitted = emit_dispatch_intervals(root)
        eq_entries = [e for e in emitted if e.reason in ("JNZ/eq",)]
        default_entries = [e for e in emitted if e.reason == "INTERVAL_DEFAULT"]
        # 2 point intervals for exact matches
        assert len(eq_entries) == 2
        targets = {e.target for e in eq_entries}
        assert targets == {10, 50}
        # INTERVAL_DEFAULT remainder intervals cover the rest of the domain
        # yes_leaf (domain [0, 0x31)): [0, 0x10) + [0x11, 0x31) → blk 5
        # no_leaf (domain [0x31, 2^32)): [0x31, 0x50) + [0x51, 2^32) → blk 6
        assert len(default_entries) == 4


# ---------------------------------------------------------------------------
# TestSortAndValidate
# ---------------------------------------------------------------------------


class TestSortAndValidate:
    def test_no_overlap(self) -> None:
        items = [
            EmittedRange(Interval(0, 5), 1),
            EmittedRange(Interval(3, 8), 2),  # overlaps with first
        ]
        with pytest.raises(AssertionError):
            sort_and_validate(items)

    def test_valid_sorted(self) -> None:
        items = [
            EmittedRange(Interval(10, 20), 2),
            EmittedRange(Interval(0, 10), 1),
        ]
        result = sort_and_validate(items)
        assert result[0].interval.lo == 0
        assert result[1].interval.lo == 10

    def test_adjacent_ok(self) -> None:
        # Adjacent (touching) intervals are not overlapping
        items = [
            EmittedRange(Interval(0, 5), 1),
            EmittedRange(Interval(5, 10), 2),
        ]
        result = sort_and_validate(items)
        assert len(result) == 2


# ---------------------------------------------------------------------------
# TestCoalesce
# ---------------------------------------------------------------------------


class TestCoalesce:
    def test_coalesce(self) -> None:
        # Two adjacent intervals with same target → merged into one
        items = [
            EmittedRange(Interval(0, 5), 42),
            EmittedRange(Interval(5, 10), 42),
        ]
        result = coalesce_same_target(items)
        assert len(result) == 1
        assert result[0].interval == Interval(0, 10)
        assert result[0].target == 42

    def test_no_coalesce_different_target(self) -> None:
        items = [
            EmittedRange(Interval(0, 5), 1),
            EmittedRange(Interval(5, 10), 2),
        ]
        result = coalesce_same_target(items)
        assert len(result) == 2

    def test_no_coalesce_gap(self) -> None:
        # Gap between intervals: not adjacent → no merge even with same target
        items = [
            EmittedRange(Interval(0, 5), 42),
            EmittedRange(Interval(6, 10), 42),
        ]
        result = coalesce_same_target(items)
        assert len(result) == 2

    def test_empty(self) -> None:
        assert coalesce_same_target([]) == []


# ---------------------------------------------------------------------------
# TestComputeGaps
# ---------------------------------------------------------------------------


class TestComputeGaps:
    def test_gaps(self) -> None:
        domain = Interval(0, 100)
        items = [
            EmittedRange(Interval(10, 20), 1),
            EmittedRange(Interval(50, 60), 2),
        ]
        gaps = compute_gaps(items, domain=domain)
        assert gaps == [Interval(0, 10), Interval(20, 50), Interval(60, 100)]

    def test_no_gaps(self) -> None:
        domain = Interval(0, 20)
        items = [
            EmittedRange(Interval(0, 10), 1),
            EmittedRange(Interval(10, 20), 2),
        ]
        gaps = compute_gaps(items, domain=domain)
        assert gaps == []

    def test_all_gap(self) -> None:
        domain = Interval(0, 10)
        gaps = compute_gaps([], domain=domain)
        assert gaps == [Interval(0, 10)]


# ---------------------------------------------------------------------------
# TestIntervalDispatcher
# ---------------------------------------------------------------------------


class TestIntervalDispatcher:
    def _build(self) -> IntervalDispatcher:
        rows = [
            IntervalRow(10, 11, "exact_ten"),   # point
            IntervalRow(20, 30, "range_20_29"),  # range
            IntervalRow(50, 51, "exact_fifty"),  # point
        ]
        return IntervalDispatcher(rows)

    def test_exact_match(self) -> None:
        d = self._build()
        assert d.lookup(10) == "exact_ten"
        assert d.lookup(50) == "exact_fifty"

    def test_range_match(self) -> None:
        d = self._build()
        assert d.lookup(20) == "range_20_29"
        assert d.lookup(29) == "range_20_29"
        assert d.lookup(25) == "range_20_29"

    def test_uncovered(self) -> None:
        d = self._build()
        assert d.lookup(0) is None
        assert d.lookup(11) is None
        assert d.lookup(30) is None
        assert d.lookup(100) is None

    def test_lookup_row(self) -> None:
        d = self._build()
        row = d.lookup_row(25)
        assert row is not None
        assert row.lo == 20
        assert row.hi == 30
        assert row.target == "range_20_29"

        assert d.lookup_row(5) is None

    def test_empty(self) -> None:
        d = IntervalDispatcher([])
        assert d.lookup(0) is None
        assert d.lookup(0xFFFFFFFF) is None
        assert len(d) == 0
        assert not d

    def test_overlap_rejected(self) -> None:
        rows = [
            IntervalRow(0, 10, 1),
            IntervalRow(5, 15, 2),
        ]
        with pytest.raises(AssertionError):
            IntervalDispatcher(rows)

    def test_from_emitted(self) -> None:
        emitted = [
            EmittedRange(Interval(0, 10), 1),
            EmittedRange(Interval(10, 20), None),  # skipped
            EmittedRange(Interval(20, 30), 3),
        ]
        d = IntervalDispatcher.from_emitted(emitted)
        assert len(d) == 2
        assert d.lookup(5) == 1
        assert d.lookup(15) is None  # None target was skipped
        assert d.lookup(25) == 3

    def test_to_handler_state_map(self) -> None:
        rows = [
            IntervalRow(10, 11, 100),    # width-1 → included
            IntervalRow(20, 30, 200),    # width-10 → excluded
            IntervalRow(50, 51, 300),    # width-1 → included
        ]
        d = IntervalDispatcher(rows)
        state_map = d.to_handler_state_map()
        assert state_map == {10: 100, 50: 300}

    def test_to_handler_range_map(self) -> None:
        rows = [
            IntervalRow(10, 11, 100),    # [10, 11) → hi_incl = 10
            IntervalRow(20, 30, 200),    # [20, 30) → hi_incl = 29
        ]
        d = IntervalDispatcher(rows)
        range_map = d.to_handler_range_map()
        assert range_map[100] == (10, 10)
        assert range_map[200] == (20, 29)


# ---------------------------------------------------------------------------
# TestIntervalDispatcherLookupRange
# ---------------------------------------------------------------------------


class TestIntervalDispatcherLookupRange:
    """Tests for IntervalDispatcher.lookup_range()."""

    def _make_dispatcher(self, rows):
        d = IntervalDispatcher.__new__(IntervalDispatcher)
        d._rows = [IntervalRow(*r) for r in rows]
        return d

    def test_single_interval_fully_inside(self):
        d = self._make_dispatcher([(10, 20, 42)])
        assert d.lookup_range(12, 15) == 42

    def test_range_spans_two_same_target(self):
        d = self._make_dispatcher([(10, 20, 42), (20, 30, 42)])
        assert d.lookup_range(15, 25) == 42

    def test_range_spans_two_different_targets(self):
        d = self._make_dispatcher([(10, 20, 42), (20, 30, 99)])
        assert d.lookup_range(15, 25) is None

    def test_no_overlap(self):
        d = self._make_dispatcher([(10, 20, 42)])
        assert d.lookup_range(30, 40) is None

    def test_empty_dispatcher(self):
        d = self._make_dispatcher([])
        assert d.lookup_range(0, 100) is None

    def test_exact_interval_match(self):
        d = self._make_dispatcher([(10, 20, 42)])
        assert d.lookup_range(10, 19) == 42

    def test_single_point_range(self):
        d = self._make_dispatcher([(10, 20, 42)])
        assert d.lookup_range(15, 15) == 42


# ---------------------------------------------------------------------------
# TestIntervalDispatcherFromStateMap
# ---------------------------------------------------------------------------


class TestIntervalDispatcherFromStateMap:
    """Tests for interval_dispatcher_from_state_map().

    This is the equality-chain adapter: a register/equality-chain
    ``StateDispatcherMap`` (``jz eax, #state, @handler``) becomes the same
    interval-set router the comparison-condition-chain path produces, so the unflatten back-edge
    emit is dispatcher-shape-agnostic.
    """

    def test_each_state_routes_to_its_handler(self) -> None:
        d = interval_dispatcher_from_state_map({0x10: 100, 0x20: 200, 0x30: 300})
        assert d.lookup(0x10) == 100
        assert d.lookup(0x20) == 200
        assert d.lookup(0x30) == 300

    def test_single_value_rows(self) -> None:
        # Each state occupies exactly [state, state + 1) — a one-point row.
        d = interval_dispatcher_from_state_map({0x42: 7})
        assert d.lookup(0x42) == 7
        assert d.lookup(0x41) is None
        assert d.lookup(0x43) is None

    def test_gap_states_uncovered(self) -> None:
        d = interval_dispatcher_from_state_map({0x10: 100, 0x30: 300})
        # 0x20 is in the gap between the two single-value rows.
        assert d.lookup(0x20) is None
        assert d.lookup(0x00) is None
        assert d.lookup(0xFFFFFFFF) is None

    def test_explicit_default_trusted_over_max_row_count(self) -> None:
        # With three single-value rows the max-row-count heuristic would pick a
        # handler (each appears once → tie). An explicit default must win.
        d = interval_dispatcher_from_state_map(
            {0x10: 100, 0x20: 200, 0x30: 300},
            default_target=999,
        )
        assert d.default_target == 999

    def test_no_default_stays_none_no_heuristic(self) -> None:
        # Exact single-value maps must NOT run the gap-row max-count heuristic
        # (it would spuriously crown a real handler the default and mis-classify
        # transitions into it as returns). With no explicit default it stays None;
        # the consumer detects returns structurally (uncovered / STOP routing).
        d = interval_dispatcher_from_state_map({0x10: 50, 0x20: 50, 0x30: 300})
        assert d.default_target is None

    def test_state_handler_is_the_default_block(self) -> None:
        # A written state can legitimately route to the shared-return block; the
        # lookup still resolves it, and default_target reports the same block.
        d = interval_dispatcher_from_state_map(
            {0x10: 100, 0x20: 777},
            default_target=777,
        )
        assert d.lookup(0x20) == 777
        assert d.default_target == 777

    def test_high_bit_state_masked_to_32_bit(self) -> None:
        # Signed/high-bit state constants are masked to their unsigned 32-bit
        # form so lookup matches the masked query.
        d = interval_dispatcher_from_state_map({0xFEB2A1D6: 182})
        assert d.lookup(0xFEB2A1D6) == 182

    def test_negative_state_normalized(self) -> None:
        # A negative Python int (signed view) maps to the same row as its
        # unsigned 32-bit representation.
        d = interval_dispatcher_from_state_map({-2: 5})
        assert d.lookup(0xFFFFFFFE) == 5

    def test_empty_map(self) -> None:
        d = interval_dispatcher_from_state_map({})
        assert len(d) == 0
        assert d.lookup(0x10) is None
        assert d.default_target is None
