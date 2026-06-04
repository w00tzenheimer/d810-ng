"""S2 unit tests: ComparisonDispatcherModel (exact ∪ interval routing).

The 28-orphan fix: an interval-routed next-state (sub_7FFD's
``0x79F598F7 ∈ [0x737189d6, 0x7c2c0220] -> blk 52``) must ``route`` to block 52
via ``WrappedInterval.contains`` instead of returning ``None`` exact-only.
"""
from __future__ import annotations

from types import SimpleNamespace

from d810.analyses.control_flow.comparison_dispatcher_model import (
    ComparisonDispatcherModel,
    build_partition,
    intervals_from_range_map,
    route_via_interval_sets,
)
from d810.analyses.control_flow.dispatcher_kind import DispatcherType
from d810.analyses.control_flow.dispatcher_resolution import (
    StateDispatcherMap,
    StateDispatcherRow,
)
from d810.analyses.control_flow.semantic_transition import resolve_state_transitions
from d810.analyses.data_flow.abstract_value import Block, Unknown

# sub_7FFD anchor values (from the acceptance metric).
_STATE = 0x79F598F7
_LO, _HI = 0x737189D6, 0x7C2C0220
_BLK52 = 52
_BLK52_EA = 0x18001450D


def _map(rows=(), *, entry=2, blocks=frozenset({2}), stkoff=0x3C):
    return StateDispatcherMap(
        rows=tuple(rows),
        dispatcher_entry_block=entry,
        dispatcher_blocks=frozenset(blocks),
        state_var_stkoff=stkoff,
        state_var_lvar_idx=None,
        source=DispatcherType.CONDITIONAL_CHAIN,
    )


def _row(state_const, target, *, block=2):
    return StateDispatcherRow(
        state_const=state_const,
        target_block=target,
        dispatcher_block=block,
        compare_block=block,
        branch_kind="eq",
        source=DispatcherType.CONDITIONAL_CHAIN,
    )


# --- the pure routing function --------------------------------------------


def _route(value, *, state_to_handler, handler_range_map=None, default_target_block=None):
    """Route via the single IntervalSet router over the complete partition."""
    return route_via_interval_sets(
        value,
        target_intervals=build_partition(
            state_to_handler, intervals_from_range_map(handler_range_map)
        ),
        default_target_block=default_target_block,
    )


def test_route_exact_first():
    assert (
        _route(0xAA, state_to_handler={0xAA: 7}) == 7
    )


def test_route_interval_resolves_the_dropped_edge():
    # THE bug: exact-only returns None; interval row resolves to 52.
    assert _route(_STATE, state_to_handler={}) is None
    assert (
        _route(
            _STATE, state_to_handler={}, handler_range_map={_BLK52: (_LO, _HI)}
        )
        == _BLK52
    )


def test_route_interval_miss_returns_none():
    out_of_range = _HI + 1
    assert (
        _route(
            out_of_range, state_to_handler={}, handler_range_map={_BLK52: (_LO, _HI)}
        )
        is None
    )


def test_route_skips_degenerate_catchall_span():
    # A near-full-word span is the dispatcher default arm, not a handler range.
    assert (
        _route(
            0x1234, state_to_handler={}, handler_range_map={99: (0, 0xFFFFFFFF)}
        )
        is None
    )


def test_route_skips_rows_already_claimed_exactly():
    # handler 7 is exact; its range row must not double-claim a different value.
    out = _route(
        0x500,
        state_to_handler={0x100: 7},
        handler_range_map={7: (0x400, 0x600)},
    )
    assert out is None


def test_route_default_arm_last():
    assert (
        _route(0xDEAD, state_to_handler={}, default_target_block=3)
        == 3
    )


# --- the model wrapper -----------------------------------------------------


def test_model_route_block_carries_ea():
    model = ComparisonDispatcherModel(
        dispatch_map=_map(),
        handler_range_map={_BLK52: (_LO, _HI)},
        block_ea={_BLK52: _BLK52_EA},
    )
    rr = model.route(_STATE)
    assert isinstance(rr, Block)
    assert rr.serial == _BLK52 and rr.ea == _BLK52_EA


def test_model_route_unknown_surfaces_reason():
    model = ComparisonDispatcherModel(dispatch_map=_map())
    rr = model.route(_STATE)
    assert isinstance(rr, Unknown)
    assert rr.reason == "state_not_in_dispatcher_map"


def test_model_metadata_from_map():
    model = ComparisonDispatcherModel(
        dispatch_map=_map(rows=[_row(0xAA, 7)], entry=2, blocks={2, 3})
    )
    assert model.state_var() == 0x3C
    assert model.entry == 2
    assert model.is_dispatcher(3) and not model.is_dispatcher(99)
    assert model.region() == frozenset({2, 3})


def test_model_resolve_target_unwraps_block():
    model = ComparisonDispatcherModel(
        dispatch_map=_map(), handler_range_map={_BLK52: (_LO, _HI)}
    )
    assert model.resolve_target(_STATE) == _BLK52
    assert model.resolve_target(_HI + 1) is None


def test_from_recovery_threads_bst_evidence():
    class _Evidence:
        handler_range_map = {_BLK52: (_LO, _HI)}
        default_block_serial = None

    recovery_map = _map(rows=[_row(0xAA, 7)])
    model = ComparisonDispatcherModel.from_recovery(
        recovery_map, bst_evidence=_Evidence()
    )
    # exact row still works
    assert model.resolve_target(0xAA) == 7
    # AND the threaded interval row now resolves 0x79F598F7
    assert model.resolve_target(_STATE) == _BLK52


def test_from_recovery_exact_only_without_evidence_matches_legacy():
    recovery_map = _map(rows=[_row(0xAA, 7)])
    model = ComparisonDispatcherModel.from_recovery(recovery_map, bst_evidence=None)
    # byte-identical to the exact-only StateDispatcherMap.resolve_target
    assert model.resolve_target(0xAA) == recovery_map.resolve_target(0xAA) == 7
    assert model.resolve_target(_STATE) is None
    assert recovery_map.resolve_target(_STATE) is None


# --- StateDispatcherMap.resolve_target delegation parity (legacy safety) ---


def test_state_dispatcher_map_resolve_target_stays_exact_only():
    m = _map(rows=[_row(0xAA, 7), _row(0xBB, 9)])
    assert m.resolve_target(0xAA) == 7
    assert m.resolve_target(0xBB) == 9
    assert m.resolve_target(0xCC) is None  # no interval, no default -> exact miss


# --- resolver wiring: routing through the model reconnects the dropped edge -


def test_resolver_drops_edge_without_model_but_resolves_with_it():
    # blk 123 writes next-state 0x79F598F7 (interval-routed to blk 52).
    facts = SimpleNamespace(
        active_observations=(
            SimpleNamespace(
                kind="StateTransitionAnchorFact",
                fact_id="f123",
                payload={
                    "source_block_serial": 123,
                    "source_state_const": _STATE,
                    "successor_kind": "branch",
                },
            ),
        )
    )
    dmap = _map(rows=[_row(0xAA, 7)], blocks={2})

    # WITHOUT the model: exact-only -> the edge is dropped (the bug).
    dropped = resolve_state_transitions(None, facts, dispatch_map=dmap)[0]
    assert dropped.resolved_next_block_serial is None
    assert dropped.resolution_reason == "state_not_in_dispatcher_map"

    # WITH the comparison model carrying the interval row -> resolves to 52.
    model = ComparisonDispatcherModel(
        dispatch_map=dmap, handler_range_map={_BLK52: (_LO, _HI)}
    )
    fixed = resolve_state_transitions(None, facts, dispatch_map=dmap, model=model)[0]
    assert fixed.resolved_next_block_serial == _BLK52
    assert fixed.resolution_reason == "resolved_exact_state"


# --- multi-interval (split-range) handler completeness ---------------------
# The lossy ``handler_range_map`` stores ONE ``(lo, hi)`` per handler, so a
# split-range handler (reachable via two disjoint intervals) drops one range.
# ``from_recovery`` now builds the complete abstract-domain ``IntervalSet`` from
# the full ``IntervalDispatcher`` rows, so BOTH ranges resolve.


def test_from_recovery_multi_interval_handler_resolves_every_range():
    from d810.analyses.control_flow.interval_map import (
        IntervalDispatcher,
        IntervalRow,
    )

    # blk 52 is reached via TWO disjoint ranges; blk 99 is the wide catch-all
    # default arm (excluded from the per-handler partition).
    dispatcher = IntervalDispatcher(
        [
            IntervalRow(0x0, 0x100, 99),
            IntervalRow(0x100, 0x200, _BLK52),  # range A: [0x100, 0x1FF]
            IntervalRow(0x200, 0x800, 99),
            IntervalRow(0x800, 0x900, _BLK52),  # range B: [0x800, 0x8FF]
            IntervalRow(0x900, 0x1_0000_0000, 99),
        ]
    )

    class _Evidence:
        handler_range_map = {_BLK52: (0x100, 0x1FF)}  # lossy: only range A
        default_block_serial = None
        dispatcher_attr = dispatcher

        def __init__(self):
            self.dispatcher = self.dispatcher_attr

    model = ComparisonDispatcherModel.from_recovery(
        _map(), bst_evidence=_Evidence()
    )
    # Range A (the one the lossy map kept) AND range B (the one it dropped)
    # both resolve to blk 52 -- the multi-interval completeness fix.
    assert model.resolve_target(0x150) == _BLK52
    assert model.resolve_target(0x850) == _BLK52
    # A true gap (no handler covers it) still surfaces as Unknown / None.
    assert model.resolve_target(0x500) is None

    # Contrast: a model carrying only the lossy single-interval map drops B.
    lossy = ComparisonDispatcherModel(
        dispatch_map=_map(), handler_range_map={_BLK52: (0x100, 0x1FF)}
    )
    assert lossy.resolve_target(0x150) == _BLK52
    assert lossy.resolve_target(0x850) is None  # range B silently dropped
