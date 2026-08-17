"""Tests for the portable concrete-state route evidence resolver."""

from __future__ import annotations

from d810.analyses.control_flow.concrete_state_route import (
    ConcreteStateRoute,
    resolve_concrete_state_route,
)
from d810.analyses.control_flow.dispatcher_resolution import (
    StateDispatcherMap,
    StateDispatcherRow,
)
from d810.analyses.control_flow.interval_map import IntervalDispatcher, IntervalRow
from d810.capabilities.dispatcher import RouterKind


def _exact(state: int, target: int) -> StateDispatcherMap:
    return StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                state_const=state,
                target_block=target,
                dispatcher_block=1,
                compare_block=2,
                branch_kind="jz",
                router_kind=RouterKind.CONDITION_CHAIN,
            ),
        ),
        dispatcher_entry_block=1,
        dispatcher_blocks=frozenset({1, 2}),
        state_var_stkoff=0x40,
        state_var_lvar_idx=None,
        router_kind=RouterKind.CONDITION_CHAIN,
    )


def test_exact_route_is_returned_with_exact_provenance() -> None:
    route = resolve_concrete_state_route(
        0x1234,
        exact_dispatcher_map=_exact(0x1234, 10),
    )

    assert route == ConcreteStateRoute(
        normalized_state=0x1234,
        target_block=10,
        source_kinds=("exact",),
    )


def test_interval_only_route_is_returned_with_interval_provenance() -> None:
    route = resolve_concrete_state_route(
        25,
        interval_dispatcher=IntervalDispatcher([IntervalRow(20, 30, 11)]),
    )

    assert route is not None
    assert route.normalized_state == 25
    assert route.target_block == 11
    assert route.source_kinds == ("interval",)


def test_agreeing_exact_and_interval_routes_merge_provenance() -> None:
    route = resolve_concrete_state_route(
        0x1234,
        exact_dispatcher_map=_exact(0x1234, 10),
        interval_dispatcher=IntervalDispatcher([IntervalRow(0x1200, 0x1300, 10)]),
    )

    assert route is not None
    assert route.target_block == 10
    assert route.source_kinds == ("exact", "interval")


def test_conflicting_exact_and_interval_routes_abstain() -> None:
    route = resolve_concrete_state_route(
        0x1234,
        exact_dispatcher_map=_exact(0x1234, 10),
        interval_dispatcher=IntervalDispatcher([IntervalRow(0x1200, 0x1300, 11)]),
    )

    assert route is None


def test_uncovered_state_abstains() -> None:
    route = resolve_concrete_state_route(
        0x1234,
        exact_dispatcher_map=_exact(0x5678, 10),
        interval_dispatcher=IntervalDispatcher([IntervalRow(0x2000, 0x2100, 11)]),
    )

    assert route is None


def test_bool_or_out_of_range_state_is_normalized_or_rejected_by_contract() -> None:
    assert resolve_concrete_state_route(True, exact_dispatcher_map=_exact(1, 10)) is None

    route = resolve_concrete_state_route(
        0x1_0000_1234,
        exact_dispatcher_map=_exact(0x1234, 10),
    )
    assert route is not None
    assert route.normalized_state == 0x1234
