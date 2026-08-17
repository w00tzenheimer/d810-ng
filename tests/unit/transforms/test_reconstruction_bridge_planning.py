"""Tests for fail-closed state routing in bridge planning."""

from __future__ import annotations

from types import SimpleNamespace

from d810.analyses.control_flow.dispatcher_resolution import (
    StateDispatcherMap,
    StateDispatcherRow,
)
from d810.analyses.control_flow.interval_map import IntervalDispatcher, IntervalRow
from d810.capabilities.dispatcher import RouterKind
from d810.transforms.reconstruction_bridge_planning import (
    plan_fixpoint_feeder_modifications,
)


class _Block:
    nsucc = 1

    def __init__(self) -> None:
        self.succs = (1,)


class _Graph:
    blocks = (10,)

    @staticmethod
    def get_block(serial: int):
        return _Block() if serial == 10 else None


class _Builder:
    @staticmethod
    def goto_redirect(**kwargs):
        return kwargs


def _exact(target: int) -> StateDispatcherMap:
    return StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                state_const=0x1234,
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


def test_conflicting_exact_and_interval_route_emits_no_modification() -> None:
    constant_result = SimpleNamespace(out_stk_maps={10: {0x40: 0x1234}})
    result = plan_fixpoint_feeder_modifications(
        flow_graph=_Graph(),
        builder=_Builder(),
        dispatcher_serial=1,
        condition_chain_blocks={1, 2},
        claimed_sources=set(),
        constant_result=constant_result,
        state_var_stkoff=0x40,
        dispatcher=IntervalDispatcher([IntervalRow(0x1200, 0x1300, 11)]),
        exact_dispatcher_map=_exact(10),
    )

    assert result.modifications == ()
    assert result.log_entries == ()
