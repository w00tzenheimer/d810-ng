"""Tests for exact state dispatcher rows."""
from __future__ import annotations

from d810.capabilities.dispatcher import RouterKind
from d810.analyses.control_flow.dispatcher_resolution import (
    StateDispatcherMap,
    StateDispatcherRow,
)


def _map() -> StateDispatcherMap:
    return StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                state_const=0x10,
                target_block=7,
                dispatcher_block=2,
                compare_block=2,
                branch_kind="jz_taken",
                source=RouterKind.CONDITION_CHAIN,
            ),
            StateDispatcherRow(
                state_const=0x20,
                target_block=9,
                dispatcher_block=2,
                compare_block=3,
                branch_kind="jnz_fallthrough",
                source=RouterKind.CONDITION_CHAIN,
            ),
        ),
        dispatcher_entry_block=2,
        dispatcher_blocks=frozenset({2, 3}),
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        source=RouterKind.CONDITION_CHAIN,
        initial_state=0x10,
    )


def test_state_to_handler_and_resolve_target() -> None:
    dispatch_map = _map()

    assert dispatch_map.state_to_handler() == {0x10: 7, 0x20: 9}
    assert dispatch_map.handler_state_map() == {7: 0x10, 9: 0x20}
    assert dispatch_map.resolve_target(0x20) == 9
    assert dispatch_map.resolve_target(0x30) is None


def test_to_dispatcher_handler_map() -> None:
    handler_map = _map().to_dispatcher_handler_map()

    assert handler_map.handler_state_map == {7: 0x10, 9: 0x20}
    assert handler_map.handler_range_map == {}
    assert handler_map.dispatcher_serial == 2
    assert handler_map.dispatcher_blocks == frozenset({2, 3})
    assert handler_map.state_var_stkoff == 0x3C
    assert handler_map.source == RouterKind.CONDITION_CHAIN
    assert handler_map.resolve_target(0x10) == 7
