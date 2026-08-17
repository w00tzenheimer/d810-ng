from types import SimpleNamespace

from d810.capabilities.dispatcher import RouterKind
from d810.passes.unflatten.state_machine import (
    _entry_bridge_requires_witness,
    _has_emulated_endpoint_rows,
    _resolve_initial_state,
)


def test_entry_bridge_requires_witness_for_conditional_chain_map() -> None:
    dmap = SimpleNamespace(
        router_kind=RouterKind.CONDITION_CHAIN,
        rows=(SimpleNamespace(branch_kind="eq"),),
    )

    assert _entry_bridge_requires_witness(dmap) is True


def test_entry_bridge_does_not_require_static_witness_for_handler_map_rows() -> None:
    dmap = SimpleNamespace(
        router_kind=RouterKind.CONDITION_CHAIN,
        rows=(SimpleNamespace(branch_kind="handler_state_map"),),
    )

    assert _entry_bridge_requires_witness(dmap) is False


def test_entry_bridge_requires_liveness_policy_for_emulated_chain() -> None:
    dmap = SimpleNamespace(
        router_kind=RouterKind.CONDITION_CHAIN,
        rows=(
            SimpleNamespace(branch_kind="emulated"),
            SimpleNamespace(branch_kind="emulated"),
        ),
    )

    assert _entry_bridge_requires_witness(dmap) is True


def test_entry_bridge_requires_liveness_policy_for_mixed_emulated_rows() -> None:
    dmap = SimpleNamespace(
        router_kind=RouterKind.CONDITION_CHAIN,
        rows=(
            SimpleNamespace(branch_kind="handler_state_map"),
            SimpleNamespace(branch_kind="emulated"),
        ),
    )

    assert _entry_bridge_requires_witness(dmap) is True
    assert _has_emulated_endpoint_rows(dmap) is True


def test_entry_bridge_static_rows_are_not_emulated_endpoint_rows() -> None:
    dmap = SimpleNamespace(
        router_kind=RouterKind.CONDITION_CHAIN,
        rows=(SimpleNamespace(branch_kind="eq"),),
    )

    assert _has_emulated_endpoint_rows(dmap) is False


def test_entry_bridge_does_not_require_witness_for_unknown_router_without_provider() -> (
    None
):
    dmap = SimpleNamespace(router_kind=RouterKind.UNKNOWN)

    assert _entry_bridge_requires_witness(dmap) is False


def test_entry_bridge_legacy_allowed_without_comparison_evidence() -> None:
    dmap = SimpleNamespace(router_kind=RouterKind.TABLE)

    assert _entry_bridge_requires_witness(dmap) is False


def test_same_block_map_initial_state_wins_over_stale_range_evidence() -> None:
    dmap = SimpleNamespace(initial_state=0x16AA65E9)
    recovery = SimpleNamespace(dispatch_map=dmap, state_var_reg=None)
    stale_range = SimpleNamespace(initial_state=0x1888937E)

    assert _resolve_initial_state(stale_range, recovery) == 0x16AA65E9
