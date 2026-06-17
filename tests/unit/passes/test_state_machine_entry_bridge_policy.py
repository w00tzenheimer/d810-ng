from types import SimpleNamespace

from d810.capabilities.dispatcher import RouterKind
from d810.passes.unflatten.state_machine import (
    _entry_bridge_requires_witness,
    _has_emulated_endpoint_rows,
)


def test_entry_bridge_requires_witness_for_conditional_chain_map() -> None:
    dmap = SimpleNamespace(
        source=RouterKind.CONDITION_CHAIN,
        rows=(SimpleNamespace(branch_kind="eq"),),
    )

    assert _entry_bridge_requires_witness(None, dmap) is True


def test_entry_bridge_does_not_require_static_witness_for_handler_map_rows() -> None:
    dmap = SimpleNamespace(
        source=RouterKind.CONDITION_CHAIN,
        rows=(SimpleNamespace(branch_kind="handler_state_map"),),
    )

    assert _entry_bridge_requires_witness(None, dmap) is False


def test_entry_bridge_requires_liveness_policy_for_emulated_chain() -> None:
    dmap = SimpleNamespace(
        source=RouterKind.CONDITION_CHAIN,
        rows=(
            SimpleNamespace(branch_kind="emulated"),
            SimpleNamespace(branch_kind="emulated"),
        ),
    )

    assert _entry_bridge_requires_witness(None, dmap) is True


def test_entry_bridge_requires_liveness_policy_for_mixed_emulated_rows() -> None:
    dmap = SimpleNamespace(
        source=RouterKind.CONDITION_CHAIN,
        rows=(
            SimpleNamespace(branch_kind="handler_state_map"),
            SimpleNamespace(branch_kind="emulated"),
        ),
    )

    assert _entry_bridge_requires_witness(None, dmap) is True
    assert _has_emulated_endpoint_rows(dmap) is True


def test_entry_bridge_static_rows_are_not_emulated_endpoint_rows() -> None:
    dmap = SimpleNamespace(
        source=RouterKind.CONDITION_CHAIN,
        rows=(SimpleNamespace(branch_kind="eq"),),
    )

    assert _has_emulated_endpoint_rows(dmap) is False


def test_entry_bridge_does_not_require_witness_for_bst_evidence_without_provider() -> None:
    dmap = SimpleNamespace(source=RouterKind.UNKNOWN)
    bst_evidence = SimpleNamespace(bst_node_blocks=(2, 4, 6, 8))

    assert _entry_bridge_requires_witness(bst_evidence, dmap) is False


def test_entry_bridge_legacy_allowed_without_comparison_evidence() -> None:
    dmap = SimpleNamespace(source=RouterKind.SWITCH)
    bst_evidence = SimpleNamespace(bst_node_blocks=())

    assert _entry_bridge_requires_witness(bst_evidence, dmap) is False
