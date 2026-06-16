from types import SimpleNamespace

from d810.analyses.control_flow.dispatcher_kind import DispatcherType
from d810.passes.unflatten.state_machine import _entry_bridge_requires_witness


def test_entry_bridge_requires_witness_for_conditional_chain_map() -> None:
    dmap = SimpleNamespace(source=DispatcherType.CONDITIONAL_CHAIN)

    assert _entry_bridge_requires_witness(None, dmap) is True


def test_entry_bridge_requires_witness_for_bst_evidence() -> None:
    dmap = SimpleNamespace(source=DispatcherType.UNKNOWN)
    bst_evidence = SimpleNamespace(bst_node_blocks=(2, 4, 6, 8))

    assert _entry_bridge_requires_witness(bst_evidence, dmap) is True


def test_entry_bridge_legacy_allowed_without_comparison_evidence() -> None:
    dmap = SimpleNamespace(source=DispatcherType.SWITCH_TABLE)
    bst_evidence = SimpleNamespace(bst_node_blocks=())

    assert _entry_bridge_requires_witness(bst_evidence, dmap) is False
