"Pure-snapshot condition-chain default-block discovery.\n\nCompanion to ``d810.backends.hexrays.evidence.condition_chain_analysis`` that holds the\nsnapshot-only half of the condition-chain dispatcher analysis surface.  This\nmodule is intentionally IDA-free at module-import time so it can be\nexercised from ``tests/unit/`` without dragging the live ``ida_hexrays``\nimports that ``condition_chain_analysis.py`` keeps for its live-mba helpers.\n\nAxis-C slice 5a (the architectural split that unblocks 5b's vendor-ref\nnormalization in ``condition_chain_analysis.py``): pulling the single\nsnapshot-based function the unit suite consumes\n(``find_condition_chain_default_block_snapshot``) out of the larger live-IDA file\nlets ``condition_chain_analysis.py`` add ``d810.hexrays.mutation.ir_translator``\nimports without tripping the ``unit-tests-no-hexrays`` import-linter\ncontract via the previous transitive path\n``tests.unit.preanalysis.flow.test_condition_chain_snapshot -> d810.backends.hexrays.evidence.condition_chain_analysis -> d810.hexrays.*``.\n"

from __future__ import annotations

from d810.core.typing import Optional

__all__ = ["find_condition_chain_default_block_snapshot"]


def find_condition_chain_default_block_snapshot(
    flow_graph: object,
    dispatcher_root_serial: int,
    condition_chain_blocks: set,
    handler_block_serials: set,
) -> Optional[int]:
    """Snapshot variant of condition-chain default block discovery using FlowGraph.

    Uses ``FlowGraph.get_block()`` and ``BlockSnapshot.succs`` instead of
    live ``mba_t`` objects.  Pure topology -- no IDA imports required.

    Args:
        flow_graph: A FlowGraph instance.
        dispatcher_root_serial: Serial of the condition-chain dispatcher root.
        condition_chain_blocks: Set of block serials that are condition-chain comparison nodes.
        handler_block_serials: Set of block serials that are handler entries.

    Returns:
        Serial of the default fall-through block, or None if not found.
    """
    if flow_graph is None:
        return None

    all_condition_chain_serials = condition_chain_blocks | {dispatcher_root_serial}

    for condition_chain_serial in all_condition_chain_serials:
        blk_snap = flow_graph.get_block(condition_chain_serial)
        if blk_snap is None:
            continue
        for succ in blk_snap.succs:
            if succ not in all_condition_chain_serials and succ not in handler_block_serials:
                return succ

    return None
