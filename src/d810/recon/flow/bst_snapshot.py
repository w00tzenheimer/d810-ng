"""Pure-snapshot BST default-block discovery.

Companion to ``d810.recon.flow.bst_analysis`` that holds the
snapshot-only half of the BST dispatcher analysis surface.  This
module is intentionally IDA-free at module-import time so it can be
exercised from ``tests/unit/`` without dragging the live ``ida_hexrays``
imports that ``bst_analysis.py`` keeps for its live-mba helpers.

Axis-C slice 5a (the architectural split that unblocks 5b's vendor-ref
normalization in ``bst_analysis.py``): pulling the single
snapshot-based function the unit suite consumes
(``find_bst_default_block_snapshot``) out of the larger live-IDA file
lets ``bst_analysis.py`` add ``d810.hexrays.mutation.ir_translator``
imports without tripping the ``unit-tests-no-hexrays`` import-linter
contract via the previous transitive path
``tests.unit.recon.flow.test_bst_snapshot -> d810.recon.flow.bst_analysis -> d810.hexrays.*``.
"""

from __future__ import annotations

from d810.core.typing import Optional

__all__ = ["find_bst_default_block_snapshot"]


def find_bst_default_block_snapshot(
    flow_graph: object,
    bst_root_serial: int,
    bst_node_blocks: set,
    handler_block_serials: set,
) -> Optional[int]:
    """Snapshot variant of ``find_bst_default_block`` using FlowGraph.

    Uses ``FlowGraph.get_block()`` and ``BlockSnapshot.succs`` instead of
    live ``mba_t`` objects.  Pure topology -- no IDA imports required.

    Args:
        flow_graph: A FlowGraph instance.
        bst_root_serial: Serial of the BST dispatcher root.
        bst_node_blocks: Set of block serials that are BST comparison nodes.
        handler_block_serials: Set of block serials that are handler entries.

    Returns:
        Serial of the default fall-through block, or None if not found.
    """
    if flow_graph is None:
        return None

    all_bst_serials = bst_node_blocks | {bst_root_serial}

    for bst_serial in all_bst_serials:
        blk_snap = flow_graph.get_block(bst_serial)
        if blk_snap is None:
            continue
        for succ in blk_snap.succs:
            if succ not in all_bst_serials and succ not in handler_block_serials:
                return succ

    return None
