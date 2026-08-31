"""Cycle-free shape normalization for logical decision-DAG endpoints."""

from __future__ import annotations

from d810.ir.flowgraph import BlockKind, BlockSnapshot

_BADADDR = 0xFFFFFFFFFFFFFFFF


def is_exact_logical_function_exit_shape(block: object) -> bool:
    """Return whether ``block`` is the sole instructionless logical exit shape.

    This validates shape only.  Callers separately bind the logical reference,
    graph generation, and exact successor edge.
    """
    return bool(
        type(block) is BlockSnapshot
        and block.kind in (BlockKind.ZERO_WAY, BlockKind.STOP)
        and not block.succs
        and not block.insn_snapshots
        and block.native_start_ea is None
        and block.start_ea == _BADADDR
    )


def is_exact_logical_function_exit_inventory_row_shape(
    row: object,
    *,
    logical_block_ref_type: type,
) -> bool:
    """Return whether an inventory row is the sole anchorless logical exit."""
    return bool(
        type(getattr(row, "block_ref", None)) is logical_block_ref_type
        and getattr(row, "block_kind", None) in (BlockKind.ZERO_WAY, BlockKind.STOP)
        and getattr(row, "anchor_ea", object()) is None
        and not getattr(row, "native_instruction_eas", ())
        and not getattr(row, "instruction_observations", ())
        and not getattr(row, "successor_serials", ())
        and getattr(row, "transfer_ea", object()) is None
        and getattr(row, "graph_start_ea", _BADADDR) == _BADADDR
    )
