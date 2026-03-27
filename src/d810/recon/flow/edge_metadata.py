"""Metadata formatting helpers for semantic DAG edges."""

from __future__ import annotations

from d810.recon.flow.linearized_state_dag import StateDagEdge
from d810.recon.flow.state_machine_analysis import StateWriteSite


def edge_kind_name(edge: StateDagEdge) -> str:
    """Return the stable string name for an edge kind."""
    kind = getattr(edge.kind, "name", None)
    return kind if isinstance(kind, str) else str(edge.kind)


def source_kind_name(edge: StateDagEdge) -> str:
    """Return the stable string name for an edge source kind."""
    kind = getattr(edge.source_anchor.kind, "name", None)
    return kind if isinstance(kind, str) else str(edge.source_anchor.kind)


def make_edge_metadata(
    edge: StateDagEdge,
    *,
    horizon_block: int | None = None,
    site: StateWriteSite | None = None,
    target_entry: int | None = None,
    first_shared_block: int | None = None,
    via_pred: int | None = None,
    emission_mode: str | None = None,
    rejection_reason: str | None = None,
) -> dict[str, int | str | None]:
    """Build stable audit metadata for one reconstruction edge decision."""
    return {
        "edge_kind": edge_kind_name(edge),
        "source_kind": source_kind_name(edge),
        "source_block": int(edge.source_anchor.block_serial),
        "branch_arm": (
            int(edge.source_anchor.branch_arm)
            if edge.source_anchor.branch_arm is not None
            else None
        ),
        "target_state": (
            int(edge.target_state & 0xFFFFFFFF)
            if edge.target_state is not None
            else None
        ),
        "target_entry_anchor": (
            int(edge.target_entry_anchor)
            if edge.target_entry_anchor is not None
            else None
        ),
        "horizon_block": int(horizon_block) if horizon_block is not None else None,
        "state_value": (
            int(site.state_value & 0xFFFFFFFF)
            if site is not None
            else None
        ),
        "state_write_ea": int(site.insn_ea) if site is not None else None,
        "target_entry": int(target_entry) if target_entry is not None else None,
        "first_shared_block": (
            int(first_shared_block) if first_shared_block is not None else None
        ),
        "via_pred": int(via_pred) if via_pred is not None else None,
        "emission_mode": emission_mode,
        "rejection_reason": rejection_reason,
    }


__all__ = [
    "edge_kind_name",
    "make_edge_metadata",
    "source_kind_name",
]
