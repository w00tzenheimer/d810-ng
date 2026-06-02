"""Alternate-edge correlator for ``COLLAPSED_TO_REWRITTEN_TARGET`` rows.

This module pairs a collapsed recon edge with an alternate
already-persisted ``state_cfg_edges`` row whose source is a RANGE_BACKED
sibling node whose owned / shared blocks overlap the collapsed
source's blocks.  The alternate edge IS the traversing route that the
collapsed exact edge is missing -- recon already discovered it; we
just need to surface the correlation.

Concrete example (sub_7FFD3338C040, snap 6):

* Collapsed edge 144: ``0x385BBE2D -> 0x63D54755`` at blk[100],
  ordered_path ``[100]``.
* Alternate edge 68:  ``0x3873BC53 -> 0x10743C4C`` at blk[101],
  ordered_path ``[101, 103, 104]``.  Source node ``0x3873BC53`` is
  RANGE_BACKED with shared_suffix ``[69, 100, 104]`` -- it shares
  blk[100] with the collapsed source ``0x385BBE2D``.
* Continuation edge 39: ``0x10743C4C -> 0x6107F8EC`` at blk[158]
  (already persisted; visible by following alternate.target_state).

Observability-only.  No recon or HCC behavior change.

Correlation rules
-----------------

For each ``state_cfg_edge_diagnostics`` row classified
``COLLAPSED_TO_REWRITTEN_TARGET``:

1. Get the collapsed source state's owned + shared blocks.
2. Find sibling ``state_cfg_nodes`` whose owned / shared blocks intersect
   that set AND whose ``classification`` is ``RANGE_BACKED``.  (Exact
   siblings are skipped because the collapsed exact edge already
   represents the exact route.)
3. For each candidate sibling, list its outgoing ``state_cfg_edges`` rows.
4. Pair the collapsed edge with each candidate alternate.  The
   ``ordered_path`` of the alternate is preserved verbatim (recon's
   own walk).
5. Record the overlap blocks for explainability.

Single-step: only the immediate sibling-traversal edge is considered.
The continuation chain (e.g. ``0x10743C4C -> 0x6107F8EC``) is NOT
recursively followed; it is a separate ``state_cfg_edges`` row already and
can be queried directly via its source_state.

If the source's blocks intersect a RANGE_BACKED sibling but that
sibling has no outgoing edge, the correlator still records the
sibling-block overlap in a row with ``alternate_edge_id = -1`` and
``reason = "range_backed_sibling_no_outgoing_edge"`` so the absence
is visible.  Without any RANGE_BACKED sibling, no row is recorded for
the collapsed edge (the diagnostic axis tells consumers why).
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from d810.core.diag.models import (
    StateCfgEdge,
    StateCfgEdgeDiagnostic,
    StateCfgNode,
    StateCfgNodeBlock,
)
from d810.core.typing import Iterable


@dataclass(frozen=True)
class AlternateCorrelation:
    """One collapsed-edge / alternate-edge pairing."""

    snapshot_id: int
    collapsed_edge_id: int
    alternate_edge_id: int
    collapsed_source_state: str | None
    collapsed_target_state: str | None
    alternate_source_state: str | None
    alternate_target_state: str | None
    alternate_ordered_path: str  # verbatim from dag_edges (JSON-encoded list)
    overlap_blocks: tuple[int, ...]
    alternate_classification: str | None
    reason: str

    def to_row(self) -> tuple:
        return (
            int(self.snapshot_id),
            int(self.collapsed_edge_id),
            int(self.alternate_edge_id),
            self.collapsed_source_state,
            self.collapsed_target_state,
            self.alternate_source_state,
            self.alternate_target_state,
            self.alternate_ordered_path,
            json.dumps(list(self.overlap_blocks)),
            self.alternate_classification,
            self.reason,
        )


def _collect_state_blocks(
    conn: sqlite3.Connection,
    snapshot_id: int,
) -> dict[str, set[int]]:
    """``{state_hex: {block_serial, ...}}`` across owned + shared roles."""
    out: dict[str, set[int]] = {}
    rows = (
        StateCfgNodeBlock.select(
            StateCfgNodeBlock.state_hex, StateCfgNodeBlock.block_serial
        )
        .where(
            (StateCfgNodeBlock.snapshot == int(snapshot_id))
            & StateCfgNodeBlock.role.in_(
                ["owned", "exclusive", "shared_suffix"]
            )
        )
        .tuples()
    )
    for state_hex, block_serial in rows:
        if state_hex is None:
            continue
        out.setdefault(str(state_hex).lower(), set()).add(int(block_serial))
    return out


def _collect_node_classifications(
    conn: sqlite3.Connection,
    snapshot_id: int,
) -> dict[str, str]:
    """``{state_hex: classification}`` for ``state_cfg_nodes``."""
    out: dict[str, str] = {}
    rows = (
        StateCfgNode.select(
            StateCfgNode.state_hex, StateCfgNode.classification
        )
        .where(StateCfgNode.snapshot == int(snapshot_id))
        .tuples()
    )
    for state_hex, classification in rows:
        if state_hex is None:
            continue
        out[str(state_hex).lower()] = str(classification)
    return out


def _collect_outgoing_edges(
    conn: sqlite3.Connection,
    snapshot_id: int,
) -> dict[str, list[tuple]]:
    """``{source_state_hex: [(edge_id, target_state, target_entry, ordered_path), ...]}``."""
    out: dict[str, list[tuple]] = {}
    rows = (
        StateCfgEdge.select(
            StateCfgEdge.edge_id,
            StateCfgEdge.source_state_hex,
            StateCfgEdge.target_state_hex,
            StateCfgEdge.source_block,
            StateCfgEdge.target_entry,
            StateCfgEdge.ordered_path,
        )
        .where(StateCfgEdge.snapshot == int(snapshot_id))
        .tuples()
    )
    for edge_id, src, tgt, _src_blk, _tgt_entry, path in rows:
        if src is None:
            continue
        out.setdefault(str(src).lower(), []).append(
            (int(edge_id), tgt, path)
        )
    return out


def _collect_collapsed_diagnostics(
    conn: sqlite3.Connection,
    snapshot_id: int,
) -> list[tuple]:
    """Return every ``COLLAPSED_TO_REWRITTEN_TARGET`` diagnostic row at
    ``snapshot_id``, joined with its source / target state hexes."""
    rows = (
        StateCfgEdgeDiagnostic.select(
            StateCfgEdgeDiagnostic.edge_id,
            StateCfgEdgeDiagnostic.source_state_hex,
            StateCfgEdgeDiagnostic.target_state_hex,
        )
        .where(
            (StateCfgEdgeDiagnostic.snapshot == int(snapshot_id))
            & (
                StateCfgEdgeDiagnostic.classification
                == "COLLAPSED_TO_REWRITTEN_TARGET"
            )
        )
        .tuples()
    )
    return [
        (int(edge_id), str(src) if src is not None else None,
         str(tgt) if tgt is not None else None)
        for edge_id, src, tgt in rows
    ]


def correlate_collapsed_edges(
    conn: sqlite3.Connection,
    snapshot_id: int,
) -> tuple[AlternateCorrelation, ...]:
    """Pair each ``COLLAPSED_TO_REWRITTEN_TARGET`` row with alternate
    edges from RANGE_BACKED sibling nodes whose blocks overlap the
    collapsed source's blocks.

    Pure read against ``state_cfg_edge_diagnostics`` / ``state_cfg_nodes`` /
    ``state_cfg_node_blocks`` / ``state_cfg_edges``.  Caller decides whether to
    persist via :func:`persist_alternate_correlations`.
    """
    collapsed_rows = _collect_collapsed_diagnostics(conn, snapshot_id)
    if not collapsed_rows:
        return ()

    state_blocks = _collect_state_blocks(conn, snapshot_id)
    node_classifications = _collect_node_classifications(conn, snapshot_id)
    outgoing = _collect_outgoing_edges(conn, snapshot_id)

    correlations: list[AlternateCorrelation] = []
    for edge_id, collapsed_src, collapsed_tgt in collapsed_rows:
        if collapsed_src is None:
            continue
        src_lower = collapsed_src.lower()
        src_blocks = state_blocks.get(src_lower, set())
        if not src_blocks:
            continue

        # Find RANGE_BACKED siblings whose owned/shared blocks
        # overlap the collapsed source's blocks.
        sibling_overlaps: list[tuple[str, frozenset[int]]] = []
        for state_hex, blocks in state_blocks.items():
            if state_hex == src_lower:
                continue
            classification = node_classifications.get(state_hex)
            if classification != "RANGE_BACKED":
                continue
            overlap = blocks & src_blocks
            if overlap:
                sibling_overlaps.append((state_hex, frozenset(overlap)))

        if not sibling_overlaps:
            continue  # no row recorded; the diagnostic itself flags the gap

        # Sort siblings by overlap size (largest first); ties broken
        # by lexical state_hex for determinism.
        sibling_overlaps.sort(
            key=lambda item: (-len(item[1]), item[0])
        )

        for sibling_state, overlap_set in sibling_overlaps:
            sibling_edges = outgoing.get(sibling_state, [])
            if not sibling_edges:
                correlations.append(
                    AlternateCorrelation(
                        snapshot_id=int(snapshot_id),
                        collapsed_edge_id=edge_id,
                        alternate_edge_id=-1,
                        collapsed_source_state=collapsed_src,
                        collapsed_target_state=collapsed_tgt,
                        alternate_source_state=sibling_state,
                        alternate_target_state=None,
                        alternate_ordered_path="[]",
                        overlap_blocks=tuple(sorted(overlap_set)),
                        alternate_classification="RANGE_BACKED",
                        reason="range_backed_sibling_no_outgoing_edge",
                    )
                )
                continue
            for alt_edge_id, alt_tgt, alt_path in sibling_edges:
                correlations.append(
                    AlternateCorrelation(
                        snapshot_id=int(snapshot_id),
                        collapsed_edge_id=edge_id,
                        alternate_edge_id=int(alt_edge_id),
                        collapsed_source_state=collapsed_src,
                        collapsed_target_state=collapsed_tgt,
                        alternate_source_state=sibling_state,
                        alternate_target_state=(
                            str(alt_tgt) if alt_tgt is not None else None
                        ),
                        alternate_ordered_path=str(alt_path or "[]"),
                        overlap_blocks=tuple(sorted(overlap_set)),
                        alternate_classification="RANGE_BACKED",
                        reason="range_backed_sibling_traversal",
                    )
                )
    return tuple(correlations)


def persist_alternate_correlations(
    conn: sqlite3.Connection,
    correlations: Iterable[AlternateCorrelation],
) -> int:
    """Persist alternate correlations.  Idempotent: existing rows for
    the same ``(snapshot_id, collapsed_edge_id, alternate_edge_id)``
    triple are deleted before insertion.  Returns the number of rows
    inserted.
    """
    rows = [c.to_row() for c in correlations]
    if not rows:
        return 0
    snapshot_ids = sorted({int(r[0]) for r in rows})
    for snap_id in snapshot_ids:
        conn.execute(
            "DELETE FROM state_cfg_edge_alternate_correlations "
            "WHERE snapshot_id = ?",
            (snap_id,),
        )
    conn.executemany(
        """
        INSERT INTO state_cfg_edge_alternate_correlations
            (snapshot_id, collapsed_edge_id, alternate_edge_id,
             collapsed_source_state, collapsed_target_state,
             alternate_source_state, alternate_target_state,
             alternate_ordered_path, overlap_blocks,
             alternate_classification, reason)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """,
        rows,
    )
    conn.commit()
    return len(rows)


__all__ = [
    "AlternateCorrelation",
    "correlate_collapsed_edges",
    "persist_alternate_correlations",
]
