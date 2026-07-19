"""Tests for alternate-edge correlator."""
from __future__ import annotations
from tests.unit.core.diag._orm_bind import make_bound_diag_db

import sqlite3

from d810.core.diag.models import (
    Snapshot,
    StateCfgEdge,
    StateCfgEdgeAlternateCorrelation,
    StateCfgEdgeDiagnostic,
    StateCfgNode,
    StateCfgNodeBlock,
)
from d810.diagnostics.alternate_correlation import (
    correlate_collapsed_edges,
    persist_alternate_correlations,
)


def _make_db() -> sqlite3.Connection:
    db = make_bound_diag_db()
    Snapshot.insert(
        id=1, label="recon_dag", func_ea_hex="0x180012df0",
        func_ea_i64=0x180012df0, maturity="MMAT_GLBOPT1", phase="pre_d810",
        block_count=0, timestamp=0.0,
    ).execute()
    return db.connection()


def _add_node(
    conn: sqlite3.Connection,
    *,
    state_hex: str,
    entry_block: int,
    classification: str,
    snap: int = 1,
) -> None:
    StateCfgNode.insert(
        snapshot=snap, state_hex=state_hex, state_i64=int(state_hex, 16),
        entry_block=entry_block, classification=classification,
        shared_suffix=None,
    ).execute()


def _add_block(
    conn: sqlite3.Connection,
    *,
    state_hex: str,
    entry_block: int,
    block_serial: int,
    block_index: int = 0,
    role: str = "owned",
    snap: int = 1,
) -> None:
    StateCfgNodeBlock.insert(
        snapshot=snap, state_hex=state_hex, entry_block=entry_block,
        block_serial=block_serial, block_index=block_index, role=role,
    ).execute()


def _add_edge(
    conn: sqlite3.Connection,
    *,
    edge_id: int,
    src: str | None,
    tgt: str | None,
    source_block: int,
    target_entry: int | None = None,
    ordered_path: str = "[]",
    kind: str = "TRANSITION",
    snap: int = 1,
) -> None:
    StateCfgEdge.insert(
        snapshot=snap, edge_id=edge_id, source_state_hex=src,
        source_state_i64=int(src, 16) if src else None, target_state_hex=tgt,
        target_state_i64=int(tgt, 16) if tgt else None, edge_kind=kind,
        source_block=source_block, source_arm=None, target_entry=target_entry,
        ordered_path=ordered_path,
    ).execute()


def _add_collapsed_diagnostic(
    conn: sqlite3.Connection,
    *,
    edge_id: int,
    src: str,
    tgt: str,
    snap: int = 1,
) -> None:
    StateCfgEdgeDiagnostic.insert(
        snapshot=snap, edge_id=edge_id,
        classification="COLLAPSED_TO_REWRITTEN_TARGET", source_state_hex=src,
        target_state_hex=tgt, edge_kind="TRANSITION", is_terminal_tail=1,
        original_state_const="0xAA", rewritten_state_const="0xBB",
        related_fact_ids="[]", reason="test collapse",
    ).execute()


def test_correlates_byte5_alternate_edge() -> None:
    """Live byte5 case: collapsed edge 144 paired with alternate edge 68."""
    conn = _make_db()
    # Collapsed source: STATE_385BBE2D, EXACT, owns blk[100]
    _add_node(
        conn, state_hex="0x00000000385bbe2d",
        entry_block=100, classification="EXACT",
    )
    _add_block(
        conn, state_hex="0x00000000385bbe2d",
        entry_block=100, block_serial=100,
    )
    # RANGE_BACKED sibling: STATE_3873BC53, owns [101,103,104] + shared
    # suffix [69,100,104]
    _add_node(
        conn, state_hex="0x000000003873bc53",
        entry_block=101, classification="RANGE_BACKED",
    )
    for blk in (101, 103, 104, 100):
        _add_block(
            conn, state_hex="0x000000003873bc53",
            entry_block=101, block_serial=blk, block_index=blk,
            role="owned",
        )
    _add_block(
        conn, state_hex="0x000000003873bc53",
        entry_block=101, block_serial=100, block_index=200,
        role="shared_suffix",
    )
    # The bad collapsed edge.
    _add_edge(
        conn, edge_id=144,
        src="0x00000000385bbe2d", tgt="0x0000000063d54755",
        source_block=100, target_entry=21, ordered_path="[100]",
    )
    # The alternate sibling edge.
    _add_edge(
        conn, edge_id=68,
        src="0x000000003873bc53", tgt="0x0000000010743c4c",
        source_block=101, target_entry=158,
        ordered_path="[101, 103, 104]",
    )
    _add_collapsed_diagnostic(
        conn, edge_id=144,
        src="0x00000000385bbe2d", tgt="0x0000000063d54755",
    )

    correlations = correlate_collapsed_edges(conn, snapshot_id=1)
    assert len(correlations) == 1
    c = correlations[0]
    assert c.collapsed_edge_id == 144
    assert c.alternate_edge_id == 68
    assert c.collapsed_source_state == "0x00000000385bbe2d"
    assert c.collapsed_target_state == "0x0000000063d54755"
    assert c.alternate_source_state == "0x000000003873bc53"
    assert c.alternate_target_state == "0x0000000010743c4c"
    assert c.alternate_ordered_path == "[101, 103, 104]"
    assert 100 in c.overlap_blocks
    assert c.reason == "range_backed_sibling_traversal"


def test_no_range_backed_sibling_no_correlation() -> None:
    """No RANGE_BACKED sibling -> no correlation row produced."""
    conn = _make_db()
    _add_node(
        conn, state_hex="0x00000000385bbe2d",
        entry_block=100, classification="EXACT",
    )
    _add_block(
        conn, state_hex="0x00000000385bbe2d",
        entry_block=100, block_serial=100,
    )
    # Add an EXACT sibling instead of RANGE_BACKED.
    _add_node(
        conn, state_hex="0x000000003873bc53",
        entry_block=101, classification="EXACT",
    )
    _add_block(
        conn, state_hex="0x000000003873bc53",
        entry_block=101, block_serial=100, role="shared_suffix",
    )
    _add_edge(
        conn, edge_id=144,
        src="0x00000000385bbe2d", tgt="0x0000000063d54755",
        source_block=100, ordered_path="[100]",
    )
    _add_edge(
        conn, edge_id=68,
        src="0x000000003873bc53", tgt="0x0000000010743c4c",
        source_block=101, ordered_path="[101]",
    )
    _add_collapsed_diagnostic(
        conn, edge_id=144,
        src="0x00000000385bbe2d", tgt="0x0000000063d54755",
    )
    correlations = correlate_collapsed_edges(conn, snapshot_id=1)
    assert correlations == ()


def test_range_backed_sibling_no_outgoing_edge() -> None:
    """RANGE_BACKED sibling with overlap but no outgoing edge -> alt_edge_id=-1."""
    conn = _make_db()
    _add_node(
        conn, state_hex="0x00000000385bbe2d",
        entry_block=100, classification="EXACT",
    )
    _add_block(
        conn, state_hex="0x00000000385bbe2d",
        entry_block=100, block_serial=100,
    )
    _add_node(
        conn, state_hex="0x000000003873bc53",
        entry_block=101, classification="RANGE_BACKED",
    )
    _add_block(
        conn, state_hex="0x000000003873bc53",
        entry_block=101, block_serial=100, role="shared_suffix",
    )
    _add_edge(
        conn, edge_id=144,
        src="0x00000000385bbe2d", tgt="0x0000000063d54755",
        source_block=100, ordered_path="[100]",
    )
    _add_collapsed_diagnostic(
        conn, edge_id=144,
        src="0x00000000385bbe2d", tgt="0x0000000063d54755",
    )
    correlations = correlate_collapsed_edges(conn, snapshot_id=1)
    assert len(correlations) == 1
    assert correlations[0].alternate_edge_id == -1
    assert correlations[0].reason == (
        "range_backed_sibling_no_outgoing_edge"
    )


def test_persist_idempotent() -> None:
    conn = _make_db()
    _add_node(
        conn, state_hex="0x00000000385bbe2d",
        entry_block=100, classification="EXACT",
    )
    _add_block(
        conn, state_hex="0x00000000385bbe2d",
        entry_block=100, block_serial=100,
    )
    _add_node(
        conn, state_hex="0x000000003873bc53",
        entry_block=101, classification="RANGE_BACKED",
    )
    _add_block(
        conn, state_hex="0x000000003873bc53",
        entry_block=101, block_serial=100, role="shared_suffix",
    )
    _add_edge(
        conn, edge_id=144,
        src="0x00000000385bbe2d", tgt="0x0000000063d54755",
        source_block=100,
    )
    _add_edge(
        conn, edge_id=68,
        src="0x000000003873bc53", tgt="0x0000000010743c4c",
        source_block=101, ordered_path="[101]",
    )
    _add_collapsed_diagnostic(
        conn, edge_id=144,
        src="0x00000000385bbe2d", tgt="0x0000000063d54755",
    )
    correlations = correlate_collapsed_edges(conn, snapshot_id=1)
    persist_alternate_correlations(conn, correlations)
    persist_alternate_correlations(conn, correlations)
    assert StateCfgEdgeAlternateCorrelation.select().count() == 1
