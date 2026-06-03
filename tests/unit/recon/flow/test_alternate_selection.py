"""Tests for alternate-edge selector."""
from __future__ import annotations
from d810.core.diag import create_diag_database

import json
import sqlite3

from d810.diagnostics.alternate_selection import (
    persist_alternate_selections,
    select_alternate_edges,
)


def _make_db() -> sqlite3.Connection:
    conn = create_diag_database(":memory:").connection()
    conn.execute(
        """
        INSERT INTO snapshots
            (id, label, func_ea_hex, func_ea_i64,
             maturity, phase, block_count, timestamp)
        VALUES (1, 'recon_dag', '0x180012df0', 0x180012df0,
                'MMAT_GLBOPT1', 'pre_d810', 0, 0.0)
        """,
    )
    conn.commit()
    return conn


def _add_block(
    conn: sqlite3.Connection,
    *,
    state_hex: str,
    entry_block: int,
    block_serial: int,
    role: str = "owned",
    block_index: int = 0,
    snap: int = 1,
) -> None:
    conn.execute(
        """
        INSERT INTO state_cfg_node_blocks
            (snapshot_id, state_hex, entry_block, block_serial,
             block_index, role)
        VALUES (?,?,?,?,?,?)
        """,
        (snap, state_hex, entry_block, block_serial, block_index, role),
    )


def _add_edge(
    conn: sqlite3.Connection,
    *,
    src: str,
    tgt: str | None,
    edge_kind: str = "TRANSITION",
    edge_id: int | None = None,
    snap: int = 1,
) -> None:
    if edge_id is None:
        edge_id = conn.execute(
            "SELECT COALESCE(MAX(edge_id),0)+1 FROM state_cfg_edges WHERE snapshot_id=?",
            (snap,),
        ).fetchone()[0]
    conn.execute(
        """
        INSERT INTO state_cfg_edges
            (snapshot_id, edge_id, source_state_hex, source_state_i64,
             target_state_hex, target_state_i64, edge_kind,
             source_block, source_arm, target_entry, ordered_path)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            snap, edge_id, src, int(src, 16) if src else None,
            tgt, int(tgt, 16) if tgt else None, edge_kind,
            None, None, None, "[]",
        ),
    )


def _add_terminal_tail_fact(
    conn: sqlite3.Connection,
    *,
    fact_id: str,
    destination_block: int,
    byte_index: int,
    snap: int = 1,
) -> None:
    payload = {
        "destination_block": destination_block,
        "byte_index": byte_index,
        "corridor_role": "terminal_tail",
    }
    conn.execute(
        """
        INSERT INTO fact_observations
            (snapshot_id, func_ea_hex, func_ea_i64, fact_id, kind,
             semantic_key, maturity, phase, confidence,
             source_block, source_ea_hex, source_ea_i64,
             block_fingerprint, mop_signature, payload, evidence)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            snap, "0x180012df0", 0x180012df0, fact_id,
            "TerminalByteEmitterFact", fact_id, "MMAT_GLBOPT1",
            "pre_d810", 0.9, destination_block, None, None, None, None,
            json.dumps(payload), "[]",
        ),
    )


def _add_correlation(
    conn: sqlite3.Connection,
    *,
    collapsed_edge: int,
    alt_edge: int,
    collapsed_src: str,
    collapsed_tgt: str,
    alt_src: str,
    alt_tgt: str | None,
    snap: int = 1,
) -> None:
    conn.execute(
        """
        INSERT INTO state_cfg_edge_alternate_correlations
            (snapshot_id, collapsed_edge_id, alternate_edge_id,
             collapsed_source_state, collapsed_target_state,
             alternate_source_state, alternate_target_state,
             alternate_ordered_path, overlap_blocks,
             alternate_classification, reason)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            snap, collapsed_edge, alt_edge,
            collapsed_src, collapsed_tgt,
            alt_src, alt_tgt, "[]", "[]", "RANGE_BACKED", "test",
        ),
    )


def test_byte5_selects_alt_with_byte6_continuation() -> None:
    """Live byte5 case: alt 68 -> 0x10743C4C -> 0x6107F8EC reaches byte6."""
    conn = _make_db()
    # Source: STATE_385BBE2D owns blk[101] (byte5 terminal_tail).
    _add_block(
        conn, state_hex="0x00000000385bbe2d",
        entry_block=100, block_serial=100,
    )
    _add_block(
        conn, state_hex="0x00000000385bbe2d",
        entry_block=100, block_serial=101, block_index=1,
    )
    _add_terminal_tail_fact(
        conn, fact_id="byte5", destination_block=101, byte_index=5,
    )
    # Alt 68 target: STATE_10743C4C, has outgoing to STATE_6107F8EC.
    # STATE_6107F8EC owns blk[217] which is byte6 terminal_tail.
    _add_block(
        conn, state_hex="0x000000006107f8ec",
        entry_block=15, block_serial=217,
    )
    _add_terminal_tail_fact(
        conn, fact_id="byte6", destination_block=217, byte_index=6,
    )
    _add_edge(
        conn, edge_id=39,
        src="0x0000000010743c4c", tgt="0x000000006107f8ec",
    )
    # Alt 112 target: STATE_6E958F99, has only CONDITIONAL_RETURN (dead-end).
    _add_edge(
        conn, edge_id=134,
        src="0x000000006e958f99", tgt=None,
        edge_kind="CONDITIONAL_RETURN",
    )

    _add_correlation(
        conn, collapsed_edge=144, alt_edge=68,
        collapsed_src="0x00000000385bbe2d",
        collapsed_tgt="0x0000000063d54755",
        alt_src="0x000000003873bc53",
        alt_tgt="0x0000000010743c4c",
    )
    _add_correlation(
        conn, collapsed_edge=144, alt_edge=112,
        collapsed_src="0x00000000385bbe2d",
        collapsed_tgt="0x0000000063d54755",
        alt_src="0x000000003873bc53",
        alt_tgt="0x000000006e958f99",
    )

    selections = select_alternate_edges(conn, snapshot_id=1, max_depth=2)
    by_alt = {s.alternate_edge_id: s for s in selections}
    sel_68 = by_alt[68]
    sel_112 = by_alt[112]

    assert sel_68.selected is True
    assert sel_68.source_byte_index == 5
    assert sel_68.reached_byte_index == 6
    assert sel_68.reached_state_hex == "0x000000006107f8ec"
    assert sel_68.reason == "later_terminal_tail_reached"

    assert sel_112.selected is False
    assert sel_112.source_byte_index == 5
    assert sel_112.reached_byte_index is None
    assert sel_112.reason == (
        "early_return_arm_no_later_terminal_tail"
    )


def test_no_source_byte_index_no_decision() -> None:
    """Source state with no terminal_tail emit -> reason no_source_byte_index."""
    conn = _make_db()
    _add_block(
        conn, state_hex="0x00000000aaaaaaaa",
        entry_block=10, block_serial=10,
    )
    # No TerminalByteEmitterFact at blk[10].
    _add_correlation(
        conn, collapsed_edge=1, alt_edge=2,
        collapsed_src="0x00000000aaaaaaaa",
        collapsed_tgt="0x00000000bbbbbbbb",
        alt_src="0x00000000cccccccc",
        alt_tgt="0x00000000dddddddd",
    )
    selections = select_alternate_edges(conn, snapshot_id=1)
    assert len(selections) == 1
    assert selections[0].selected is False
    assert selections[0].reason == "no_source_byte_index"
    assert selections[0].source_byte_index is None


def test_depth_cap_respected() -> None:
    """Later-byte reachable only at depth 3 -> rejected when max_depth=2."""
    conn = _make_db()
    _add_block(
        conn, state_hex="0x00000000aaaaaaaa",
        entry_block=10, block_serial=10,
    )
    _add_terminal_tail_fact(
        conn, fact_id="src", destination_block=10, byte_index=5,
    )
    # Chain: alt_target -> A -> B -> C; only C owns a byte6 block.
    _add_edge(
        conn, src="0x00000000bbbbbbbb", tgt="0x00000000cccccccc",
    )
    _add_edge(
        conn, src="0x00000000cccccccc", tgt="0x00000000dddddddd",
    )
    _add_edge(
        conn, src="0x00000000dddddddd", tgt="0x00000000eeeeeeee",
    )
    _add_block(
        conn, state_hex="0x00000000eeeeeeee",
        entry_block=99, block_serial=99,
    )
    _add_terminal_tail_fact(
        conn, fact_id="b6", destination_block=99, byte_index=6,
    )
    _add_correlation(
        conn, collapsed_edge=1, alt_edge=2,
        collapsed_src="0x00000000aaaaaaaa",
        collapsed_tgt="0x00000000ffffffff",
        alt_src="0x00000000cafecafe",
        alt_tgt="0x00000000bbbbbbbb",
    )
    # max_depth=2: cannot reach 0xee (3 hops away).
    sels_2 = select_alternate_edges(conn, snapshot_id=1, max_depth=2)
    assert sels_2[0].selected is False
    assert sels_2[0].reason == "no_later_terminal_tail_within_depth"
    # max_depth=4: now reachable.
    sels_4 = select_alternate_edges(conn, snapshot_id=1, max_depth=4)
    assert sels_4[0].selected is True
    assert sels_4[0].reached_byte_index == 6


def test_persist_idempotent() -> None:
    conn = _make_db()
    _add_correlation(
        conn, collapsed_edge=1, alt_edge=2,
        collapsed_src="0x00000000aaaaaaaa",
        collapsed_tgt="0x00000000bbbbbbbb",
        alt_src="0x00000000cccccccc",
        alt_tgt="0x00000000dddddddd",
    )
    selections = select_alternate_edges(conn, snapshot_id=1)
    persist_alternate_selections(conn, selections)
    persist_alternate_selections(conn, selections)
    n = conn.execute(
        "SELECT COUNT(*) FROM state_cfg_edge_alternate_selections"
    ).fetchone()[0]
    assert n == 1
