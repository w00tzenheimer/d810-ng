"""Tests for alternate-edge selector."""
from __future__ import annotations
from tests.unit.core.diag._orm_bind import make_bound_diag_db

import json
import sqlite3

from d810._vendor.peewee import fn
from d810.core.diag.models import (
    FactObservation,
    Snapshot,
    StateCfgEdge,
    StateCfgEdgeAlternateCorrelation,
    StateCfgEdgeAlternateSelection,
    StateCfgNodeBlock,
)
from d810.diagnostics.alternate_selection import (
    persist_alternate_selections,
    select_alternate_edges,
)


def _make_db() -> sqlite3.Connection:
    db = make_bound_diag_db()
    Snapshot.insert(
        id=1, label="recon_dag", func_ea_hex="0x180012df0",
        func_ea_i64=0x180012df0, maturity="MMAT_GLBOPT1", phase="pre_d810",
        block_count=0, timestamp=0.0,
    ).execute()
    return db.connection()


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
    StateCfgNodeBlock.insert(
        snapshot=snap, state_hex=state_hex, entry_block=entry_block,
        block_serial=block_serial, block_index=block_index, role=role,
    ).execute()


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
        max_id = (
            StateCfgEdge.select(fn.MAX(StateCfgEdge.edge_id))
            .where(StateCfgEdge.snapshot == snap)
            .scalar()
        )
        edge_id = (max_id or 0) + 1
    StateCfgEdge.insert(
        snapshot=snap, edge_id=edge_id, source_state_hex=src,
        source_state_i64=int(src, 16) if src else None, target_state_hex=tgt,
        target_state_i64=int(tgt, 16) if tgt else None, edge_kind=edge_kind,
        source_block=None, source_arm=None, target_entry=None, ordered_path="[]",
    ).execute()


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
    FactObservation.insert(
        snapshot=snap, func_ea_hex="0x180012df0", func_ea_i64=0x180012df0,
        fact_id=fact_id, kind="TerminalByteEmitterFact", semantic_key=fact_id,
        maturity="MMAT_GLBOPT1", phase="pre_d810", confidence=0.9,
        source_block=destination_block, source_ea_hex=None, source_ea_i64=None,
        block_fingerprint=None, mop_signature=None, payload=json.dumps(payload),
        evidence="[]",
    ).execute()


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
    StateCfgEdgeAlternateCorrelation.insert(
        snapshot=snap, collapsed_edge_id=collapsed_edge,
        alternate_edge_id=alt_edge, collapsed_source_state=collapsed_src,
        collapsed_target_state=collapsed_tgt, alternate_source_state=alt_src,
        alternate_target_state=alt_tgt, alternate_ordered_path="[]",
        overlap_blocks="[]", alternate_classification="RANGE_BACKED",
        reason="test",
    ).execute()


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
    assert StateCfgEdgeAlternateSelection.select().count() == 1
