"""Tests for BST single-hop enrichment of StateTransitionAnchorFact."""
from __future__ import annotations
from tests.unit.core.diag._orm_bind import make_bound_diag_db

import json
import sqlite3

from d810.diagnostics.bst_resolution import (
    BstInterval,
    load_latest_bst_intervals_from_db,
    parse_bst_intervals,
    persist_bst_resolutions,
    resolve_state_transition_facts,
    resolve_via_intervals,
)
from d810.core.diag.snapshot import snapshot_bst_interval_dispatcher_rows


def _make_db() -> sqlite3.Connection:
    conn = make_bound_diag_db().connection()
    conn.execute(
        """
        INSERT INTO snapshots
            (id, label, func_ea_hex, func_ea_i64,
             maturity, phase, block_count, timestamp)
        VALUES (1, 'MMAT_LOCOPT_pre_d810', '0x180012df0',
                0x180012df0, 'MMAT_LOCOPT', 'pre_d810', 0, 0.0)
        """,
    )
    conn.commit()
    return conn


def _add_transition_fact(
    conn: sqlite3.Connection,
    *,
    fact_id: str,
    block: int,
    source_const: int,
    successor_kind: str,
    snap: int = 1,
    canonical_stkoff_hex: str = "0x3c",
) -> None:
    payload = {
        "source_block_serial": block,
        "source_state_const": source_const,
        "source_state_const_hex": f"0x{source_const:08x}",
        "successor_kind": successor_kind,
        "transit_blocks": [],
        "successor_block_serial": None,
        "next_state_const": None,
        "next_state_const_hex": None,
        "state_var_stkoff": int(canonical_stkoff_hex, 16),
        "state_var_stkoff_hex": canonical_stkoff_hex,
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
            "StateTransitionAnchorFact", fact_id, "MMAT_LOCOPT",
            "pre_d810", 0.85, block, None, None, None, None,
            json.dumps(payload), "[]",
        ),
    )


def _add_state_write_anchor(
    conn: sqlite3.Connection,
    *,
    block: int,
    state_const: int,
    canonical_stkoff_hex: str = "0x3c",
    snap: int = 1,
    instruction_index: int = 0,
) -> None:
    payload = {
        "block_serial": block,
        "state_const": state_const,
        "state_const_u64": state_const,
        "state_const_hex": f"0x{state_const:016x}",
        "state_var_stkoff": int(canonical_stkoff_hex, 16),
        "state_var_stkoff_hex": canonical_stkoff_hex,
        "instruction_index": instruction_index,
        "instruction_ea_hex": f"0x{0x180000000 + block:016x}",
    }
    fact_id = (
        f"state_write_anchor:blk={block}:insn={instruction_index}:"
        f"ea=0x{0x180000000 + block:x}:stkoff={canonical_stkoff_hex}"
    )
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
            "StateWriteAnchorFact", fact_id, "MMAT_LOCOPT",
            "pre_d810", 0.9, block, None, None, None, None,
            json.dumps(payload), "[]",
        ),
    )


def test_parse_bst_intervals_basic() -> None:
    payload = json.dumps([
        {"lo": "0x100", "hi": "0x200", "target": 7},
        {"lo": "0x200", "hi": "0x300", "target": 8},
    ])
    intervals = parse_bst_intervals(payload)
    assert len(intervals) == 2
    assert intervals[0] == BstInterval(lo=0x100, hi=0x200, target_block=7)


def test_load_latest_bst_intervals_from_db() -> None:
    conn = _make_db()
    conn.execute(
        """
        INSERT INTO snapshots
            (id, label, func_ea_hex, func_ea_i64,
             maturity, phase, block_count, timestamp)
        VALUES (2, 'MMAT_GLBOPT1_post_d810', '0x180012df0',
                0x180012df0, 'MMAT_GLBOPT1', 'post_d810', 0, 1.0)
        """,
    )
    snapshot_bst_interval_dispatcher_rows(
        conn,
        1,
        [{"lo": 0x100, "hi": 0x180, "target": 7}],
        dispatcher_entry_block=2,
        maturity="MMAT_GLBOPT1",
    )
    snapshot_bst_interval_dispatcher_rows(
        conn,
        2,
        [{"lo": 0x200, "hi": 0x280, "target": 8}],
        dispatcher_entry_block=3,
        maturity="MMAT_GLBOPT1",
    )

    intervals = load_latest_bst_intervals_from_db(conn)

    assert intervals == (BstInterval(lo=0x200, hi=0x280, target_block=8),)


def test_resolve_via_intervals_point_match() -> None:
    intervals = (
        BstInterval(lo=0x10743C4C, hi=0x10743C4D, target_block=158),
        BstInterval(lo=0x10743C4D, hi=0x11CD1DA3, target_block=160),
    )
    assert resolve_via_intervals(intervals, 0x10743C4C) == 158
    assert resolve_via_intervals(intervals, 0x10743C4D) == 160
    # No match -> None
    assert resolve_via_intervals(intervals, 0xFFFFFFFF) is None


def test_resolve_via_intervals_range_match() -> None:
    intervals = (
        BstInterval(lo=0x57BE6FD1, hi=0x5D0AEBD3, target_block=76),
    )
    # 0x5A21D9DB falls in [0x57BE6FD1, 0x5D0AEBD3) -> 76
    assert resolve_via_intervals(intervals, 0x5A21D9DB) == 76


def test_resolve_branch_with_local_state_write() -> None:
    """branch successor_kind + BST hit + handler has local state-write."""
    conn = _make_db()
    _add_transition_fact(
        conn,
        fact_id="state_transition_anchor:blk=100:foo",
        block=100,
        source_const=0x5A21D9DB,
        successor_kind="branch",
    )
    _add_state_write_anchor(conn, block=76, state_const=0x10743C4C)
    intervals = (
        BstInterval(lo=0x57BE6FD1, hi=0x5D0AEBD3, target_block=76),
    )
    resolutions = resolve_state_transition_facts(
        conn, bst_intervals=intervals, locopt_snapshot_id=1,
    )
    assert len(resolutions) == 1
    r = resolutions[0]
    assert r.source_block_serial == 100
    assert r.bst_resolved_next_block_serial == 76
    assert r.bst_resolved_next_state_const_hex == "0x0000000010743c4c"
    assert r.bst_resolution_reason == (
        "bst_row_matched_with_local_state_write"
    )
    assert r.bst_resolution_maturity == "MMAT_GLBOPT1"


def test_resolve_branch_handler_has_no_state_write() -> None:
    """branch + BST hit + resolved handler has no canonical state-write."""
    conn = _make_db()
    _add_transition_fact(
        conn,
        fact_id="state_transition_anchor:blk=100:foo",
        block=100,
        source_const=0x5A21D9DB,
        successor_kind="branch",
    )
    # Note: NO StateWriteAnchorFact at block 76.
    intervals = (
        BstInterval(lo=0x57BE6FD1, hi=0x5D0AEBD3, target_block=76),
    )
    resolutions = resolve_state_transition_facts(
        conn, bst_intervals=intervals, locopt_snapshot_id=1,
    )
    assert len(resolutions) == 1
    r = resolutions[0]
    assert r.bst_resolved_next_block_serial == 76
    assert r.bst_resolved_next_state_const_hex is None
    assert r.bst_resolution_reason == (
        "bst_row_matched_no_local_state_write_at_handler"
    )


def test_resolve_no_bst_row() -> None:
    """branch + BST has no row covering the source const."""
    conn = _make_db()
    _add_transition_fact(
        conn,
        fact_id="state_transition_anchor:blk=100:foo",
        block=100,
        source_const=0xDEADBEEF,
        successor_kind="branch",
    )
    intervals = (
        BstInterval(lo=0x100, hi=0x200, target_block=7),
    )
    resolutions = resolve_state_transition_facts(
        conn, bst_intervals=intervals, locopt_snapshot_id=1,
    )
    assert len(resolutions) == 1
    assert resolutions[0].bst_resolution_reason == "no_bst_row"
    assert resolutions[0].bst_resolved_next_block_serial is None


def test_resolve_non_branch_successor_skipped() -> None:
    """successor_kind = direct -> no BST resolution attempted."""
    conn = _make_db()
    _add_transition_fact(
        conn,
        fact_id="state_transition_anchor:blk=100:foo",
        block=100,
        source_const=0x5A21D9DB,
        successor_kind="direct",
    )
    intervals = (
        BstInterval(lo=0x57BE6FD1, hi=0x5D0AEBD3, target_block=76),
    )
    resolutions = resolve_state_transition_facts(
        conn, bst_intervals=intervals, locopt_snapshot_id=1,
    )
    assert len(resolutions) == 1
    assert resolutions[0].bst_resolved_next_block_serial is None
    assert "successor_kind=direct" in resolutions[0].bst_resolution_reason


def test_resolve_no_bst_intervals() -> None:
    """Empty interval set -> no_bst_intervals_available reason."""
    conn = _make_db()
    _add_transition_fact(
        conn,
        fact_id="state_transition_anchor:blk=100:foo",
        block=100,
        source_const=0x5A21D9DB,
        successor_kind="branch",
    )
    resolutions = resolve_state_transition_facts(
        conn, bst_intervals=(), locopt_snapshot_id=1,
    )
    assert len(resolutions) == 1
    assert (
        resolutions[0].bst_resolution_reason
        == "no_bst_intervals_available"
    )


def test_persist_idempotent() -> None:
    conn = _make_db()
    _add_transition_fact(
        conn,
        fact_id="state_transition_anchor:blk=100:foo",
        block=100,
        source_const=0x5A21D9DB,
        successor_kind="branch",
    )
    _add_state_write_anchor(conn, block=76, state_const=0x10743C4C)
    intervals = (
        BstInterval(lo=0x57BE6FD1, hi=0x5D0AEBD3, target_block=76),
    )
    resolutions = resolve_state_transition_facts(
        conn, bst_intervals=intervals, locopt_snapshot_id=1,
    )
    persist_bst_resolutions(conn, resolutions)
    persist_bst_resolutions(conn, resolutions)
    rows = conn.execute(
        "SELECT COUNT(*) FROM state_transition_bst_resolutions"
    ).fetchone()
    assert rows[0] == 1
