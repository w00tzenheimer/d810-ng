"""Tests for generic state-dispatcher transition enrichment."""
from __future__ import annotations
from tests.unit.core.diag._orm_bind import make_bound_diag_db

import json
import sqlite3

from d810.core.diag.snapshot import snapshot_state_dispatcher_rows
from d810.diagnostics.state_dispatcher_resolution import (
    load_latest_state_dispatcher_map_from_db,
    persist_state_dispatch_resolutions,
    resolve_state_transition_facts_with_dispatcher,
)


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
    conn.execute(
        """
        INSERT INTO snapshots
            (id, label, func_ea_hex, func_ea_i64,
             maturity, phase, block_count, timestamp)
        VALUES (2, 'MMAT_GLBOPT1_post_d810', '0x180012df0',
                0x180012df0, 'MMAT_GLBOPT1', 'post_d810', 0, 1.0)
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
    successor_kind: str = "branch",
) -> None:
    payload = {
        "source_block_serial": block,
        "source_state_const": source_const,
        "source_state_const_hex": f"0x{source_const:08x}",
        "successor_kind": successor_kind,
        "state_var_stkoff_hex": "0x3c",
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
            1,
            "0x180012df0",
            0x180012DF0,
            fact_id,
            "StateTransitionAnchorFact",
            fact_id,
            "MMAT_LOCOPT",
            "pre_d810",
            0.85,
            block,
            None,
            None,
            None,
            None,
            json.dumps(payload),
            "[]",
        ),
    )


def _add_state_write_anchor(
    conn: sqlite3.Connection,
    *,
    block: int,
    state_const: int,
) -> None:
    payload = {
        "block_serial": block,
        "state_const_u64": state_const,
        "state_const_hex": f"0x{state_const:016x}",
        "state_var_stkoff_hex": "0x3c",
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
            1,
            "0x180012df0",
            0x180012DF0,
            f"state_write_anchor:blk={block}",
            "StateWriteAnchorFact",
            f"state_write_anchor:blk={block}",
            "MMAT_LOCOPT",
            "pre_d810",
            0.9,
            block,
            None,
            None,
            None,
            None,
            json.dumps(payload),
            "[]",
        ),
    )


def test_loads_rows_and_resolves_exact_state() -> None:
    conn = _make_db()
    snapshot_state_dispatcher_rows(
        conn,
        2,
        [
            {
                "state_const": 0x89407346,
                "target_block": 76,
                "dispatcher_entry_block": 5,
                "compare_block": 6,
                "dispatcher_kind": "CONDITIONAL_CHAIN",
                "branch_kind": "jz_taken",
            }
        ],
        dispatcher_entry_block=5,
        dispatcher_kind="CONDITIONAL_CHAIN",
        maturity="MMAT_GLBOPT1",
    )
    _add_transition_fact(
        conn,
        fact_id="state_transition_anchor:blk=100",
        block=100,
        source_const=0x89407346,
    )
    _add_state_write_anchor(conn, block=76, state_const=0x10743C4C)

    dispatch_map = load_latest_state_dispatcher_map_from_db(conn)
    resolutions = resolve_state_transition_facts_with_dispatcher(
        conn,
        dispatch_map=dispatch_map,
        locopt_snapshot_id=1,
    )

    assert dispatch_map is not None
    assert dispatch_map.resolve_target(0x89407346) == 76
    assert len(resolutions) == 1
    assert resolutions[0].resolved_next_block_serial == 76
    assert (
        resolutions[0].resolved_next_state_const_hex
        == "0x0000000010743c4c"
    )
    assert resolutions[0].resolution_reason == "resolved_exact_state"


def test_reports_state_not_in_dispatcher_map() -> None:
    conn = _make_db()
    snapshot_state_dispatcher_rows(
        conn,
        2,
        [{"state_const": 0x10, "target_block": 7}],
        dispatcher_entry_block=5,
        dispatcher_kind="CONDITIONAL_CHAIN",
    )
    _add_transition_fact(
        conn,
        fact_id="state_transition_anchor:blk=100",
        block=100,
        source_const=0x20,
    )

    resolutions = resolve_state_transition_facts_with_dispatcher(
        conn,
        dispatch_map=load_latest_state_dispatcher_map_from_db(conn),
        locopt_snapshot_id=1,
    )

    assert resolutions[0].resolution_reason == "state_not_in_dispatcher_map"


def test_handler_state_map_rows_do_not_mark_handler_as_dispatcher() -> None:
    conn = _make_db()
    snapshot_state_dispatcher_rows(
        conn,
        2,
        [
            {
                "state_const": 0x10,
                "target_block": 7,
                "dispatcher_entry_block": 5,
                "compare_block": 7,
                "dispatcher_kind": "CONDITIONAL_CHAIN",
                "branch_kind": "handler_state_map",
            }
        ],
        dispatcher_entry_block=5,
        dispatcher_kind="CONDITIONAL_CHAIN",
    )
    _add_transition_fact(
        conn,
        fact_id="state_transition_anchor:blk=100",
        block=100,
        source_const=0x10,
    )

    dispatch_map = load_latest_state_dispatcher_map_from_db(conn)
    resolutions = resolve_state_transition_facts_with_dispatcher(
        conn,
        dispatch_map=dispatch_map,
        locopt_snapshot_id=1,
    )

    assert dispatch_map is not None
    assert dispatch_map.dispatcher_blocks == frozenset({5})
    assert resolutions[0].resolved_next_block_serial == 7
    assert resolutions[0].resolution_reason == "resolved_exact_state"


def test_persist_idempotent() -> None:
    conn = _make_db()
    _add_transition_fact(
        conn,
        fact_id="state_transition_anchor:blk=100",
        block=100,
        source_const=0x20,
    )
    resolutions = resolve_state_transition_facts_with_dispatcher(
        conn,
        dispatch_map=None,
        locopt_snapshot_id=1,
    )

    persist_state_dispatch_resolutions(conn, resolutions)
    persist_state_dispatch_resolutions(conn, resolutions)

    row = conn.execute(
        "SELECT COUNT(*) FROM state_transition_dispatch_resolutions"
    ).fetchone()
    assert row[0] == 1
