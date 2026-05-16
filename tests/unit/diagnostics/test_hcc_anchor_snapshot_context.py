"""Unit tests for HCC anchor snapshot diagnostics."""
from __future__ import annotations

import json
import sqlite3

from d810.diagnostics.hcc_anchor_snapshot_context import (
    collect_anchor_snapshot_context_from_connection,
    default_anchor_snapshot_context,
)


def _make_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE snapshots (id INTEGER PRIMARY KEY, label TEXT)")
    conn.execute(
        "CREATE TABLE blocks (snapshot_id INTEGER, serial INTEGER, preds TEXT, succs TEXT)"
    )
    return conn


def _insert_snapshot(conn: sqlite3.Connection, snapshot_id: int, label: str) -> None:
    conn.execute(
        "INSERT INTO snapshots (id, label) VALUES (?, ?)",
        (snapshot_id, label),
    )


def _insert_block(
    conn: sqlite3.Connection,
    snapshot_id: int,
    serial: int,
    *,
    preds: list[int] | None = None,
    succs: list[int] | None = None,
) -> None:
    conn.execute(
        "INSERT INTO blocks (snapshot_id, serial, preds, succs) VALUES (?, ?, ?, ?)",
        (
            snapshot_id,
            serial,
            json.dumps(preds or []),
            json.dumps(succs or []),
        ),
    )


def test_default_anchor_snapshot_context_is_unknown():
    assert default_anchor_snapshot_context() == {
        "preds_pre_pipeline": "UNKNOWN",
        "preds_post_hcc": "UNKNOWN",
        "preds_post_pipeline": "UNKNOWN",
        "succs_pre_pipeline": "UNKNOWN",
        "succs_post_hcc": "UNKNOWN",
        "succs_post_pipeline": "UNKNOWN",
        "reachable_from_entry_post_pipeline": "UNKNOWN",
        "survives_glbopt1_post_d810": "UNKNOWN",
        "earliest_kill_point": "unknown",
    }


def test_collect_anchor_snapshot_context_reports_first_missing_snapshot():
    conn = _make_conn()
    _insert_snapshot(conn, 1, "maturity_MMAT_GLBOPT1_pre_d810")
    _insert_snapshot(conn, 2, "handler_chain_composer_post_apply")
    _insert_snapshot(conn, 3, "post_pipeline")
    _insert_snapshot(conn, 4, "maturity_MMAT_GLBOPT1_post_d810")
    _insert_block(conn, 1, 0, succs=[10])
    _insert_block(conn, 1, 10, preds=[0], succs=[20])
    _insert_block(conn, 1, 20, preds=[10], succs=[])
    _insert_block(conn, 2, 0, succs=[10])
    _insert_block(conn, 2, 10, preds=[0], succs=[30])
    _insert_block(conn, 2, 30, preds=[10], succs=[])
    _insert_block(conn, 3, 0, succs=[99])
    _insert_block(conn, 4, 0, succs=[99])

    context = collect_anchor_snapshot_context_from_connection(
        conn,
        anchor_serial=10,
    )

    assert context == {
        "preds_pre_pipeline": "[blk[0]]",
        "preds_post_hcc": "[blk[0]]",
        "preds_post_pipeline": "UNKNOWN",
        "succs_pre_pipeline": "[blk[20]]",
        "succs_post_hcc": "[blk[30]]",
        "succs_post_pipeline": "UNKNOWN",
        "reachable_from_entry_post_pipeline": "NO",
        "survives_glbopt1_post_d810": "NO",
        "earliest_kill_point": "post_pipeline",
    }


def test_collect_anchor_snapshot_context_keeps_latest_label_instance():
    conn = _make_conn()
    _insert_snapshot(conn, 1, "maturity_MMAT_GLBOPT1_pre_d810")
    _insert_snapshot(conn, 2, "maturity_MMAT_GLBOPT1_pre_d810")
    _insert_snapshot(conn, 3, "handler_chain_composer_post_apply")
    _insert_snapshot(conn, 4, "post_pipeline")
    _insert_snapshot(conn, 5, "maturity_MMAT_GLBOPT1_post_d810")
    _insert_block(conn, 1, 10, preds=[1], succs=[2])
    _insert_block(conn, 2, 10, preds=[3], succs=[4])
    _insert_block(conn, 3, 10, preds=[3], succs=[4])
    _insert_block(conn, 4, 10, preds=[3], succs=[4])
    _insert_block(conn, 5, 10, preds=[3], succs=[4])

    context = collect_anchor_snapshot_context_from_connection(
        conn,
        anchor_serial=10,
    )

    assert context["preds_pre_pipeline"] == "[blk[3]]"
    assert context["succs_pre_pipeline"] == "[blk[4]]"
    assert context["earliest_kill_point"] == "NEVER"
