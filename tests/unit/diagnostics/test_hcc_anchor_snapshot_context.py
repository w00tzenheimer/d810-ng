"""Unit tests for HCC anchor snapshot diagnostics."""
from __future__ import annotations

import json

from d810.core.diag import create_diag_database
from d810.core.diag.models import Block, Snapshot
from d810.diagnostics.hcc_anchor_snapshot_context import (
    collect_anchor_snapshot_context_from_connection,
    default_anchor_snapshot_context,
)


def _make_conn():
    # create_diag_database binds the Models to this in-memory DB so the ORM
    # reads in collect_anchor_snapshot_context_from_connection hit it.
    return create_diag_database(":memory:")


def _insert_snapshot(db, snapshot_id: int, label: str) -> None:
    Snapshot.insert(
        id=snapshot_id,
        label=label,
        func_ea_hex="0x0",
        func_ea_i64=0,
        maturity="MMAT_GLBOPT1",
        phase="unknown",
        block_count=0,
        timestamp=0.0,
    ).execute()


def _insert_block(
    db,
    snapshot_id: int,
    serial: int,
    *,
    preds: list[int] | None = None,
    succs: list[int] | None = None,
) -> None:
    Block.insert(
        snapshot=snapshot_id,
        serial=serial,
        block_type=0,
        type_name="",
        nsucc=len(succs or []),
        npred=len(preds or []),
        succs=json.dumps(succs or []),
        preds=json.dumps(preds or []),
        insn_count=0,
    ).execute()


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
    db = _make_conn()
    _insert_snapshot(db, 1, "maturity_MMAT_GLBOPT1_pre_d810")
    _insert_snapshot(db, 2, "handler_chain_composer_post_apply")
    _insert_snapshot(db, 3, "post_pipeline")
    _insert_snapshot(db, 4, "maturity_MMAT_GLBOPT1_post_d810")
    _insert_block(db, 1, 0, succs=[10])
    _insert_block(db, 1, 10, preds=[0], succs=[20])
    _insert_block(db, 1, 20, preds=[10], succs=[])
    _insert_block(db, 2, 0, succs=[10])
    _insert_block(db, 2, 10, preds=[0], succs=[30])
    _insert_block(db, 2, 30, preds=[10], succs=[])
    _insert_block(db, 3, 0, succs=[99])
    _insert_block(db, 4, 0, succs=[99])

    context = collect_anchor_snapshot_context_from_connection(
        db.connection(),
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
    db = _make_conn()
    _insert_snapshot(db, 1, "maturity_MMAT_GLBOPT1_pre_d810")
    _insert_snapshot(db, 2, "maturity_MMAT_GLBOPT1_pre_d810")
    _insert_snapshot(db, 3, "handler_chain_composer_post_apply")
    _insert_snapshot(db, 4, "post_pipeline")
    _insert_snapshot(db, 5, "maturity_MMAT_GLBOPT1_post_d810")
    _insert_block(db, 1, 10, preds=[1], succs=[2])
    _insert_block(db, 2, 10, preds=[3], succs=[4])
    _insert_block(db, 3, 10, preds=[3], succs=[4])
    _insert_block(db, 4, 10, preds=[3], succs=[4])
    _insert_block(db, 5, 10, preds=[3], succs=[4])

    context = collect_anchor_snapshot_context_from_connection(
        db.connection(),
        anchor_serial=10,
    )

    assert context["preds_pre_pipeline"] == "[blk[3]]"
    assert context["succs_pre_pipeline"] == "[blk[4]]"
    assert context["earliest_kill_point"] == "NEVER"
