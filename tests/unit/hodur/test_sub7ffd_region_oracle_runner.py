"""Tests for the sub7FFD Hodur oracle test-support runner."""
from __future__ import annotations

import json
import sqlite3

from tests.system.e2e.hodur.sub7ffd_region_oracle_runner import (
    render_region_oracle_report,
    resolve_oracle_snap_ids,
)
from tests.unit.core.diag._orm_bind import make_bound_diag_db
from d810.core.diag.models import Block, FactObservation, Snapshot

_FUNC_EA = "0x0000000180012df0"
_FUNC_EA_I64 = 0x180012DF0


def _make_conn_with_snaps(snaps: list[tuple[int, str]]) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE snapshots (id INTEGER PRIMARY KEY, label TEXT NOT NULL)"
    )
    conn.executemany("INSERT INTO snapshots (id, label) VALUES (?, ?)", snaps)
    conn.commit()
    return conn


def _insert_snapshot(snap_id: int, label: str) -> None:
    Snapshot.insert(
        id=snap_id,
        label=label,
        func_ea_hex=_FUNC_EA,
        func_ea_i64=_FUNC_EA_I64,
        maturity="MMAT_GLBOPT1",
        phase="post_d810",
        block_count=1,
        timestamp=0.0,
    ).execute()


def _insert_byte_fact(
    snap_id: int,
    *,
    block_serial: int = 161,
) -> None:
    FactObservation.insert(
        snapshot=snap_id,
        func_ea_hex=_FUNC_EA,
        func_ea_i64=_FUNC_EA_I64,
        fact_id=f"tbe_3_{snap_id}",
        kind="TerminalByteEmitterFact",
        semantic_key="byte_emit_3",
        maturity="MMAT_GLBOPT1",
        phase="post_bundle_stabilize",
        confidence=1.0,
        source_block=block_serial,
        payload=json.dumps(
            {
                "byte_index": 3,
                "block_serial": block_serial,
                "corridor_role": "terminal_tail",
                "source_byte_expression": "v52[3]",
                "destination_buffer_expression": "%var_dst.8",
                "counter_carrier": "%var_53.8",
                "guard_condition": "jcnd %var_53.8 == #3.8, @241",
                "emitter_role": "memory_store",
            }
        ),
        evidence="{}",
    ).execute()


def _insert_block(snap_id: int, serial: int) -> None:
    Block.insert(
        snapshot=snap_id,
        serial=serial,
        block_type=1,
        type_name="BLT_1WAY",
        start_ea_hex=_FUNC_EA,
        start_ea_i64=_FUNC_EA_I64,
        end_ea_hex="0x0000000180012e00",
        end_ea_i64=0x180012E00,
        npred=0,
        nsucc=1,
        preds="[]",
        succs="[218]",
        insn_count=0,
    ).execute()


def test_resolver_picks_highest_id_for_primary_label() -> None:
    conn = _make_conn_with_snaps(
        [
            (3, "post_bundle_stabilize"),
            (5, "post_bundle_stabilize"),
            (4, "post_pipeline"),
            (10, "GLBOPT1_post_d810"),
        ]
    )
    snap17, snap18 = resolve_oracle_snap_ids(
        conn,
        snap17_labels=("post_bundle_stabilize", "post_pipeline"),
        snap18_labels=("GLBOPT1_post_d810",),
    )
    assert (snap17, snap18) == (5, 10)


def test_resolver_falls_back_and_keeps_snap17_before_snap18() -> None:
    conn = _make_conn_with_snaps(
        [
            (17, "post_bundle_stabilize"),
            (18, "post_d810"),
            (27, "post_bundle_stabilize"),
        ]
    )
    snap17, snap18 = resolve_oracle_snap_ids(
        conn,
        snap17_labels=("missing", "post_bundle_stabilize"),
        snap18_labels=("GLBOPT1_post_d810", "post_d810"),
    )
    assert (snap17, snap18) == (17, 18)


def test_resolver_returns_partial_results() -> None:
    conn = _make_conn_with_snaps([(7, "post_pipeline")])
    snap17, snap18 = resolve_oracle_snap_ids(
        conn,
        snap17_labels=("post_bundle_stabilize", "post_pipeline"),
        snap18_labels=("GLBOPT1_post_d810",),
    )
    assert snap17 == 7
    assert snap18 is None


def test_render_report_emits_concrete_d810_feature_values() -> None:
    db = make_bound_diag_db()
    conn = db.connection()
    _insert_snapshot(17, "post_bundle_stabilize")
    _insert_snapshot(18, "GLBOPT1_post_d810")
    _insert_byte_fact(17)
    _insert_block(17, 161)

    payload = json.loads(
        render_region_oracle_report(conn, func_ea_hex=_FUNC_EA, json_output=True)
    )
    snap17 = {f["feature"]: f["value"] for f in payload["snap17_features"]}
    snap18 = {f["feature"]: f["value"] for f in payload["snap18_features"]}

    assert snap17["byte_emit_3_present"] is True
    assert snap17["byte_emit_3_source_form"] == "indexed_base_plus_k"
    assert snap17["byte_emit_3_destination_present"] is True
    assert snap17["byte_emit_3_counter_update_present"] is True
    assert snap17["early_return_guard_3_present"] is True
    assert snap18["byte_emit_3_present"] is False


def test_render_report_resolves_moved_sub7ffd_by_function_name() -> None:
    db = make_bound_diag_db()
    conn = db.connection()
    _insert_snapshot(17, "post_bundle_stabilize")
    _insert_snapshot(18, "GLBOPT1_post_d810")
    _insert_byte_fact(17)
    _insert_block(17, 161)

    body = render_region_oracle_report(
        conn,
        func_ea_hex="0x0000000180013910",
        func_name="sub_7FFD3338C040",
    )

    assert "Status: no_ref_spec" not in body
    assert "Function: sub_7FFD3338C040 (0x0000000180013910)" in body


def test_render_report_includes_microblock_evidence() -> None:
    db = make_bound_diag_db()
    conn = db.connection()
    _insert_snapshot(17, "post_bundle_stabilize")
    _insert_snapshot(18, "GLBOPT1_post_d810")
    _insert_byte_fact(17)
    _insert_block(17, 161)

    body = render_region_oracle_report(
        conn,
        func_ea_hex=_FUNC_EA,
        microblocks=True,
    )
    assert "## Microblock Evidence" in body
    assert "161" in body


def test_render_report_detects_byte_emit_survival_at_snap17() -> None:
    db = make_bound_diag_db()
    conn = db.connection()
    _insert_snapshot(5, "maturity_MMAT_GLBOPT1_pre_d810")
    _insert_snapshot(17, "post_bundle_stabilize")
    _insert_snapshot(18, "GLBOPT1_post_d810")
    _insert_byte_fact(5)
    _insert_block(5, 161)
    _insert_block(17, 200)

    payload = json.loads(
        render_region_oracle_report(conn, func_ea_hex=_FUNC_EA, json_output=True)
    )
    snap17 = {f["feature"]: f["value"] for f in payload["snap17_features"]}
    snap18 = {f["feature"]: f["value"] for f in payload["snap18_features"]}

    assert snap17["byte_emit_3_present"] is True
    assert snap17["byte_emit_3_source_form"] == "indexed_base_plus_k"
    assert snap18["byte_emit_3_present"] is False
