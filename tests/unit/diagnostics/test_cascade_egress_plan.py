"""Tests for the cascade-egress-plan diag subcommand."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from d810.core.diag import diag_models_on, open_diag_database
from d810.core.diag.models import Block, FactObservation, Instruction, Snapshot
from d810.diagnostics.cascade_egress_plan import (
    _json_int_tuple,
    choose_fact_snapshot,
    choose_target_snapshot,
    load_blocks,
    load_sites,
    run_plan,
)


# ---------------------------------------------------------------------------
# Synthetic diag DB fixture
# ---------------------------------------------------------------------------


def _make_diag_db(tmp_path: Path) -> Path:
    """Build a diag SQLite shaped enough to exercise every helper + run_plan.

    Layout:
      - snap 5  = MMAT_GLBOPT1 / pre_d810   (fact rows live here)
      - snap 17 = post_bundle_stabilize     (target CFG snapshot)
      - snap 99 = dump_raw_lvars            (skipped by target picker)

    Block topology at snap 17:
      blk[0] -> blk[10] -> blk[20] -> blk[100] (BLT_STOP)
                       -> blk[30] -> blk[100]
    """
    from d810.core.diag import create_diag_database

    db_path = tmp_path / "diag.sqlite3"
    db_obj = create_diag_database(str(db_path))
    with diag_models_on(db_obj):
        Snapshot.insert_many([
            dict(id=5,  label="pre_d810",              func_ea_hex="0x0", func_ea_i64=0, maturity="MMAT_GLBOPT1", phase="pre_d810",   block_count=0, timestamp=0.0),
            dict(id=17, label="post_bundle_stabilize", func_ea_hex="0x0", func_ea_i64=0, maturity="MMAT_GLBOPT1", phase="post_apply", block_count=0, timestamp=0.0),
            dict(id=99, label="dump_raw_lvars",        func_ea_hex="0x0", func_ea_i64=0, maturity="MMAT_LVARS",   phase="post_d810",  block_count=0, timestamp=0.0),
        ]).execute()
        Block.insert_many([
            dict(snapshot=17, serial=0,   block_type=4, type_name="BLT_NWAY", start_ea_hex="0x180014000", start_ea_i64=0, end_ea_hex=None, end_ea_i64=None, nsucc=1, npred=0,    succs="[10]",       preds="[]",        insn_count=0),
            dict(snapshot=17, serial=10,  block_type=2, type_name="BLT_2WAY", start_ea_hex="0x180014100", start_ea_i64=0, end_ea_hex=None, end_ea_i64=None, nsucc=2, npred=1,    succs="[20, 30]",   preds="[0]",       insn_count=0),
            dict(snapshot=17, serial=20,  block_type=1, type_name="BLT_1WAY", start_ea_hex="0x180014200", start_ea_i64=0, end_ea_hex=None, end_ea_i64=None, nsucc=1, npred=1,    succs="[100]",      preds="[10]",      insn_count=0),
            dict(snapshot=17, serial=30,  block_type=1, type_name="BLT_1WAY", start_ea_hex="0x180014300", start_ea_i64=0, end_ea_hex=None, end_ea_i64=None, nsucc=1, npred=1,    succs="[100]",      preds="[10]",      insn_count=0),
            dict(snapshot=17, serial=100, block_type=0, type_name="BLT_STOP", start_ea_hex="0x180014FFF", start_ea_i64=0, end_ea_hex=None, end_ea_i64=None, nsucc=0, npred=2,    succs="[]",         preds="[20, 30]",  insn_count=0),
        ]).execute()
        Instruction.insert_many([
            dict(snapshot=17, block_serial=20, insn_index=0, ea_hex="0x0", ea_i64=0, opcode=4, opcode_name="m_mov", dstr="mov #0xAA.8, %var_8.8"),
            dict(snapshot=17, block_serial=30, insn_index=0, ea_hex="0x0", ea_i64=0, opcode=4, opcode_name="m_mov", dstr="mov #0xBB.8, %var_8.8"),
        ]).execute()
        FactObservation.insert(
            snapshot=5, func_ea_hex="0x0", func_ea_i64=0,
            fact_id="fact_byte_3", kind="TerminalByteEmitterFact",
            semantic_key="byte_emit_3", maturity="MMAT_GLBOPT1", phase="pre_d810",
            confidence=0.85,
            source_ea_hex="0x180014210",
            payload=json.dumps({
                "byte_index": 3,
                "destination_block": 20,
                "block_ea": 0x180014200,
                "opcode": "m_stx",
                "emitter_role": "memory_store",
                "corridor_role": "terminal_tail",
                "destination_buffer_expression": "[ds.2:.+%var_188.8]",
                "source_byte_expression": "xdu([ds.2:%var_190.8+#3.8].1)",
            }),
            evidence="{}",
        ).execute()
        FactObservation.insert(
            snapshot=5, func_ea_hex="0x0", func_ea_i64=0,
            fact_id="fact_byte_6", kind="TerminalByteEmitterFact",
            semantic_key="byte_emit_6", maturity="MMAT_GLBOPT1", phase="pre_d810",
            confidence=0.85,
            source_ea_hex="0x180014310",
            payload=json.dumps({
                "byte_index": 6,
                "destination_block": 30,
                "block_ea": 0x180014300,
                "opcode": "m_stx",
                "emitter_role": "memory_store",
                "corridor_role": "terminal_tail",
                "destination_buffer_expression": "[ds.2:.+%var_188.8]",
                "source_byte_expression": "xdu([ds.2:%var_190.8+#6.8].1)",
            }),
            evidence="{}",
        ).execute()
        # An unrelated fact that must be skipped.
        FactObservation.insert(
            snapshot=5, func_ea_hex="0x0", func_ea_i64=0,
            fact_id="fact_other", kind="LoopCarrierFact",
            semantic_key="loop_carrier", maturity="MMAT_GLBOPT1", phase="pre_d810",
            confidence=0.0,
            payload=json.dumps({}),
            evidence="{}",
        ).execute()
        db_obj.connection().commit()
    db_obj.close()
    return db_path


@pytest.fixture()
def diag_db(tmp_path: Path) -> Path:
    return _make_diag_db(tmp_path)


# ---------------------------------------------------------------------------
# _json_int_tuple
# ---------------------------------------------------------------------------


def test_json_int_tuple_parses_int_list() -> None:
    assert _json_int_tuple("[1, 2, 3]") == (1, 2, 3)


def test_json_int_tuple_returns_empty_on_bad_json() -> None:
    assert _json_int_tuple("not json") == ()


def test_json_int_tuple_returns_empty_on_non_list_payload() -> None:
    assert _json_int_tuple('{"a": 1}') == ()


def test_json_int_tuple_skips_non_int_entries() -> None:
    assert _json_int_tuple('[1, "two", 3.5, 4]') == (1, 3, 4)


def test_json_int_tuple_handles_none() -> None:
    assert _json_int_tuple(None) == ()


# ---------------------------------------------------------------------------
# choose_fact_snapshot / choose_target_snapshot
# ---------------------------------------------------------------------------


def test_choose_fact_snapshot_prefers_glbopt1_pre_d810(diag_db: Path) -> None:
    conn = sqlite3.connect(str(diag_db))
    try:
        assert choose_fact_snapshot(conn) == 5
    finally:
        conn.close()


def test_choose_fact_snapshot_falls_back_to_any_snapshot_with_facts(
    tmp_path: Path,
) -> None:
    db = tmp_path / "x.sqlite3"
    conn = sqlite3.connect(str(db))
    try:
        conn.executescript(
            "CREATE TABLE snapshots(id INTEGER PRIMARY KEY, label TEXT,"
            " maturity TEXT, phase TEXT);"
            "CREATE TABLE fact_observations(snapshot_id INTEGER, fact_id TEXT,"
            " kind TEXT, payload TEXT, source_ea_hex TEXT, confidence REAL);"
            "INSERT INTO snapshots VALUES (8, 'late', 'MMAT_LVARS', 'post_d810');"
            "INSERT INTO fact_observations VALUES"
            " (8, 'f', 'TerminalByteEmitterFact', '{}', NULL, 0.0);"
        )
        conn.commit()
        assert choose_fact_snapshot(conn) == 8
    finally:
        conn.close()


def test_choose_fact_snapshot_raises_when_no_facts(tmp_path: Path) -> None:
    db = tmp_path / "empty.sqlite3"
    conn = sqlite3.connect(str(db))
    try:
        conn.executescript(
            "CREATE TABLE snapshots(id INTEGER PRIMARY KEY, label TEXT,"
            " maturity TEXT, phase TEXT);"
            "CREATE TABLE fact_observations(snapshot_id INTEGER, fact_id TEXT,"
            " kind TEXT, payload TEXT, source_ea_hex TEXT, confidence REAL);"
        )
        conn.commit()
        with pytest.raises(LookupError):
            choose_fact_snapshot(conn)
    finally:
        conn.close()


def test_choose_target_snapshot_prefers_post_bundle_stabilize(diag_db: Path) -> None:
    conn = sqlite3.connect(str(diag_db))
    try:
        assert choose_target_snapshot(conn) == 17
    finally:
        conn.close()


def test_choose_target_snapshot_falls_back_to_glbopt1_non_post_d810(
    tmp_path: Path,
) -> None:
    """No post_bundle_stabilize snapshot -- fall back to most recent
    MMAT_GLBOPT1 snapshot that isn't post_d810 or dump_raw_*."""
    db = tmp_path / "x.sqlite3"
    conn = sqlite3.connect(str(db))
    try:
        conn.executescript(
            "CREATE TABLE snapshots(id INTEGER PRIMARY KEY, label TEXT,"
            " maturity TEXT, phase TEXT);"
            "CREATE TABLE blocks(snapshot_id INTEGER, serial INTEGER,"
            " type_name TEXT, start_ea_hex TEXT, preds TEXT, succs TEXT);"
            "INSERT INTO snapshots VALUES"
            " (5, 'pre_d810', 'MMAT_GLBOPT1', 'pre_d810');"
            "INSERT INTO snapshots VALUES"
            " (7, 'dump_raw_lvars', 'MMAT_GLBOPT1', 'post_apply');"
            "INSERT INTO snapshots VALUES"
            " (8, 'something_else', 'MMAT_GLBOPT1', 'post_apply');"
            "INSERT INTO blocks VALUES (5, 0, 'BLT_NWAY', '0x100', '[]', '[]');"
            "INSERT INTO blocks VALUES (8, 0, 'BLT_NWAY', '0x100', '[]', '[]');"
        )
        conn.commit()
        assert choose_target_snapshot(conn) == 8
    finally:
        conn.close()


def test_choose_target_snapshot_raises_when_nothing_eligible(
    tmp_path: Path,
) -> None:
    db = tmp_path / "x.sqlite3"
    conn = sqlite3.connect(str(db))
    try:
        conn.executescript(
            "CREATE TABLE snapshots(id INTEGER PRIMARY KEY, label TEXT,"
            " maturity TEXT, phase TEXT);"
            "CREATE TABLE blocks(snapshot_id INTEGER, serial INTEGER,"
            " type_name TEXT, start_ea_hex TEXT, preds TEXT, succs TEXT);"
        )
        conn.commit()
        with pytest.raises(LookupError):
            choose_target_snapshot(conn)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# load_blocks
# ---------------------------------------------------------------------------


def test_load_blocks_attaches_opcodes_and_text(diag_db: Path) -> None:
    db = open_diag_database(str(diag_db))
    try:
        blocks = load_blocks(db.connection(), 17)
    finally:
        db.close()
    assert sorted(blocks) == [0, 10, 20, 30, 100]
    assert blocks[20].insn_opcodes == ("m_mov",)
    assert "var_8" in blocks[20].insn_text[0]
    assert blocks[100].type_name == "BLT_STOP"
    assert blocks[10].succs == (20, 30)
    assert blocks[10].preds == (0,)


def test_load_blocks_empty_when_snapshot_missing(diag_db: Path) -> None:
    db = open_diag_database(str(diag_db))
    try:
        assert load_blocks(db.connection(), 999) == {}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# load_sites
# ---------------------------------------------------------------------------


def test_load_sites_returns_one_per_terminal_byte_fact(diag_db: Path) -> None:
    db = open_diag_database(str(diag_db))
    try:
        sites = load_sites(db.connection(), 5)
    finally:
        db.close()
    by_byte = {s.byte_index: s for s in sites}
    assert sorted(by_byte) == [3, 6]
    assert by_byte[3].block_serial == 20
    assert by_byte[3].fact_id == "fact_byte_3"
    assert by_byte[3].source_ea_hex == "0x180014210"
    assert by_byte[3].confidence == pytest.approx(0.85)


def test_load_sites_skips_non_terminal_fact_kinds(diag_db: Path) -> None:
    db = open_diag_database(str(diag_db))
    try:
        sites = load_sites(db.connection(), 5)
    finally:
        db.close()
    # The LoopCarrierFact row we inserted must not appear.
    assert all("fact_byte_" in s.fact_id for s in sites)


def test_load_sites_skips_malformed_payload(tmp_path: Path) -> None:
    db_path = tmp_path / "bad.sqlite3"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(
            "CREATE TABLE fact_observations(snapshot_id INTEGER,"
            " fact_id TEXT, kind TEXT, payload TEXT,"
            " source_ea_hex TEXT, confidence REAL);"
        )
        conn.execute(
            "INSERT INTO fact_observations VALUES (?,?,?,?,?,?)",
            (5, "bad", "TerminalByteEmitterFact", "{not json", None, 0.0),
        )
        conn.execute(
            "INSERT INTO fact_observations VALUES (?,?,?,?,?,?)",
            (5, "non_dict", "TerminalByteEmitterFact", "[1,2,3]", None, 0.0),
        )
        conn.commit()
    finally:
        conn.close()
    db = open_diag_database(str(db_path))
    try:
        sites = load_sites(db.connection(), 5)
    finally:
        db.close()
    assert sites == []


# ---------------------------------------------------------------------------
# run_plan
# ---------------------------------------------------------------------------


def test_run_plan_emits_snapshot_headers(diag_db: Path) -> None:
    out = run_plan(diag_db)
    assert "# fact snapshot: 5" in out
    assert "# target snapshot: 17" in out


def test_run_plan_returns_error_when_db_missing(tmp_path: Path) -> None:
    out = run_plan(tmp_path / "nope.sqlite3")
    assert out.startswith("Error: diag DB not found")


def test_run_plan_returns_error_when_no_facts(tmp_path: Path) -> None:
    db = tmp_path / "no_facts.sqlite3"
    conn = sqlite3.connect(str(db))
    try:
        conn.executescript(
            "CREATE TABLE snapshots(id INTEGER PRIMARY KEY, label TEXT,"
            " maturity TEXT, phase TEXT);"
            "CREATE TABLE blocks(snapshot_id INTEGER, serial INTEGER,"
            " type_name TEXT, start_ea_hex TEXT, preds TEXT, succs TEXT);"
            "CREATE TABLE fact_observations(snapshot_id INTEGER, fact_id TEXT,"
            " kind TEXT, payload TEXT, source_ea_hex TEXT, confidence REAL);"
            "CREATE TABLE instructions(snapshot_id INTEGER, block_serial INTEGER,"
            " insn_index INTEGER, opcode_name TEXT, dstr TEXT);"
        )
        conn.commit()
    finally:
        conn.close()
    out = run_plan(db)
    assert "Error:" in out
    assert "TerminalByteEmitterFact" in out


def test_run_plan_explicit_snapshots_honoured(diag_db: Path) -> None:
    out = run_plan(diag_db, fact_snapshot_id=5, target_snapshot_id=17)
    assert "# fact snapshot: 5" in out
    assert "# target snapshot: 17" in out


def test_run_plan_renders_planner_body(diag_db: Path) -> None:
    """The cfg-layer ``format_cascade_egress_plan`` body should follow the
    header lines. We just sanity-check the markdown table header is there
    -- the cfg-layer module owns the precise format."""
    out = run_plan(diag_db)
    # format_cascade_egress_plan emits a markdown table with a byte column.
    assert "byte" in out.lower()
