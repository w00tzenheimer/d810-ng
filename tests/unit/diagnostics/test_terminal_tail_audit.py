"""Tests for the terminal-tail audit diag subcommand."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from d810.core.diag import diag_models_on, open_diag_database
from d810.core.diag.models import Block, FactObservation, Snapshot
from d810.diagnostics.terminal_tail_audit import (
    build_block_lookup,
    build_fact_lookup,
    build_initial_states_at_snap,
    glbopt1_snapshots,
    iter_observations,
    run_audit,
)

# ---------------------------------------------------------------------------
# Fixture: a minimal diag DB shaped enough to exercise each helper.
# ---------------------------------------------------------------------------


def _make_diag_db(tmp_path: Path) -> Path:
    """Build a minimal diag SQLite with two GLBOPT1 snapshots (pre_d810 and
    post_bundle_stabilize) and three byte-emit facts at byte_index 2,3,6
    that survive into the second snapshot."""
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
            dict(snapshot=5,  serial=56,  block_type=1, type_name="BLT_1WAY", start_ea_hex="0x180014C00", start_ea_i64=0, end_ea_hex=None, end_ea_i64=None, nsucc=1, npred=1, succs="[]", preds="[]", insn_count=3),
            dict(snapshot=5,  serial=163, block_type=2, type_name="BLT_2WAY", start_ea_hex="0x180014D00", start_ea_i64=0, end_ea_hex=None, end_ea_i64=None, nsucc=2, npred=2, succs="[]", preds="[]", insn_count=5),
            dict(snapshot=5,  serial=217, block_type=1, type_name="BLT_1WAY", start_ea_hex="0x180014E00", start_ea_i64=0, end_ea_hex=None, end_ea_i64=None, nsucc=1, npred=1, succs="[]", preds="[]", insn_count=4),
            dict(snapshot=17, serial=56,  block_type=1, type_name="BLT_1WAY", start_ea_hex="0x180014C00", start_ea_i64=0, end_ea_hex=None, end_ea_i64=None, nsucc=1, npred=1, succs="[]", preds="[]", insn_count=3),
            dict(snapshot=17, serial=163, block_type=2, type_name="BLT_2WAY", start_ea_hex="0x180014D00", start_ea_i64=0, end_ea_hex=None, end_ea_i64=None, nsucc=2, npred=2, succs="[]", preds="[]", insn_count=5),
        ]).execute()
        # byte 2 fact at snap 5
        FactObservation.insert(
            snapshot=5, func_ea_hex="0x0", func_ea_i64=0,
            fact_id="1", kind="TerminalByteEmitterFact",
            semantic_key="byte_emit_2", maturity="MMAT_GLBOPT1", phase="pre_d810",
            confidence=1.0, payload=json.dumps({
                "byte_index": 2,
                "block_serial": 56,
                "corridor_role": "terminal_tail",
                "source_byte_expression": "xdu([ds.2:%var_190.8+#2.8].1)",
                "destination_buffer_expression": "[ds.2:.+%var_188.8]",
                "counter_carrier": "var_178",
                "block_ea_hex": "0x180014C00",
            }), evidence="{}",
        ).execute()
        # byte 3 fact at snap 5
        FactObservation.insert(
            snapshot=5, func_ea_hex="0x0", func_ea_i64=0,
            fact_id="2", kind="TerminalByteEmitterFact",
            semantic_key="byte_emit_3", maturity="MMAT_GLBOPT1", phase="pre_d810",
            confidence=1.0, payload=json.dumps({
                "byte_index": 3,
                "block_serial": 163,
                "corridor_role": "terminal_tail",
                "source_byte_expression": "xdu([ds.2:%var_190.8+#3.8].1)",
                "destination_buffer_expression": "[ds.2:.+%var_188.8]",
                "counter_carrier": "var_178",
                "block_ea_hex": "0x180014D00",
            }), evidence="{}",
        ).execute()
        # byte 3 fact at snap 17 (survives bundle stabilize)
        FactObservation.insert(
            snapshot=17, func_ea_hex="0x0", func_ea_i64=0,
            fact_id="3", kind="TerminalByteEmitterFact",
            semantic_key="byte_emit_3", maturity="MMAT_GLBOPT1", phase="post_apply",
            confidence=1.0, payload=json.dumps({
                "byte_index": 3,
                "block_serial": 163,
                "corridor_role": "terminal_tail",
                "source_byte_expression": "xdu([ds.2:%var_190.8+#3.8].1)",
                "destination_buffer_expression": "[ds.2:.+%var_188.8]",
                "counter_carrier": "var_178",
                "block_ea_hex": "0x180014D00",
            }), evidence="{}",
        ).execute()
        # byte 6 fact at snap 5 only (lost at snap 17 in our fixture)
        FactObservation.insert(
            snapshot=5, func_ea_hex="0x0", func_ea_i64=0,
            fact_id="4", kind="TerminalByteEmitterFact",
            semantic_key="byte_emit_6", maturity="MMAT_GLBOPT1", phase="pre_d810",
            confidence=1.0, payload=json.dumps({
                "byte_index": 6,
                "block_serial": 217,
                "corridor_role": "terminal_tail",
                "source_byte_expression": "xdu([ds.2:%var_190.8+#6.8].1)",
                "destination_buffer_expression": "[ds.2:.+%var_188.8]",
                "counter_carrier": "var_178",
                "block_ea_hex": "0x180014E00",
            }), evidence="{}",
        ).execute()
        # An unrelated fact that should NOT show up in the audit.
        FactObservation.insert(
            snapshot=5, func_ea_hex="0x0", func_ea_i64=0,
            fact_id="5", kind="LoopCarrierFact",
            semantic_key="loop_carrier", maturity="MMAT_GLBOPT1", phase="pre_d810",
            confidence=1.0, payload=json.dumps({"some_field": "ignored"}),
            evidence="{}",
        ).execute()
        db_obj.connection().commit()
    db_obj.close()
    return db_path


@pytest.fixture()
def diag_db(tmp_path: Path) -> Path:
    return _make_diag_db(tmp_path)


# ---------------------------------------------------------------------------
# iter_observations
# ---------------------------------------------------------------------------


def test_iter_observations_returns_only_terminal_byte_emitter_rows(diag_db: Path) -> None:
    db = open_diag_database(str(diag_db))
    try:
        obs = iter_observations(db.connection())
    finally:
        db.close()
    byte_indices = sorted({o.byte_index for o in obs})
    assert byte_indices == [2, 3, 6]
    # Bytes 2 and 6 only appear at snap 5; byte 3 appears at snap 5 and snap 17.
    by_snap = sorted({(o.snapshot_id, o.byte_index) for o in obs})
    assert by_snap == [(5, 2), (5, 3), (5, 6), (17, 3)]


def test_iter_observations_carries_label_and_phase(diag_db: Path) -> None:
    db = open_diag_database(str(diag_db))
    try:
        obs = iter_observations(db.connection())
    finally:
        db.close()
    snap_5 = next(o for o in obs if o.snapshot_id == 5 and o.byte_index == 3)
    assert snap_5.maturity == "MMAT_GLBOPT1"
    assert snap_5.phase == "pre_d810"
    assert snap_5.label == "pre_d810"
    assert snap_5.corridor_role == "terminal_tail"


def test_iter_observations_skips_rows_without_block_serial(tmp_path: Path) -> None:
    db_path = tmp_path / "no_block.sqlite3"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(
            """
            CREATE TABLE snapshots(id INTEGER PRIMARY KEY, label TEXT,
                maturity TEXT, phase TEXT);
            CREATE TABLE fact_observations(snapshot_id INTEGER, fact_id INTEGER,
                kind TEXT, maturity TEXT, phase TEXT, payload TEXT);
            INSERT INTO snapshots VALUES (5, 'pre_d810', 'MMAT_GLBOPT1', 'pre_d810');
            """
        )
        conn.execute(
            "INSERT INTO fact_observations VALUES (?, ?, ?, ?, ?, ?)",
            (5, 1, "TerminalByteEmitterFact", "MMAT_GLBOPT1", "pre_d810",
             json.dumps({"byte_index": 2})),  # no block_serial
        )
        conn.commit()
    finally:
        conn.close()
    db = open_diag_database(str(db_path))
    try:
        obs = iter_observations(db.connection())
    finally:
        db.close()
    assert obs == []


def test_iter_observations_skips_malformed_payload(tmp_path: Path) -> None:
    db_path = tmp_path / "bad_json.sqlite3"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(
            """
            CREATE TABLE snapshots(id INTEGER PRIMARY KEY, label TEXT,
                maturity TEXT, phase TEXT);
            CREATE TABLE fact_observations(snapshot_id INTEGER, fact_id INTEGER,
                kind TEXT, maturity TEXT, phase TEXT, payload TEXT);
            INSERT INTO snapshots VALUES (5, 'pre_d810', 'MMAT_GLBOPT1', 'pre_d810');
            INSERT INTO fact_observations VALUES
                (5, 1, 'TerminalByteEmitterFact', 'MMAT_GLBOPT1', 'pre_d810',
                 '{bad json');
            """
        )
        conn.commit()
    finally:
        conn.close()
    db = open_diag_database(str(db_path))
    try:
        assert iter_observations(db.connection()) == []
    finally:
        db.close()


# ---------------------------------------------------------------------------
# build_initial_states_at_snap
# ---------------------------------------------------------------------------


def test_build_initial_states_pairs_byte_index_with_block_start_ea(
    diag_db: Path,
) -> None:
    db = open_diag_database(str(diag_db))
    try:
        states = build_initial_states_at_snap(db.connection(), 5)
    finally:
        db.close()
    by_byte = {s.byte_index: s for s in states}
    assert set(by_byte) == {2, 3, 6}
    assert by_byte[3].block_serial == 163
    assert by_byte[3].start_ea_hex == "0x180014D00"


def test_build_initial_states_skips_when_block_row_missing(tmp_path: Path) -> None:
    db_path = tmp_path / "no_block_row.sqlite3"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(
            """
            CREATE TABLE snapshots(id INTEGER PRIMARY KEY, label TEXT,
                maturity TEXT, phase TEXT);
            CREATE TABLE blocks(snapshot_id INTEGER, serial INTEGER,
                start_ea_hex TEXT, npred INTEGER, nsucc INTEGER,
                insn_count INTEGER);
            CREATE TABLE fact_observations(snapshot_id INTEGER, fact_id INTEGER,
                kind TEXT, maturity TEXT, phase TEXT, payload TEXT);
            INSERT INTO snapshots VALUES (5, 'pre_d810', 'MMAT_GLBOPT1', 'pre_d810');
            """
        )
        conn.execute(
            "INSERT INTO fact_observations VALUES (?, ?, ?, ?, ?, ?)",
            (5, 1, "TerminalByteEmitterFact", "MMAT_GLBOPT1", "pre_d810",
             json.dumps({
                 "byte_index": 3,
                 "block_serial": 999,
                 "corridor_role": "terminal_tail",
             })),
        )
        conn.commit()
    finally:
        conn.close()
    db = open_diag_database(str(db_path))
    try:
        states = build_initial_states_at_snap(db.connection(), 5)
    finally:
        db.close()
    assert states == []


# ---------------------------------------------------------------------------
# build_block_lookup
# ---------------------------------------------------------------------------


def test_build_block_lookup_keys_by_snap_and_ea(diag_db: Path) -> None:
    db = open_diag_database(str(diag_db))
    try:
        lookup = build_block_lookup(db.connection(), [5, 17])
    finally:
        db.close()
    assert (5, "0x180014C00") in lookup
    assert lookup[(5, "0x180014C00")] == (56, 1, 1, 3)
    assert (17, "0x180014C00") in lookup
    # Lookup for byte-6's block at snap 17 should be absent (we did not
    # insert a block row for serial 217 at snap 17).
    assert (17, "0x180014E00") not in lookup


def test_build_block_lookup_empty_input_returns_empty(diag_db: Path) -> None:
    db = open_diag_database(str(diag_db))
    try:
        assert build_block_lookup(db.connection(), []) == {}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# glbopt1_snapshots
# ---------------------------------------------------------------------------


def test_glbopt1_snapshots_skips_dump_raw_and_blockless(diag_db: Path) -> None:
    # Insert the extra snapshots via ORM, then inspect read-only via
    # open_diag_database (glbopt1_snapshots stays raw SQL).
    extra_db = open_diag_database(str(diag_db))
    with diag_models_on(extra_db):
        # Add a blockless GLBOPT1 snapshot that the helper must skip.
        Snapshot.insert(
            id=10, label="state_write_reconstruction_dag",
            func_ea_hex="0x0", func_ea_i64=0,
            maturity="MMAT_GLBOPT1", phase="unknown",
            block_count=0, timestamp=0.0,
        ).execute()
        # Add a dump_raw GLBOPT1 snapshot that the helper must skip.
        Snapshot.insert(
            id=50, label="dump_raw_lvars_after",
            func_ea_hex="0x0", func_ea_i64=0,
            maturity="MMAT_GLBOPT1", phase="post_apply",
            block_count=0, timestamp=0.0,
        ).execute()
        extra_db.connection().commit()
    snaps = glbopt1_snapshots(extra_db.connection())
    extra_db.close()
    ids = [s for s, _, _ in snaps]
    assert ids == [5, 17]


# ---------------------------------------------------------------------------
# build_fact_lookup
# ---------------------------------------------------------------------------


def test_build_fact_lookup_marks_snapshot_byte_pairs(diag_db: Path) -> None:
    db = open_diag_database(str(diag_db))
    try:
        lookup = build_fact_lookup(db.connection(), [5, 17])
    finally:
        db.close()
    assert lookup.get((5, 2)) is True
    assert lookup.get((5, 3)) is True
    assert lookup.get((5, 6)) is True
    assert lookup.get((17, 3)) is True
    # Byte 6 was not re-captured at snap 17.
    assert (17, 6) not in lookup


# ---------------------------------------------------------------------------
# run_audit (end-to-end)
# ---------------------------------------------------------------------------


def test_run_audit_returns_no_facts_message_when_db_empty(tmp_path: Path) -> None:
    db = tmp_path / "empty.sqlite3"
    conn = sqlite3.connect(str(db))
    try:
        conn.executescript(
            "CREATE TABLE fact_observations(snapshot_id INTEGER, fact_id INTEGER,"
            " kind TEXT, maturity TEXT, phase TEXT, payload TEXT);"
            "CREATE TABLE snapshots(id INTEGER PRIMARY KEY, label TEXT,"
            " maturity TEXT, phase TEXT);"
        )
        conn.commit()
    finally:
        conn.close()
    out = run_audit(db)
    assert "No TerminalByteEmitterFact rows" in out


def test_run_audit_renders_timeline_report(diag_db: Path) -> None:
    out = run_audit(diag_db)
    assert "byte" in out.lower()
    # All three captured bytes should appear in the timeline output.
    assert "2" in out and "3" in out and "6" in out


def test_run_audit_with_show_edges_dumps_per_observation_detail(
    diag_db: Path,
) -> None:
    out = run_audit(diag_db, show_edges=True)
    assert "Per-observation detail" in out
    # We expect at least one detail line for each of the 4 observation rows.
    detail_lines = [line for line in out.splitlines() if " snap=" in line]
    assert len(detail_lines) == 4


def test_run_audit_with_localize_includes_localization_section(
    diag_db: Path,
) -> None:
    out = run_audit(diag_db, localize=True)
    # localize_byte_emit_loss renders a header, which we just sanity-check
    # for inclusion -- the cfg-layer module owns the precise format.
    assert "byte" in out.lower()
    # The localization section appears after the timeline; ensure the output
    # is non-empty beyond the timeline header.
    assert len(out.splitlines()) > 6
