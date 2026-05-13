"""Unit tests for python -m d810.diagnostics region-* subcommands."""
from __future__ import annotations

import sqlite3

import pytest

from d810.diagnostics.__main__ import _resolve_oracle_snap_ids


def _make_conn_with_snaps(snaps: list[tuple[int, str]]) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE snapshots (id INTEGER PRIMARY KEY, label TEXT NOT NULL)"
    )
    conn.executemany("INSERT INTO snapshots (id, label) VALUES (?, ?)", snaps)
    conn.commit()
    return conn


def test_resolver_picks_highest_id_for_primary_label():
    conn = _make_conn_with_snaps([
        (3, "post_bundle_stabilize"),
        (5, "post_bundle_stabilize"),
        (4, "post_pipeline"),
        (10, "GLBOPT1_post_d810"),
    ])
    snap17, snap18 = _resolve_oracle_snap_ids(
        conn,
        snap17_labels=("post_bundle_stabilize", "post_pipeline"),
        snap18_labels=("GLBOPT1_post_d810",),
    )
    assert snap17 == 5
    assert snap18 == 10


def test_resolver_falls_back_through_label_list():
    conn = _make_conn_with_snaps([
        (4, "post_pipeline"),
        (10, "post_d810"),
    ])
    snap17, snap18 = _resolve_oracle_snap_ids(
        conn,
        snap17_labels=("post_bundle_stabilize", "post_pipeline"),
        snap18_labels=("maturity_MMAT_GLBOPT1_post_d810", "GLBOPT1_post_d810", "post_d810"),
    )
    assert snap17 == 4
    assert snap18 == 10


def test_resolver_returns_none_when_unresolvable():
    conn = _make_conn_with_snaps([(1, "irrelevant")])
    snap17, snap18 = _resolve_oracle_snap_ids(
        conn,
        snap17_labels=("post_bundle_stabilize",),
        snap18_labels=("GLBOPT1_post_d810",),
    )
    assert snap17 is None
    assert snap18 is None


def test_resolver_returns_partial_results():
    conn = _make_conn_with_snaps([(7, "post_pipeline")])
    snap17, snap18 = _resolve_oracle_snap_ids(
        conn,
        snap17_labels=("post_bundle_stabilize", "post_pipeline"),
        snap18_labels=("GLBOPT1_post_d810",),
    )
    assert snap17 == 7
    assert snap18 is None


def test_resolver_picks_snap17_strictly_before_snap18():
    """Multi-round case: post_bundle_stabilize appears twice, but only
    the round-1 copy (id=17) is BEFORE the post_d810 capture (id=18).
    The round-2 replay (id=27) must NOT be selected."""
    conn = _make_conn_with_snaps([
        (17, "post_bundle_stabilize"),
        (18, "GLBOPT1_post_d810"),
        (27, "post_bundle_stabilize"),  # round-2 replay AFTER snap18
    ])
    snap17, snap18 = _resolve_oracle_snap_ids(
        conn,
        snap17_labels=("post_bundle_stabilize",),
        snap18_labels=("GLBOPT1_post_d810",),
    )
    assert snap18 == 18
    assert snap17 == 17  # not 27


def test_region_shape_subcommand_lists_persisted_features(tmp_path):
    """Subprocess: python -m d810.diagnostics region-shape lists rows."""
    import json
    import os
    import subprocess
    import sys
    from d810.core.diag.schema import create_tables

    db_path = tmp_path / "test.diag.sqlite3"
    conn = sqlite3.connect(str(db_path))
    create_tables(conn)
    conn.execute(
        "INSERT INTO region_shape_features "
        "(func_ea_hex, func_ea_i64, snapshot_id, source, region, "
        " feature, value_text, evidence_json) VALUES "
        "(?, ?, ?, ?, ?, ?, ?, ?)",
        ("0x0000000180012df0", 0x180012df0, 17, "D810_SNAPSHOT",
         "terminal_tail", "byte_emit_3_present", "True",
         json.dumps({"side": "d810", "block_serial": 161})),
    )
    conn.commit()
    conn.close()

    env = {**os.environ, "PYTHONPATH": "src"}
    result = subprocess.run(
        [sys.executable, "-m", "d810.diagnostics", "region-shape",
         "--db", str(db_path), "--func-ea", "0x0000000180012df0"],
        capture_output=True, text=True, env=env,
    )
    assert result.returncode == 0, result.stderr
    assert "byte_emit_3_present" in result.stdout
    assert "D810_SNAPSHOT" in result.stdout


def test_region_shape_subcommand_filters_by_source_and_snapshot_id(tmp_path):
    import json
    import os
    import subprocess
    import sys
    from d810.core.diag.schema import create_tables

    db_path = tmp_path / "test.diag.sqlite3"
    conn = sqlite3.connect(str(db_path))
    create_tables(conn)
    rows = [
        (None, "REF", "ref_feat_1"),
        (17, "D810_SNAPSHOT", "snap17_feat_1"),
        (18, "D810_SNAPSHOT", "snap18_feat_1"),
    ]
    for snap_id, source, feature in rows:
        conn.execute(
            "INSERT INTO region_shape_features "
            "(func_ea_hex, func_ea_i64, snapshot_id, source, region, "
            " feature, value_text, evidence_json) VALUES "
            "(?, ?, ?, ?, ?, ?, ?, ?)",
            ("0x0000000180012df0", 0x180012df0, snap_id, source,
             "terminal_tail", feature, "True", json.dumps({})),
        )
    conn.commit()
    conn.close()

    env = {**os.environ, "PYTHONPATH": "src"}

    # Filter by source.
    r = subprocess.run(
        [sys.executable, "-m", "d810.diagnostics", "region-shape",
         "--db", str(db_path), "--func-ea", "0x0000000180012df0",
         "--source", "REF"],
        capture_output=True, text=True, env=env,
    )
    assert r.returncode == 0, r.stderr
    assert "ref_feat_1" in r.stdout
    assert "snap17_feat_1" not in r.stdout

    # Filter by snapshot_id.
    r = subprocess.run(
        [sys.executable, "-m", "d810.diagnostics", "region-shape",
         "--db", str(db_path), "--func-ea", "0x0000000180012df0",
         "--snapshot-id", "17"],
        capture_output=True, text=True, env=env,
    )
    assert r.returncode == 0, r.stderr
    assert "snap17_feat_1" in r.stdout
    assert "ref_feat_1" not in r.stdout

    # JSON output.
    r = subprocess.run(
        [sys.executable, "-m", "d810.diagnostics", "region-shape",
         "--db", str(db_path), "--func-ea", "0x0000000180012df0",
         "--json"],
        capture_output=True, text=True, env=env,
    )
    assert r.returncode == 0, r.stderr
    payload = json.loads(r.stdout)
    assert isinstance(payload, list)
    assert len(payload) == 3


def test_region_diff_happy_path_writes_artifact(tmp_path):
    """End-to-end: subprocess `python -m d810.diagnostics region-diff`."""
    import os
    import subprocess
    import sys
    from d810.core.diag.schema import create_tables

    db = tmp_path / "live.diag.sqlite3"
    conn = sqlite3.connect(str(db))
    create_tables(conn)
    # snapshots row needs all NOT NULL columns:
    # id, label, func_ea_hex, func_ea_i64, maturity, phase, block_count, timestamp.
    for snap_id, label in (
        (17, "post_bundle_stabilize"),
        (18, "GLBOPT1_post_d810"),
    ):
        conn.execute(
            "INSERT INTO snapshots (id, label, func_ea_hex, func_ea_i64, "
            " maturity, phase, block_count, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (snap_id, label, "0x0000000180012df0", 0x180012df0,
             "MMAT_GLBOPT1", "post_d810", 5, 0.0),
        )
    conn.commit()
    conn.close()

    out = tmp_path / "test.oracle.md"
    env = {**os.environ, "PYTHONPATH": "src"}
    result = subprocess.run(
        [sys.executable, "-m", "d810.diagnostics", "region-diff",
         "--db", str(db), "--func-ea", "0x0000000180012df0",
         "--persist", "--output", str(out)],
        capture_output=True, text=True, env=env,
    )
    assert result.returncode == 0, result.stderr
    assert out.exists()
    body = out.read_text()
    assert "Region Oracle" in body
    assert f"oracle written: {out}" in result.stdout


def test_terminal_tail_dce_subcommand_lists_persisted_causes(tmp_path):
    """Subprocess: python -m d810.diagnostics terminal-tail-dce."""
    import json, os, sys, subprocess
    from d810.core.diag.schema import create_tables

    db = tmp_path / "test.diag.sqlite3"
    conn = sqlite3.connect(str(db))
    create_tables(conn)
    conn.execute(
        "INSERT INTO terminal_tail_dce_causes "
        "(func_ea_hex, func_ea_i64, byte_index, last_present_snapshot_id, "
        " first_missing_snapshot_id, last_block_serial, last_ea_hex, "
        " cause, recommended_action, rationale, evidence_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("0x0000000180012df0", 0x180012df0, 3, 17, 18, 161,
         "0x0000000180012df0", "FOLDED_INTO_SURVIVING_BYTE_EMIT",
         "STRUCTURER_SHAPING", "tail-equivalent fold",
         json.dumps({"side": "d810"})),
    )
    conn.commit()
    conn.close()

    env = {**os.environ, "PYTHONPATH": "src"}
    result = subprocess.run(
        [sys.executable, "-m", "d810.diagnostics", "terminal-tail-dce",
         "--db", str(db), "--func-ea", "0x0000000180012df0"],
        capture_output=True, text=True, env=env,
    )
    assert result.returncode == 0
    assert "FOLDED_INTO_SURVIVING_BYTE_EMIT" in result.stdout
    assert "byte_index" in result.stdout.lower()


def test_terminal_tail_dce_subcommand_filters_by_byte_index(tmp_path):
    import json, os, sys, subprocess
    from d810.core.diag.schema import create_tables

    db = tmp_path / "test.diag.sqlite3"
    conn = sqlite3.connect(str(db))
    create_tables(conn)
    for byte_index, cause in (
        (2, "FOLDED_INTO_SURVIVING_BYTE_EMIT"),
        (3, "DCE_DEAD_WRITE"),
    ):
        conn.execute(
            "INSERT INTO terminal_tail_dce_causes "
            "(func_ea_hex, func_ea_i64, byte_index, "
            " last_present_snapshot_id, first_missing_snapshot_id, "
            " last_block_serial, last_ea_hex, cause, "
            " recommended_action, rationale, evidence_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("0x0000000180012df0", 0x180012df0, byte_index, 17, 18,
             100 + byte_index, "0x0", cause,
             "STRUCTURER_SHAPING", "...",
             json.dumps({})),
        )
    conn.commit()
    conn.close()

    env = {**os.environ, "PYTHONPATH": "src"}
    result = subprocess.run(
        [sys.executable, "-m", "d810.diagnostics", "terminal-tail-dce",
         "--db", str(db), "--func-ea", "0x0000000180012df0",
         "--byte-index", "2"],
        capture_output=True, text=True, env=env,
    )
    assert result.returncode == 0
    assert "FOLDED_INTO_SURVIVING_BYTE_EMIT" in result.stdout
    assert "DCE_DEAD_WRITE" not in result.stdout


def test_region_diff_emits_real_d810_feature_values(tmp_path):
    """Re-running region-diff against a populated diag DB must NOT
    produce all-False D810 columns. byte_emit_<k>_present should reflect
    actual TerminalByteEmitterFact rows.
    """
    import json as _json, os, sqlite3 as _sql, sys, subprocess
    from d810.core.diag.schema import create_tables

    db = tmp_path / "real.diag.sqlite3"
    conn = _sql.connect(str(db))
    create_tables(conn)
    # Two snapshots: snap17 has byte_emit fact rows, snap18 has none.
    for snap_id, label in (
        (17, "post_bundle_stabilize"),
        (18, "GLBOPT1_post_d810"),
    ):
        conn.execute(
            "INSERT INTO snapshots (id, label, func_ea_hex, func_ea_i64, "
            " maturity, phase, block_count, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (snap_id, label, "0x0000000180012df0", 0x180012df0,
             "MMAT_GLBOPT1", "post_d810", 1, 0.0),
        )

    # Insert one byte_emit fact at snap17 for byte_index=3.
    conn.execute(
        "INSERT INTO fact_observations "
        "(snapshot_id, func_ea_hex, func_ea_i64, fact_id, kind, "
        " semantic_key, maturity, phase, confidence, payload, evidence) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (17, "0x0000000180012df0", 0x180012df0, "1",
         "TerminalByteEmitterFact", "byte_3", "MMAT_GLBOPT1",
         "post_bundle_stabilize", 1.0,
         _json.dumps({"byte_index": 3, "block_serial": 161,
                      "corridor_role": "terminal_tail"}),
         "{}"),
    )
    # Insert the matching block at snap17.
    conn.execute(
        "INSERT INTO blocks (snapshot_id, serial, block_type, type_name, "
        " start_ea_hex, start_ea_i64, npred, nsucc, preds, succs, "
        " insn_count) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (17, 161, 1, "BLT_1WAY", "0x0000000180012df0", 0x180012df0,
         0, 1, "[]", "[218]", 0),
    )
    conn.commit()
    conn.close()

    out = tmp_path / "real.oracle.md"
    env = {**os.environ, "PYTHONPATH": "src"}
    result = subprocess.run(
        [sys.executable, "-m", "d810.diagnostics", "region-diff",
         "--db", str(db), "--func-ea", "0x0000000180012df0",
         "--persist", "--output", str(out), "--json"],
        capture_output=True, text=True, env=env,
    )
    assert result.returncode == 0, result.stderr
    payload = _json.loads(out.read_text())

    # snap17: byte_emit_3_present must be True (we populated the fact).
    s17_byte3 = next(
        (f for f in payload["snap17_features"]
         if f["feature"] == "byte_emit_3_present"),
        None,
    )
    assert s17_byte3 is not None, "byte_emit_3_present row missing for snap17"
    assert s17_byte3["value"] in (True, "True"), (
        f"snap17.byte_emit_3_present should be truthy, got {s17_byte3['value']!r}"
    )

    # snap18: same byte should be False (no fact row at snap18).
    s18_byte3 = next(
        (f for f in payload["snap18_features"]
         if f["feature"] == "byte_emit_3_present"),
        None,
    )
    assert s18_byte3 is not None
    assert s18_byte3["value"] in (False, "False"), (
        f"snap18.byte_emit_3_present should be falsy, got {s18_byte3['value']!r}"
    )

    # Verify DCE rows persisted.
    conn = _sql.connect(str(db))
    n = conn.execute(
        "SELECT COUNT(*) FROM terminal_tail_dce_causes"
    ).fetchone()[0]
    conn.close()
    assert n > 0, "DCE causes should be persisted by --persist"


def test_region_diff_microblocks_evidence_includes_block_serial(tmp_path):
    """With --microblocks the evidence for byte_emit_3_present must carry
    the witness block_serial (161) computed from the populated snapshot.
    """
    import json as _json, os, sqlite3 as _sql, sys, subprocess
    from d810.core.diag.schema import create_tables

    db = tmp_path / "real.diag.sqlite3"
    conn = _sql.connect(str(db))
    create_tables(conn)
    for snap_id, label in (
        (17, "post_bundle_stabilize"),
        (18, "GLBOPT1_post_d810"),
    ):
        conn.execute(
            "INSERT INTO snapshots (id, label, func_ea_hex, func_ea_i64, "
            " maturity, phase, block_count, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (snap_id, label, "0x0000000180012df0", 0x180012df0,
             "MMAT_GLBOPT1", "post_d810", 1, 0.0),
        )
    conn.execute(
        "INSERT INTO fact_observations "
        "(snapshot_id, func_ea_hex, func_ea_i64, fact_id, kind, "
        " semantic_key, maturity, phase, confidence, payload, evidence) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (17, "0x0000000180012df0", 0x180012df0, "1",
         "TerminalByteEmitterFact", "byte_3", "MMAT_GLBOPT1",
         "post_bundle_stabilize", 1.0,
         _json.dumps({"byte_index": 3, "block_serial": 161,
                      "corridor_role": "terminal_tail"}),
         "{}"),
    )
    conn.execute(
        "INSERT INTO blocks (snapshot_id, serial, block_type, type_name, "
        " start_ea_hex, start_ea_i64, npred, nsucc, preds, succs, "
        " insn_count) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (17, 161, 1, "BLT_1WAY", "0x0000000180012df0", 0x180012df0,
         0, 1, "[]", "[218]", 0),
    )
    conn.commit()
    conn.close()

    out = tmp_path / "evidence.oracle.md"
    env = {**os.environ, "PYTHONPATH": "src"}
    result = subprocess.run(
        [sys.executable, "-m", "d810.diagnostics", "region-diff",
         "--db", str(db), "--func-ea", "0x0000000180012df0",
         "--microblocks", "--output", str(out)],
        capture_output=True, text=True, env=env,
    )
    assert result.returncode == 0, result.stderr
    body = out.read_text()
    assert "## Microblock Evidence" in body
    # snap17 byte_emit_3 evidence should mention the witness block_serial.
    assert "161" in body, "Microblock evidence should reference witness serial"


def test_region_diff_survival_detects_byte_emit_block_at_snap17(tmp_path):
    """byte_emit_<k>_present should be True at snap17 if the byte_emit
    BLOCK survived from snap5 to snap17, even if the fact only fires at
    snap5 (pre_d810).
    """
    import json as _json, os, sqlite3 as _sql, sys, subprocess
    from d810.core.diag.schema import create_tables

    db = tmp_path / "real.diag.sqlite3"
    conn = _sql.connect(str(db))
    create_tables(conn)

    def _ins_snap(snap_id, label):
        conn.execute(
            "INSERT INTO snapshots (id, label, func_ea_hex, func_ea_i64, "
            " maturity, phase, block_count, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (snap_id, label, "0x0000000180012df0", 0x180012df0,
             "MMAT_GLBOPT1", "post_d810", 1, 0.0),
        )

    _ins_snap(5, "maturity_MMAT_GLBOPT1_pre_d810")
    _ins_snap(17, "post_bundle_stabilize")
    _ins_snap(18, "GLBOPT1_post_d810")

    # Fact at snap5 only.
    conn.execute(
        "INSERT INTO fact_observations "
        "(snapshot_id, func_ea_hex, func_ea_i64, fact_id, kind, "
        " semantic_key, maturity, phase, confidence, payload, evidence) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (5, "0x0000000180012df0", 0x180012df0, "tbe_3_snap5",
         "TerminalByteEmitterFact", "byte_emit_3", "MMAT_GLBOPT1",
         "pre_d810", 1.0,
         _json.dumps({"byte_index": 3, "block_serial": 161,
                      "corridor_role": "terminal_tail"}),
         _json.dumps({})),
    )
    # snap5 block at start_ea 0x180012df0
    conn.execute(
        "INSERT INTO blocks (snapshot_id, serial, block_type, type_name, "
        " start_ea_hex, start_ea_i64, end_ea_hex, end_ea_i64, "
        " npred, nsucc, preds, succs, insn_count) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (5, 161, 1, "BLT_1WAY", "0x0000000180012df0", 0x180012df0,
         "0x0000000180012e00", 0x180012e00, 0, 1, "[]", "[218]", 3),
    )
    # snap17 block at SAME start_ea (survived) but different serial
    conn.execute(
        "INSERT INTO blocks (snapshot_id, serial, block_type, type_name, "
        " start_ea_hex, start_ea_i64, end_ea_hex, end_ea_i64, "
        " npred, nsucc, preds, succs, insn_count) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (17, 200, 1, "BLT_1WAY", "0x0000000180012df0", 0x180012df0,
         "0x0000000180012e00", 0x180012e00, 0, 1, "[]", "[218]", 3),
    )
    # snap18: NO block with that EA (the block was DCE'd by IDA finalization)
    conn.commit()
    conn.close()

    out = tmp_path / "out.oracle.md"
    env = {**os.environ, "PYTHONPATH": "src"}
    result = subprocess.run(
        [sys.executable, "-m", "d810.diagnostics", "region-diff",
         "--db", str(db), "--func-ea", "0x0000000180012df0",
         "--output", str(out), "--json"],
        capture_output=True, text=True, env=env,
    )
    assert result.returncode == 0, result.stderr
    payload = _json.loads(out.read_text())

    s17_byte3 = next(
        (f for f in payload["snap17_features"]
         if f["feature"] == "byte_emit_3_present"),
        None,
    )
    assert s17_byte3 is not None
    # Survival: block exists at snap17 even though fact only fired at snap5.
    assert s17_byte3["value"] in (True, "True"), (
        f"byte_emit_3_present at snap17 should be True (survival), "
        f"got {s17_byte3['value']!r}"
    )

    # snap18: block was DCE'd, so not present.
    s18_byte3 = next(
        (f for f in payload["snap18_features"]
         if f["feature"] == "byte_emit_3_present"),
        None,
    )
    assert s18_byte3 is not None
    assert s18_byte3["value"] in (False, "False"), (
        f"byte_emit_3_present at snap18 should be False (DCE'd), "
        f"got {s18_byte3['value']!r}"
    )
