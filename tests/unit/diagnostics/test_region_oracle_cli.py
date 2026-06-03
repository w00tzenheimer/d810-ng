"""Unit tests for generic python -m d810.diagnostics region-* subcommands."""
from __future__ import annotations
from d810.core.diag import create_diag_database



def test_region_shape_subcommand_lists_persisted_features(tmp_path):
    """Subprocess: python -m d810.diagnostics region-shape lists rows."""
    import json
    import os
    import subprocess
    import sys

    db_path = tmp_path / "test.diag.sqlite3"
    conn = create_diag_database(str(db_path)).connection()
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

    db_path = tmp_path / "test.diag.sqlite3"
    conn = create_diag_database(str(db_path)).connection()
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


def test_terminal_tail_dce_subcommand_lists_persisted_causes(tmp_path):
    """Subprocess: python -m d810.diagnostics terminal-tail-dce."""
    import json, os, sys, subprocess

    db = tmp_path / "test.diag.sqlite3"
    conn = create_diag_database(str(db)).connection()
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

    db = tmp_path / "test.diag.sqlite3"
    conn = create_diag_database(str(db)).connection()
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
