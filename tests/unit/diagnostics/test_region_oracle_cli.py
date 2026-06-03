"""Unit tests for generic python -m d810.diagnostics region-* subcommands."""
from __future__ import annotations
from d810.core.diag import create_diag_database, diag_models_on
from d810.core.diag.models import RegionShapeFeature, TerminalTailDceCause



def test_region_shape_subcommand_lists_persisted_features(tmp_path):
    """Subprocess: python -m d810.diagnostics region-shape lists rows."""
    import json
    import os
    import subprocess
    import sys

    db_path = tmp_path / "test.diag.sqlite3"
    db = create_diag_database(str(db_path))
    with diag_models_on(db):
        RegionShapeFeature.insert(
            func_ea_hex="0x0000000180012df0",
            func_ea_i64=0x180012df0,
            snapshot_id=17,
            source="D810_SNAPSHOT",
            region="terminal_tail",
            feature="byte_emit_3_present",
            value_text="True",
            evidence_json=json.dumps({"side": "d810", "block_serial": 161}),
        ).execute()
    db.close()

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
    db = create_diag_database(str(db_path))
    with diag_models_on(db):
        rows = [
            (None, "REF", "ref_feat_1"),
            (17, "D810_SNAPSHOT", "snap17_feat_1"),
            (18, "D810_SNAPSHOT", "snap18_feat_1"),
        ]
        RegionShapeFeature.insert_many([
            dict(
                func_ea_hex="0x0000000180012df0",
                func_ea_i64=0x180012df0,
                snapshot_id=snap_id,
                source=source,
                region="terminal_tail",
                feature=feature,
                value_text="True",
                evidence_json=json.dumps({}),
            )
            for snap_id, source, feature in rows
        ]).execute()
    db.close()

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
    diag_db = create_diag_database(str(db))
    with diag_models_on(diag_db):
        TerminalTailDceCause.insert(
            func_ea_hex="0x0000000180012df0",
            func_ea_i64=0x180012df0,
            byte_index=3,
            last_present_snapshot_id=17,
            first_missing_snapshot_id=18,
            last_block_serial=161,
            last_ea_hex="0x0000000180012df0",
            cause="FOLDED_INTO_SURVIVING_BYTE_EMIT",
            recommended_action="STRUCTURER_SHAPING",
            rationale="tail-equivalent fold",
            evidence_json=json.dumps({"side": "d810"}),
        ).execute()
    diag_db.close()

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
    diag_db = create_diag_database(str(db))
    with diag_models_on(diag_db):
        TerminalTailDceCause.insert_many([
            dict(
                func_ea_hex="0x0000000180012df0",
                func_ea_i64=0x180012df0,
                byte_index=byte_index,
                last_present_snapshot_id=17,
                first_missing_snapshot_id=18,
                last_block_serial=100 + byte_index,
                last_ea_hex="0x0",
                cause=cause,
                recommended_action="STRUCTURER_SHAPING",
                rationale="...",
                evidence_json=json.dumps({}),
            )
            for byte_index, cause in (
                (2, "FOLDED_INTO_SURVIVING_BYTE_EMIT"),
                (3, "DCE_DEAD_WRITE"),
            )
        ]).execute()
    diag_db.close()

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
