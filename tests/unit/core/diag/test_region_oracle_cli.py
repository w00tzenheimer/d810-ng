"""Unit tests for python -m d810.core.diag region-* subcommands."""
from __future__ import annotations

import sqlite3

import pytest

from d810.core.diag.__main__ import _resolve_oracle_snap_ids


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


def test_region_shape_subcommand_lists_persisted_features(tmp_path):
    """Subprocess: python -m d810.core.diag region-shape lists rows."""
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
        [sys.executable, "-m", "d810.core.diag", "region-shape",
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
        [sys.executable, "-m", "d810.core.diag", "region-shape",
         "--db", str(db_path), "--func-ea", "0x0000000180012df0",
         "--source", "REF"],
        capture_output=True, text=True, env=env,
    )
    assert r.returncode == 0, r.stderr
    assert "ref_feat_1" in r.stdout
    assert "snap17_feat_1" not in r.stdout

    # Filter by snapshot_id.
    r = subprocess.run(
        [sys.executable, "-m", "d810.core.diag", "region-shape",
         "--db", str(db_path), "--func-ea", "0x0000000180012df0",
         "--snapshot-id", "17"],
        capture_output=True, text=True, env=env,
    )
    assert r.returncode == 0, r.stderr
    assert "snap17_feat_1" in r.stdout
    assert "ref_feat_1" not in r.stdout

    # JSON output.
    r = subprocess.run(
        [sys.executable, "-m", "d810.core.diag", "region-shape",
         "--db", str(db_path), "--func-ea", "0x0000000180012df0",
         "--json"],
        capture_output=True, text=True, env=env,
    )
    assert r.returncode == 0, r.stderr
    payload = json.loads(r.stdout)
    assert isinstance(payload, list)
    assert len(payload) == 3
