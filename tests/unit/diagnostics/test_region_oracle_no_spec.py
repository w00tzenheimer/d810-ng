"""No-spec stub and structured-error tests for `region-diff`.

The production handler lives in d810.cfg.region_oracle_cli. These tests
shell out to `python -m d810.diagnostics region-diff` to exercise the
full importlib-dispatched path.
"""
from __future__ import annotations

import os
import sqlite3
import subprocess
import sys

import pytest

from d810.core.diag.schema import create_tables


def _env() -> dict:
    return {**os.environ, "PYTHONPATH": "src"}


def _insert_snapshot(conn, *, snap_id, label):
    conn.execute(
        "INSERT INTO snapshots (id, label, func_ea_hex, func_ea_i64, "
        " maturity, phase, block_count, timestamp) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (snap_id, label, "0x0000000180012df0", 0x180012df0,
         "MMAT_GLBOPT1", "post_d810", 0, 0.0),
    )


def test_region_diff_unregistered_func_returns_no_ref_spec_stub_to_stdout(tmp_path):
    db = tmp_path / "x.diag.sqlite3"
    conn = sqlite3.connect(str(db))
    create_tables(conn)
    _insert_snapshot(conn, snap_id=1, label="preopt")
    conn.commit()
    conn.close()

    result = subprocess.run(
        [sys.executable, "-m", "d810.diagnostics", "region-diff",
         "--db", str(db), "--func-ea", "0x00000000DEADBEEF"],
        capture_output=True, text=True, env=_env(),
    )
    assert result.returncode == 0, result.stderr
    assert "Status: no_ref_spec" in result.stdout


def test_region_diff_unregistered_func_writes_stub_to_output_path(tmp_path):
    db = tmp_path / "x.diag.sqlite3"
    conn = sqlite3.connect(str(db))
    create_tables(conn)
    _insert_snapshot(conn, snap_id=1, label="preopt")
    conn.commit()
    conn.close()

    out = tmp_path / "stub.oracle.md"
    result = subprocess.run(
        [sys.executable, "-m", "d810.diagnostics", "region-diff",
         "--db", str(db), "--func-ea", "0x00000000DEADBEEF",
         "--output", str(out)],
        capture_output=True, text=True, env=_env(),
    )
    assert result.returncode == 0, result.stderr
    assert out.exists()
    body = out.read_text()
    assert "Status: no_ref_spec" in body
    assert f"oracle written: {out}" in result.stdout


def test_region_diff_schema_missing_snapshots_exits_2(tmp_path):
    db = tmp_path / "broken.sqlite3"
    conn = sqlite3.connect(str(db))
    # Intentionally do NOT create_tables(): no snapshots table.
    conn.commit()
    conn.close()

    result = subprocess.run(
        [sys.executable, "-m", "d810.diagnostics", "region-diff",
         "--db", str(db), "--func-ea", "0x0000000180012df0"],
        capture_output=True, text=True, env=_env(),
    )
    assert result.returncode == 2
    err = result.stderr.lower()
    assert ("schema mismatch" in err) or ("no such table" in err)


def test_region_diff_unresolvable_snap_labels_exits_2(tmp_path):
    db = tmp_path / "no_snaps.diag.sqlite3"
    conn = sqlite3.connect(str(db))
    create_tables(conn)
    _insert_snapshot(conn, snap_id=1, label="preopt")
    conn.commit()
    conn.close()

    result = subprocess.run(
        [sys.executable, "-m", "d810.diagnostics", "region-diff",
         "--db", str(db), "--func-ea", "0x0000000180012df0"],
        capture_output=True, text=True, env=_env(),
    )
    assert result.returncode == 2
    assert "cannot resolve snap17/snap18" in result.stderr.lower()


def test_region_diff_snap17_ge_snap18_exits_2(tmp_path):
    db = tmp_path / "x.diag.sqlite3"
    conn = sqlite3.connect(str(db))
    create_tables(conn)
    _insert_snapshot(conn, snap_id=1, label="post_bundle_stabilize")
    _insert_snapshot(conn, snap_id=2, label="GLBOPT1_post_d810")
    conn.commit()
    conn.close()

    result = subprocess.run(
        [sys.executable, "-m", "d810.diagnostics", "region-diff",
         "--db", str(db), "--func-ea", "0x0000000180012df0",
         "--snap17", "5", "--snap18", "3"],
        capture_output=True, text=True, env=_env(),
    )
    assert result.returncode == 2
    assert "snap17" in result.stderr.lower()
