"""Tests for MBA diagnostic snapshot schema creation."""
import sqlite3

import pytest

from d810.core.diag.schema import create_tables


def test_create_tables_creates_all_expected_tables():
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )
    tables = [row[0] for row in cursor]
    assert "blocks" in tables
    assert "block_observations" in tables
    assert "block_lineage" in tables
    assert "instructions" in tables
    assert "snapshots" in tables
    assert "dag_edges" in tables
    assert "dag_nodes" in tables
    assert "dag_node_blocks" in tables
    assert "dag_local_segments" in tables
    assert "dag_local_edges" in tables
    assert "modifications" in tables
    assert "block_classification" in tables
    assert "rendered_programs" in tables
    assert "rendered_program_nodes" in tables
    assert "rendered_program_lines" in tables


def test_create_tables_idempotent():
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
    create_tables(conn)  # should not raise


def test_json_extract_on_meta_columns():
    """Verify SQLite JSON extension works for meta column queries."""
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
    # Insert a block with JSON meta containing valranges
    conn.execute(
        "INSERT INTO snapshots VALUES "
        "(1, 'test', '0x0000000000001000', 0x1000, 'GLBOPT1', 'unknown', 3, 0.0)"
    )
    conn.execute(
        "INSERT INTO blocks VALUES "
        "(1, 206, 2, 'BLT_2WAY', NULL, NULL, NULL, NULL, 2, 2, "
        "'[207,208]', '[62,204]', 1, ?)",
        ('{"valranges": {"0x3C": "==432DC789"}, "flags": ["MBL_GOTO"]}',),
    )
    # Query with json_extract
    row = conn.execute(
        "SELECT json_extract(meta, '$.valranges.0x3C') FROM blocks "
        "WHERE snapshot_id=1 AND serial=206"
    ).fetchone()
    assert row[0] == "==432DC789"
    # Query with json_each on succs
    succs = conn.execute(
        "SELECT value FROM json_each("
        "(SELECT succs FROM blocks WHERE snapshot_id=1 AND serial=206))"
    ).fetchall()
    assert [r[0] for r in succs] == [207, 208]


def test_edge_kind_check_constraint_rejects_invalid():
    """Verify CHECK constraint on edge_kind column."""
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
    conn.execute(
        "INSERT INTO snapshots VALUES "
        "(1, 'test', '0x0000000000001000', 0x1000, 'GLBOPT1', 'unknown', 3, 0.0)"
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO dag_edges VALUES "
            "(1, 1, NULL, NULL, NULL, NULL, 'INVALID_KIND', "
            "NULL, NULL, NULL, '[]')"
        )


def test_phase_check_constraint_rejects_invalid():
    """Verify CHECK constraint on phase column rejects invalid values."""
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO snapshots VALUES "
            "(1, 'test', '0x0000000000001000', 0x1000, 'GLBOPT1', "
            "'INVALID_PHASE', 3, 0.0)"
        )


def test_phase_check_constraint_accepts_valid():
    """Verify CHECK constraint accepts all valid phase values."""
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
    valid_phases = ['pre_d810', 'post_apply', 'post_gut_wire', 'post_pipeline', 'post_d810', 'unknown']
    for i, phase in enumerate(valid_phases):
        conn.execute(
            "INSERT INTO snapshots VALUES "
            "(?, 'test', '0x0000000000001000', 0x1000, 'GLBOPT1', ?, 3, 0.0)",
            (i + 1, phase),
        )
    count = conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
    assert count == 6


def test_var_writes_view_exists():
    """Verify the var_writes view is created."""
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='view' ORDER BY name"
    )
    views = [row[0] for row in cursor]
    assert "var_writes" in views
