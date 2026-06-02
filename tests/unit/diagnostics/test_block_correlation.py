"""Tests for block trace and block lineage diagnostics."""
from __future__ import annotations
from d810.core.diag import create_diag_database

import json
import sqlite3
from pathlib import Path

import pytest

from d810.diagnostics.__main__ import main
from d810.diagnostics.query import block_trace_by_ea
from d810.core.diag.schema import create_tables
from d810.core.diag.snapshot import _dual


def _insert_snapshot(conn: sqlite3.Connection, snap_id: int, label: str) -> None:
    fh, fi = _dual(0x180010000)
    conn.execute(
        "INSERT INTO snapshots VALUES (?, ?, ?, ?, 'MMAT_GLBOPT1', 'unknown', 0, 0.0)",
        (snap_id, label, fh, fi),
    )


def _insert_block(
    conn: sqlite3.Connection,
    snap_id: int,
    serial: int,
    *,
    start_ea: int,
    end_ea: int,
    insn_count: int = 1,
) -> None:
    sh, si = _dual(start_ea)
    eh, ei = _dual(end_ea)
    conn.execute(
        "INSERT INTO blocks VALUES (?,?,1,'BLT_1WAY',?,?,?,?,1,0,?,?,?,NULL)",
        (
            snap_id,
            serial,
            sh,
            si,
            eh,
            ei,
            json.dumps([]),
            json.dumps([]),
            insn_count,
        ),
    )


def _insert_observation(
    conn: sqlite3.Connection,
    snap_id: int,
    serial: int,
    *,
    start_ea: int,
    body_fingerprint: str,
) -> None:
    sh, si = _dual(start_ea)
    conn.execute(
        "INSERT INTO block_observations VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            snap_id,
            serial,
            "MMAT_GLBOPT1",
            "unknown",
            sh,
            si,
            1,
            f"ea:{serial}",
            f"op:{serial}",
            f"operand:{serial}",
            body_fingerprint,
        ),
    )


def _insert_insn(
    conn: sqlite3.Connection,
    snap_id: int,
    serial: int,
    *,
    ea: int,
) -> None:
    eh, ei = _dual(ea)
    conn.execute(
        "INSERT INTO instructions VALUES (?,?,?,?,?,1,'m_mov',NULL,NULL,NULL,"
        "NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)",
        (snap_id, serial, 0, eh, ei),
    )


@pytest.fixture()
def correlation_conn() -> sqlite3.Connection:
    conn = create_diag_database(":memory:").connection()
    _insert_snapshot(conn, 1, "pre")
    _insert_snapshot(conn, 2, "post")
    _insert_block(conn, 1, 10, start_ea=0x180010000, end_ea=0x180010010)
    _insert_block(conn, 2, 20, start_ea=0x180010000, end_ea=0x180010020)
    _insert_observation(
        conn,
        1,
        10,
        start_ea=0x180010000,
        body_fingerprint="fnv1a64:0xaaaaaaaaaaaaaaaa",
    )
    _insert_observation(
        conn,
        2,
        20,
        start_ea=0x180010000,
        body_fingerprint="fnv1a64:0xaaaaaaaaaaaaaaaa",
    )
    conn.execute(
        "INSERT INTO block_lineage VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            2,
            20,
            1,
            10,
            "0x0000000180010000",
            "fnv1a64:0xaaaaaaaaaaaaaaaa",
            "duplicate",
            "unit-test duplicate",
            "planner-20",
            "InsertBlock",
            None,
        ),
    )
    conn.commit()
    yield conn
    conn.close()


def _create_correlation_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "correlation.sqlite3"
    disk_conn = create_diag_database(str(db_path)).connection()
    _insert_snapshot(disk_conn, 1, "pre")
    _insert_snapshot(disk_conn, 2, "post")
    _insert_block(disk_conn, 1, 10, start_ea=0x180010000, end_ea=0x180010010)
    _insert_block(disk_conn, 2, 20, start_ea=0x180010000, end_ea=0x180010020)
    _insert_observation(
        disk_conn,
        1,
        10,
        start_ea=0x180010000,
        body_fingerprint="fnv1a64:0xaaaaaaaaaaaaaaaa",
    )
    _insert_observation(
        disk_conn,
        2,
        20,
        start_ea=0x180010000,
        body_fingerprint="fnv1a64:0xaaaaaaaaaaaaaaaa",
    )
    disk_conn.execute(
        "INSERT INTO block_lineage VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            2,
            20,
            1,
            10,
            "0x0000000180010000",
            "fnv1a64:0xaaaaaaaaaaaaaaaa",
            "duplicate",
            "unit-test duplicate",
            "planner-20",
            "InsertBlock",
            None,
        ),
    )
    disk_conn.commit()
    disk_conn.close()
    return db_path


def _create_legacy_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "legacy.sqlite3"
    conn = create_diag_database(str(db_path)).connection()
    conn.execute("DROP TABLE block_observations")
    conn.execute("DROP TABLE block_lineage")
    _insert_snapshot(conn, 1, "legacy")
    _insert_block(conn, 1, 30, start_ea=0x180020000, end_ea=0x180020010)
    _insert_insn(conn, 1, 30, ea=0x180020004)
    conn.execute(
        "INSERT INTO cfg_provenance VALUES (?,?,?,?,?,?,?,?)",
        (1, 0, "unit", "CREATE", 30, None, "created in test", None),
    )
    conn.commit()
    conn.close()
    return db_path


class TestBlockTraceQuery:
    def test_ea_trace_marks_ambiguous_observation_matches(
        self,
        correlation_conn: sqlite3.Connection,
    ) -> None:
        result = block_trace_by_ea(correlation_conn, 0x180010000)
        assert result["source"] == "block_observations"
        assert result["ambiguous"] is True
        assert [
            (row["snapshot_id"], row["serial"])
            for row in result["matches"]
        ] == [(1, 10), (2, 20)]


class TestBlockTraceCli:
    def test_ea_trace_shows_all_ambiguous_matches(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture,
    ) -> None:
        db_path = _create_correlation_db(tmp_path)
        rc = main(["block-trace", "--db", str(db_path), "--ea", "0x180010000"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "AMBIGUOUS: 2 matching blocks" in out
        assert "snap 1 (pre) blk[10]" in out
        assert "snap 2 (post) blk[20]" in out

    def test_serial_trace_uses_observation_correlation(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture,
    ) -> None:
        db_path = _create_correlation_db(tmp_path)
        rc = main([
            "block-trace",
            "--db",
            str(db_path),
            "--snapshot",
            "2",
            "--serial",
            "20",
        ])
        assert rc == 0
        out = capsys.readouterr().out
        assert "anchor: snap 2 (post) blk[20]" in out
        assert "same_start_ea+same_body" in out

    def test_ea_trace_falls_back_without_observations_table(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture,
    ) -> None:
        db_path = _create_legacy_db(tmp_path)
        rc = main(["block-trace", "--db", str(db_path), "--ea", "0x180020004"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "source=blocks" in out
        assert "block_observations table not available" in out
        assert "snap 1 (legacy) blk[30]" in out
        assert "range_contains" in out


class TestBlockLineageCli:
    def test_lineage_uses_direct_lineage_table(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture,
    ) -> None:
        db_path = _create_correlation_db(tmp_path)
        rc = main([
            "block-lineage",
            "--db",
            str(db_path),
            "--snapshot",
            "2",
            "--serial",
            "20",
        ])
        assert rc == 0
        out = capsys.readouterr().out
        assert "creation_kind=duplicate" in out
        assert "origin=snap 1 blk[10]" in out
        assert "origin observations:" in out
        assert "snap 1 (pre) blk[10]" in out

    def test_lineage_falls_back_to_cfg_provenance(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture,
    ) -> None:
        db_path = _create_legacy_db(tmp_path)
        rc = main([
            "block-lineage",
            "--db",
            str(db_path),
            "--snapshot",
            "1",
            "--serial",
            "30",
        ])
        assert rc == 0
        out = capsys.readouterr().out
        assert "block_lineage table not available" in out
        assert "cfg_provenance:" in out
        assert "action=CREATE" in out
