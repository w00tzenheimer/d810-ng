"""Tests for block trace and block lineage diagnostics."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from d810.core.diag import create_diag_database, diag_models_on
from d810.core.diag.models import (
    Block,
    BlockLineage,
    BlockObservation,
    CfgProvenance,
    Instruction,
    Snapshot,
)
from d810.core.diag.snapshot import _dual
from d810.diagnostics.__main__ import main
from d810.diagnostics.query import block_trace_by_ea
from tests.unit.core.diag._orm_bind import make_bound_diag_db


def _insert_snapshot(snap_id: int, label: str) -> None:
    fh, fi = _dual(0x180010000)
    Snapshot.insert(
        id=snap_id,
        label=label,
        func_ea_hex=fh,
        func_ea_i64=fi,
        maturity="MMAT_GLBOPT1",
        phase="unknown",
        block_count=0,
        timestamp=0.0,
    ).execute()


def _insert_block(
    snap_id: int,
    serial: int,
    *,
    start_ea: int,
    end_ea: int,
    insn_count: int = 1,
) -> None:
    sh, si = _dual(start_ea)
    eh, ei = _dual(end_ea)
    Block.insert(
        snapshot=snap_id,
        serial=serial,
        block_type=1,
        type_name="BLT_1WAY",
        start_ea_hex=sh,
        start_ea_i64=si,
        end_ea_hex=eh,
        end_ea_i64=ei,
        nsucc=1,
        npred=0,
        succs=json.dumps([]),
        preds=json.dumps([]),
        insn_count=insn_count,
        meta=None,
    ).execute()


def _insert_observation(
    snap_id: int,
    serial: int,
    *,
    start_ea: int,
    body_fingerprint: str,
) -> None:
    sh, si = _dual(start_ea)
    BlockObservation.insert(
        snapshot=snap_id,
        serial=serial,
        maturity="MMAT_GLBOPT1",
        phase="unknown",
        start_ea_hex=sh,
        start_ea_i64=si,
        insn_count=1,
        insn_ea_fingerprint=f"ea:{serial}",
        opcode_fingerprint=f"op:{serial}",
        operand_fingerprint=f"operand:{serial}",
        body_fingerprint=body_fingerprint,
    ).execute()


def _insert_insn(
    snap_id: int,
    serial: int,
    *,
    ea: int,
) -> None:
    eh, ei = _dual(ea)
    Instruction.insert(
        snapshot=snap_id,
        block_serial=serial,
        insn_index=0,
        ea_hex=eh,
        ea_i64=ei,
        opcode=1,
        opcode_name="m_mov",
        dest_type=None,
        dest_stkoff=None,
        dest_size=None,
        src_l_type=None,
        src_l_stkoff=None,
        src_l_value_hex=None,
        src_l_value_i64=None,
        src_r_type=None,
        src_r_stkoff=None,
        src_r_value_hex=None,
        src_r_value_i64=None,
        dstr=None,
        meta=None,
    ).execute()


@pytest.fixture()
def correlation_conn() -> sqlite3.Connection:
    db = make_bound_diag_db()
    _insert_snapshot(1, "pre")
    _insert_snapshot(2, "post")
    _insert_block(1, 10, start_ea=0x180010000, end_ea=0x180010010)
    _insert_block(2, 20, start_ea=0x180010000, end_ea=0x180010020)
    _insert_observation(
        1,
        10,
        start_ea=0x180010000,
        body_fingerprint="fnv1a64:0xaaaaaaaaaaaaaaaa",
    )
    _insert_observation(
        2,
        20,
        start_ea=0x180010000,
        body_fingerprint="fnv1a64:0xaaaaaaaaaaaaaaaa",
    )
    BlockLineage.insert(
        snapshot=2,
        serial=20,
        origin_snapshot_id=1,
        origin_serial=10,
        origin_start_ea_hex="0x0000000180010000",
        origin_body_fingerprint="fnv1a64:0xaaaaaaaaaaaaaaaa",
        creation_kind="duplicate",
        creation_reason="unit-test duplicate",
        planner_block_id="planner-20",
        source_mod_type="InsertBlock",
        extra_json=None,
    ).execute()
    conn = db.connection()
    conn.commit()
    yield conn
    conn.close()


def _create_correlation_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "correlation.sqlite3"
    db = create_diag_database(str(db_path))
    with diag_models_on(db):
        _insert_snapshot(1, "pre")
        _insert_snapshot(2, "post")
        _insert_block(1, 10, start_ea=0x180010000, end_ea=0x180010010)
        _insert_block(2, 20, start_ea=0x180010000, end_ea=0x180010020)
        _insert_observation(
            1,
            10,
            start_ea=0x180010000,
            body_fingerprint="fnv1a64:0xaaaaaaaaaaaaaaaa",
        )
        _insert_observation(
            2,
            20,
            start_ea=0x180010000,
            body_fingerprint="fnv1a64:0xaaaaaaaaaaaaaaaa",
        )
        BlockLineage.insert(
            snapshot=2,
            serial=20,
            origin_snapshot_id=1,
            origin_serial=10,
            origin_start_ea_hex="0x0000000180010000",
            origin_body_fingerprint="fnv1a64:0xaaaaaaaaaaaaaaaa",
            creation_kind="duplicate",
            creation_reason="unit-test duplicate",
            planner_block_id="planner-20",
            source_mod_type="InsertBlock",
            extra_json=None,
        ).execute()
        db.connection().commit()
    db.close()
    return db_path


def _create_legacy_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "legacy.sqlite3"
    db = create_diag_database(str(db_path))
    conn = db.connection()
    # Schema DDL manipulation — kept raw (DROP TABLE is schema/DDL subject SQL)
    conn.execute("DROP TABLE block_observations")
    conn.execute("DROP TABLE block_lineage")
    with diag_models_on(db):
        _insert_snapshot(1, "legacy")
        _insert_block(1, 30, start_ea=0x180020000, end_ea=0x180020010)
        _insert_insn(1, 30, ea=0x180020004)
        CfgProvenance.insert(
            snapshot=1,
            seq=0,
            pass_name="unit",
            action="CREATE",
            block_serial=30,
            target_serial=None,
            reason="created in test",
            extra_json=None,
        ).execute()
        db.connection().commit()
    db.close()
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
