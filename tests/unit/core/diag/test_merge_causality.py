"""Tests for the ``merge-causality`` query and CLI subcommand.

Builds a minimal two-snapshot scenario: three FROM blocks vanish in TO,
each via a different disposition (absorbed / deleted / synthesized_only).
Locks in the cross-tab, the per-block disposition classification, and the
EA-based absorber inference.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from d810.core.diag.__main__ import main
from d810.core.diag.query import merge_causality
from d810.core.diag.schema import create_tables
from d810.core.diag.snapshot import _dual


_FROM_LABEL = "from_snap"
_TO_LABEL = "to_snap"


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
    type_name: str = "BLT_1WAY",
    preds: list[int] | None = None,
    succs: list[int] | None = None,
    insn_count: int = 0,
) -> None:
    preds = preds or []
    succs = succs or []
    conn.execute(
        "INSERT INTO blocks VALUES (?,?,1,?,NULL,NULL,NULL,NULL,?,?,?,?,?,NULL)",
        (
            snap_id,
            serial,
            type_name,
            len(succs),
            len(preds),
            json.dumps(succs),
            json.dumps(preds),
            insn_count,
        ),
    )


def _insert_insn(
    conn: sqlite3.Connection,
    snap_id: int,
    block_serial: int,
    insn_index: int,
    *,
    ea: int,
    opcode_name: str,
) -> None:
    ea_h, ea_i = _dual(ea)
    conn.execute(
        "INSERT INTO instructions VALUES (?,?,?,?,?,1,?,NULL,NULL,NULL,"
        "NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)",
        (snap_id, block_serial, insn_index, ea_h, ea_i, opcode_name),
    )


@pytest.fixture()
def merge_causality_db(tmp_path: Path) -> Path:
    """Two snapshots: FROM has blk 10/20/30/40, TO has blk 10/50.

    Disposition layout:
    - blk 10: survives (in both snapshots) — NOT vanished
    - blk 20: vanishes, EAs 0x100..0x103 survive in TO blk 10 → absorbed
    - blk 30: vanishes, all EAs 0x200..0x203 are gone in TO → deleted
    - blk 40: vanishes, only synthesized insns (ea=0) → synthesized_only
    """
    db_path = tmp_path / "merge.sqlite3"
    conn = sqlite3.connect(str(db_path))
    create_tables(conn)

    # FROM snapshot (snap 1)
    _insert_snapshot(conn, 1, _FROM_LABEL)
    _insert_block(conn, 1, 10, insn_count=2, succs=[20])
    _insert_insn(conn, 1, 10, 0, ea=0x100, opcode_name="op_4")
    _insert_insn(conn, 1, 10, 1, ea=0x101, opcode_name="op_4")
    _insert_block(conn, 1, 20, insn_count=4, succs=[30], preds=[10])
    for i, ea in enumerate((0x102, 0x103, 0x104, 0x105)):
        _insert_insn(conn, 1, 20, i, ea=ea, opcode_name="op_4")
    _insert_block(conn, 1, 30, insn_count=3, succs=[40], preds=[20])
    for i, ea in enumerate((0x200, 0x201, 0x202)):
        _insert_insn(conn, 1, 30, i, ea=ea, opcode_name="m_und")
    _insert_block(conn, 1, 40, insn_count=2, preds=[30])
    for i in range(2):
        _insert_insn(conn, 1, 40, i, ea=0x0, opcode_name="op_4")

    # TO snapshot (snap 2) — blk 10 absorbs blk 20's content; blk 50 is new.
    _insert_snapshot(conn, 2, _TO_LABEL)
    _insert_block(conn, 2, 10, insn_count=5, succs=[50])
    # blk 10 in TO keeps its own EAs plus blk 20's first three (0x102..0x104)
    for i, ea in enumerate((0x100, 0x101, 0x102, 0x103, 0x104)):
        _insert_insn(conn, 2, 10, i, ea=ea, opcode_name="op_4")
    _insert_block(conn, 2, 50, insn_count=1, preds=[10])
    _insert_insn(conn, 2, 50, 0, ea=0x300, opcode_name="op_1")

    conn.commit()
    conn.close()
    return db_path


class TestMergeCausalityQuery:
    def test_counts_match(self, merge_causality_db: Path) -> None:
        conn = sqlite3.connect(str(merge_causality_db))
        result = merge_causality(conn, 1, 2)
        assert result["from_block_count"] == 4
        assert result["to_block_count"] == 2
        assert result["vanished_count"] == 3

    def test_vanished_serials_sorted(self, merge_causality_db: Path) -> None:
        conn = sqlite3.connect(str(merge_causality_db))
        result = merge_causality(conn, 1, 2)
        serials = [r["serial"] for r in result["vanished"]]
        assert serials == [20, 30, 40]

    def test_absorbed_has_best_match(self, merge_causality_db: Path) -> None:
        conn = sqlite3.connect(str(merge_causality_db))
        result = merge_causality(conn, 1, 2)
        blk20 = next(r for r in result["vanished"] if r["serial"] == 20)
        assert blk20["disposition"] == "absorbed"
        assert blk20["absorber"] is not None
        assert blk20["absorber"]["serial"] == 10
        # blk 20 had 4 real EAs; 3 of them survive in TO blk 10.
        assert blk20["absorber"]["matching_eas"] == 3
        assert blk20["absorber"]["vanished_real_ea_count"] == 4

    def test_deleted_has_no_absorber(self, merge_causality_db: Path) -> None:
        conn = sqlite3.connect(str(merge_causality_db))
        result = merge_causality(conn, 1, 2)
        blk30 = next(r for r in result["vanished"] if r["serial"] == 30)
        assert blk30["disposition"] == "deleted"
        assert blk30["absorber"] is None
        # m_und-only content class is recognized from the symbolic name.
        assert blk30["content_class"] == "m_und_only"

    def test_synthesized_only_detected(self, merge_causality_db: Path) -> None:
        conn = sqlite3.connect(str(merge_causality_db))
        result = merge_causality(conn, 1, 2)
        blk40 = next(r for r in result["vanished"] if r["serial"] == 40)
        assert blk40["disposition"] == "synthesized_only"
        assert blk40["absorber"] is None

    def test_absorber_reports_tail_opcode(self, merge_causality_db: Path) -> None:
        conn = sqlite3.connect(str(merge_causality_db))
        result = merge_causality(conn, 1, 2)
        blk20 = next(r for r in result["vanished"] if r["serial"] == 20)
        assert blk20["tail_opcode"] == "op_4"


class TestMergeCausalityCli:
    def test_summary_default(
        self, merge_causality_db: Path, capsys: pytest.CaptureFixture
    ) -> None:
        rc = main([
            "merge-causality",
            "--db", str(merge_causality_db),
            "--from-label", _FROM_LABEL,
            "--to-label", _TO_LABEL,
        ])
        assert rc == 0
        out = capsys.readouterr().out
        assert "vanished: 3 blocks" in out
        assert "cross-tab" in out
        # Summary-only by default — no per-block detail lines.
        assert "blk[20]" not in out
        assert "detail rows suppressed" in out

    def test_cross_tab_counts(
        self, merge_causality_db: Path, capsys: pytest.CaptureFixture
    ) -> None:
        rc = main([
            "merge-causality",
            "--db", str(merge_causality_db),
            "--from-label", _FROM_LABEL,
            "--to-label", _TO_LABEL,
        ])
        assert rc == 0
        out = capsys.readouterr().out
        # One absorbed (blk 20), one deleted (blk 30), one synthesized_only (blk 40).
        # The TOTAL row should show 1/1/1/3.
        assert " 1 " in out  # disposition columns
        assert "TOTAL" in out
        assert "               1" in out  # absorbed column has 1

    def test_limit_shows_details(
        self, merge_causality_db: Path, capsys: pytest.CaptureFixture
    ) -> None:
        rc = main([
            "merge-causality",
            "--db", str(merge_causality_db),
            "--from-label", _FROM_LABEL,
            "--to-label", _TO_LABEL,
            "--limit", "5",
        ])
        assert rc == 0
        out = capsys.readouterr().out
        assert "blk[20]" in out
        assert "blk[30]" in out
        assert "blk[40]" in out
        assert "absorber: blk[10]" in out
        assert "deleted" in out
        assert "synth-only" in out

    def test_only_disposition_filter(
        self, merge_causality_db: Path, capsys: pytest.CaptureFixture
    ) -> None:
        rc = main([
            "merge-causality",
            "--db", str(merge_causality_db),
            "--from-label", _FROM_LABEL,
            "--to-label", _TO_LABEL,
            "--only-disposition", "deleted",
            "--limit", "5",
        ])
        assert rc == 0
        out = capsys.readouterr().out
        assert "blk[30]" in out
        assert "blk[20]" not in out
        assert "blk[40]" not in out

    def test_unknown_label_errors(
        self, merge_causality_db: Path, capsys: pytest.CaptureFixture
    ) -> None:
        with pytest.raises(SystemExit) as exc:
            main([
                "merge-causality",
                "--db", str(merge_causality_db),
                "--from-label", "does_not_exist",
                "--to-label", _TO_LABEL,
            ])
        assert exc.value.code == 1
        err = capsys.readouterr().err
        assert "no snapshot with label=" in err
