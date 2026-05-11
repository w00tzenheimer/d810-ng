"""Tests for the HCC byte-cascade trace parser + report."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from d810.diagnostics.hcc_byte_cascade_trace import (
    ByteCascadeRow,
    enrich_rows_with_db,
    format_report,
    format_report_json,
    parse_trace_line,
    parse_trace_log,
)


# ---------------------------------------------------------------------------
# parse_trace_line
# ---------------------------------------------------------------------------


def _line(**fields: object) -> str:
    parts = " ".join(f"{k}={v}" for k, v in fields.items())
    return f"HCC_BYTE_CASCADE_TRACE_ROW {parts}"


def test_parses_minimal_row() -> None:
    row = parse_trace_line(
        _line(
            byte=2,
            block_ea="0x0000000180014C00",
            block_serial=56,
            entry_anchor=56,
            dag_node="STATE_72AFE1BC",
            in_dag=1,
            in_corrected_dag=1,
            in_region_table=0,
            raw_candidate=1,
            candidate_rejection="-",
            accepted_stage="primary_execution",
            emitted_mod="InsertBlock",
            preserved_in_insertblock=1,
            first_dropped_stage="-",
            final_status="preserved_insertblock",
        )
    )
    assert row is not None
    assert row.byte == 2
    assert row.block_ea == "0x0000000180014C00"
    assert row.block_serial == 56
    assert row.in_dag is True
    assert row.preserved_in_insertblock is True
    assert row.final_status == "preserved_insertblock"


def test_tolerates_logger_prefix() -> None:
    raw = (
        "2026-05-11 09:00:00 D810.hodur.strategy.handler_chain_composer INFO "
        "HCC_BYTE_CASCADE_TRACE_ROW byte=3 block_ea=0x180014D00 block_serial=163 "
        "entry_anchor=163 dag_node=STATE_X in_dag=1 in_corrected_dag=1 "
        "in_region_table=0 raw_candidate=1 candidate_rejection='-' "
        "accepted_stage=- emitted_mod=- preserved_in_insertblock=0 "
        "first_dropped_stage=postprocess final_status=lost"
    )
    row = parse_trace_line(raw)
    assert row is not None
    assert row.byte == 3
    assert row.final_status == "lost"
    assert row.first_dropped_stage == "postprocess"


def test_parses_quoted_rejection_with_spaces_and_specials() -> None:
    row = parse_trace_line(
        "HCC_BYTE_CASCADE_TRACE_ROW byte=6 block_ea=? block_serial=? "
        "entry_anchor=? dag_node=? in_dag=0 in_corrected_dag=0 "
        "in_region_table=0 raw_candidate=0 "
        "candidate_rejection='dispatcher_region_block' "
        "accepted_stage=- emitted_mod=- preserved_in_insertblock=0 "
        "first_dropped_stage=- final_status=unknown"
    )
    assert row is not None
    assert row.byte == 6
    assert row.candidate_rejection == "dispatcher_region_block"
    assert row.block_serial is None
    assert row.entry_anchor is None


def test_returns_none_for_non_trace_line() -> None:
    assert parse_trace_line("just a regular log line") is None


def test_returns_none_when_byte_field_missing() -> None:
    assert parse_trace_line("HCC_BYTE_CASCADE_TRACE_ROW final_status=lost") is None


# ---------------------------------------------------------------------------
# parse_trace_log
# ---------------------------------------------------------------------------


def test_parse_log_returns_one_row_per_byte_sorted() -> None:
    log_text = "\n".join(
        [
            "noise line",
            _line(
                byte=5, block_ea="0x180014E00", block_serial=101, entry_anchor=101,
                dag_node="?", in_dag=1, in_corrected_dag=1, in_region_table=0,
                raw_candidate=0, candidate_rejection="-",
                accepted_stage="-", emitted_mod="-",
                preserved_in_insertblock=0,
                first_dropped_stage="postprocess",
                final_status="lost",
            ),
            _line(
                byte=2, block_ea="0x180014C00", block_serial=56, entry_anchor=56,
                dag_node="?", in_dag=1, in_corrected_dag=1, in_region_table=0,
                raw_candidate=1, candidate_rejection="-",
                accepted_stage="primary_execution", emitted_mod="InsertBlock",
                preserved_in_insertblock=1, first_dropped_stage="-",
                final_status="preserved_insertblock",
            ),
        ]
    )
    rows = parse_trace_log(log_text)
    assert [r.byte for r in rows] == [2, 5]


def test_parse_log_keeps_last_observation_per_byte() -> None:
    first = _line(
        byte=3, block_ea="0x1", block_serial=10, entry_anchor=10, dag_node="?",
        in_dag=1, in_corrected_dag=1, in_region_table=0, raw_candidate=1,
        candidate_rejection="-", accepted_stage="primary_execution",
        emitted_mod="InsertBlock", preserved_in_insertblock=1,
        first_dropped_stage="-", final_status="preserved_insertblock",
    )
    second = _line(
        byte=3, block_ea="0x1", block_serial=10, entry_anchor=10, dag_node="?",
        in_dag=1, in_corrected_dag=1, in_region_table=0, raw_candidate=0,
        candidate_rejection="-", accepted_stage="-",
        emitted_mod="-", preserved_in_insertblock=0,
        first_dropped_stage="postprocess", final_status="lost",
    )
    rows = parse_trace_log("\n".join([first, second]))
    assert len(rows) == 1
    assert rows[0].final_status == "lost"
    assert rows[0].first_dropped_stage == "postprocess"


# ---------------------------------------------------------------------------
# format_report
# ---------------------------------------------------------------------------


def _row(
    byte: int,
    *,
    final_status: str,
    first_dropped_stage: str = "-",
    candidate_rejection: str = "-",
    accepted_stage: str = "-",
    emitted_mod: str = "-",
    preserved_in_insertblock: bool = False,
    in_dag: bool = True,
    in_corrected_dag: bool = True,
    in_region_table: bool = False,
    raw_candidate: bool = False,
    db_var190_refs: dict[str, int] | None = None,
) -> ByteCascadeRow:
    return ByteCascadeRow(
        byte=byte,
        block_ea=f"0x{byte:016X}",
        block_serial=byte * 10,
        entry_anchor=byte * 10,
        dag_node=f"STATE_{byte}",
        in_dag=in_dag,
        in_corrected_dag=in_corrected_dag,
        in_region_table=in_region_table,
        raw_candidate=raw_candidate,
        candidate_rejection=candidate_rejection,
        accepted_stage=accepted_stage,
        emitted_mod=emitted_mod,
        preserved_in_insertblock=preserved_in_insertblock,
        first_dropped_stage=first_dropped_stage,
        final_status=final_status,
        db_var190_refs=db_var190_refs or {},
    )


def test_format_report_empty_input() -> None:
    text = format_report([])
    assert "no `HCC_BYTE_CASCADE_TRACE_ROW`" in text


def test_format_report_renders_table_and_summary() -> None:
    rows = [
        _row(2, final_status="preserved_insertblock", preserved_in_insertblock=True,
             accepted_stage="primary_execution", emitted_mod="InsertBlock"),
        _row(3, final_status="lost", first_dropped_stage="postprocess"),
    ]
    out = format_report(rows, func_label="sub_7FFD3338C040")
    assert "## HCC byte-cascade trace for sub_7FFD3338C040" in out
    assert "| byte | block_ea |" in out
    assert "| 2 |" in out and "| 3 |" in out
    assert "byte 3: `lost`" in out
    assert "first dropped at `postprocess`" in out
    # The preserved row should not appear in the summary section.
    assert "byte 2:" not in out.split("### Summary")[1]


def test_format_report_renders_db_xref_table_when_refs_present() -> None:
    rows = [
        _row(
            3,
            final_status="lost",
            first_dropped_stage="postprocess",
            db_var190_refs={"pre_d810": 1, "post_bundle_stabilize": 1, "post_d810": 0},
        ),
    ]
    out = format_report(rows)
    assert "Cross-reference" in out
    assert "pre_d810" in out and "post_d810" in out


def test_format_report_json_round_trips() -> None:
    rows = [
        _row(2, final_status="preserved_insertblock", preserved_in_insertblock=True),
    ]
    payload = json.loads(format_report_json(rows))
    assert payload[0]["byte"] == 2
    assert payload[0]["final_status"] == "preserved_insertblock"
    assert payload[0]["preserved_in_insertblock"] is True


# ---------------------------------------------------------------------------
# enrich_rows_with_db (integration with a real sqlite file)
# ---------------------------------------------------------------------------


def _make_diag_db(tmp_path: Path) -> Path:
    db = tmp_path / "diag.sqlite3"
    conn = sqlite3.connect(str(db))
    try:
        conn.executescript(
            """
            CREATE TABLE snapshots(id INTEGER PRIMARY KEY, label TEXT);
            CREATE TABLE instructions(snapshot_id INTEGER, dstr TEXT);
            INSERT INTO snapshots(id, label) VALUES
                (5, 'pre_d810'),
                (17, 'post_bundle_stabilize'),
                (18, 'post_d810');
            INSERT INTO instructions(snapshot_id, dstr) VALUES
                (5, 'stx ([ds.2:%var_190.8+#3.8].1)'),
                (17, 'stx ([ds.2:%var_190.8+#3.8].1)'),
                (17, 'stx ([ds.2:%var_190.8+#3.8].1) second copy'),
                (5, 'stx ([ds.2:%var_190.8+#6.8].1)');
            """
        )
        conn.commit()
    finally:
        conn.close()
    return db


def test_enrich_returns_rows_unchanged_when_db_missing(tmp_path: Path) -> None:
    rows = [_row(3, final_status="lost")]
    enriched = enrich_rows_with_db(rows, tmp_path / "nope.sqlite3")
    assert enriched[0].db_var190_refs == {}


def test_enrich_counts_var190_refs_per_snapshot(tmp_path: Path) -> None:
    db = _make_diag_db(tmp_path)
    rows = [_row(3, final_status="lost"), _row(6, final_status="lost")]
    enriched = enrich_rows_with_db(rows, db)
    refs_byte3 = enriched[0].db_var190_refs
    refs_byte6 = enriched[1].db_var190_refs
    assert refs_byte3.get("pre_d810") == 1
    assert refs_byte3.get("post_bundle_stabilize") == 2
    assert "post_d810" not in refs_byte3
    assert refs_byte6.get("pre_d810") == 1


def test_enrich_skips_byte_zero() -> None:
    rows = [_row(0, final_status="lost")]
    enriched = enrich_rows_with_db(rows, Path("/nonexistent"))
    assert enriched[0].db_var190_refs == {}


# ---------------------------------------------------------------------------
# Top-level convenience: verify a small log file end-to-end
# ---------------------------------------------------------------------------


def test_end_to_end_minimal_log(tmp_path: Path) -> None:
    db = _make_diag_db(tmp_path)
    log = tmp_path / "d810.log"
    log.write_text(
        "\n".join(
            [
                "boilerplate line",
                _line(
                    byte=3, block_ea="0x180014D00", block_serial=163,
                    entry_anchor=163, dag_node="STATE_72AFE1BC",
                    in_dag=1, in_corrected_dag=1, in_region_table=0,
                    raw_candidate=1, candidate_rejection="-",
                    accepted_stage="-", emitted_mod="-",
                    preserved_in_insertblock=0,
                    first_dropped_stage="postprocess",
                    final_status="lost",
                ),
            ]
        )
    )
    rows = parse_trace_log(log.read_text())
    rows = enrich_rows_with_db(rows, db)
    out = format_report(rows, func_label="sub_7FFD3338C040")
    assert "byte 3: `lost`" in out
    assert "first dropped at `postprocess`" in out
    assert "pre_d810" in out and "post_bundle_stabilize" in out
