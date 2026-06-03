"""Tests for the HCC byte-cascade trace parser + report."""
from __future__ import annotations

import json
from pathlib import Path

from d810.core.diag import create_diag_database, diag_models_on
from d810.core.diag.models import Instruction, Snapshot
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
    source_eas: tuple[str, ...] = (),
    db_source_ea_survival: dict[str, dict[str, int]] | None = None,
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
        source_eas=source_eas,
        db_var190_refs=db_var190_refs or {},
        db_source_ea_survival=db_source_ea_survival or {},
    )


# Convenient default for refinement tests: byte K with one source EA and a
# per-snapshot survival map keyed by that same EA.
def _survival(snapshot_to_count: dict[str, int], ea: str) -> dict[str, dict[str, int]]:
    return {label: {ea: int(count)} for label, count in snapshot_to_count.items()}


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
    db_path = tmp_path / "diag.sqlite3"
    db = create_diag_database(str(db_path))
    with diag_models_on(db):
        snap5 = Snapshot.create(
            id=5, label="pre_d810", func_ea_hex="0x0000000000000000",
            func_ea_i64=0, maturity="GLBOPT1", phase="unknown",
            block_count=0, timestamp=0.0,
        )
        snap17 = Snapshot.create(
            id=17, label="post_bundle_stabilize", func_ea_hex="0x0000000000000000",
            func_ea_i64=0, maturity="GLBOPT1", phase="unknown",
            block_count=0, timestamp=0.0,
        )
        Snapshot.create(
            id=18, label="post_d810", func_ea_hex="0x0000000000000000",
            func_ea_i64=0, maturity="GLBOPT1", phase="unknown",
            block_count=0, timestamp=0.0,
        )
        Instruction.insert_many([
            dict(snapshot=snap5.id, block_serial=0, insn_index=0,
                 ea_hex="0x0000000000001000", ea_i64=0x1000,
                 opcode=0, opcode_name="stx",
                 dstr="stx ([ds.2:%var_190.8+#3.8].1)"),
            dict(snapshot=snap17.id, block_serial=0, insn_index=0,
                 ea_hex="0x0000000000001001", ea_i64=0x1001,
                 opcode=0, opcode_name="stx",
                 dstr="stx ([ds.2:%var_190.8+#3.8].1)"),
            dict(snapshot=snap17.id, block_serial=0, insn_index=1,
                 ea_hex="0x0000000000001002", ea_i64=0x1002,
                 opcode=0, opcode_name="stx",
                 dstr="stx ([ds.2:%var_190.8+#3.8].1) second copy"),
            dict(snapshot=snap5.id, block_serial=0, insn_index=1,
                 ea_hex="0x0000000000001003", ea_i64=0x1003,
                 opcode=0, opcode_name="stx",
                 dstr="stx ([ds.2:%var_190.8+#6.8].1)"),
        ]).execute()
    db.close()
    return db_path


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
    assert refs_byte3.get("post_d810") == 0
    assert refs_byte6.get("pre_d810") == 1
    assert refs_byte6.get("post_bundle_stabilize") == 0
    assert refs_byte6.get("post_d810") == 0


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


# ---------------------------------------------------------------------------
# preserved_redirect refinement (snap17 -> snap18 EA cross-check)
# ---------------------------------------------------------------------------


def test_final_status_refined_passthrough_for_non_preserved_redirect() -> None:
    """The refinement is a no-op for every status other than
    `preserved_redirect`."""
    for status in (
        "preserved_insertblock",
        "redirected_away",
        "region_detection_gap",
        "unmaterialized_original_block",
        "no_dag_evidence",
        "lost",
        "unknown",
    ):
        row = _row(byte=2, final_status=status)
        assert row.final_status_refined == status


def test_final_status_refined_leaves_preserved_redirect_when_db_absent() -> None:
    """If there's no diag-DB enrichment, we can't decide and must keep the
    original status."""
    row = _row(byte=3, final_status="preserved_redirect")
    assert row.final_status_refined == "preserved_redirect"


def test_final_status_refined_with_evidence_when_post_d810_has_refs() -> None:
    """Per-source-EA survival at a finalization snapshot promotes the
    refined status to ``preserved_redirect_with_evidence``."""
    ea = "0x180014d10"
    row = _row(
        byte=3, final_status="preserved_redirect",
        source_eas=(ea,),
        db_source_ea_survival=_survival(
            {
                "pre_d810": 1,
                "maturity_MMAT_GLBOPT1_post_d810": 1,
            },
            ea=ea,
        ),
    )
    assert row.final_status_refined == "preserved_redirect_with_evidence"


def test_final_status_refined_ignores_early_post_d810_refs() -> None:
    """LOCOPT / CALLS post_d810 snapshots predate HCC's GLBOPT1
    finalization. They can still contain the byte's EA and must NOT mask
    the snap17 -> snap18 loss.
    """
    ea = "0x180014d10"
    row = _row(
        byte=3, final_status="preserved_redirect",
        source_eas=(ea,),
        db_source_ea_survival=_survival(
            {
                "maturity_MMAT_LOCOPT_post_d810": 1,
                "maturity_MMAT_CALLS_post_d810": 1,
                "maturity_MMAT_GLBOPT1_post_d810": 0,
                "maturity_MMAT_GLBOPT2_pre_d810": 0,
                "dump_raw_sub_7FFD3338C040_GLBOPT1": 1,
            },
            ea=ea,
        ),
    )
    assert row.final_status_refined == "redirect_only_finalization_loss"


def test_final_status_refined_counts_dump_d810_lvars_refs() -> None:
    ea = "0x180014e10"
    row = _row(
        byte=6, final_status="preserved_redirect",
        source_eas=(ea,),
        db_source_ea_survival=_survival(
            {
                "maturity_MMAT_GLBOPT1_post_d810": 0,
                "dump_d810_sub_7FFD3338C040": 1,
            },
            ea=ea,
        ),
    )
    assert row.final_status_refined == "preserved_redirect_with_evidence"


def test_final_status_refined_finalization_loss_when_post_d810_is_zero() -> None:
    ea = "0x180014e10"
    row = _row(
        byte=6, final_status="preserved_redirect",
        source_eas=(ea,),
        db_source_ea_survival=_survival(
            {
                "pre_d810": 1,
                "post_bundle_stabilize": 2,
                "maturity_MMAT_GLBOPT1_post_d810": 0,
            },
            ea=ea,
        ),
    )
    assert row.final_status_refined == "redirect_only_finalization_loss"


def test_final_status_refined_treats_mmat_lvars_as_post_d810() -> None:
    """``MMAT_LVARS`` snapshots are downstream of optimize_global and
    count the same way as ``post_d810`` for the refinement decision."""
    ea = "0x180014f10"
    row = _row(
        byte=4, final_status="preserved_redirect",
        source_eas=(ea,),
        db_source_ea_survival=_survival(
            {"pre_d810": 1, "MMAT_LVARS_pre_d810": 0},
            ea=ea,
        ),
    )
    assert row.final_status_refined == "redirect_only_finalization_loss"


def test_final_status_refined_keeps_status_when_no_post_d810_snapshot() -> None:
    """When the DB doesn't have any snapshot tagged post_d810 / MMAT_LVARS,
    we can't make the call -- keep the original preserved_redirect verdict
    instead of falsely promoting/demoting it."""
    ea = "0x180014abc"
    row = _row(
        byte=5, final_status="preserved_redirect",
        source_eas=(ea,),
        db_source_ea_survival=_survival(
            {"pre_d810": 1, "post_bundle_stabilize": 1},
            ea=ea,
        ),
    )
    assert row.final_status_refined == "preserved_redirect"


def test_final_status_refined_requires_source_eas() -> None:
    """A row with NO ``source_eas`` cannot be refined; broad var_190
    counts no longer drive the decision."""
    row = _row(
        byte=3, final_status="preserved_redirect",
        source_eas=(),
        db_var190_refs={"maturity_MMAT_GLBOPT1_post_d810": 0},
    )
    assert row.final_status_refined == "preserved_redirect"


def test_final_status_refined_promotes_if_any_source_ea_survives() -> None:
    """A byte with multiple source EAs is preserved if ANY of them
    survives at any finalization snapshot."""
    ea1, ea2 = "0x180014d10", "0x180014d20"
    row = _row(
        byte=3, final_status="preserved_redirect",
        source_eas=(ea1, ea2),
        db_source_ea_survival={
            "maturity_MMAT_GLBOPT1_post_d810": {ea1: 0, ea2: 1},
        },
    )
    assert row.final_status_refined == "preserved_redirect_with_evidence"


def test_report_table_shows_refined_status_column() -> None:
    ea_lost = "0x180014d10"
    ea_keep = "0x180014e10"
    rows = [
        _row(
            byte=3, final_status="preserved_redirect",
            source_eas=(ea_lost,),
            db_source_ea_survival=_survival(
                {"pre_d810": 1, "maturity_MMAT_GLBOPT1_post_d810": 0},
                ea=ea_lost,
            ),
        ),
        _row(
            byte=6, final_status="preserved_redirect",
            source_eas=(ea_keep,),
            db_source_ea_survival=_survival(
                {"pre_d810": 1, "maturity_MMAT_GLBOPT1_post_d810": 1},
                ea=ea_keep,
            ),
        ),
    ]
    out = format_report(rows)
    assert "final_refined" in out
    # byte 3: refined -> redirect_only_finalization_loss (post_d810=0).
    assert "redirect_only_finalization_loss" in out
    # byte 6: refined -> preserved_redirect_with_evidence (post_d810>0).
    assert "preserved_redirect_with_evidence" in out


def test_summary_uses_refined_status_for_byte3_loss() -> None:
    """A `preserved_redirect` row that the refinement reclassifies into
    `redirect_only_finalization_loss` must appear in the loss summary
    (it was a false success before)."""
    ea = "0x180014d10"
    rows = [
        _row(
            byte=3, final_status="preserved_redirect",
            first_dropped_stage="-",
            source_eas=(ea,),
            db_source_ea_survival=_survival(
                {"pre_d810": 1, "maturity_MMAT_GLBOPT1_post_d810": 0},
                ea=ea,
            ),
        ),
    ]
    out = format_report(rows)
    assert "byte 3: `redirect_only_finalization_loss`" in out
    assert "optimize_global DCE" in out


def test_summary_skips_refined_preserved_with_evidence() -> None:
    """A preserved_redirect row promoted to
    `preserved_redirect_with_evidence` must NOT appear in the loss
    summary."""
    ea = "0x180014e10"
    rows = [
        _row(
            byte=6, final_status="preserved_redirect",
            source_eas=(ea,),
            db_source_ea_survival=_survival(
                {"pre_d810": 1, "maturity_MMAT_GLBOPT1_post_d810": 1},
                ea=ea,
            ),
        ),
    ]
    out = format_report(rows)
    # No "### Summary" block since the only row is preserved.
    assert "byte 6:" not in out.split("### Summary")[-1] or "### Summary" not in out


def test_to_dict_emits_refined_status_and_source_eas() -> None:
    ea = "0x180014d10"
    row = _row(
        byte=3, final_status="preserved_redirect",
        source_eas=(ea, "0x180014d20"),
        db_source_ea_survival=_survival(
            {"pre_d810": 1, "maturity_MMAT_GLBOPT1_post_d810": 0},
            ea=ea,
        ),
    )
    payload = row.to_dict()
    assert payload["final_status_refined"] == "redirect_only_finalization_loss"
    assert payload["source_eas"] == [ea, "0x180014d20"]
    assert "db_source_ea_survival" in payload
    assert payload["db_source_ea_survival"]["maturity_MMAT_GLBOPT1_post_d810"][ea] == 0


# ---------------------------------------------------------------------------
# Parser: source_eas tokenisation
# ---------------------------------------------------------------------------


def test_parse_trace_line_pulls_source_eas() -> None:
    body = _line(
        byte=3, block_ea="0x180014D00", block_serial=163, entry_anchor=163,
        dag_node="STATE_X", in_dag=1, in_corrected_dag=1, in_region_table=0,
        raw_candidate=1, candidate_rejection="-",
        accepted_stage="-", emitted_mod="-", preserved_in_insertblock=0,
        first_dropped_stage="-", final_status="preserved_redirect",
    )
    # Tracer emits source_eas after n_evidence and before in_dag; inject it.
    body = body.replace(
        "block_ea=0x180014D00",
        "block_ea=0x180014D00 source_eas=0x180014D10,0x180014D20",
    )
    row = parse_trace_line(body)
    assert row is not None
    assert row.source_eas == ("0x180014D10", "0x180014D20")


def test_enrich_populates_db_source_ea_survival(tmp_path: Path) -> None:
    """``_count_source_ea_survival_per_snapshot`` (driven via
    ``enrich_rows_with_db``) returns a per-snapshot per-EA survival map
    keyed by lowercase 16-digit hex, matching the diag DB schema."""
    db_path = tmp_path / "src_ea.sqlite3"
    db = create_diag_database(str(db_path))
    with diag_models_on(db):
        snap5 = Snapshot.create(
            id=5, label="maturity_MMAT_GLBOPT1_pre_d810",
            func_ea_hex="0x0000000000000000", func_ea_i64=0,
            maturity="MMAT_GLBOPT1", phase="unknown",
            block_count=0, timestamp=0.0,
        )
        snap18 = Snapshot.create(
            id=18, label="maturity_MMAT_GLBOPT1_post_d810",
            func_ea_hex="0x0000000000000000", func_ea_i64=0,
            maturity="MMAT_GLBOPT1", phase="unknown",
            block_count=0, timestamp=0.0,
        )
        Instruction.insert_many([
            dict(snapshot=snap5.id, block_serial=0, insn_index=0,
                 ea_hex="0x0000000180014d10", ea_i64=0x180014d10,
                 opcode=0, opcode_name="stx", dstr="stx ..."),
            dict(snapshot=snap5.id, block_serial=0, insn_index=1,
                 ea_hex="0x0000000180014d20", ea_i64=0x180014d20,
                 opcode=0, opcode_name="stx", dstr="stx ..."),
            dict(snapshot=snap18.id, block_serial=0, insn_index=0,
                 ea_hex="0x0000000180014d20", ea_i64=0x180014d20,
                 opcode=0, opcode_name="stx", dstr="stx ..."),
        ]).execute()
    db.close()
    # Tracer emits uppercase 16-digit hex; the helper normalises to lower.
    row = _row(
        byte=3, final_status="preserved_redirect",
        source_eas=("0x0000000180014D10", "0x0000000180014D20"),
    )
    [enriched] = enrich_rows_with_db([row], db_path)
    survival = enriched.db_source_ea_survival
    assert (
        survival["maturity_MMAT_GLBOPT1_pre_d810"]["0x0000000180014d10"] == 1
    )
    assert (
        survival["maturity_MMAT_GLBOPT1_pre_d810"]["0x0000000180014d20"] == 1
    )
    # Byte's first EA is dead post_d810; second survives.
    assert (
        survival["maturity_MMAT_GLBOPT1_post_d810"]["0x0000000180014d10"] == 0
    )
    assert (
        survival["maturity_MMAT_GLBOPT1_post_d810"]["0x0000000180014d20"] == 1
    )
    # Refinement still promotes because at least one source EA survives.
    assert enriched.final_status_refined == "preserved_redirect_with_evidence"


def test_enrich_marks_redirect_only_finalization_loss_when_all_source_eas_dead(
    tmp_path: Path,
) -> None:
    """A byte whose every source EA is gone at post_d810 demotes to
    `redirect_only_finalization_loss` after enrichment."""
    db_path = tmp_path / "all_dead.sqlite3"
    db = create_diag_database(str(db_path))
    with diag_models_on(db):
        snap5 = Snapshot.create(
            id=5, label="maturity_MMAT_GLBOPT1_pre_d810",
            func_ea_hex="0x0000000000000000", func_ea_i64=0,
            maturity="MMAT_GLBOPT1", phase="unknown",
            block_count=0, timestamp=0.0,
        )
        Snapshot.create(
            id=18, label="maturity_MMAT_GLBOPT1_post_d810",
            func_ea_hex="0x0000000000000000", func_ea_i64=0,
            maturity="MMAT_GLBOPT1", phase="unknown",
            block_count=0, timestamp=0.0,
        )
        # snap5 has the EA; snap18 has nothing matching.
        Instruction.insert(
            snapshot=snap5.id, block_serial=0, insn_index=0,
            ea_hex="0x0000000180014d10", ea_i64=0x180014d10,
            opcode=0, opcode_name="stx", dstr="stx ...",
        ).execute()
    db.close()
    row = _row(
        byte=3, final_status="preserved_redirect",
        source_eas=("0x0000000180014D10",),
    )
    [enriched] = enrich_rows_with_db([row], db_path)
    assert enriched.final_status_refined == "redirect_only_finalization_loss"


def test_parse_trace_line_treats_dash_source_eas_as_empty_tuple() -> None:
    body = _line(
        byte=2, block_ea="0x0", block_serial=0, entry_anchor=0,
        dag_node="?", in_dag=1, in_corrected_dag=1, in_region_table=0,
        raw_candidate=0, candidate_rejection="-",
        accepted_stage="-", emitted_mod="-", preserved_in_insertblock=0,
        first_dropped_stage="-", final_status="region_detection_gap",
    )
    body = body.replace(
        "block_ea=0x0", "block_ea=0x0 source_eas=-",
    )
    row = parse_trace_line(body)
    assert row is not None
    assert row.source_eas == ()
