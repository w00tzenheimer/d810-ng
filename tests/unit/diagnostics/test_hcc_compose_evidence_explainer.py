"""Unit tests for the HCC Compose Evidence Explainer.

Covers bucket priority ordering, target row selection, region log
parsing, formatting, and the full DB-join pipeline against an
in-memory SQLite fixture.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from d810.diagnostics.hcc_byte_cascade_trace import ByteCascadeRow
from d810.diagnostics.hcc_compose_evidence_explainer import (
    ComposeEvidenceExplanation,
    ModRow,
    RegionLoweringHit,
    _parse_region_lowering_log,
    _region_hits_for_block,
    classify,
    explain,
    explain_byte,
    format_report,
    format_report_json,
    select_target_rows,
)


def _row(
    byte: int,
    *,
    final_status: str = "unmaterialized_original_block",
    block_serial: int | None = 118,
    block_ea: str = "0x180014f07",
    preserved_in_insertblock: bool = False,
) -> ByteCascadeRow:
    return ByteCascadeRow(
        byte=byte,
        block_ea=block_ea,
        block_serial=block_serial,
        entry_anchor=block_serial,
        dag_node="?",
        in_dag=True,
        in_corrected_dag=True,
        in_region_table=True,
        raw_candidate=True,
        candidate_rejection="-",
        accepted_stage="-",
        emitted_mod="-",
        preserved_in_insertblock=preserved_in_insertblock,
        first_dropped_stage="-",
        final_status=final_status,
    )


def _mod(
    *,
    mod_index: int = 0,
    mod_type: str = "RedirectGoto",
    source_block: int | None = None,
    target_block: int | None = None,
    old_target: int | None = None,
    role: str = "source_block",
) -> ModRow:
    return ModRow(
        mod_index=mod_index,
        mod_type=mod_type,
        source_block=source_block,
        target_block=target_block,
        old_target=old_target,
        status="emitted",
        reason=None,
        role=role,
    )


# ---------------------------------------------------------------------------
# Bucket priority -- one test per bucket, in priority order
# ---------------------------------------------------------------------------


def test_no_mod_touches_block_when_modifications_are_empty():
    explanation = classify(_row(2), [], [], snapshot_id=7)
    assert explanation.bucket == "no_mod_touches_block"
    assert explanation.first_responsible_step == "compose_region"


def test_inconsistency_when_preserved_in_insertblock_with_any_mod():
    """preserved_in_insertblock=1 + unmaterialized + a mod touches block ->
    flag the inconsistency rather than picking a structural bucket."""
    explanation = classify(
        _row(2, preserved_in_insertblock=True),
        [_mod(mod_type="InsertBlock", target_block=118, role="target_block")],
        [],
        snapshot_id=7,
    )
    assert explanation.bucket == "insertblock_with_evidence_inconsistency"


def test_insertblock_succ_no_byte_evidence_when_insertblock_present_and_not_preserved():
    explanation = classify(
        _row(2, preserved_in_insertblock=False),
        [_mod(mod_type="InsertBlock", target_block=118, role="target_block")],
        [],
        snapshot_id=7,
    )
    assert explanation.bucket == "insertblock_succ_no_byte_evidence"
    assert explanation.first_responsible_step == "compose_region.body_filter"


def test_redirected_away_only_when_block_is_only_redirect_source():
    explanation = classify(
        _row(2),
        [_mod(mod_type="RedirectGoto", source_block=118, role="source_block")],
        [],
        snapshot_id=7,
    )
    assert explanation.bucket == "redirected_away_only"
    assert explanation.first_responsible_step == "compose_region.exit_wiring"


def test_redirect_target_only_no_evidence_when_block_is_only_target():
    explanation = classify(
        _row(2),
        [_mod(mod_type="RedirectGoto", target_block=118, role="target_block")],
        [],
        snapshot_id=7,
    )
    assert explanation.bucket == "redirect_target_only_no_evidence"


def test_redirect_target_only_when_block_is_old_target():
    """old_target role still counts as target-side."""
    explanation = classify(
        _row(2),
        [_mod(mod_type="RedirectGoto", old_target=118, role="old_target")],
        [],
        snapshot_id=7,
    )
    assert explanation.bucket == "redirect_target_only_no_evidence"


def test_unclassified_when_mod_kind_is_unknown():
    """A mod that isn't a redirect or InsertBlock falls into the catch-all."""
    explanation = classify(
        _row(2),
        [_mod(mod_type="ZeroStateWrite", source_block=118, role="source_block")],
        [],
        snapshot_id=7,
    )
    assert explanation.bucket == "unclassified"


# ---------------------------------------------------------------------------
# Target row selection
# ---------------------------------------------------------------------------


def test_select_target_rows_default_picks_unmaterialized_only():
    rows = [
        _row(0, final_status="preserved_redirect"),
        _row(2, final_status="unmaterialized_original_block"),
        _row(4, final_status="unmaterialized_original_block"),
    ]
    assert [r.byte for r in select_target_rows(rows, None)] == [2, 4]


def test_select_target_rows_with_explicit_filter():
    rows = [
        _row(0, final_status="preserved_redirect"),
        _row(2, final_status="unmaterialized_original_block"),
    ]
    assert [r.byte for r in select_target_rows(rows, [0])] == [0]


# ---------------------------------------------------------------------------
# REGION_LOWERING_CANDIDATE log parser
# ---------------------------------------------------------------------------


_SAMPLE_REGION_LOG = """
2026-05-12 00:11:46,019 - D810.hodur.strategy.handler_chain_composer - INFO -  - MMAT_GLBOPT1 - REGION_LOWERING_CANDIDATE
  phase=PRE_COMPOSE
  head_state=0x610BB4D9 head_entry=blk[8]
  tail_state=0x610BB4D9 exit_target=blk[106]
  old_physical_pred=None
  transition_sources=[blk[192]]
  nontransition_sources=[blk[118]]
  splice_source_block=blk[192]
  splice_old_target=blk[2]
  proposed_splice=blk[192] --replace 192->2--> inserted(copy handlers=[blk[8]]) -> blk[106]
  eligibility=UNCONDITIONAL_1WAY
  reason='single TRANSITION source is a 1-way block; semantic splice eligible'
  divergence_from_old=UNKNOWN
  same_batch_regions_total=10
  source_covered_by_other_region=False
  yes_handlers_subclass=N/A
"""


def test_parse_region_lowering_log_extracts_named_fields():
    entries = _parse_region_lowering_log(_SAMPLE_REGION_LOG)
    assert len(entries) == 1
    e = entries[0]
    assert e["head_state"] == "0x610BB4D9"
    assert e["head_entry"] == 8
    assert e["splice_source_block"] == 192
    assert e["transition_sources"] == (192,)
    assert e["nontransition_sources"] == (118,)
    assert e["eligibility"] == "UNCONDITIONAL_1WAY"
    assert "single TRANSITION source" in e["reason"]


def test_region_hits_for_block_finds_role_when_block_is_nontransition_source():
    entries = _parse_region_lowering_log(_SAMPLE_REGION_LOG)
    hits = _region_hits_for_block(entries, 118)
    assert len(hits) == 1
    assert hits[0].head_state_hex == "0x610BB4D9"
    assert hits[0].eligibility == "UNCONDITIONAL_1WAY"
    assert "nontransition_source" in hits[0].role


def test_region_hits_returns_empty_when_block_not_mentioned():
    entries = _parse_region_lowering_log(_SAMPLE_REGION_LOG)
    assert _region_hits_for_block(entries, 999) == []


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------


def test_format_report_handles_empty_input():
    text = format_report([])
    assert "no `unmaterialized_original_block` rows" in text


def test_format_report_renders_per_byte_section():
    explanation = ComposeEvidenceExplanation(
        byte=2,
        block_ea="0x180014f07",
        block_serial=118,
        snapshot_id=7,
        bucket="no_mod_touches_block",
        first_responsible_step="compose_region",
        narrative="byte's block is in HCC's raw region table but no mod...",
        preserved_in_insertblock=False,
        mod_rows=(),
        region_hits=(
            RegionLoweringHit(
                head_state_hex="0x610BB4D9",
                head_entry=8,
                tail_state_hex="0x610BB4D9",
                eligibility="UNCONDITIONAL_1WAY",
                reason="splice eligible",
                splice_source_block=192,
                exit_target="blk[106]",
                role="nontransition_source",
            ),
        ),
    )
    text = format_report([explanation], func_label="sub_test")
    assert "## HCC Compose Evidence Explainer for sub_test" in text
    assert "no_mod_touches_block" in text
    assert "compose_region" in text
    assert "0x180014f07" in text
    assert "REGION_LOWERING_CANDIDATE" in text
    assert "0x610BB4D9" in text


def test_format_report_json_round_trips():
    explanation = ComposeEvidenceExplanation(
        byte=2,
        block_ea="0x180014f07",
        block_serial=118,
        snapshot_id=7,
        bucket="no_mod_touches_block",
        first_responsible_step="compose_region",
        narrative="x",
        preserved_in_insertblock=False,
        mod_rows=(),
        region_hits=(),
    )
    text = format_report_json([explanation])
    decoded = json.loads(text)
    assert decoded[0]["byte"] == 2
    assert decoded[0]["bucket"] == "no_mod_touches_block"


# ---------------------------------------------------------------------------
# DB-join pipeline (in-memory SQLite)
# ---------------------------------------------------------------------------


@pytest.fixture
def in_memory_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.executescript(
        """
        CREATE TABLE snapshots (id INTEGER PRIMARY KEY, label TEXT);
        CREATE TABLE modifications (
            snapshot_id INTEGER, mod_index INTEGER, mod_type TEXT,
            source_block INTEGER, target_block INTEGER, old_target INTEGER,
            write_site_ea_hex TEXT, write_site_ea_i64 INTEGER,
            write_site_blk INTEGER, status TEXT, reason TEXT,
            PRIMARY KEY (snapshot_id, mod_index)
        );
        INSERT INTO snapshots VALUES (7, 'hcc_post_apply');
        -- block 200 is the target of an InsertBlock; trace will say
        -- preserved_in_insertblock=0 -> insertblock_succ_no_byte_evidence.
        INSERT INTO modifications VALUES
            (7, 0, 'InsertBlock', 199, 200, 201, NULL, NULL, NULL, 'emitted', NULL);
        -- block 300 is the source of a redirect (rewired away).
        INSERT INTO modifications VALUES
            (7, 1, 'RedirectGoto', 300, 999, 998, NULL, NULL, NULL, 'emitted', NULL);
        -- block 400 is only a target of redirects.
        INSERT INTO modifications VALUES
            (7, 2, 'RedirectGoto', 401, 400, 999, NULL, NULL, NULL, 'emitted', NULL);
        -- block 500 has no mod referencing it.
        """
    )
    conn.commit()
    return conn


def test_explain_byte_no_mod_touches_block_when_block_500(in_memory_db):
    row = _row(4, block_serial=500)
    explanation = explain_byte(in_memory_db, row, region_entries=[])
    assert explanation.bucket == "no_mod_touches_block"
    assert explanation.snapshot_id == 7


def test_explain_byte_insertblock_succ_no_byte_evidence_when_block_200(in_memory_db):
    row = _row(2, block_serial=200, preserved_in_insertblock=False)
    explanation = explain_byte(in_memory_db, row, region_entries=[])
    assert explanation.bucket == "insertblock_succ_no_byte_evidence"
    # Block appears as target_block of the InsertBlock.
    assert any(m.mod_type == "InsertBlock" for m in explanation.mod_rows)


def test_explain_byte_redirected_away_only_when_block_300(in_memory_db):
    row = _row(5, block_serial=300)
    explanation = explain_byte(in_memory_db, row, region_entries=[])
    assert explanation.bucket == "redirected_away_only"


def test_explain_byte_redirect_target_only_when_block_400(in_memory_db):
    row = _row(6, block_serial=400)
    explanation = explain_byte(in_memory_db, row, region_entries=[])
    assert explanation.bucket == "redirect_target_only_no_evidence"


def test_explain_with_missing_db_falls_back_to_trace_only(tmp_path: Path):
    rows = [_row(2, block_serial=118)]
    explanations = explain(
        rows, tmp_path / "missing.sqlite3", "", bytes_filter=[2],
    )
    assert len(explanations) == 1
    # No DB -> no mods -> no_mod_touches_block (trace-only fallback).
    assert explanations[0].bucket == "no_mod_touches_block"


def test_explain_attaches_region_hits_when_log_provided(in_memory_db):
    row = _row(2, block_serial=118)
    entries = _parse_region_lowering_log(_SAMPLE_REGION_LOG)
    explanation = explain_byte(in_memory_db, row, region_entries=entries)
    assert len(explanation.region_hits) == 1
    assert explanation.region_hits[0].eligibility == "UNCONDITIONAL_1WAY"
