"""Unit tests for the HCC unsupported_edge_kind explainer.

Covers verdict logic (safe-to-allow vs correct-rejection), target row
selection, formatting, and the full DB-join pipeline against an
in-memory SQLite fixture.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from tests.unit.core.diag._orm_bind import make_bound_diag_db
from d810.core.diag.models import (
    Block,
    FactObservation,
    Snapshot,
    StateCfgEdge,
    StateCfgNode,
    StateCfgNodeBlock,
)
from d810.diagnostics.hcc_byte_cascade_trace import ByteCascadeRow
from d810.diagnostics.hcc_unsupported_edge_kind_explainer import (
    ALLOWED_EDGE_KINDS,
    EdgeKindExplanation,
    REJECTION_CHECK_LABEL,
    RejectedEdgeRow,
    _parse_int_list,
    _parse_ordered_path,
    _verdict_for,
    explain,
    explain_byte,
    format_report,
    format_report_json,
    select_target_rows,
)


def _row(
    byte: int,
    *,
    candidate_rejection: str = "unsupported_edge_kind",
    block_serial: int | None = 100,
    block_ea: str = "0x180014f07",
) -> ByteCascadeRow:
    return ByteCascadeRow(
        byte=byte,
        block_ea=block_ea,
        block_serial=block_serial,
        entry_anchor=block_serial,
        dag_node="?",
        in_dag=True,
        in_corrected_dag=True,
        in_region_table=False,
        raw_candidate=False,
        candidate_rejection=candidate_rejection,
        accepted_stage="-",
        emitted_mod="-",
        preserved_in_insertblock=False,
        first_dropped_stage="-",
        final_status="region_detection_gap",
    )


# ---------------------------------------------------------------------------
# Constants exposed by the module
# ---------------------------------------------------------------------------


def test_allowed_edge_kinds_match_check_in_recon_builder():
    """Allowed kinds must match SemanticEdgeKind.{TRANSITION,CONDITIONAL_TRANSITION}.

    Update this test together with the rejection check in
    `d810.analyses.control_flow.reconstruction_candidate_builder.build_reconstruction_candidate`
    if the gate ever changes -- this assertion is the contract.
    """
    assert ALLOWED_EDGE_KINDS == {"TRANSITION", "CONDITIONAL_TRANSITION"}


def test_rejection_check_label_points_at_recon_builder():
    assert "reconstruction_candidate_builder" in REJECTION_CHECK_LABEL
    assert "build_reconstruction_candidate" in REJECTION_CHECK_LABEL


# ---------------------------------------------------------------------------
# Verdict logic
# ---------------------------------------------------------------------------


def _rejected_edge(
    *,
    edge_kind: str = "EXIT_ROUTINE",
    target_byte_facts: tuple[int, ...] = (),
    target_has_same_byte_fact: bool = False,
) -> RejectedEdgeRow:
    return RejectedEdgeRow(
        edge_id=0,
        source_block=100,
        source_state_hex="0xa",
        target_state_hex="0xb",
        target_entry_block=200,
        edge_kind=edge_kind,
        ordered_path=(),
        target_block_serials=(200,),
        target_byte_facts=target_byte_facts,
        target_has_same_byte_fact=target_has_same_byte_fact,
        cfg_source_succs=(),
        cfg_source_preds=(),
    )


def test_verdict_no_outgoing_when_no_rejected_edges():
    verdict, narrative = _verdict_for([])
    assert verdict == "no_outgoing_rejected_edges"
    assert "different state or snapshot" in narrative


def test_verdict_safe_to_allow_when_target_has_same_byte_fact():
    edges = [_rejected_edge(target_has_same_byte_fact=True)]
    verdict, narrative = _verdict_for(edges)
    assert verdict == "rejection_appears_safe_to_allow"
    assert "would NOT lose byte-cascade evidence" in narrative


def test_verdict_correct_when_no_byte_fact_on_target():
    edges = [_rejected_edge(target_has_same_byte_fact=False)]
    verdict, narrative = _verdict_for(edges)
    assert verdict == "rejection_appears_correct"
    assert "byte needs a different path" in narrative


def test_verdict_safe_when_at_least_one_edge_carries_the_byte_fact():
    """Mixed bag: one safe edge + one correct edge -> overall safe."""
    edges = [
        _rejected_edge(target_has_same_byte_fact=False),
        _rejected_edge(target_has_same_byte_fact=True),
    ]
    verdict, _ = _verdict_for(edges)
    assert verdict == "rejection_appears_safe_to_allow"


# ---------------------------------------------------------------------------
# Target row selection
# ---------------------------------------------------------------------------


def test_select_target_rows_default_picks_unsupported_edge_kind_only():
    rows = [
        _row(0, candidate_rejection="unsupported_edge_kind"),
        _row(1, candidate_rejection="-"),
        _row(2, candidate_rejection="missing_target_state"),
    ]
    selected = select_target_rows(rows, None)
    assert [r.byte for r in selected] == [0]


def test_select_target_rows_respects_explicit_bytes_filter():
    rows = [
        _row(0, candidate_rejection="-"),
        _row(2, candidate_rejection="unsupported_edge_kind"),
        _row(3, candidate_rejection="-"),
    ]
    selected = select_target_rows(rows, [0, 2])
    assert [r.byte for r in selected] == [0, 2]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_parse_int_list_handles_csv_and_whitespace():
    assert _parse_int_list("1 2 3") == (1, 2, 3)
    assert _parse_int_list("1, 2, 3") == (1, 2, 3)
    assert _parse_int_list("0x10 32") == (16, 32)


def test_parse_ordered_path_handles_json_array():
    assert _parse_ordered_path("[10, 20, 30]") == (10, 20, 30)


def test_parse_ordered_path_handles_whitespace_form():
    assert _parse_ordered_path("10 20 30") == (10, 20, 30)


def test_parse_ordered_path_handles_empty_input():
    assert _parse_ordered_path("") == ()


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------


def test_format_report_handles_empty_input():
    text = format_report([])
    assert "no `unsupported_edge_kind` rows found" in text


def test_format_report_renders_per_byte_section():
    explanation = EdgeKindExplanation(
        byte=2,
        block_ea="0x180014f07",
        block_serial=118,
        state_hex="0xabc",
        snapshot_id=7,
        rejected_edges=(_rejected_edge(),),
        verdict="rejection_appears_correct",
        narrative="byte needs a different path.",
    )
    text = format_report([explanation], func_label="sub_test")
    assert "## HCC unsupported_edge_kind Explainer for sub_test" in text
    # Allowed kinds line, rendered in sorted order.
    assert "CONDITIONAL_TRANSITION, TRANSITION" in text
    assert "build_reconstruction_candidate" in text
    assert "byte 2" in text
    assert "EXIT_ROUTINE" in text
    assert "rejection_appears_correct" in text


def test_format_report_json_round_trips():
    explanation = EdgeKindExplanation(
        byte=2,
        block_ea="0x180014f07",
        block_serial=118,
        state_hex="0xabc",
        snapshot_id=7,
        rejected_edges=(_rejected_edge(),),
        verdict="rejection_appears_correct",
        narrative="byte needs a different path.",
    )
    text = format_report_json([explanation])
    decoded = json.loads(text)
    assert decoded[0]["byte"] == 2
    assert decoded[0]["verdict"] == "rejection_appears_correct"
    assert decoded[0]["rejected_edges"][0]["edge_kind"] == "EXIT_ROUTINE"


# ---------------------------------------------------------------------------
# DB-join pipeline (in-memory SQLite)
# ---------------------------------------------------------------------------


@pytest.fixture
def in_memory_db() -> sqlite3.Connection:
    # make_bound_diag_db binds the Models so explain_byte's ORM reads
    # target this in-memory DB; the fixture returns the live connection.
    db = make_bound_diag_db()
    Snapshot.insert(
        id=7, label="GLBOPT1_post_d810", func_ea_hex="0x0", func_ea_i64=0,
        maturity="MMAT_GLBOPT1", phase="unknown", block_count=0, timestamp=0.0,
    ).execute()
    # byte's block 100 -> state A; A has 2 outgoing edges, both rejected
    # (one to safe target B with byte fact, one to non-byte target C).
    StateCfgNode.insert_many([
        dict(snapshot=7, state_hex="0xa", state_i64=10, entry_block=100,
             classification="EXACT", shared_suffix=None),
        dict(snapshot=7, state_hex="0xb", state_i64=11, entry_block=200,
             classification="EXACT", shared_suffix=None),
        dict(snapshot=7, state_hex="0xc", state_i64=12, entry_block=300,
             classification="EXACT", shared_suffix=None),
    ]).execute()
    StateCfgNodeBlock.insert_many([
        dict(snapshot=7, state_hex="0xa", entry_block=100, block_serial=100,
             block_index=0, role="owned"),
        dict(snapshot=7, state_hex="0xb", entry_block=200, block_serial=200,
             block_index=0, role="owned"),
        dict(snapshot=7, state_hex="0xc", entry_block=300, block_serial=300,
             block_index=0, role="owned"),
    ]).execute()
    StateCfgEdge.insert_many([
        dict(snapshot=7, edge_id=0, source_state_hex="0xa", source_state_i64=10,
             target_state_hex="0xb", target_state_i64=11,
             edge_kind="EXIT_ROUTINE", source_block=100, source_arm=None,
             target_entry=200, ordered_path="[100, 200]"),
        dict(snapshot=7, edge_id=1, source_state_hex="0xa", source_state_i64=10,
             target_state_hex="0xc", target_state_i64=12,
             edge_kind="CONDITIONAL_RETURN", source_block=100, source_arm=None,
             target_entry=300, ordered_path="[100, 300]"),
    ]).execute()
    Block.insert_many([
        dict(snapshot=7, serial=100, block_type=0, type_name="BLT_2WAY",
             nsucc=2, npred=0, succs="200 300", preds="[]", insn_count=0),
        dict(snapshot=7, serial=200, block_type=0, type_name="BLT_1WAY",
             nsucc=1, npred=1, succs="300", preds="[]", insn_count=0),
        dict(snapshot=7, serial=300, block_type=0, type_name="BLT_STOP",
             nsucc=0, npred=2, succs="", preds="[]", insn_count=0),
    ]).execute()
    # TerminalByteEmitterFact for byte 2 on block 200 (target B carries
    # byte 2's role; the EXIT_ROUTINE rejection looks safe to relax). No
    # fact on block 300 (target C is genuinely a non-byte path).
    FactObservation.insert(
        snapshot=7, func_ea_hex="f", func_ea_i64=1, fact_id="fact_b2",
        kind="TerminalByteEmitterFact", semantic_key="k",
        maturity="MMAT_GLBOPT1", phase="pre_d810", confidence=0.9,
        source_block=200,
        payload='{"byte_index": 2, "corridor_role": "terminal_tail"}',
        evidence="{}",
    ).execute()
    return db.connection()


def test_explain_byte_classifies_safe_to_allow_when_target_carries_byte_fact(
    in_memory_db,
):
    row = _row(2, block_serial=100)
    explanation = explain_byte(in_memory_db, row)
    assert explanation.state_hex == "0xa"
    assert explanation.snapshot_id == 7
    assert explanation.verdict == "rejection_appears_safe_to_allow"
    assert len(explanation.rejected_edges) == 2
    kinds = {e.edge_kind for e in explanation.rejected_edges}
    assert kinds == {"EXIT_ROUTINE", "CONDITIONAL_RETURN"}
    safe_edge = next(e for e in explanation.rejected_edges if e.edge_kind == "EXIT_ROUTINE")
    assert safe_edge.target_byte_facts == (2,)
    assert safe_edge.target_has_same_byte_fact is True


def test_explain_byte_classifies_correct_when_no_target_byte_fact(in_memory_db):
    """byte 9 doesn't appear on any target -> rejection is correct."""
    row = _row(9, block_serial=100)
    explanation = explain_byte(in_memory_db, row)
    assert explanation.verdict == "rejection_appears_correct"
    for e in explanation.rejected_edges:
        assert e.target_has_same_byte_fact is False


def test_explain_with_missing_db_returns_no_db_verdict_per_byte(tmp_path: Path):
    rows = [_row(2, block_serial=100)]
    explanations = explain(rows, tmp_path / "missing.sqlite3", bytes_filter=[2])
    assert len(explanations) == 1
    assert explanations[0].verdict == "no_db"
    assert "missing.sqlite3" in explanations[0].narrative


def test_explain_byte_no_state_for_block_returns_named_verdict(in_memory_db):
    """Block serial that has no state_cfg_node_blocks row -> no_state_for_block."""
    row = _row(2, block_serial=999)
    explanation = explain_byte(in_memory_db, row)
    assert explanation.verdict == "no_state_for_block"
    assert explanation.state_hex is None


def test_format_report_block_includes_edge_table_for_real_explanation(in_memory_db):
    row = _row(2, block_serial=100)
    explanation = explain_byte(in_memory_db, row)
    text = format_report([explanation])
    assert "EXIT_ROUTINE" in text
    assert "CONDITIONAL_RETURN" in text
    assert "rejection_appears_safe_to_allow" in text
    # Source block CFG shape should appear (succ list 200 300)
    assert "200" in text and "300" in text
