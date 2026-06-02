"""Unit tests for the HCC Region Admission Explainer classifier.

Covers the priority ordering of bucket assignment and the
formatting/no-DB fallback path. DB-side joins are exercised by an
in-memory SQLite fixture.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from d810.core.diag import create_diag_database
from d810.core.diag.models import (
    RegionShapeFeature,
    Snapshot,
    StateCfgEdge,
    StateCfgNode,
    StateCfgNodeBlock,
)
from d810.diagnostics.hcc_byte_cascade_trace import ByteCascadeRow
from d810.diagnostics.hcc_region_admission_explainer import (
    AdmissionEvidence,
    MIN_ADMISSIBLE_CHAIN_LEN,
    classify,
    explain,
    format_report,
    format_report_json,
    gather_evidence,
    gather_evidence_no_db,
    select_target_rows,
)


def _row(
    byte: int,
    *,
    final_status: str = "region_detection_gap",
    candidate_rejection: str = "-",
    accepted_stage: str = "-",
    first_dropped_stage: str = "-",
    raw_candidate: bool = False,
    in_dag: bool = True,
    in_corrected_dag: bool = True,
    in_region_table: bool = False,
    block_serial: int | None = 100,
    block_ea: str = "0x180014000",
) -> ByteCascadeRow:
    return ByteCascadeRow(
        byte=byte,
        block_ea=block_ea,
        block_serial=block_serial,
        entry_anchor=block_serial,
        dag_node="?",
        in_dag=in_dag,
        in_corrected_dag=in_corrected_dag,
        in_region_table=in_region_table,
        raw_candidate=raw_candidate,
        candidate_rejection=candidate_rejection,
        accepted_stage=accepted_stage,
        emitted_mod="-",
        preserved_in_insertblock=False,
        first_dropped_stage=first_dropped_stage,
        final_status=final_status,
    )


def _empty_evidence(byte: int = 4) -> AdmissionEvidence:
    return AdmissionEvidence(
        byte=byte,
        block_serial=100,
        block_ea="0x180014000",
        state_hex=None,
        snapshot_id=None,
        dag_pred_count=0,
        dag_succ_count=0,
        chain_size=0,
        neighbors_admitted=0,
        neighbor_state_hexes=(),
    )


# ---------------------------------------------------------------------------
# Bucket priority -- one test per bucket, in priority order
# ---------------------------------------------------------------------------


def test_candidate_rejection_wins_over_everything_else():
    row = _row(
        2,
        candidate_rejection="unsupported_edge_kind",
        first_dropped_stage="call_barrier_collision",  # would otherwise win
        accepted_stage="postprocess",
    )
    explanation = classify(row, _empty_evidence(2))
    assert explanation.bucket == "candidate_rejected_pre_raw_region"
    assert explanation.first_responsible_stage == "candidate_build"


def test_call_barrier_collision_wins_when_no_candidate_rejection():
    row = _row(
        3,
        candidate_rejection="-",
        first_dropped_stage="call_barrier_collision",
    )
    explanation = classify(row, _empty_evidence(3))
    assert explanation.bucket == "call_barrier_collision"
    assert explanation.first_responsible_stage == "call_barrier_collision"


def test_payload_filter_wins_when_dropped_at_payload_stage():
    row = _row(
        4,
        candidate_rejection="-",
        first_dropped_stage="payload_intermediate_filter",
    )
    explanation = classify(row, _empty_evidence(4))
    assert explanation.bucket == "payload_or_intermediate_filter"
    assert explanation.first_responsible_stage == "payload_intermediate_filter"


def test_corridor_filter_also_maps_to_payload_or_intermediate_bucket():
    row = _row(4, first_dropped_stage="corridor_filter")
    assert (
        classify(row, _empty_evidence(4)).bucket
        == "payload_or_intermediate_filter"
    )


def test_region_table_merge_loss_when_accepted_via_fallback_without_raw_candidate():
    row = _row(
        5,
        candidate_rejection="-",
        accepted_stage="postprocess",
        raw_candidate=False,
    )
    explanation = classify(row, _empty_evidence(5))
    assert explanation.bucket == "region_table_merge_loss"
    assert explanation.first_responsible_stage == "raw_region_table"


def test_fallback_with_raw_candidate_does_not_match_merge_loss_bucket():
    """raw_candidate=True means HCC built a real candidate; fallback then
    isn't a merge loss. Falls through to the chain-based diagnostics."""
    row = _row(
        5,
        accepted_stage="postprocess",
        raw_candidate=True,  # raw candidate existed -> not a merge loss
    )
    explanation = classify(
        row,
        AdmissionEvidence(
            byte=5,
            block_serial=100,
            block_ea="0x180014000",
            state_hex="0xabc",
            snapshot_id=7,
            dag_pred_count=2,
            dag_succ_count=2,
            chain_size=10,
            neighbors_admitted=3,
            neighbor_state_hexes=("0x1", "0x2", "0x3"),
        ),
    )
    assert explanation.bucket == "no_accepted_pred_or_succ"


def test_not_in_chain_when_dag_node_has_no_neighbors():
    row = _row(4, candidate_rejection="-", accepted_stage="-")
    explanation = classify(row, _empty_evidence(4))
    assert explanation.bucket == "not_in_chain"
    assert explanation.first_responsible_stage == "seed_dag"


def test_chain_too_short_when_chain_below_threshold():
    assert MIN_ADMISSIBLE_CHAIN_LEN == 3, (
        "test relies on the documented threshold; update both together"
    )
    row = _row(4, candidate_rejection="-", accepted_stage="-")
    evidence = AdmissionEvidence(
        byte=4,
        block_serial=100,
        block_ea="0x180014000",
        state_hex="0xabc",
        snapshot_id=7,
        dag_pred_count=1,
        dag_succ_count=0,
        chain_size=2,  # < MIN_ADMISSIBLE_CHAIN_LEN
        neighbors_admitted=0,
        neighbor_state_hexes=("0x1",),
    )
    explanation = classify(row, evidence)
    assert explanation.bucket == "chain_too_short"
    assert explanation.first_responsible_stage == "raw_region_table"


def test_no_accepted_pred_or_succ_is_the_catch_all():
    row = _row(4, candidate_rejection="-", accepted_stage="-")
    evidence = AdmissionEvidence(
        byte=4,
        block_serial=100,
        block_ea="0x180014000",
        state_hex="0xabc",
        snapshot_id=7,
        dag_pred_count=2,
        dag_succ_count=2,
        chain_size=10,
        neighbors_admitted=0,
        neighbor_state_hexes=("0x1", "0x2", "0x3"),
    )
    explanation = classify(row, evidence)
    assert explanation.bucket == "no_accepted_pred_or_succ"
    assert explanation.first_responsible_stage == "raw_region_table"


# ---------------------------------------------------------------------------
# Target row selection
# ---------------------------------------------------------------------------


def test_select_target_rows_default_picks_region_detection_gap_only():
    rows = [
        _row(0, final_status="preserved_redirect"),
        _row(2, final_status="region_detection_gap"),
        _row(4, final_status="region_detection_gap"),
    ]
    selected = select_target_rows(rows, None)
    assert [r.byte for r in selected] == [2, 4]


def test_select_target_rows_with_explicit_bytes_overrides_default_filter():
    rows = [
        _row(0, final_status="preserved_redirect"),
        _row(2, final_status="region_detection_gap"),
    ]
    selected = select_target_rows(rows, [0, 5])
    assert [r.byte for r in selected] == [0]


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------


def test_format_report_emits_per_byte_verdict_lines():
    row = _row(
        2,
        candidate_rejection="unsupported_edge_kind",
        block_ea="0x180014f07",
    )
    explanation = classify(row, _empty_evidence(2))
    text = format_report([explanation], func_label="sub_test")
    assert "## HCC Region Admission Explainer for sub_test" in text
    assert "0x180014f07" in text
    assert "candidate_rejected_pre_raw_region" in text
    assert "candidate_build" in text
    assert "unsupported_edge_kind" in text


def test_format_report_handles_empty_input():
    text = format_report([])
    assert "no `region_detection_gap` rows found" in text


def test_format_report_json_round_trips_via_dataclass_dict():
    row = _row(2, candidate_rejection="unsupported_edge_kind")
    explanation = classify(row, _empty_evidence(2))
    text = format_report_json([explanation])
    assert '"bucket": "candidate_rejected_pre_raw_region"' in text
    assert '"byte": 2' in text


# ---------------------------------------------------------------------------
# DB-join shape (in-memory SQLite)
# ---------------------------------------------------------------------------


@pytest.fixture
def in_memory_db() -> sqlite3.Connection:
    """Build a minimal diag-shaped DB exercising the join paths.

    create_diag_database binds the Models so gather_evidence's ORM reads
    target this in-memory DB; the fixture returns the live connection.
    """
    db = create_diag_database(":memory:")
    Snapshot.insert(
        id=7, label="GLBOPT1_post_d810", func_ea_hex="0x0", func_ea_i64=0,
        maturity="MMAT_GLBOPT1", phase="unknown", block_count=0, timestamp=0.0,
    ).execute()
    # byte's block 100 owned by state A; A has neighbors B, C
    StateCfgNode.insert_many([
        dict(snapshot=7, state_hex="0xa", state_i64=10, entry_block=200,
             classification="EXACT", shared_suffix=None),
        dict(snapshot=7, state_hex="0xb", state_i64=11, entry_block=201,
             classification="EXACT", shared_suffix=None),
        dict(snapshot=7, state_hex="0xc", state_i64=12, entry_block=202,
             classification="EXACT", shared_suffix=None),
    ]).execute()
    StateCfgNodeBlock.insert_many([
        dict(snapshot=7, state_hex="0xa", entry_block=200, block_serial=100,
             block_index=0, role="owned"),
        dict(snapshot=7, state_hex="0xb", entry_block=201, block_serial=101,
             block_index=0, role="owned"),
        dict(snapshot=7, state_hex="0xc", entry_block=202, block_serial=102,
             block_index=0, role="owned"),
    ]).execute()
    StateCfgEdge.insert_many([
        dict(snapshot=7, edge_id=0, source_state_hex="0xb", source_state_i64=11,
             target_state_hex="0xa", target_state_i64=10, edge_kind="TRANSITION",
             source_block=11, source_arm=None, target_entry=200, ordered_path=""),
        dict(snapshot=7, edge_id=1, source_state_hex="0xa", source_state_i64=10,
             target_state_hex="0xc", target_state_i64=12, edge_kind="TRANSITION",
             source_block=10, source_arm=None, target_entry=202, ordered_path=""),
    ]).execute()
    # region feature value names blk[101] => B is admitted, A and C are not
    RegionShapeFeature.insert(
        func_ea_hex="f", func_ea_i64=1, snapshot_id=7, source="D810",
        region="h1", feature="members", value_text="blk[101]", evidence_json="{}",
    ).execute()
    return db.connection()


def test_gather_evidence_resolves_chain_size_and_neighbors(in_memory_db):
    row = _row(4, block_serial=100)
    evidence = gather_evidence(in_memory_db, row)
    assert evidence.state_hex == "0xa"
    assert evidence.snapshot_id == 7
    assert evidence.dag_pred_count == 1
    assert evidence.dag_succ_count == 1
    assert evidence.chain_size == 3  # A, B, C reachable
    assert set(evidence.neighbor_state_hexes) == {"0xb", "0xc"}
    # B is admitted via region feature, C is not.
    assert evidence.neighbors_admitted == 1


def test_gather_evidence_no_db_returns_empty_record_for_missing_db(tmp_path: Path):
    row = _row(4, block_serial=100)
    explanations = explain([row], tmp_path / "missing.sqlite3", bytes_filter=[4])
    assert len(explanations) == 1
    # No DB -> evidence is empty, dag_pred_count==0 and dag_succ_count==0,
    # so the classifier puts it in 'not_in_chain'.
    assert explanations[0].bucket == "not_in_chain"


def test_gather_evidence_no_db_helper_returns_zeroed_evidence():
    row = _row(4, block_serial=100)
    ev = gather_evidence_no_db(row)
    assert ev.state_hex is None
    assert ev.snapshot_id is None
    assert ev.dag_pred_count == 0
    assert ev.dag_succ_count == 0
    assert ev.chain_size == 0
    assert ev.neighbors_admitted == 0
