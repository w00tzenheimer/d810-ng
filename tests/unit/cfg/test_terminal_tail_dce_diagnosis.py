"""Tests for terminal-tail DCE cause diagnosis."""
from __future__ import annotations

from d810.cfg.terminal_tail_dce_diagnosis import (
    ByteEmitDceClassification,
    ByteEmitSnapshotEvidence,
    DceCause,
    RecommendedAction,
    classify_all,
    classify_byte_emit_dce,
    format_dce_table,
    recommend_overall_action,
)


def _ev(**kwargs) -> ByteEmitSnapshotEvidence:
    defaults = dict(
        byte_index=2,
        snap17_block_serial=118,
        snap17_block_ea="0x180014817",
        snap17_npred=2,
        snap17_nsucc=2,
        snap17_in_scc=False,
        snap17_in_giant_scc=False,
        snap17_unique_pred=False,
        snap17_shares_succ_with_other_byte=False,
        snap17_dominated_by_prior_return=False,
        snap17_memory_write_appears_dead=False,
        snap18_block_present=False,
        snap18_fact_detected=False,
        snap18_surviving_byte_absorbs=False,
    )
    defaults.update(kwargs)
    return ByteEmitSnapshotEvidence(**defaults)


class TestClassifyByteEmitDce:
    def test_block_present_with_fact_classifies_survives(self) -> None:
        c = classify_byte_emit_dce(_ev(snap18_block_present=True, snap18_fact_detected=True))
        assert c.cause is DceCause.SURVIVES
        assert c.recommended_action is RecommendedAction.NONE

    def test_block_present_without_fact_classifies_collector_gap(self) -> None:
        c = classify_byte_emit_dce(_ev(snap18_block_present=True, snap18_fact_detected=False))
        assert c.cause is DceCause.COLLECTOR_GAP
        assert c.recommended_action is RecommendedAction.COLLECTOR_FIX

    def test_unreachable_at_snap17(self) -> None:
        c = classify_byte_emit_dce(_ev(snap17_npred=0))
        assert c.cause is DceCause.UNREACHABLE_AT_SNAP17
        assert c.recommended_action is RecommendedAction.PRESERVATION

    def test_redirected_around_before_finalization(self) -> None:
        c = classify_byte_emit_dce(_ev(
            snap17_unique_pred=True, snap17_dominated_by_prior_return=True,
        ))
        assert c.cause is DceCause.REDIRECTED_AROUND_BEFORE_FINALIZATION
        assert c.recommended_action is RecommendedAction.PRESERVATION

    def test_merged_into_shared_folded_body(self) -> None:
        c = classify_byte_emit_dce(_ev(snap17_shares_succ_with_other_byte=True))
        assert c.cause is DceCause.MERGED_INTO_SHARED_FOLDED_BODY
        assert c.recommended_action is RecommendedAction.STRUCTURER_SHAPING

    def test_dce_dead_write(self) -> None:
        c = classify_byte_emit_dce(_ev(snap17_memory_write_appears_dead=True))
        assert c.cause is DceCause.DCE_DEAD_WRITE
        assert c.recommended_action is RecommendedAction.PRESERVATION

    def test_folded_into_surviving_byte_emit(self) -> None:
        c = classify_byte_emit_dce(_ev(snap18_surviving_byte_absorbs=True))
        assert c.cause is DceCause.FOLDED_INTO_SURVIVING_BYTE_EMIT
        assert c.recommended_action is RecommendedAction.STRUCTURER_SHAPING

    def test_ida_native_unknown_falls_through_when_no_signal(self) -> None:
        c = classify_byte_emit_dce(_ev())  # all defaults — no signals
        assert c.cause is DceCause.IDA_NATIVE_UNKNOWN
        assert c.recommended_action is RecommendedAction.RECONSTRUCTION

    def test_no_snap17_evidence_classifies_unknown(self) -> None:
        c = classify_byte_emit_dce(_ev(snap17_block_serial=None, snap17_block_ea=None))
        assert c.cause is DceCause.IDA_NATIVE_UNKNOWN

    def test_priority_block_present_beats_other_signals(self) -> None:
        # Even with all snap17 signals set, block-present at snap18 wins.
        c = classify_byte_emit_dce(_ev(
            snap17_npred=0, snap17_unique_pred=True,
            snap17_shares_succ_with_other_byte=True,
            snap17_memory_write_appears_dead=True,
            snap18_block_present=True, snap18_fact_detected=True,
        ))
        assert c.cause is DceCause.SURVIVES

    def test_priority_surviving_absorbs_beats_unreachable(self) -> None:
        # surviving_absorbs is checked BEFORE unreachable.
        c = classify_byte_emit_dce(_ev(
            snap17_npred=0,
            snap18_surviving_byte_absorbs=True,
        ))
        assert c.cause is DceCause.FOLDED_INTO_SURVIVING_BYTE_EMIT


class TestClassifyAll:
    def test_sorts_by_byte_index(self) -> None:
        evs = [
            _ev(byte_index=5, snap18_block_present=True, snap18_fact_detected=True),
            _ev(byte_index=2, snap17_npred=0),
            _ev(byte_index=0, snap18_block_present=True, snap18_fact_detected=True),
        ]
        results = classify_all(evs)
        assert [c.byte_index for c in results] == [0, 2, 5]


class TestRecommendOverallAction:
    def test_preservation_takes_priority(self) -> None:
        cs = (
            classify_byte_emit_dce(_ev(byte_index=0, snap17_npred=0)),  # PRESERVATION
            classify_byte_emit_dce(_ev(byte_index=1, snap17_shares_succ_with_other_byte=True)),  # STRUCTURER
        )
        action, reason = recommend_overall_action(cs)
        assert action is RecommendedAction.PRESERVATION
        assert "PRESERVATION" in reason or "preservation" in reason

    def test_structurer_when_no_preservation_or_reconstruction(self) -> None:
        cs = (
            classify_byte_emit_dce(_ev(byte_index=2, snap17_shares_succ_with_other_byte=True)),
            classify_byte_emit_dce(_ev(byte_index=3, snap18_surviving_byte_absorbs=True)),
        )
        action, _ = recommend_overall_action(cs)
        assert action is RecommendedAction.STRUCTURER_SHAPING

    def test_collector_fix_when_only_collector_gap(self) -> None:
        cs = (
            classify_byte_emit_dce(_ev(byte_index=0,
                                        snap18_block_present=True,
                                        snap18_fact_detected=False)),
        )
        action, _ = recommend_overall_action(cs)
        assert action is RecommendedAction.COLLECTOR_FIX

    def test_none_when_all_survive(self) -> None:
        cs = (
            classify_byte_emit_dce(_ev(byte_index=k,
                                        snap18_block_present=True,
                                        snap18_fact_detected=True))
            for k in range(7)
        )
        action, reason = recommend_overall_action(cs)
        assert action is RecommendedAction.NONE
        assert "no work needed" in reason


class TestFormatDceTable:
    def test_renders_markdown_with_action_column(self) -> None:
        cs = (
            classify_byte_emit_dce(_ev(byte_index=2, snap17_shares_succ_with_other_byte=True)),
            classify_byte_emit_dce(_ev(byte_index=3, snap17_npred=0)),
        )
        text = format_dce_table(cs)
        assert "| byte | cause | action | rationale |" in text
        assert "merged_into_shared_folded_body" in text
        assert "preservation" in text or "structurer_shaping" in text
