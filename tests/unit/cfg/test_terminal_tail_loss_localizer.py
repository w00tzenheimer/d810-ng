"""Tests for terminal-tail loss localizer."""
from __future__ import annotations

from d810.cfg.terminal_tail_loss_localizer import (
    ByteEmitInitialState,
    ByteEmitSurvival,
    LossLocalizationReport,
    SnapshotBlockView,
    build_block_survival,
    format_localization_report,
    localize_byte_emit_loss,
)


def _initial(byte_index: int, snap: int = 5, serial: int = 100, ea: str = "0x1") -> ByteEmitInitialState:
    return ByteEmitInitialState(
        byte_index=byte_index, snapshot_id=snap,
        block_serial=serial, start_ea_hex=ea,
    )


SNAPSHOTS_FULL = [
    (5, "MMAT_GLBOPT1_pre_d810", "pre_d810"),
    (8, "handler_chain_composer_post_apply", "post_apply"),
    (9, "dispatcher_trampoline_skip_post_apply", "post_apply"),
    (17, "post_bundle_stabilize", "post_apply"),
    (18, "MMAT_GLBOPT1_post_d810", "post_d810"),
]


class TestBuildBlockSurvival:
    def test_block_present_at_every_snapshot(self) -> None:
        # block ea 0xAA exists at all 5 snapshots with same metadata.
        lookup = {(s, "0xAA"): (100, 1, 1, 5) for s, _, _ in SNAPSHOTS_FULL}
        surv = build_block_survival(_initial(0, ea="0xAA"), SNAPSHOTS_FULL, lookup)
        assert surv.byte_index == 0
        assert surv.survives_pipeline
        assert surv.first_loss is None
        assert surv.last_present is not None
        assert surv.inferred_cause == "survives_pipeline"

    def test_block_absent_at_post_d810_means_ida_native_fold(self) -> None:
        # Present at snap 5, 8, 9, 17 — absent at snap 18 (post_d810).
        lookup = {
            (s, "0xAA"): (100, 1, 1, 5)
            for s, _, _ in SNAPSHOTS_FULL[:-1]
        }
        surv = build_block_survival(_initial(0, ea="0xAA"), SNAPSHOTS_FULL, lookup)
        assert not surv.survives_pipeline
        assert surv.last_present.snapshot_id == 17
        assert surv.first_loss.snapshot_id == 18
        assert surv.inferred_cause == "ida_native_maturity_fold"

    def test_block_absent_at_intermediate_phase_means_d810_strategy(self) -> None:
        # Present at snap 5, 8 — absent at snap 9 (dispatcher_trampoline_skip).
        lookup = {(5, "0xBB"): (100, 1, 1, 5), (8, "0xBB"): (100, 1, 1, 5)}
        surv = build_block_survival(_initial(2, ea="0xBB"), SNAPSHOTS_FULL, lookup)
        assert surv.first_loss.snapshot_id == 9
        assert surv.inferred_cause == "d810_strategy_phase_post_apply"

    def test_block_missing_throughout(self) -> None:
        surv = build_block_survival(_initial(0, ea="0xCC"), SNAPSHOTS_FULL, {})
        assert surv.last_present is None
        assert surv.first_loss is None
        # No first_loss because never observed present; survives_pipeline is True
        # by definition (no transition observed).
        assert surv.survives_pipeline


class TestSnapshotBlockView:
    def test_present_property(self) -> None:
        v = SnapshotBlockView(
            snapshot_id=5, snapshot_label="x", snapshot_phase="pre_d810",
            block_serial=100, npred=1, nsucc=2, insn_count=3,
        )
        assert v.present
        v_absent = SnapshotBlockView(
            snapshot_id=5, snapshot_label="x", snapshot_phase="pre_d810",
            block_serial=None, npred=None, nsucc=None, insn_count=None,
        )
        assert not v_absent.present


class TestLocalizeByteEmitLoss:
    def test_aggregates_multiple_bytes_in_byte_index_order(self) -> None:
        # Byte 0 survives; byte 2 lost at snap 18.
        lookup = {(s, "0xAA"): (100, 1, 1, 5) for s, _, _ in SNAPSHOTS_FULL}
        for s, _, _ in SNAPSHOTS_FULL[:-1]:
            lookup[(s, "0xBB")] = (200, 1, 1, 5)
        report = localize_byte_emit_loss(
            [_initial(2, ea="0xBB"), _initial(0, ea="0xAA")],
            SNAPSHOTS_FULL,
            lookup,
        )
        assert [s.byte_index for s in report.survivals] == [0, 2]
        assert report.survivals[0].survives_pipeline
        assert not report.survivals[1].survives_pipeline

    def test_cause_summary_groups_by_cause(self) -> None:
        # 3 bytes: 1 survives, 2 lost to IDA native fold.
        lookup = {(s, "0xAA"): (100, 1, 1, 5) for s, _, _ in SNAPSHOTS_FULL}
        for ea in ("0xBB", "0xCC"):
            for s, _, _ in SNAPSHOTS_FULL[:-1]:
                lookup[(s, ea)] = (100, 1, 1, 5)
        report = localize_byte_emit_loss(
            [
                _initial(0, ea="0xAA"),
                _initial(2, ea="0xBB"),
                _initial(3, ea="0xCC"),
            ],
            SNAPSHOTS_FULL,
            lookup,
        )
        counts = report.cause_counts()
        assert counts["survives_pipeline"] == 1
        assert counts["ida_native_maturity_fold"] == 2

    def test_format_report_renders_markdown_with_present_indices(self) -> None:
        lookup = {
            (s, "0xAA"): (100, 1, 1, 5) for s, _, _ in SNAPSHOTS_FULL[:-1]
        }
        report = localize_byte_emit_loss(
            [_initial(2, ea="0xAA")], SNAPSHOTS_FULL, lookup,
        )
        text = format_localization_report(report)
        assert "Byte-emit block survival" in text
        assert "ida_native_maturity_fold" in text
        # Each snapshot column rendered as blk[N]/Mp or X.
        assert "blk[100]/1p" in text
        assert "X" in text


class TestFactDetectionDimension:
    def test_block_present_fact_detected_is_full_survival(self) -> None:
        lookup = {(s, "0xAA"): (100, 1, 1, 5) for s, _, _ in SNAPSHOTS_FULL}
        fact_lookup = {(s, 0): True for s, _, _ in SNAPSHOTS_FULL}
        surv = build_block_survival(
            _initial(0, ea="0xAA"), SNAPSHOTS_FULL, lookup, fact_lookup,
        )
        assert all(e.fact_detected for e in surv.timeline if e.present)
        assert surv.fact_first_loss is None
        assert surv.inferred_cause == "survives_pipeline"

    def test_block_present_fact_absent_at_post_d810(self) -> None:
        # Block survives every snapshot, but fact stops firing at snap 18.
        lookup = {(s, "0xAA"): (100, 1, 1, 5) for s, _, _ in SNAPSHOTS_FULL}
        fact_lookup = {(s, 0): True for s, _, _ in SNAPSHOTS_FULL[:-1]}
        # snap 18 omitted from fact_lookup → fact_detected=False there.
        surv = build_block_survival(
            _initial(0, ea="0xAA"), SNAPSHOTS_FULL, lookup, fact_lookup,
        )
        assert surv.first_loss is None  # block survives
        assert surv.fact_first_loss is not None
        assert surv.fact_first_loss.snapshot_id == 18
        assert surv.inferred_cause == "fact_collector_lost_pattern"


class TestSurvivalCauseEdgeCases:
    def test_block_appears_after_initial_disappearance(self) -> None:
        # Edge case: block missing at snap 8, reappears at snap 17.
        lookup = {
            (5, "0xDD"): (100, 1, 1, 5),
            # snap 8, 9 absent
            (17, "0xDD"): (200, 1, 1, 5),
            # snap 18 absent
        }
        surv = build_block_survival(_initial(0, ea="0xDD"), SNAPSHOTS_FULL, lookup)
        # First loss is the FIRST absence after first presence.
        assert surv.first_loss.snapshot_id == 8
        assert not surv.survives_pipeline
