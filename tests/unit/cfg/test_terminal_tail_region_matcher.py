"""Tests for the terminal-tail region matcher."""
from __future__ import annotations

from d810.cfg.terminal_tail_region_matcher import (
    ByteEmitObservation,
    ByteEmitSourceForm,
    FirstLossEntry,
    SnapshotMeta,
    TailRegionRole,
    _classify_source_form,
    aggregate_byte_emit_timeline,
    format_report,
)


def _obs(
    *,
    snap: int,
    maturity: str,
    phase: str,
    block: int,
    byte_index: int,
    label: str = "",
    counter: str = "%var_1C0",
    source: ByteEmitSourceForm = ByteEmitSourceForm.INDEXED,
) -> ByteEmitObservation:
    return ByteEmitObservation(
        snapshot_id=snap,
        maturity=maturity,
        phase=phase,
        label=label or f"snap{snap}",
        block_serial=block,
        byte_index=byte_index,
        corridor_role="terminal_byte_emitter",
        counter_carrier=counter,
        source_form=source,
        destination_present=True,
        counter_update_present=True,
    )


class TestClassifySourceForm:
    def test_indexed_with_decimal_constant(self) -> None:
        assert _classify_source_form("%var_X+#2.8", 2) is ByteEmitSourceForm.INDEXED

    def test_indexed_with_hex_constant(self) -> None:
        assert _classify_source_form("%var_X+#a.8", 0xA) is ByteEmitSourceForm.INDEXED

    def test_folded_when_mba_operators_present(self) -> None:
        assert (
            _classify_source_form("%var_X << l (a ^ b) | %var_Y", 3)
            is ByteEmitSourceForm.FOLDED
        )

    def test_base_only_for_simple_pointer(self) -> None:
        assert (
            _classify_source_form("[ds.2: %var_178.8].8", 0)
            is ByteEmitSourceForm.BASE_ONLY
        )

    def test_absent_for_none_or_empty(self) -> None:
        assert _classify_source_form(None, 0) is ByteEmitSourceForm.ABSENT
        assert _classify_source_form("", 0) is ByteEmitSourceForm.ABSENT


class TestAggregateByteEmitTimeline:
    def test_empty_input_returns_empty_report(self) -> None:
        report = aggregate_byte_emit_timeline([])
        assert report.timeline == ()
        assert all(fl.is_missing_throughout for fl in report.first_losses)
        assert report.last_d810_controlled_entry is None
        assert report.glbopt1_post_d810_entry is None

    def test_seven_byte_emits_at_one_snapshot(self) -> None:
        obs = [
            _obs(snap=5, maturity="MMAT_GLBOPT1", phase="pre_d810", block=100 + k, byte_index=k)
            for k in range(7)
        ]
        report = aggregate_byte_emit_timeline(obs)
        assert len(report.timeline) == 1
        e = report.timeline[0]
        assert e.present_indices() == (0, 1, 2, 3, 4, 5, 6)
        assert e.missing_indices() == ()

    def test_first_loss_detection(self) -> None:
        # 7 bytes at GLBOPT1 pre, only 0 + 1 at GLBOPT1 post.
        obs = [
            _obs(snap=5, maturity="MMAT_GLBOPT1", phase="pre_d810", block=10 + k, byte_index=k)
            for k in range(7)
        ]
        obs += [
            _obs(snap=18, maturity="MMAT_GLBOPT1", phase="post_d810", block=20 + k, byte_index=k)
            for k in (0, 1)
        ]
        report = aggregate_byte_emit_timeline(obs)
        # 0, 1 survive; 2..6 lost between snap 5 and snap 18.
        for k in (0, 1):
            fl = report.first_losses[k]
            assert fl.survives_pipeline
            assert fl.last_present_snapshot.snapshot_id == 18
        for k in (2, 3, 4, 5, 6):
            fl = report.first_losses[k]
            assert not fl.survives_pipeline
            assert fl.last_present_snapshot.snapshot_id == 5
            assert fl.first_absent_snapshot.snapshot_id == 18
            assert fl.inferred_cause == "d810_apply_within_MMAT_GLBOPT1"

    def test_ida_native_fold_inferred_when_phase_crosses_maturity(self) -> None:
        obs = [
            _obs(snap=4, maturity="MMAT_CALLS", phase="post_d810", block=10, byte_index=2),
            # blank at GLBOPT1 pre — so the fold happened between CALLS-post
            # and GLBOPT1-pre, which is IDA-controlled.
        ]
        report = aggregate_byte_emit_timeline(obs)
        fl = report.first_losses[2]
        assert fl.last_present_snapshot.maturity == "MMAT_CALLS"
        # Without a downstream snapshot showing absence, fl.first_absent is None
        # (survives_pipeline is True because we never observed absence).
        assert fl.survives_pipeline

    def test_ida_native_fold_when_we_observe_absence_at_next_maturity(self) -> None:
        obs = [
            _obs(snap=4, maturity="MMAT_CALLS", phase="post_d810", block=10, byte_index=2),
            # No byte_index=2 in GLBOPT1 pre, but other bytes present so the
            # snapshot exists.
            _obs(snap=5, maturity="MMAT_GLBOPT1", phase="pre_d810", block=20, byte_index=0),
        ]
        report = aggregate_byte_emit_timeline(obs)
        fl2 = report.first_losses[2]
        assert fl2.last_present_snapshot.maturity == "MMAT_CALLS"
        assert fl2.first_absent_snapshot.maturity == "MMAT_GLBOPT1"
        assert fl2.inferred_cause.startswith("ida_native_fold_")

    def test_glbopt1_post_d810_entry_extracted(self) -> None:
        obs = [
            _obs(snap=5, maturity="MMAT_GLBOPT1", phase="pre_d810", block=10, byte_index=0),
            _obs(snap=18, maturity="MMAT_GLBOPT1", phase="post_d810", block=20, byte_index=0),
        ]
        report = aggregate_byte_emit_timeline(obs)
        assert report.glbopt1_post_d810_entry is not None
        assert report.glbopt1_post_d810_entry.snapshot.snapshot_id == 18

    def test_first_write_wins_dedupe(self) -> None:
        # Two observations for the same (snap_id, byte_index) but different
        # blocks. First-write-wins keeps the first observation.
        obs = [
            _obs(snap=5, maturity="MMAT_GLBOPT1", phase="pre_d810", block=10, byte_index=0),
            _obs(snap=5, maturity="MMAT_GLBOPT1", phase="pre_d810", block=99, byte_index=0),
        ]
        report = aggregate_byte_emit_timeline(obs)
        assert len(report.timeline) == 1
        kept = report.timeline[0].byte_emits[0]
        assert kept.block_serial == 10  # first observation wins

    def test_format_report_renders_markdown(self) -> None:
        obs = [
            _obs(snap=5, maturity="MMAT_GLBOPT1", phase="pre_d810", block=10 + k, byte_index=k)
            for k in range(7)
        ]
        obs += [
            _obs(snap=18, maturity="MMAT_GLBOPT1", phase="post_d810", block=20 + k, byte_index=k)
            for k in (0, 1)
        ]
        text = format_report(aggregate_byte_emit_timeline(obs))
        assert "## Byte-emit timeline" in text
        assert "## First-loss report" in text
        assert "## GLBOPT1 post-D810" in text
        assert "byte_emits: [0, 1]" in text
        assert "missing byte_emits: [2, 3, 4, 5, 6]" in text


class TestRoleEnum:
    def test_role_values(self) -> None:
        # Verify the enum has the documented role names.
        assert TailRegionRole.TAIL_INIT.value == "TAIL_INIT"
        assert TailRegionRole.BYTE_EMIT.value == "BYTE_EMIT"
        assert TailRegionRole.EARLY_RETURN_GUARD.value == "EARLY_RETURN_GUARD"
        assert TailRegionRole.CLEANUP_ZERO_STORE16.value == "CLEANUP_ZERO_STORE16"
        assert TailRegionRole.REAL_LOOP_BLOCK.value == "REAL_LOOP_BLOCK"
        assert TailRegionRole.RESIDUAL_SCC_BACKEDGE.value == "RESIDUAL_SCC_BACKEDGE"
        assert TailRegionRole.UNKNOWN.value == "UNKNOWN"


class TestSnapshotMetaKey:
    def test_key_returns_tuple(self) -> None:
        m = SnapshotMeta(snapshot_id=5, maturity="MMAT_GLBOPT1", phase="pre_d810", label="x")
        assert m.key() == ("MMAT_GLBOPT1", "pre_d810")
