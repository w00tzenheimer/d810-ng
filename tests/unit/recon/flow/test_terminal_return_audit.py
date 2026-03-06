"""Unit tests for terminal_return_audit -- pure analysis, no IDA dependency."""
from __future__ import annotations

import pytest

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.recon.flow.terminal_return_audit import (
    TerminalReturnAuditReport,
    TerminalReturnSiteAudit,
    TerminalReturnSourceKind,
    build_terminal_return_audit,
    from_dict,
    to_dict,
)

# BLT_STOP = 1, BLT_1WAY = 2 (normal fall-through)
_BLT_STOP = 1
_BLT_1WAY = 2


def _make_block(
    serial: int,
    block_type: int = _BLT_1WAY,
    succs: tuple[int, ...] = (),
    preds: tuple[int, ...] = (),
) -> BlockSnapshot:
    """Helper to create a minimal BlockSnapshot for testing."""
    return BlockSnapshot(
        serial=serial,
        block_type=block_type,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0x1000 + serial * 0x10,
        insn_snapshots=(),
    )


def _make_cfg(blocks: list[BlockSnapshot], entry: int = 0) -> FlowGraph:
    """Helper to build a FlowGraph from a list of BlockSnapshots."""
    block_map = {b.serial: b for b in blocks}
    return FlowGraph(
        blocks=block_map,
        entry_serial=entry,
        func_ea=0x400000,
    )


class TestDirectReturnClassification:
    """Handler exit IS the BLT_STOP block -> DIRECT_RETURN, corridor_length=0."""

    def test_direct_return_classification(self) -> None:
        # Block 0 (entry) -> Block 10 (handler) -> Block 20 (exit = BLT_STOP)
        blocks = [
            _make_block(0, succs=(10,)),
            _make_block(10, succs=(20,), preds=(0,)),
            _make_block(20, block_type=_BLT_STOP, preds=(10,)),
        ]
        cfg = _make_cfg(blocks)

        report = build_terminal_return_audit(
            cfg=cfg,
            terminal_handler_serials={10},
            exit_map={10: 20},
            total_handlers=1,
        )

        assert len(report.sites) == 1
        site = report.sites[0]
        assert site.handler_serial == 10
        assert site.exit_serial == 20
        assert site.source_kind == TerminalReturnSourceKind.DIRECT_RETURN
        assert site.return_block_serial == 20
        assert site.corridor_length == 0


class TestEpilogueCorridorClassification:
    """Handler exit -> single-pred chain -> BLT_STOP -> EPILOGUE_CORRIDOR."""

    def test_epilogue_corridor_classification(self) -> None:
        # Block 0 (entry) -> Block 10 (handler exit) -> Block 11 (single pred) -> Block 12 (BLT_STOP, single pred)
        blocks = [
            _make_block(0, succs=(10,)),
            _make_block(10, succs=(11,), preds=(0,)),
            _make_block(11, succs=(12,), preds=(10,)),
            _make_block(12, block_type=_BLT_STOP, preds=(11,)),
        ]
        cfg = _make_cfg(blocks)

        report = build_terminal_return_audit(
            cfg=cfg,
            terminal_handler_serials={10},
            exit_map={10: 10},
            total_handlers=1,
        )

        assert len(report.sites) == 1
        site = report.sites[0]
        assert site.source_kind == TerminalReturnSourceKind.EPILOGUE_CORRIDOR
        assert site.return_block_serial == 12
        assert site.corridor_length == 2  # 10 -> 11 -> 12 = 2 hops


class TestSharedEpilogueClassification:
    """Handler exit -> block with multiple preds -> SHARED_EPILOGUE."""

    def test_shared_epilogue_classification(self) -> None:
        # Block 0 (entry) -> Block 10 (handler A exit)
        #                  -> Block 20 (handler B exit)
        # Both -> Block 30 (shared epilogue, BLT_STOP, 2 preds)
        blocks = [
            _make_block(0, succs=(10, 20)),
            _make_block(10, succs=(30,), preds=(0,)),
            _make_block(20, succs=(30,), preds=(0,)),
            _make_block(30, block_type=_BLT_STOP, preds=(10, 20)),
        ]
        cfg = _make_cfg(blocks)

        report = build_terminal_return_audit(
            cfg=cfg,
            terminal_handler_serials={10},
            exit_map={10: 10},
            total_handlers=2,
        )

        assert len(report.sites) == 1
        site = report.sites[0]
        assert site.source_kind == TerminalReturnSourceKind.SHARED_EPILOGUE
        assert site.return_block_serial == 30
        assert site.corridor_length == 1


class TestUnreachableClassification:
    """Handler exit has no path to BLT_STOP -> UNREACHABLE."""

    def test_unreachable_classification(self) -> None:
        # Block 0 (entry) -> Block 10 (handler exit) -> Block 11 (dead end, no succs, not BLT_STOP)
        blocks = [
            _make_block(0, succs=(10,)),
            _make_block(10, succs=(11,), preds=(0,)),
            _make_block(11, block_type=_BLT_1WAY, succs=(), preds=(10,)),
        ]
        cfg = _make_cfg(blocks)

        report = build_terminal_return_audit(
            cfg=cfg,
            terminal_handler_serials={10},
            exit_map={10: 10},
            total_handlers=1,
        )

        assert len(report.sites) == 1
        site = report.sites[0]
        assert site.source_kind == TerminalReturnSourceKind.UNREACHABLE
        assert site.return_block_serial is None
        assert site.corridor_length == 0

    def test_unreachable_none_exit(self) -> None:
        """Exit serial is None -> UNREACHABLE."""
        blocks = [_make_block(0)]
        cfg = _make_cfg(blocks)

        report = build_terminal_return_audit(
            cfg=cfg,
            terminal_handler_serials={10},
            exit_map={10: None},
            total_handlers=1,
        )

        assert len(report.sites) == 1
        assert report.sites[0].source_kind == TerminalReturnSourceKind.UNREACHABLE

    def test_unreachable_missing_exit_block(self) -> None:
        """Exit serial references a block not in CFG -> UNREACHABLE."""
        blocks = [_make_block(0)]
        cfg = _make_cfg(blocks)

        report = build_terminal_return_audit(
            cfg=cfg,
            terminal_handler_serials={10},
            exit_map={10: 99},
            total_handlers=1,
        )

        assert len(report.sites) == 1
        assert report.sites[0].source_kind == TerminalReturnSourceKind.UNREACHABLE


class TestSummaryFormat:
    """Verify summary() output format."""

    def test_summary_format(self) -> None:
        report = TerminalReturnAuditReport(
            function_ea=0x400000,
            total_handlers=10,
            terminal_handlers=4,
            sites=(
                TerminalReturnSiteAudit(
                    handler_serial=1, exit_serial=2,
                    source_kind=TerminalReturnSourceKind.DIRECT_RETURN,
                    return_block_serial=2,
                ),
                TerminalReturnSiteAudit(
                    handler_serial=3, exit_serial=4,
                    source_kind=TerminalReturnSourceKind.EPILOGUE_CORRIDOR,
                    return_block_serial=5, corridor_length=2,
                ),
                TerminalReturnSiteAudit(
                    handler_serial=6, exit_serial=7,
                    source_kind=TerminalReturnSourceKind.SHARED_EPILOGUE,
                    return_block_serial=8, corridor_length=1,
                ),
                TerminalReturnSiteAudit(
                    handler_serial=9, exit_serial=None,
                    source_kind=TerminalReturnSourceKind.UNREACHABLE,
                ),
            ),
        )
        summary = report.summary()
        assert summary == "4/10 terminal handlers: 1 direct, 1 corridor, 1 shared, 1 unreachable"

    def test_summary_zero_handlers(self) -> None:
        report = TerminalReturnAuditReport(
            function_ea=0x400000,
            total_handlers=5,
            terminal_handlers=0,
            sites=(),
        )
        assert "0/5 terminal handlers" in report.summary()


class TestRoundtripSerialization:
    """to_dict -> from_dict preserves all fields."""

    def test_roundtrip_serialization(self) -> None:
        original = TerminalReturnAuditReport(
            function_ea=0x400000,
            total_handlers=8,
            terminal_handlers=3,
            sites=(
                TerminalReturnSiteAudit(
                    handler_serial=1, exit_serial=2,
                    source_kind=TerminalReturnSourceKind.DIRECT_RETURN,
                    return_block_serial=2, corridor_length=0,
                    has_rax_write=True, notes="clean return",
                ),
                TerminalReturnSiteAudit(
                    handler_serial=3, exit_serial=4,
                    source_kind=TerminalReturnSourceKind.EPILOGUE_CORRIDOR,
                    return_block_serial=5, corridor_length=3,
                    has_rax_write=False, notes="",
                ),
                TerminalReturnSiteAudit(
                    handler_serial=6, exit_serial=None,
                    source_kind=TerminalReturnSourceKind.UNREACHABLE,
                    return_block_serial=None, corridor_length=0,
                    has_rax_write=None, notes="no path to BLT_STOP from exit",
                ),
            ),
        )

        data = to_dict(original)
        restored = from_dict(data)

        assert restored.function_ea == original.function_ea
        assert restored.total_handlers == original.total_handlers
        assert restored.terminal_handlers == original.terminal_handlers
        assert len(restored.sites) == len(original.sites)

        for orig_site, rest_site in zip(original.sites, restored.sites):
            assert rest_site.handler_serial == orig_site.handler_serial
            assert rest_site.exit_serial == orig_site.exit_serial
            assert rest_site.source_kind == orig_site.source_kind
            assert rest_site.return_block_serial == orig_site.return_block_serial
            assert rest_site.corridor_length == orig_site.corridor_length
            assert rest_site.has_rax_write == orig_site.has_rax_write
            assert rest_site.notes == orig_site.notes

    def test_roundtrip_empty_sites(self) -> None:
        original = TerminalReturnAuditReport(
            function_ea=0x100, total_handlers=0, terminal_handlers=0, sites=(),
        )
        assert from_dict(to_dict(original)) == original


class TestEmptyTerminalHandlers:
    """0 terminal handlers -> report with empty sites."""

    def test_empty_terminal_handlers(self) -> None:
        blocks = [
            _make_block(0, succs=(1,)),
            _make_block(1, block_type=_BLT_STOP, preds=(0,)),
        ]
        cfg = _make_cfg(blocks)

        report = build_terminal_return_audit(
            cfg=cfg,
            terminal_handler_serials=set(),
            exit_map={},
            total_handlers=5,
        )

        assert report.terminal_handlers == 0
        assert report.total_handlers == 5
        assert report.sites == ()
        assert "0/5" in report.summary()


class TestSharedMergeAtExitBlock:
    """P1-2: Exit block with multiple preds should be SHARED_EPILOGUE, not EPILOGUE_CORRIDOR."""

    def test_shared_merge_at_exit_block_classified_correctly(self) -> None:
        """Exit block has 2+ preds, downstream is single-pred -> SHARED_EPILOGUE."""
        # Handler 10 exits at block 20 (which has 2 preds: 10 and 15).
        # Block 20 -> Block 21 (single-pred) -> Block 22 (BLT_STOP, single-pred).
        # Even though 21 and 22 are single-pred, block 20 itself is multi-pred,
        # so this is SHARED_EPILOGUE, not EPILOGUE_CORRIDOR.
        blocks = [
            _make_block(0, succs=(10, 15)),
            _make_block(10, succs=(20,), preds=(0,)),
            _make_block(15, succs=(20,), preds=(0,)),
            _make_block(20, succs=(21,), preds=(10, 15)),
            _make_block(21, succs=(22,), preds=(20,)),
            _make_block(22, block_type=_BLT_STOP, preds=(21,)),
        ]
        cfg = _make_cfg(blocks)

        report = build_terminal_return_audit(
            cfg=cfg,
            terminal_handler_serials={10},
            exit_map={10: 20},
            total_handlers=2,
        )

        assert len(report.sites) == 1
        site = report.sites[0]
        assert site.source_kind == TerminalReturnSourceKind.SHARED_EPILOGUE
        assert site.return_block_serial == 22
        assert site.corridor_length == 2


class TestRaxWriteDetection:
    """P1-1: has_rax_write should reflect rax_write_serials intersection with path."""

    def test_rax_write_detected_on_corridor_path(self) -> None:
        """Pass rax_write_serials containing a corridor block -> has_rax_write=True."""
        # Handler 10 -> exit 10 -> 11 (single-pred) -> 12 (BLT_STOP, single-pred)
        blocks = [
            _make_block(0, succs=(10,)),
            _make_block(10, succs=(11,), preds=(0,)),
            _make_block(11, succs=(12,), preds=(10,)),
            _make_block(12, block_type=_BLT_STOP, preds=(11,)),
        ]
        cfg = _make_cfg(blocks)

        report = build_terminal_return_audit(
            cfg=cfg,
            terminal_handler_serials={10},
            exit_map={10: 10},
            total_handlers=1,
            rax_write_serials={11},
        )

        assert len(report.sites) == 1
        site = report.sites[0]
        assert site.has_rax_write is True

    def test_rax_write_not_found_on_path(self) -> None:
        """Pass rax_write_serials not containing any path block -> has_rax_write=False."""
        # Same corridor as above, but rax_write_serials contains block 99 (not on path)
        blocks = [
            _make_block(0, succs=(10,)),
            _make_block(10, succs=(11,), preds=(0,)),
            _make_block(11, succs=(12,), preds=(10,)),
            _make_block(12, block_type=_BLT_STOP, preds=(11,)),
        ]
        cfg = _make_cfg(blocks)

        report = build_terminal_return_audit(
            cfg=cfg,
            terminal_handler_serials={10},
            exit_map={10: 10},
            total_handlers=1,
            rax_write_serials={99},
        )

        assert len(report.sites) == 1
        site = report.sites[0]
        assert site.has_rax_write is False

    def test_rax_write_none_when_not_provided(self) -> None:
        """Omit rax_write_serials -> has_rax_write=None (existing behavior)."""
        blocks = [
            _make_block(0, succs=(10,)),
            _make_block(10, succs=(11,), preds=(0,)),
            _make_block(11, block_type=_BLT_STOP, preds=(10,)),
        ]
        cfg = _make_cfg(blocks)

        report = build_terminal_return_audit(
            cfg=cfg,
            terminal_handler_serials={10},
            exit_map={10: 10},
            total_handlers=1,
        )

        assert len(report.sites) == 1
        site = report.sites[0]
        assert site.has_rax_write is None

    def test_rax_write_in_handler_body_detected_for_direct_return(self) -> None:
        """Handler block writes rax, successor is BLT_STOP -> has_rax_write=True."""
        # Handler 10 writes rax in its own body; its successor (20) is BLT_STOP.
        # _classify_exit returns path_serials=(20,) which does NOT contain 10,
        # but the fix includes handler_serial in the checked set.
        blocks = [
            _make_block(0, succs=(10,)),
            _make_block(10, succs=(20,), preds=(0,)),
            _make_block(20, block_type=_BLT_STOP, preds=(10,)),
        ]
        cfg = _make_cfg(blocks)

        report = build_terminal_return_audit(
            cfg=cfg,
            terminal_handler_serials={10},
            exit_map={10: 20},
            total_handlers=1,
            rax_write_serials={10},
        )

        assert len(report.sites) == 1
        site = report.sites[0]
        assert site.source_kind == TerminalReturnSourceKind.DIRECT_RETURN
        assert site.has_rax_write is True

    def test_rax_write_none_for_unreachable(self) -> None:
        """Even with rax_write_serials provided, UNREACHABLE -> has_rax_write=None."""
        blocks = [_make_block(0)]
        cfg = _make_cfg(blocks)

        report = build_terminal_return_audit(
            cfg=cfg,
            terminal_handler_serials={10},
            exit_map={10: None},
            total_handlers=1,
            rax_write_serials={0, 10},
        )

        assert len(report.sites) == 1
        site = report.sites[0]
        assert site.has_rax_write is None


class TestMultiExitTerminalHandler:
    """A handler with multiple terminal paths emits multiple audit rows."""

    def test_multi_exit_emits_multiple_sites(self) -> None:
        """Handler 10 has TWO terminal paths exiting at blocks 20 and 30.

        Both exits lead to different BLT_STOP blocks.  The audit should
        produce TWO TerminalReturnSiteAudit entries for handler 10, and
        terminal_handlers count should be 1 (one unique handler).
        """
        # Handler 10 -> exit 20 -> BLT_STOP (block 21)
        #            -> exit 30 -> BLT_STOP (block 31)
        blocks = [
            _make_block(0, succs=(10,)),
            _make_block(10, succs=(20, 30), preds=(0,)),
            _make_block(20, succs=(21,), preds=(10,)),
            _make_block(21, block_type=_BLT_STOP, preds=(20,)),
            _make_block(30, succs=(31,), preds=(10,)),
            _make_block(31, block_type=_BLT_STOP, preds=(30,)),
        ]
        cfg = _make_cfg(blocks)

        report = build_terminal_return_audit(
            cfg=cfg,
            terminal_handler_serials={10},
            exit_map={10: [20, 30]},  # multi-exit list form
            total_handlers=3,
        )

        assert report.terminal_handlers == 1
        assert report.total_handlers == 3
        assert len(report.sites) == 2

        sites_by_exit = {s.exit_serial: s for s in report.sites}
        assert 20 in sites_by_exit
        assert 30 in sites_by_exit
        assert sites_by_exit[20].handler_serial == 10
        assert sites_by_exit[30].handler_serial == 10
        assert sites_by_exit[20].source_kind == TerminalReturnSourceKind.EPILOGUE_CORRIDOR
        assert sites_by_exit[20].return_block_serial == 21
        assert sites_by_exit[30].source_kind == TerminalReturnSourceKind.EPILOGUE_CORRIDOR
        assert sites_by_exit[30].return_block_serial == 31

    def test_multi_exit_mixed_reachability(self) -> None:
        """One terminal path reaches BLT_STOP, another is unreachable."""
        blocks = [
            _make_block(0, succs=(10,)),
            _make_block(10, succs=(20,), preds=(0,)),
            _make_block(20, block_type=_BLT_STOP, preds=(10,)),
        ]
        cfg = _make_cfg(blocks)

        report = build_terminal_return_audit(
            cfg=cfg,
            terminal_handler_serials={10},
            exit_map={10: [20, 99]},  # 99 not in CFG -> UNREACHABLE
            total_handlers=2,
        )

        assert len(report.sites) == 2
        sites_by_exit = {s.exit_serial: s for s in report.sites}
        assert sites_by_exit[20].source_kind == TerminalReturnSourceKind.DIRECT_RETURN
        assert sites_by_exit[99].source_kind == TerminalReturnSourceKind.UNREACHABLE

    def test_legacy_scalar_exit_map_still_works(self) -> None:
        """Legacy dict[int, int | None] form still produces correct results."""
        blocks = [
            _make_block(0, succs=(10,)),
            _make_block(10, succs=(20,), preds=(0,)),
            _make_block(20, block_type=_BLT_STOP, preds=(10,)),
        ]
        cfg = _make_cfg(blocks)

        report = build_terminal_return_audit(
            cfg=cfg,
            terminal_handler_serials={10},
            exit_map={10: 20},  # legacy scalar form
            total_handlers=1,
        )

        assert len(report.sites) == 1
        assert report.sites[0].exit_serial == 20
        assert report.sites[0].source_kind == TerminalReturnSourceKind.DIRECT_RETURN


class TestMultipleTerminalHandlers:
    """Multiple terminal handlers with mixed classifications."""

    def test_mixed_classifications(self) -> None:
        # Handler 10: exit 20 is BLT_STOP -> DIRECT_RETURN
        # Handler 30: exit 40 -> 50 (single pred) -> 60 BLT_STOP (single pred) -> EPILOGUE_CORRIDOR
        # Handler 70: exit None -> UNREACHABLE
        blocks = [
            _make_block(0, succs=(10, 30)),
            _make_block(10, succs=(20,), preds=(0,)),
            _make_block(20, block_type=_BLT_STOP, preds=(10,)),
            _make_block(30, succs=(40,), preds=(0,)),
            _make_block(40, succs=(50,), preds=(30,)),
            _make_block(50, succs=(60,), preds=(40,)),
            _make_block(60, block_type=_BLT_STOP, preds=(50,)),
        ]
        cfg = _make_cfg(blocks)

        report = build_terminal_return_audit(
            cfg=cfg,
            terminal_handler_serials={10, 30, 70},
            exit_map={10: 20, 30: 40, 70: None},
            total_handlers=5,
        )

        assert len(report.sites) == 3
        assert report.terminal_handlers == 3
        assert report.total_handlers == 5

        site_by_handler = {s.handler_serial: s for s in report.sites}
        assert site_by_handler[10].source_kind == TerminalReturnSourceKind.DIRECT_RETURN
        assert site_by_handler[30].source_kind == TerminalReturnSourceKind.EPILOGUE_CORRIDOR
        assert site_by_handler[30].corridor_length == 2  # 40 -> 50 -> 60
        assert site_by_handler[70].source_kind == TerminalReturnSourceKind.UNREACHABLE
