"""Unit tests for terminal-cone detection (pure model layer, no IDA)."""
from __future__ import annotations

import pytest

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot

# Block type constants (mirrors ida_hexrays BLT_* enum).
BLT_STOP = 1
BLT_1WAY = 2
BLT_2WAY = 3


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_deep_cleanup_path(
    start: int,
    stop_serial: int,
    parent_serial: int,
) -> list[BlockSnapshot]:
    """Build a chain of 7 blocks from *start* to BLT_STOP at *stop_serial*.

    Returns blocks: start, start+1, ..., start+5, stop_serial.
    The chain is deep enough (>=6) to pass the _MIN_CLEANUP_DEPTH filter.
    *parent_serial* is the predecessor of the first block.
    """
    chain: list[BlockSnapshot] = []
    for i in range(6):
        s = start + i
        nxt = start + i + 1 if i < 5 else stop_serial
        pred = (parent_serial,) if i == 0 else (start + i - 1,)
        chain.append(BlockSnapshot(
            serial=s, block_type=BLT_1WAY, succs=(nxt,), preds=pred,
            flags=0, start_ea=0x2000 + s * 0x10,
            insn_snapshots=(InsnSnapshot(opcode=0x01, ea=0x2000 + s * 0x10, operands=()),),
        ))
    chain.append(BlockSnapshot(
        serial=stop_serial, block_type=BLT_STOP, succs=(), preds=(start + 5,),
        flags=0, start_ea=0x2000 + stop_serial * 0x10,
        insn_snapshots=(),
    ))
    return chain


def _make_insn(opcode: int = 0x01, ea: int = 0x1000) -> InsnSnapshot:
    """Minimal instruction snapshot."""
    return InsnSnapshot(opcode=opcode, ea=ea, operands=())


def _make_block(
    serial: int,
    block_type: int = BLT_1WAY,
    succs: tuple[int, ...] = (),
    preds: tuple[int, ...] = (),
    insns: tuple[InsnSnapshot, ...] | None = None,
) -> BlockSnapshot:
    if insns is None:
        insns = (_make_insn(),)
    return BlockSnapshot(
        serial=serial,
        block_type=block_type,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0x1000 + serial * 0x10,
        insn_snapshots=insns,
    )


def _make_flowgraph(blocks: list[BlockSnapshot], entry: int = 0) -> FlowGraph:
    blk_map = {b.serial: b for b in blocks}
    return FlowGraph(blocks=blk_map, entry_serial=entry, func_ea=0x4000)


# ---------------------------------------------------------------------------
# Tests for detect_terminal_state_families_snapshot
# ---------------------------------------------------------------------------

class TestDetectTerminalStateFamilies:
    """Tests targeting ``detect_terminal_state_families_snapshot``."""

    @staticmethod
    def _detect(
        flow_graph: FlowGraph,
        dispatchers: set[int],
        side_effect_blocks: set[int] | None = None,
    ) -> set[int]:
        from d810.recon.flow.state_machine_analysis import (
            detect_terminal_state_families_snapshot,
        )
        return detect_terminal_state_families_snapshot(
            flow_graph, dispatchers, side_effect_blocks,
        )

    def test_empty_cone_no_dispatchers(self) -> None:
        """Empty dispatcher set -> empty result."""
        blk0 = _make_block(0, BLT_1WAY, succs=(1,), preds=())
        blk1 = _make_block(1, BLT_STOP, succs=(), preds=(0,))
        fg = _make_flowgraph([blk0, blk1], entry=0)

        result = self._detect(fg, set())
        assert result == set()

    def test_empty_cone_no_blt_stop(self) -> None:
        """Dispatchers exist but no arm reaches BLT_STOP -> empty result."""
        # Dispatcher blk[0] is 2-way with arms -> blk[1], blk[2]; neither is BLT_STOP.
        blk0 = _make_block(0, BLT_2WAY, succs=(1, 2), preds=())
        blk1 = _make_block(1, BLT_1WAY, succs=(), preds=(0,))
        blk2 = _make_block(2, BLT_1WAY, succs=(), preds=(0,))
        fg = _make_flowgraph([blk0, blk1, blk2], entry=0)

        result = self._detect(fg, {0})
        assert result == set()

    def test_single_boundary_block(self) -> None:
        """One dispatcher with a non-dispatcher arm reaching BLT_STOP (deep)."""
        #  0 (dispatcher, 2-way) -> 1 (dispatcher), 2 (non-dispatcher)
        #  2 -> deep cleanup chain (>=6 blocks) -> BLT_STOP
        blk0 = _make_block(0, BLT_2WAY, succs=(1, 2), preds=())
        blk1 = _make_block(1, BLT_2WAY, succs=(), preds=(0,))
        cleanup = _make_deep_cleanup_path(start=2, stop_serial=99, parent_serial=0)
        fg = _make_flowgraph([blk0, blk1] + cleanup, entry=0)

        result = self._detect(fg, {0, 1}, side_effect_blocks={3})
        assert 0 in result

    def test_reverse_predecessor_cone(self) -> None:
        """Linear BST chain A->B->C where C is boundary -> cone = {A, B, C}."""
        # Chain: 10 -> 11 -> 12 (all dispatchers, 2-way)
        # 12 has non-dispatcher arm -> 20 -> 30 (BLT_STOP)
        blk10 = _make_block(10, BLT_2WAY, succs=(11, 13), preds=())
        blk11 = _make_block(11, BLT_2WAY, succs=(12, 14), preds=(10,))
        blk12 = _make_block(12, BLT_2WAY, succs=(15, 20), preds=(11,))
        # Non-dispatcher successors (handler bodies, no BLT_STOP path).
        blk13 = _make_block(13, BLT_1WAY, succs=(), preds=(10,))
        blk14 = _make_block(14, BLT_1WAY, succs=(), preds=(11,))
        blk15 = _make_block(15, BLT_1WAY, succs=(), preds=(12,))
        # Deep terminal path from blk12's non-dispatcher arm.
        cleanup = _make_deep_cleanup_path(start=20, stop_serial=99, parent_serial=12)
        fg = _make_flowgraph(
            [blk10, blk11, blk12, blk13, blk14, blk15] + cleanup,
            entry=10,
        )

        dispatchers = {10, 11, 12}
        result = self._detect(fg, dispatchers, side_effect_blocks={21})
        # Boundary: blk12 (arm 20 reaches BLT_STOP).
        # Reverse cone: 12's pred 11 is dispatcher -> add 11; 11's pred 10 is dispatcher -> add 10.
        # Cone = {10, 11, 12} = all 3 dispatchers.
        # Majority: 3 > 3//2=1 -> escalation to ALL dispatchers (same set here).
        assert result == {10, 11, 12}

    def test_root_reach_escalation(self) -> None:
        """When cone reaches a dispatcher root, result includes the root's component."""
        # 5 dispatchers: 0, 1, 2, 3, 4.
        # Chain 0->1->2 forms cone (2 is boundary, BFS reaches BLT_STOP).
        # 0 has no dispatcher predecessors → it's a dispatcher root.
        # Cone = {0, 1, 2} contains root 0 → escalate to root 0's component.
        # 3 and 4 are in a separate component (not reachable from root 0).
        blk0 = _make_block(0, BLT_2WAY, succs=(1, 10), preds=())
        blk1 = _make_block(1, BLT_2WAY, succs=(2, 11), preds=(0,))
        blk2 = _make_block(2, BLT_2WAY, succs=(12, 20), preds=(1,))
        blk3 = _make_block(3, BLT_2WAY, succs=(13, 14), preds=())
        blk4 = _make_block(4, BLT_2WAY, succs=(15, 16), preds=())
        # Non-dispatcher leaves (no BLT_STOP).
        blk10 = _make_block(10, BLT_1WAY, succs=(), preds=(0,))
        blk11 = _make_block(11, BLT_1WAY, succs=(), preds=(1,))
        blk12 = _make_block(12, BLT_1WAY, succs=(), preds=(2,))
        blk13 = _make_block(13, BLT_1WAY, succs=(), preds=(3,))
        blk14 = _make_block(14, BLT_1WAY, succs=(), preds=(3,))
        blk15 = _make_block(15, BLT_1WAY, succs=(), preds=(4,))
        blk16 = _make_block(16, BLT_1WAY, succs=(), preds=(4,))
        # Deep terminal path from blk2's arm.
        cleanup = _make_deep_cleanup_path(start=20, stop_serial=99, parent_serial=2)
        fg = _make_flowgraph(
            [blk0, blk1, blk2, blk3, blk4,
             blk10, blk11, blk12, blk13, blk14, blk15, blk16]
            + cleanup,
            entry=0,
        )

        dispatchers = {0, 1, 2, 3, 4}
        result = self._detect(fg, dispatchers, side_effect_blocks={21})
        # Cone = {0, 1, 2}. Root 0 is in cone → escalate to root 0's
        # component {0, 1, 2}. Blocks 3 and 4 are unreachable from root 0.
        assert result == {0, 1, 2}

    def test_two_components_only_terminal_protected(self) -> None:
        """Two root components — only the one with the terminal cone is protected."""
        # Component A: root 0 → 1 → 2 (boundary, arm 50 reaches BLT_STOP).
        # Component B: root 100 → 101 → 102 (no terminal arm).
        # Only component A should be in the result.
        blk0 = _make_block(0, BLT_2WAY, succs=(1, 10), preds=())
        blk1 = _make_block(1, BLT_2WAY, succs=(2, 11), preds=(0,))
        blk2 = _make_block(2, BLT_2WAY, succs=(12, 50), preds=(1,))
        blk100 = _make_block(100, BLT_2WAY, succs=(101, 110), preds=())
        blk101 = _make_block(101, BLT_2WAY, succs=(102, 111), preds=(100,))
        blk102 = _make_block(102, BLT_2WAY, succs=(112, 113), preds=(101,))
        # Non-dispatcher leaves.
        blk10 = _make_block(10, BLT_1WAY, succs=(), preds=(0,))
        blk11 = _make_block(11, BLT_1WAY, succs=(), preds=(1,))
        blk12 = _make_block(12, BLT_1WAY, succs=(), preds=(2,))
        blk110 = _make_block(110, BLT_1WAY, succs=(), preds=(100,))
        blk111 = _make_block(111, BLT_1WAY, succs=(), preds=(101,))
        blk112 = _make_block(112, BLT_1WAY, succs=(), preds=(102,))
        blk113 = _make_block(113, BLT_1WAY, succs=(), preds=(102,))
        # Deep terminal path from component A.
        cleanup = _make_deep_cleanup_path(start=50, stop_serial=99, parent_serial=2)

        fg = _make_flowgraph(
            [blk0, blk1, blk2, blk100, blk101, blk102,
             blk10, blk11, blk12, blk110, blk111, blk112, blk113]
            + cleanup,
            entry=0,
        )
        dispatchers = {0, 1, 2, 100, 101, 102}
        result = self._detect(fg, dispatchers, side_effect_blocks={51})
        # Component A (root 0): {0, 1, 2} protected.
        # Component B (root 100): not in cone, not protected.
        assert result == {0, 1, 2}

    def test_no_root_reach_no_escalation(self) -> None:
        """When the cone does NOT reach a dispatcher root, no escalation."""
        # Dispatcher cycle: 10->11->12->10 (no root — every dispatcher
        # has a dispatcher predecessor).  blk12 is boundary (arm 50
        # reaches BLT_STOP).  Cone = {10, 11, 12} = full cycle.
        # dispatcher_roots = {} (empty, all have dispatcher preds).
        # roots & cone = {} → no escalation.
        # Extra isolated dispatcher 20 is NOT in the cone.
        blk10 = _make_block(10, BLT_2WAY, succs=(11, 100), preds=(12,))
        blk11 = _make_block(11, BLT_2WAY, succs=(12, 101), preds=(10,))
        blk12 = _make_block(12, BLT_2WAY, succs=(10, 50), preds=(11,))
        blk20 = _make_block(20, BLT_2WAY, succs=(102, 103), preds=())
        # Non-dispatcher leaves.
        blk100 = _make_block(100, BLT_1WAY, succs=(), preds=(10,))
        blk101 = _make_block(101, BLT_1WAY, succs=(), preds=(11,))
        blk102 = _make_block(102, BLT_1WAY, succs=(), preds=(20,))
        blk103 = _make_block(103, BLT_1WAY, succs=(), preds=(20,))
        # Deep terminal path from blk12's arm 50.
        cleanup_blks = _make_deep_cleanup_path(start=50, stop_serial=99, parent_serial=12)

        fg = _make_flowgraph(
            [blk10, blk11, blk12, blk20,
             blk100, blk101, blk102, blk103,
             ] + cleanup_blks,
            entry=10,
        )
        dispatchers = {10, 11, 12, 20}
        result = self._detect(fg, dispatchers, side_effect_blocks={51})
        # Cone = {10, 11, 12}. No dispatcher root in cone (all have
        # dispatcher preds within the cycle). blk20 is a root but not
        # in cone. No escalation → only cycle blocks returned.
        assert result == {10, 11, 12}


# ---------------------------------------------------------------------------
# Tests for _restricted_reach_stop
# ---------------------------------------------------------------------------

class TestRestrictedReachStop:
    """Tests targeting ``_restricted_reach_stop``."""

    @staticmethod
    def _reach(fg: FlowGraph, start: int, forbidden: set[int]) -> bool:
        from d810.recon.flow.state_machine_analysis import _restricted_reach_stop
        return _restricted_reach_stop(fg, start, forbidden)

    def test_direct_stop(self) -> None:
        """Start block IS BLT_STOP -> True."""
        blk0 = _make_block(0, BLT_STOP, succs=(), preds=())
        fg = _make_flowgraph([blk0], entry=0)
        assert self._reach(fg, 0, set()) is True

    def test_blocked_by_forbidden(self) -> None:
        """Path to BLT_STOP goes through forbidden block -> False."""
        blk0 = _make_block(0, BLT_1WAY, succs=(1,), preds=())
        blk1 = _make_block(1, BLT_1WAY, succs=(2,), preds=(0,))
        blk2 = _make_block(2, BLT_STOP, succs=(), preds=(1,))
        fg = _make_flowgraph([blk0, blk1, blk2], entry=0)
        # Block 1 is forbidden — cannot traverse it.
        assert self._reach(fg, 0, {1}) is False

    def test_no_stop_block(self) -> None:
        """No BLT_STOP reachable at all -> False."""
        blk0 = _make_block(0, BLT_1WAY, succs=(1,), preds=())
        blk1 = _make_block(1, BLT_1WAY, succs=(), preds=(0,))
        fg = _make_flowgraph([blk0, blk1], entry=0)
        assert self._reach(fg, 0, set()) is False


# ---------------------------------------------------------------------------
# Tests for FlowMaturityContext cache invalidation
# ---------------------------------------------------------------------------

    # NOTE: FlowMaturityContext.refresh_mba() cache invalidation is tested
    # in system/runtime tests (requires IDA). The reset is a single-line
    # attribute assignment in context.py — verified by code review.
