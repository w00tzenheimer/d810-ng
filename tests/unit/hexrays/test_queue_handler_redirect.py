"""Unit tests for the _queue_handler_redirect logic extracted from HodurUnflattener.

These tests are fully self-contained — no IDA or d810 imports required.
The function under test is extracted as a standalone helper that mirrors the
exact branching logic of HodurUnflattener._queue_handler_redirect.

If the production code changes, update ``_queue_handler_redirect_impl`` to match.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional
from unittest.mock import MagicMock, call

import pytest

# ---------------------------------------------------------------------------
# Local mirror of HandlerPathResult (same fields as in unflattener_hodur.py)
# ---------------------------------------------------------------------------

@dataclass
class HandlerPathResult:
    exit_block: int
    final_state: Optional[int]
    state_writes: list
    ordered_path: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Standalone implementation of the _queue_handler_redirect logic.
#
# This mirrors exactly the production code in:
#   src/d810/optimizers/microcode/flow/flattening/unflattener_hodur.py
#   HodurUnflattener._queue_handler_redirect
#
# Keep in sync with the production method when it changes.
# ---------------------------------------------------------------------------

_log = logging.getLogger(__name__)


def _queue_handler_redirect_impl(
    *,
    path: HandlerPathResult,
    target: int,
    reason: str,
    claimed_exits: dict[int, int],
    claimed_edges: dict[tuple[int, int], int],
    bst_node_blocks: set[int],
    mba_get_mblock,      # callable: serial -> mblock-like | None
    deferred,            # mock with queue_goto_change / queue_edge_redirect
) -> bool:
    """Standalone implementation matching HodurUnflattener._queue_handler_redirect."""
    exit_blk = mba_get_mblock(path.exit_block)

    # Fast path: exit block not yet claimed by any handler.
    if path.exit_block not in claimed_exits:
        deferred.queue_goto_change(
            block_serial=path.exit_block,
            new_target=target,
            rule_priority=550,
            description=reason,
        )
        claimed_exits[path.exit_block] = target
        return True

    # Already claimed for the same target — no-op.
    if claimed_exits[path.exit_block] == target:
        return True

    # Conflict: exit_block claimed for a different target. Use edge-level redirect.
    if len(path.ordered_path) >= 2:
        via_pred = path.ordered_path[-2]
    else:
        _log.warning(
            "EDGE_REDIRECT: no via_pred for exit blk[%d] -> target %d "
            "(ordered_path too short: %s)",
            path.exit_block, target, path.ordered_path,
        )
        return False

    # Determine old_target (current successor of exit_block leading to dispatcher).
    old_target = 0
    if exit_blk is not None and exit_blk.nsucc() > 0:
        old_target = exit_blk.succ(0)

    # Check if this specific edge is already claimed.
    edge_key = (path.exit_block, via_pred)
    if edge_key in claimed_edges:
        if claimed_edges[edge_key] == target:
            return True  # Already claimed for same target.
        # Escalate: walk backward through ordered_path to find an unclaimed edge.
        _log.info(
            "EDGE_ESCALATION: edge (%d, %d) claimed for %d, searching earlier segment for target %d",
            path.exit_block, via_pred, claimed_edges[edge_key], target,
        )
        found_src: int | None = None
        found_pred: int | None = None
        for i in range(len(path.ordered_path) - 2, 0, -1):
            seg_src = path.ordered_path[i]
            seg_pred = path.ordered_path[i - 1]
            seg_key = (seg_src, seg_pred)
            if seg_key not in claimed_edges and seg_src not in bst_node_blocks:
                # Validate edge-split preconditions before accepting this pair.
                seg_src_blk = mba_get_mblock(seg_src)
                seg_pred_blk = mba_get_mblock(seg_pred)
                if seg_src_blk is None or seg_pred_blk is None:
                    continue
                if seg_src_blk.nsucc() != 1:
                    continue
                if seg_pred_blk.nsucc() != 1:
                    continue
                if not any(
                    seg_pred_blk.succ(j) == seg_src
                    for j in range(seg_pred_blk.nsucc())
                ):
                    continue
                found_src = seg_src
                found_pred = seg_pred
                break
        if found_src is None or found_pred is None:
            _log.warning(
                "EDGE_REDIRECT: all path segments claimed for exit blk[%d] -> target %d, "
                "cannot queue redirect",
                path.exit_block, target,
            )
            return False
        src_block = found_src
        use_pred = found_pred
        src_blk = mba_get_mblock(src_block)
        old_target = src_blk.succ(0) if src_blk is not None and src_blk.nsucc() > 0 else 0
    else:
        src_block = path.exit_block
        use_pred = via_pred

    deferred.queue_edge_redirect(
        src_block=src_block,
        old_target=old_target,
        new_target=target,
        via_pred=use_pred,
        rule_priority=550,
        description=reason,
    )
    claimed_edges[(src_block, use_pred)] = target
    return True


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

class _FakeMblock:
    """Minimal mblock double with configurable successors."""

    def __init__(self, succs: list[int]) -> None:
        self._succs = succs

    def nsucc(self) -> int:
        return len(self._succs)

    def succ(self, i: int) -> int:
        return self._succs[i]


def _call(
    *,
    path: HandlerPathResult,
    target: int,
    blocks: dict[int, _FakeMblock],
    claimed_exits: dict[int, int] | None = None,
    claimed_edges: dict[tuple[int, int], int] | None = None,
    bst_node_blocks: set[int] | None = None,
    reason: str = "test",
) -> tuple[bool, MagicMock]:
    """Call the implementation and return (result, deferred_mock)."""
    deferred = MagicMock()
    result = _queue_handler_redirect_impl(
        path=path,
        target=target,
        reason=reason,
        claimed_exits=claimed_exits if claimed_exits is not None else {},
        claimed_edges=claimed_edges if claimed_edges is not None else {},
        bst_node_blocks=bst_node_blocks if bst_node_blocks is not None else set(),
        mba_get_mblock=lambda serial: blocks.get(serial),
        deferred=deferred,
    )
    return result, deferred


def _path(
    exit_block: int,
    ordered_path: list[int],
    final_state: Optional[int] = 0xDEAD,
) -> HandlerPathResult:
    return HandlerPathResult(
        exit_block=exit_block,
        final_state=final_state,
        state_writes=[],
        ordered_path=ordered_path,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestDirectPathUnclaimed:
    """Fast path: exit_block not yet in claimed_exits."""

    def test_calls_queue_goto_change_and_returns_true(self):
        claimed_exits: dict[int, int] = {}
        result, deferred = _call(
            path=_path(exit_block=10, ordered_path=[5, 10]),
            target=30,
            blocks={10: _FakeMblock([20])},
            claimed_exits=claimed_exits,
        )
        assert result is True
        deferred.queue_goto_change.assert_called_once_with(
            block_serial=10, new_target=30, rule_priority=550, description="test",
        )
        assert claimed_exits[10] == 30

    def test_claimed_exits_updated(self):
        claimed_exits: dict[int, int] = {}
        _call(
            path=_path(exit_block=10, ordered_path=[10]),
            target=99,
            blocks={10: _FakeMblock([20])},
            claimed_exits=claimed_exits,
        )
        assert claimed_exits.get(10) == 99


class TestSameTargetNoop:
    """exit_block already claimed for the same target -> True, no new queue call."""

    def test_returns_true_without_queuing(self):
        result, deferred = _call(
            path=_path(exit_block=10, ordered_path=[5, 10]),
            target=30,
            blocks={10: _FakeMblock([20])},
            claimed_exits={10: 30},
        )
        assert result is True
        deferred.queue_goto_change.assert_not_called()
        deferred.queue_edge_redirect.assert_not_called()


class TestConflictEdgeRedirect:
    """exit_block claimed for different target, valid via_pred -> queue_edge_redirect."""

    def test_calls_queue_edge_redirect_returns_true(self):
        result, deferred = _call(
            path=_path(exit_block=10, ordered_path=[5, 10]),
            target=30,
            blocks={10: _FakeMblock([20]), 5: _FakeMblock([10])},
            claimed_exits={10: 99},
        )
        assert result is True
        deferred.queue_edge_redirect.assert_called_once()
        kw = deferred.queue_edge_redirect.call_args.kwargs
        assert kw["new_target"] == 30
        assert kw["via_pred"] == 5
        assert kw["src_block"] == 10


class TestEscalationWalksBackward:
    """(exit_block, via_pred) already claimed -> walks to earlier segment."""

    def test_uses_upstream_pair(self):
        # ordered_path=[3, 5, 10]; edge (10,5) claimed; (5,3) is free + valid
        result, deferred = _call(
            path=_path(exit_block=10, ordered_path=[3, 5, 10]),
            target=30,
            blocks={
                10: _FakeMblock([20]),
                5: _FakeMblock([10]),
                3: _FakeMblock([5]),
            },
            claimed_exits={10: 99},
            claimed_edges={(10, 5): 99},
        )
        assert result is True
        deferred.queue_edge_redirect.assert_called_once()
        kw = deferred.queue_edge_redirect.call_args.kwargs
        assert kw["src_block"] == 5
        assert kw["via_pred"] == 3
        assert kw["new_target"] == 30


class TestEscalationShapeValidation:
    """Backward walk validates edge-split preconditions."""

    def test_skips_nsucc_gt1_finds_valid_pair(self):
        # ordered_path=[2, 5, 8, 10]; edge (10,8) claimed
        # pair (8,5): blk8.nsucc()=2 -> INVALID, skip
        # pair (5,2): blk5.nsucc()=1, blk2.nsucc()=1, 2->5 exists -> VALID
        result, deferred = _call(
            path=_path(exit_block=10, ordered_path=[2, 5, 8, 10]),
            target=30,
            blocks={
                10: _FakeMblock([20]),
                8: _FakeMblock([10, 99]),   # nsucc=2, invalid
                5: _FakeMblock([8]),
                2: _FakeMblock([5]),
            },
            claimed_exits={10: 99},
            claimed_edges={(10, 8): 99},
        )
        assert result is True
        kw = deferred.queue_edge_redirect.call_args.kwargs
        assert kw["src_block"] == 5
        assert kw["via_pred"] == 2

    def test_skips_when_pred_nsucc_gt1(self):
        # pair (5,3): blk3.nsucc()=2 -> INVALID for seg_pred
        result, deferred = _call(
            path=_path(exit_block=10, ordered_path=[3, 5, 10]),
            target=30,
            blocks={
                10: _FakeMblock([20]),
                5: _FakeMblock([10]),
                3: _FakeMblock([5, 77]),    # nsucc=2, invalid as seg_pred
            },
            claimed_exits={10: 99},
            claimed_edges={(10, 5): 99},
        )
        assert result is False
        deferred.queue_edge_redirect.assert_not_called()

    def test_skips_when_edge_does_not_exist(self):
        # pair (5,3): blk3.succ(0)=77 != 5 -> edge 3->5 doesn't exist
        result, deferred = _call(
            path=_path(exit_block=10, ordered_path=[3, 5, 10]),
            target=30,
            blocks={
                10: _FakeMblock([20]),
                5: _FakeMblock([10]),
                3: _FakeMblock([77]),       # goes to 77, not 5
            },
            claimed_exits={10: 99},
            claimed_edges={(10, 5): 99},
        )
        assert result is False
        deferred.queue_edge_redirect.assert_not_called()


class TestEscalationAllClaimedReturnsFalse:
    """All (src, pred) pairs in ordered_path are claimed -> returns False."""

    def test_returns_false_when_all_claimed(self):
        result, deferred = _call(
            path=_path(exit_block=10, ordered_path=[3, 5, 10]),
            target=30,
            blocks={
                10: _FakeMblock([20]),
                5: _FakeMblock([10]),
                3: _FakeMblock([5]),
            },
            claimed_exits={10: 99},
            claimed_edges={(10, 5): 99, (5, 3): 99},
        )
        assert result is False
        deferred.queue_edge_redirect.assert_not_called()


class TestShortOrderedPathReturnsFalse:
    """ordered_path has only 1 element (no via_pred) -> returns False."""

    def test_single_element_path(self):
        result, deferred = _call(
            path=_path(exit_block=10, ordered_path=[10]),
            target=30,
            blocks={10: _FakeMblock([20])},
            claimed_exits={10: 99},
        )
        assert result is False
        deferred.queue_goto_change.assert_not_called()
        deferred.queue_edge_redirect.assert_not_called()
