"""Tests for HodurUnflattener._queue_handler_redirect.

These tests call the REAL production method on HodurUnflattener by binding it
to a hand-rolled test double.  No mocks are used.

Pure-logic unit test.  The only IDA dependency is the import of
``HodurUnflattener`` itself (which transitively imports ``ida_hexrays``).
The method under test uses only duck-typed ``self.mba`` / ``self.deferred``
protocols, so the test doubles are plain Python classes.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from d810.optimizers.microcode.flow.flattening.hodur.datamodel import (
    HandlerPathResult,
)

try:
    from d810.optimizers.microcode.flow.flattening.hodur.unflattener import (
        HodurUnflattener,
    )
except ImportError:
    HodurUnflattener = None  # type: ignore[assignment,misc]

pytestmark = pytest.mark.skipif(
    HodurUnflattener is None,
    reason="HodurUnflattener requires ida_hexrays at import time",
)


# ---------------------------------------------------------------------------
# Hand-rolled test doubles (no mocks)
# ---------------------------------------------------------------------------

class _FakeMblock:
    """Minimal mblock double with configurable successors."""

    def __init__(self, succs: list[int], preds: list[int] | None = None) -> None:
        self._succs = succs
        self._preds = preds or []

    def nsucc(self) -> int:
        return len(self._succs)

    def succ(self, i: int) -> int:
        return self._succs[i]

    def npred(self) -> int:
        return len(self._preds)

    def pred(self, i: int) -> int:
        return self._preds[i]


@dataclass
class _CallRecord:
    method: str
    kwargs: dict


@dataclass
class _FakeDeferred:
    """Records queue_goto_change / queue_edge_redirect calls for assertions."""

    calls: list[_CallRecord] = field(default_factory=list)

    def queue_goto_change(self, **kwargs) -> None:
        self.calls.append(_CallRecord("queue_goto_change", kwargs))

    def queue_edge_redirect(self, **kwargs) -> None:
        self.calls.append(_CallRecord("queue_edge_redirect", kwargs))


class _FakeMba:
    """Minimal mba double that returns _FakeMblock by serial."""

    def __init__(self, blocks: dict[int, _FakeMblock]) -> None:
        self._blocks = blocks

    def get_mblock(self, serial: int):
        return self._blocks.get(serial)


class _FakeInstance:
    """Test double standing in for HodurUnflattener ``self``."""

    def __init__(self, blocks: dict[int, _FakeMblock]) -> None:
        self.mba = _FakeMba(blocks)
        self.deferred = _FakeDeferred()
        self._last_redirect_meta = None
        # Bind the REAL production method to this instance.
        assert HodurUnflattener is not None
        self._queue_handler_redirect = (
            HodurUnflattener._queue_handler_redirect.__get__(self)
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _call(
    *,
    path: HandlerPathResult,
    target: int,
    blocks: dict[int, _FakeMblock],
    claimed_exits: dict[int, int] | None = None,
    claimed_edges: dict[tuple[int, int], int] | None = None,
    bst_node_blocks: set[int] | None = None,
    reason: str = "test",
) -> tuple[bool, _FakeInstance]:
    """Call the production method; return (result, instance) for assertions."""
    ce = claimed_exits if claimed_exits is not None else {}
    ck = claimed_edges if claimed_edges is not None else {}
    bn = bst_node_blocks if bst_node_blocks is not None else set()
    instance = _FakeInstance(blocks)
    result = instance._queue_handler_redirect(
        path=path,
        target=target,
        reason=reason,
        claimed_exits=ce,
        claimed_edges=ck,
        bst_node_blocks=bn,
    )
    return result, instance


def _path(
    exit_block: int,
    ordered_path: list[int],
    final_state: int | None = 0xDEAD,
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
        result, instance = _call(
            path=_path(exit_block=10, ordered_path=[5, 10]),
            target=30,
            blocks={10: _FakeMblock([20])},
            claimed_exits=claimed_exits,
        )
        assert result is True
        assert len(instance.deferred.calls) == 1
        c = instance.deferred.calls[0]
        assert c.method == "queue_goto_change"
        assert c.kwargs["block_serial"] == 10
        assert c.kwargs["new_target"] == 30
        assert c.kwargs["rule_priority"] == 550
        assert c.kwargs["description"] == "test"
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
        result, instance = _call(
            path=_path(exit_block=10, ordered_path=[5, 10]),
            target=30,
            blocks={10: _FakeMblock([20])},
            claimed_exits={10: 30},
        )
        assert result is True
        assert len(instance.deferred.calls) == 0


class TestConflictEdgeRedirect:
    """exit_block claimed for different target, valid via_pred -> queue_edge_redirect."""

    def test_calls_queue_edge_redirect_returns_true(self):
        result, instance = _call(
            path=_path(exit_block=10, ordered_path=[5, 10]),
            target=30,
            blocks={10: _FakeMblock([20]), 5: _FakeMblock([10])},
            claimed_exits={10: 99},
        )
        assert result is True
        assert len(instance.deferred.calls) == 1
        c = instance.deferred.calls[0]
        assert c.method == "queue_edge_redirect"
        assert c.kwargs["new_target"] == 30
        assert c.kwargs["via_pred"] == 5
        assert c.kwargs["src_block"] == 10


class TestEscalationWalksBackward:
    """(exit_block, via_pred) already claimed -> walks to earlier segment."""

    def test_uses_upstream_pair(self):
        # ordered_path=[3, 5, 10]; edge (10,5) claimed; (5,3) is free + valid
        result, instance = _call(
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
        assert len(instance.deferred.calls) == 1
        c = instance.deferred.calls[0]
        assert c.method == "queue_edge_redirect"
        assert c.kwargs["src_block"] == 5
        assert c.kwargs["via_pred"] == 3
        assert c.kwargs["new_target"] == 30


class TestEscalationShapeValidation:
    """Backward walk validates edge-split preconditions."""

    def test_skips_nsucc_gt1_finds_valid_pair(self):
        # ordered_path=[2, 5, 8, 10]; edge (10,8) claimed
        # pair (8,5): blk8.nsucc()=2 -> INVALID, skip
        # pair (5,2): blk5.nsucc()=1, blk2.nsucc()=1, 2->5 exists -> VALID
        result, instance = _call(
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
        c = instance.deferred.calls[0]
        assert c.kwargs["src_block"] == 5
        assert c.kwargs["via_pred"] == 2

    def test_skips_when_pred_nsucc_gt1(self):
        # pair (5,3): blk3.nsucc()=2 -> INVALID for seg_pred
        result, instance = _call(
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
        assert len(instance.deferred.calls) == 0

    def test_skips_when_edge_does_not_exist(self):
        # pair (5,3): blk3.succ(0)=77 != 5 -> edge 3->5 doesn't exist
        result, instance = _call(
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
        assert len(instance.deferred.calls) == 0


class TestEscalationAllClaimedReturnsFalse:
    """All (src, pred) pairs in ordered_path are claimed -> returns False."""

    def test_returns_false_when_all_claimed(self):
        result, instance = _call(
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
        assert len(instance.deferred.calls) == 0


class TestShortOrderedPathReturnsFalse:
    """ordered_path has only 1 element (no via_pred) -> returns False."""

    def test_single_element_path(self):
        result, instance = _call(
            path=_path(exit_block=10, ordered_path=[10]),
            target=30,
            blocks={10: _FakeMblock([20])},
            claimed_exits={10: 99},
        )
        assert result is False
        assert len(instance.deferred.calls) == 0
