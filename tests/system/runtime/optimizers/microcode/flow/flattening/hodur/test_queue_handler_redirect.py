"""Tests for HodurRuleServices._queue_handler_redirect.

The helper is intentionally disabled.  It used to queue direct
``DeferredGraphModifier`` mutations, bypassing the modern PlanFragment ->
PatchPlan path.  These tests keep that disabled contract visible so a future
caller cannot silently revive the old direct-deferred mutation path.

Pure-logic unit test.  The only IDA dependency is the import of
``HodurRuleServices`` itself (which transitively imports ``ida_hexrays``).
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
    from d810.optimizers.microcode.flow.flattening.hodur.rule_services import (
        HodurRuleServices,
    )
except ImportError:
    HodurRuleServices = None  # type: ignore[assignment,misc]

pytestmark = pytest.mark.skipif(
    HodurRuleServices is None,
    reason="HodurRuleServices requires ida_hexrays at import time",
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
    """Test double standing in for the hosted rule state."""

    def __init__(self, blocks: dict[int, _FakeMblock]) -> None:
        self.mba = _FakeMba(blocks)
        self.deferred = _FakeDeferred()
        self._last_redirect_meta = None
        assert HodurRuleServices is not None
        self._support = HodurRuleServices(self)


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
    result = instance._support._queue_handler_redirect(
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

def test_legacy_queue_handler_redirect_is_disabled_and_side_effect_free():
    claimed_exits: dict[int, int] = {}
    claimed_edges: dict[tuple[int, int], int] = {}
    result, instance = _call(
        path=_path(exit_block=10, ordered_path=[5, 10]),
        target=30,
        blocks={10: _FakeMblock([20]), 5: _FakeMblock([10])},
        claimed_exits=claimed_exits,
        claimed_edges=claimed_edges,
    )

    assert result is False
    assert instance.deferred.calls == []
    assert claimed_exits == {}
    assert claimed_edges == {}
    assert instance._last_redirect_meta == {
        "kind": "disabled_legacy_queue_handler_redirect",
        "source_block": 10,
        "via_pred": None,
        "target": 30,
    }
