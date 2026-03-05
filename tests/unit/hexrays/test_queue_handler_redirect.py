"""Unit tests for HodurUnflattener._queue_handler_redirect.

These tests call the REAL production method on HodurUnflattener by binding it
to a mock instance.  All IDA C++ extension modules and the d810 submodules
that subclass them are stubbed out at module level (same technique used in
test_deferred_edge_redirect.py) so no IDA runtime is required.

Mock approach
-------------
- IDA C++ modules (ida_hexrays, ida_pro, …) get an _IntAutoStub that returns
  unique integers for attribute access, satisfying constant comparisons.
- d810 submodules whose classes inherit from IDA types at module level are also
  _IntAutoStub-ed to prevent TypeError from Python's C-extension rules.
- ``d810.optimizers.microcode.flow.flattening.generic`` and
  ``d810.optimizers.microcode.handler`` are given hand-crafted stub modules
  that expose real Python base classes (``GenericUnflatteningRule``,
  ``ConfigParam``) with the minimal surface needed for HodurUnflattener's
  class-body to parse.
- The other flattening submodules imported by unflattener_hodur (dispatcher_detection,
  safeguards, transition_builder, utils) are _IntAutoStub-ed as their symbols
  are only used inside method bodies, never at class-definition time.
- ``object.__new__(HodurUnflattener)`` creates an uninitialised instance;
  ``HodurUnflattener._queue_handler_redirect.__get__(instance)`` binds the
  REAL production method to it.  ``instance.mba`` and ``instance.deferred``
  are MagicMock objects.
"""
from __future__ import annotations

import sys
import types
from dataclasses import dataclass
from d810.core.typing import Any
from unittest.mock import MagicMock


# ---------------------------------------------------------------------------
# Step 1: _IntAutoStub — satisfies integer constant comparisons in IDA modules
# ---------------------------------------------------------------------------

class _IntAutoStub(types.ModuleType):
    """Returns a unique int for any unknown attribute access."""

    _counter: int = 0

    def __getattr__(self, name: str) -> int:
        if name.startswith("__"):
            raise AttributeError(name)
        _IntAutoStub._counter += 1
        val: int = _IntAutoStub._counter
        setattr(self, name, val)
        return val


# ---------------------------------------------------------------------------
# Step 2: Hand-crafted stub for d810.optimizers.microcode.handler
#         Provides a real ConfigParam dataclass (frozen=True to match prod).
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _ConfigParam:
    name: str
    type: type
    default: Any
    description: str
    choices: tuple | None = None


_handler_stub = types.ModuleType("d810.optimizers.microcode.handler")
_handler_stub.ConfigParam = _ConfigParam  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Step 3: Hand-crafted stub for d810.optimizers.microcode.flow.flattening.generic
#         Provides a real GenericUnflatteningRule base class with CONFIG_SCHEMA=().
# ---------------------------------------------------------------------------

class _GenericUnflatteningRule:
    """Minimal stub base class for HodurUnflattener."""
    CONFIG_SCHEMA: tuple = ()
    CATEGORY: str = ""
    PRIORITY: int = 0
    DEFAULT_UNFLATTENING_MATURITIES: list = []


_generic_stub = types.ModuleType("d810.optimizers.microcode.flow.flattening.generic")
_generic_stub.GenericUnflatteningRule = _GenericUnflatteningRule  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Step 4: Install all stubs BEFORE any d810 import
# ---------------------------------------------------------------------------

_IDA_STUB_NAMES = (
    "ida_hexrays", "ida_pro", "idaapi", "ida_bytes", "ida_funcs",
    "ida_kernwin", "ida_name", "ida_nalt", "ida_segment", "ida_typeinf",
    "ida_ua", "ida_xref", "ida_gdl", "ida_lines", "ida_range",
    "ida_ida", "idc", "idautils", "ida_idp",
)

# d810 submodules with IDA-inheriting classes at module level, or with deep
# transitive IDA imports that are only used inside method bodies.
_D810_STUB_NAMES = (
    "d810.hexrays.mutation.cfg_verify",
    "d810.hexrays.utils.hexrays_formatters",
    "d810.hexrays.utils.hexrays_helpers",
    "d810.hexrays.ir.cfg_queries",
    "d810.hexrays.ir.cfg_utils",
    "d810.hexrays.mutation.cfg_mutations",
    "d810.cfg.flowgraph",
    "d810.evaluator.hexrays_microcode.tracker",
    "d810.recon.flow.bst_analysis",
    "d810.hexrays.utils.arch_utils",
    "d810.hexrays.utils.table_utils",
    "d810.hexrays.expr.ast",
    "d810.hexrays.hexrays_microcode.emulator",
    "d810.hexrays.expr.z3_utils",
    "d810.cfg.dominator",
    "d810.recon.flow.dispatcher_detection",
    "d810.optimizers.microcode.flow.flattening.safeguards",
    "d810.recon.flow.transition_builder",
    "d810.optimizers.microcode.flow.flattening.utils",
    # flow/__init__.py imports these under the `else` branch when ida_hexrays
    # appears importable — stub them to prevent deep transitive pulls.
    "d810.optimizers.microcode.flow.constant_prop.global_const_inline",
    "d810.optimizers.microcode.flow.flattening.block_merge",
    "d810.optimizers.microcode.flow.flattening.mba_state_preconditioner",
    "d810.optimizers.microcode.flow.jumps.indirect_branch",
    "d810.optimizers.microcode.flow.jumps.indirect_call",
    "d810.optimizers.microcode.flow.identity_call",
)

_saved: dict[str, types.ModuleType | None] = {}

for _name in _IDA_STUB_NAMES + _D810_STUB_NAMES:
    _saved[_name] = sys.modules.get(_name)
    if _name not in sys.modules:
        sys.modules[_name] = _IntAutoStub(_name)

# Install the hand-crafted stubs (overwrite any auto-stub if already present).
_saved["d810.optimizers.microcode.handler"] = sys.modules.get("d810.optimizers.microcode.handler")
sys.modules["d810.optimizers.microcode.handler"] = _handler_stub

_saved["d810.optimizers.microcode.flow.flattening.generic"] = sys.modules.get(
    "d810.optimizers.microcode.flow.flattening.generic"
)
sys.modules["d810.optimizers.microcode.flow.flattening.generic"] = _generic_stub

# Now import — HandlerPathResult is a pure dataclass; HodurUnflattener we only
# bind its method, never call __init__.
from d810.optimizers.microcode.flow.flattening.unflattener_hodur import (  # noqa: E402
    HandlerPathResult,
    HodurUnflattener,
)

# Restore saved modules after import (good hygiene).
for _name, _orig in _saved.items():
    if _orig is None:
        sys.modules.pop(_name, None)
    else:
        sys.modules[_name] = _orig

import pytest  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeMblock:
    """Minimal mblock double with configurable successors."""

    def __init__(self, succs: list[int]) -> None:
        self._succs = succs

    def nsucc(self) -> int:
        return len(self._succs)

    def succ(self, i: int) -> int:
        return self._succs[i]


def _make_instance(blocks: dict[int, _FakeMblock]) -> MagicMock:
    """Create a mock HodurUnflattener instance with the REAL _queue_handler_redirect bound."""
    instance = MagicMock()
    instance.mba.get_mblock.side_effect = lambda serial: blocks.get(serial)
    # Bind the REAL production method to the mock instance.
    instance._queue_handler_redirect = (
        HodurUnflattener._queue_handler_redirect.__get__(instance)
    )
    return instance


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
    """Call the production method; return (result, instance) for assertions."""
    ce = claimed_exits if claimed_exits is not None else {}
    ck = claimed_edges if claimed_edges is not None else {}
    bn = bst_node_blocks if bst_node_blocks is not None else set()
    instance = _make_instance(blocks)
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
        instance.deferred.queue_goto_change.assert_called_once_with(
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
        result, instance = _call(
            path=_path(exit_block=10, ordered_path=[5, 10]),
            target=30,
            blocks={10: _FakeMblock([20])},
            claimed_exits={10: 30},
        )
        assert result is True
        instance.deferred.queue_goto_change.assert_not_called()
        instance.deferred.queue_edge_redirect.assert_not_called()


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
        instance.deferred.queue_edge_redirect.assert_called_once()
        kw = instance.deferred.queue_edge_redirect.call_args.kwargs
        assert kw["new_target"] == 30
        assert kw["via_pred"] == 5
        assert kw["src_block"] == 10


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
        instance.deferred.queue_edge_redirect.assert_called_once()
        kw = instance.deferred.queue_edge_redirect.call_args.kwargs
        assert kw["src_block"] == 5
        assert kw["via_pred"] == 3
        assert kw["new_target"] == 30


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
        kw = instance.deferred.queue_edge_redirect.call_args.kwargs
        assert kw["src_block"] == 5
        assert kw["via_pred"] == 2

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
        instance.deferred.queue_edge_redirect.assert_not_called()

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
        instance.deferred.queue_edge_redirect.assert_not_called()


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
        instance.deferred.queue_edge_redirect.assert_not_called()


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
        instance.deferred.queue_goto_change.assert_not_called()
        instance.deferred.queue_edge_redirect.assert_not_called()
