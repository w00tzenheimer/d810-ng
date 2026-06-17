"""Explicit cross-maturity dispatcher-analysis history (E5 step 2).

Replaces the hidden cross-maturity state that the retired live
dispatcher-analysis owner kept inside a per-function object.  The two
load-bearing facts --
``previous_router_kind`` and ``persisted_initial_state`` -- become an explicit,
immutable :class:`DispatcherHistory` value owned by a small
:class:`DispatcherHistoryStore` keyed by ``func_ea``.  Consumers then
access dispatcher analysis through the stateless
``analyze_dispatcher_live(mba, store=...)`` helper:

    lift(mba) -> FlowGraph
    analyze_dispatcher(flow_graph, previous_router_kind=..., persisted_initial_state=...)

The promotion rule is identical to the retired live dispatcher history
(pinned by ``tests/.../test_dispatcher_history_store.py`` and
mirrored by this module's own test): on each new maturity the prior
analysis' ``router_kind`` and -- only when not ``None`` --
``initial_state`` are carried forward.

The live ``lift`` import means this module needs ``ida_hexrays`` at
import; it sits in the optimizer layer alongside the legacy adapter.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core import getLogger
from d810.hexrays.mutation.ir_translator import lift
from d810.analyses.control_flow.dispatcher_analysis import (
    DispatcherAnalysis,
    analyze_dispatcher,
)
from d810.capabilities.dispatcher import RouterKind

logger = getLogger("D810.dispatcher")

__all__ = [
    # Re-export so consumers import analysis + access in one place.
    "DispatcherAnalysis",
    "RouterKind",
    "DispatcherHistory",
    "DispatcherHistoryStore",
    "DEFAULT_DISPATCHER_HISTORY_STORE",
    "analyze_dispatcher_live",
    "is_dispatcher_block",
    "should_skip_dispatcher",
]


@dataclass(frozen=True, slots=True)
class DispatcherHistory:
    """Cross-maturity dispatcher facts carried forward between maturities.

    Immutable; ``advanced_with`` returns the history to use at the NEXT
    maturity after observing ``analysis`` at the current one.
    """

    previous_router_kind: RouterKind | None = None
    persisted_initial_state: int | None = None

    def advanced_with(self, analysis: DispatcherAnalysis) -> "DispatcherHistory":
        """Promotion rule used by dispatcher-history promotion:

        * ``previous_router_kind`` <- this analysis' ``router_kind``.
        * ``persisted_initial_state`` <- this analysis' ``initial_state``
          ONLY when it is not ``None`` (a later ``None`` must not clobber
          a previously-known concrete state).
        """
        return DispatcherHistory(
            previous_router_kind=analysis.router_kind,
            persisted_initial_state=(
                analysis.initial_state
                if analysis.initial_state is not None
                else self.persisted_initial_state
            ),
        )


_EMPTY_HISTORY = DispatcherHistory()


class DispatcherHistoryStore:
    """Per-``func_ea`` cross-maturity history + same-maturity analysis memo.

    Owns exactly the state the live dispatcher analysis used to hide: the
    carried-forward :class:`DispatcherHistory` and a one-slot memo of the
    last analysis (so repeated queries at the same maturity do not
    re-lift / re-analyze).
    """

    def __init__(self) -> None:
        self._history: dict[int, DispatcherHistory] = {}
        # func_ea -> (maturity, analysis) one-slot memo.
        self._memo: dict[int, tuple[int, DispatcherAnalysis]] = {}

    def history_for(self, func_ea: int) -> DispatcherHistory:
        return self._history.get(int(func_ea), _EMPTY_HISTORY)

    def cached_analysis(
        self, func_ea: int, maturity: int
    ) -> DispatcherAnalysis | None:
        entry = self._memo.get(int(func_ea))
        if entry is not None and entry[0] == int(maturity):
            return entry[1]
        return None

    def record(
        self, func_ea: int, maturity: int, analysis: DispatcherAnalysis
    ) -> None:
        """Memoize ``analysis`` at ``maturity`` and advance the carried
        history so the NEXT maturity sees this analysis' facts."""
        key = int(func_ea)
        self._memo[key] = (int(maturity), analysis)
        self._history[key] = self.history_for(key).advanced_with(analysis)

    def clear(self, func_ea: int | None = None) -> None:
        if func_ea is None:
            self._history.clear()
            self._memo.clear()
            return
        key = int(func_ea)
        self._history.pop(key, None)
        self._memo.pop(key, None)


# Process-wide default store (mirrors the legacy class-level cache scope).
DEFAULT_DISPATCHER_HISTORY_STORE = DispatcherHistoryStore()


def analyze_dispatcher_live(
    mba: "object",
    *,
    store: DispatcherHistoryStore = DEFAULT_DISPATCHER_HISTORY_STORE,
) -> DispatcherAnalysis:
    """Lift ``mba`` and run the pure analyzer with cross-maturity history.

    Live entry point for dispatcher analysis over a Hex-Rays ``mba``:
    reads the carried history for the function, returns the same-maturity
    memo when present, otherwise lifts + analyzes and records the result.
    """
    func_ea = int(mba.entry_ea)
    maturity = int(mba.maturity)

    cached = store.cached_analysis(func_ea, maturity)
    if cached is not None:
        return cached

    history = store.history_for(func_ea)
    flow_graph = lift(mba)
    analysis = analyze_dispatcher(
        flow_graph,
        previous_router_kind=history.previous_router_kind,
        persisted_initial_state=history.persisted_initial_state,
    )
    store.record(func_ea, maturity, analysis)
    return analysis


def is_dispatcher_block(analysis: DispatcherAnalysis, serial: int) -> bool:
    """Whether ``serial`` is flagged a dispatcher in ``analysis``."""
    block = analysis.blocks.get(serial)
    return bool(block.is_dispatcher) if block is not None else False


def should_skip_dispatcher(mba: "object", blk: "object") -> bool:
    """Skip a block for switch-table-style patching when it belongs to a
    conditional-chain dispatcher.

    Thin live helper over ``analyze_dispatcher_live``. Only
    conditional-chain dispatchers are skipped; switch-table style requires
    modifying dispatcher blocks.
    """
    analysis = analyze_dispatcher_live(mba)
    if not analysis.is_conditional_chain:
        return False
    return is_dispatcher_block(analysis, blk.serial)
