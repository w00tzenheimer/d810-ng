"""Pure-data dispatcher analysis facts.

Companion to ``d810.recon.flow.dispatcher_detection`` that holds the
fully-pure data classes used by dispatcher analysis -- no
``ida_hexrays`` types in any field annotation, no live IDA calls in
any method body.

Axis-C slice B1a step 1 (per the
``docs/plans/axis-c2-split-queue.md`` plan): pulling the genuinely
pure analysis-result types out of the larger live-IDA file gives
future caller-side refactors (the planned step 2 -- threading a pure
``DispatcherAnalysis`` result through ``fixpred_signals`` instead of
constructing ``DispatcherCache`` inside the collector) a clean type
target to consume.

Intentionally NOT in this slice:

* ``DispatcherCache``                -- analysis machinery,
  vendor-coupled by design; stays in ``dispatcher_detection``.
* ``StateVariableCandidate``         -- carries ``ida_hexrays.mop_t``
  in its field annotation AND uses ``idaapi.mop_S`` in
  ``get_native_stack_offset``; needs lifter-based normalization
  before it can move (future slice).
* ``DispatcherAnalysis``             -- references
  ``StateVariableCandidate``; moves with it.

Dependency direction is one-way:
``dispatcher_detection -> dispatcher_facts``, never the reverse.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntFlag

__all__ = ["BlockAnalysis", "DispatcherStrategy"]


class DispatcherStrategy(IntFlag):
    """Flags indicating which strategies detected a block as a dispatcher."""

    NONE = 0
    HIGH_FAN_IN = 1 << 0  # >=N predecessors
    STATE_COMPARISON = 1 << 1  # Compares against large constants
    LOOP_HEADER = 1 << 2  # Natural loop header
    PREDECESSOR_UNIFORM = 1 << 3  # Most preds are unconditional jumps
    CONSTANT_FREQUENCY = 1 << 4  # Many unique constants compared
    BACK_EDGE = 1 << 5  # Has incoming back-edges
    NESTED_LOOP = 1 << 6  # Part of nested loop structure
    SMALL_BLOCK = 1 << 7  # Few instructions (dispatchers are typically tight)
    SWITCH_JUMP = 1 << 8  # Contains jtbl or computed goto


@dataclass
class BlockAnalysis:
    """Analysis results for a single block."""

    serial: int
    strategies: DispatcherStrategy = DispatcherStrategy.NONE
    score: float = 0.0

    # Strategy-specific data
    predecessor_count: int = 0
    unconditional_pred_count: int = 0
    state_constants: set[int] = field(default_factory=set)
    back_edge_sources: list[int] = field(default_factory=list)
    loop_depth: int = 0

    @property
    def is_dispatcher(self) -> bool:
        """True if any strategy flagged this block as a dispatcher."""
        return self.strategies != DispatcherStrategy.NONE

    @property
    def is_strong_dispatcher(self) -> bool:
        """True if multiple strategies agree this is a dispatcher."""
        # Count set bits
        count = bin(self.strategies).count("1")
        return count >= 2
