"""Pure-data dispatcher analysis facts.

Holds the pure data classes used by dispatcher analysis -- no
``ida_hexrays`` types in any field annotation, no live IDA calls in
any method body.  Consumed by the pure analyzer at
``d810.recon.flow.dispatcher_analysis`` and the live adapter at
``d810.optimizers.microcode.flow.dispatcher.dispatcher_history``.

Companion modules:

* ``d810.recon.flow.dispatcher_kind`` -- ``DispatcherType`` enum.
* ``d810.recon.flow.dispatcher_analysis`` -- pure
  ``analyze_dispatcher(flow_graph)`` + ``DispatcherAnalysis`` result.
* ``d810.optimizers.microcode.flow.dispatcher.dispatcher_history`` --
  live adapter (``analyze_dispatcher_live``: mba lift + explicit
  cross-maturity history store).

This module imports only ``d810.cfg.flowgraph``; all dependencies
flow upward (recon-flow facts -> recon-flow analyzer -> optimizers
live adapter), never the reverse.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntFlag

from d810.cfg.flowgraph import MopSnapshot, OperandKind

__all__ = ["BlockAnalysis", "DispatcherStrategy", "StateVariableCandidate"]


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


@dataclass
class StateVariableCandidate:
    """A candidate for the state variable (portable -- E3-schema).

    The operand identity is held as a portable
    ``d810.cfg.flowgraph.MopSnapshot``, NOT a live ``ida_hexrays.mop_t``.
    The live adapter at
    ``d810.optimizers.microcode.flow.dispatcher.dispatcher_history`` is
    the only construction site -- ``analyze_dispatcher_live`` lifts the mba via
    ``d810.hexrays.mutation.ir_translator.lift`` and then the pure
    ``analyze_dispatcher(flow_graph, ...)`` populates this candidate
    from the resulting snapshot.

    Field names ``mop_type`` / ``mop_offset`` / ``mop_size`` are kept
    for backward compatibility with existing consumers; their values
    mirror what the live-IDA helpers used to compute and can also be
    derived from ``mop`` directly via ``mop.kind`` /
    ``d810.cfg.mop_identity.mop_snapshot_offset(mop)`` / ``mop.size``.
    """

    mop: MopSnapshot
    mop_type: int = 0  # Mirror of mop.t (raw backend operand type; diagnostic)
    mop_offset: int = 0  # For STACK: stack offset; for REGISTER: register number
    mop_size: int = 4  # Operand size in bytes (mirrors mop.size)
    init_value: int | None = None
    comparison_count: int = 0
    assignment_count: int = 0
    unique_constants: set[int] = field(default_factory=set)
    comparison_blocks: list[int] = field(default_factory=list)
    assignment_blocks: list[int] = field(default_factory=list)
    score: float = 0.0

    def get_native_stack_offset(self, frame_size: int) -> int | None:
        """Convert microcode stack offset to native stack offset.

        Microcode stores stack offsets counting UP from the bottom of
        the frame, while native code uses offsets DOWN from RBP/RSP.
        Returns ``None`` if the candidate isn't a stack-resident
        variable.

        Args:
            frame_size: Total frame size from the live ``mba_t``.
                (Frame size is not part of the portable contract; the
                caller is responsible for sourcing it -- a live
                optimizer-layer caller reads ``mba.frsize``.)

        Returns:
            Native stack offset (negative, relative to frame base),
            or ``None`` if ``mop`` is not a stack operand or has no
            stack-offset bit captured.
        """
        if self.mop.kind is not OperandKind.STACK:
            return None
        if self.mop.stkoff is None:
            return None
        # display_offset counts down from frame top; native offset
        # is the negation relative to RBP.
        display_offset = frame_size - int(self.mop.stkoff)
        return -display_offset
