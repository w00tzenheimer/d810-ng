"""Value-range capability Protocol + portable result type.

Describes the backend boundary for "what concrete value / interval can the
state variable hold at this block?" queries.  The Hex-Rays implementation
(:class:`HexRaysValRangeCapability`) lives at
``d810.evaluator.hexrays_microcode.value_range_capability`` because the
resolution requires live ``ida_hexrays`` access (``mblock_t.get_valranges`` and,
as a fallback, the custom forward value-range fixpoint in
``d810.evaluator.hexrays_microcode.valrange_dataflow``).  A future angr / Ghidra
backend would implement this Protocol next to its own value-range analysis.

This is the unifying surface over the three existing value-range modules:

* ``evaluator/hexrays_microcode/valranges.py`` -- IDA-native ``get_valranges``
  queries + ``IntervalDispatcher`` probing (the primary source);
* ``evaluator/hexrays_microcode/valrange_dataflow.py`` -- the hand-rolled
  forward value-range fixpoint (the fallback when IDA's native ranges are
  unavailable at the current maturity);
* ``backends/hexrays/evidence/valrange_resolution.py`` -- the existing
  ``ValrangeResolutionStrategy`` consumer.

Rather than merging those (two evaluator engines + one backend strategy, at
different layers), this capability is the single portable contract the §1a
``RecoverStateTransitions`` domain consumes via ``capabilities.optional`` to
resolve transitions the exact equality-chain cannot.

``state_var_stkoff`` / ``block_serial`` cross the boundary as plain ints so the
Protocol stays portable; live operands (the block, the dispatcher, an insn
anchor) are passed positionally as ``Any`` per the LSP-contravariance rationale
documented in :mod:`d810.capabilities.use_def_safety`.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Any, Protocol

__all__ = ["ValRange", "ValRangeCapability"]


@dataclass(frozen=True, slots=True)
class ValRange:
    """Portable inclusive value range ``[lo, hi]`` for an operand of ``width`` bytes.

    Lives in the capability layer so any backend can construct ranges without an
    upward import.  A backend that can only prove a single value returns
    ``lo == hi``; a backend with no information returns ``None`` rather than a
    full-width range, so callers can distinguish "unknown" from "any value".

    Attributes:
        lo: Inclusive lower bound (unsigned).
        hi: Inclusive upper bound (unsigned).
        width: Operand width in bytes.
    """

    lo: int
    hi: int
    width: int

    @property
    def is_singleton(self) -> bool:
        """True when the range collapses to exactly one value."""
        return self.lo == self.hi

    def single(self) -> int | None:
        """Return the sole value when this is a singleton, else ``None``."""
        return int(self.lo) if self.lo == self.hi else None

    def contains(self, value: int) -> bool:
        """True when ``value`` falls within the inclusive range."""
        return self.lo <= int(value) <= self.hi


class ValRangeCapability(Protocol):
    """Capability boundary for value-range state resolution.

    A concrete backend answers value-range queries about the state variable at a
    given block, which the §1a transition recovery uses to resolve handler exits
    that the exact equality-chain detector left unresolved (MBA-obfuscated state
    computations, range-routed handlers).  All methods are read-only; ``None``
    means "could not resolve / unknown", never a guessed value.
    """

    def resolve_state_value(
        self,
        block_serial: int,
        state_var_stkoff: int,
        *,
        at_insn: Any = None,
    ) -> int | None:
        """Return the single concrete value the state variable holds at the block.

        Queries the backend's value-range analysis for the state operand at
        ``state_var_stkoff`` and returns the value only when the range collapses
        to a single value (no over-approximation), else ``None``.

        Args:
            block_serial: Serial of the block to query.
            state_var_stkoff: Stack offset of the state variable.
            at_insn: Optional live instruction anchor (``ida_hexrays.minsn_t``);
                defaults to the backend's natural query point. ``Any`` for layer
                discipline.
        """
        ...

    def probe_dispatcher_target(
        self,
        block_serial: int,
        state_var_stkoff: int,
        dispatcher: Any,
        *,
        at_insn: Any = None,
    ) -> int | None:
        """Return the unique dispatcher target reachable from the block's state range.

        For each row of ``dispatcher`` (an ``IntervalDispatcher``), tests whether
        the block's incoming value range for the state variable overlaps the
        row's interval.  Returns the target block serial when exactly one row
        matches (a singleton range routes directly), else ``None``.

        Args:
            block_serial: Serial of the block to query.
            state_var_stkoff: Stack offset of the state variable.
            dispatcher: An ``IntervalDispatcher`` with handler interval rows.
                ``Any`` for layer discipline (it lives in ``d810.analyses``).
            at_insn: Optional live instruction anchor; defaults to the block
                head.
        """
        ...

    def state_value_range(
        self,
        block_serial: int,
        state_var_stkoff: int,
        *,
        at_insn: Any = None,
    ) -> ValRange | None:
        """Return the value range of the state variable at the block, or ``None``.

        ``None`` means the backend could not bound the variable (empty or
        all-values range); a bounded result is a :class:`ValRange`.
        """
        ...
