"""Recurrence-analysis capability Protocols.

Describes the backend boundary for recurrence (loop-evolution) analysis.
Concrete implementations live under ``d810.backends/<vendor>/`` (or an analyses
default) and are injected via the composition root.

Per-type-by-layer annotation discipline (RESOLVE-FIRST for LS8 S4):

* ir-layer operands (``ValueRef``, ``ExprRef``) are **real-imported** -- ``ir``
  sits below ``capabilities`` so the edge is downward-legal (precedent:
  ``constant_fixpoint`` imports ``d810.ir.results``).
* analyses-layer types (``LoopRef``/``Region``/``RecurrenceExpr``) are annotated
  ``Any`` -- ``analyses`` sits ABOVE ``capabilities``, so a real import would be
  an upward-fatal edge.  Protocol parameters are contravariant, so ``Any`` is
  what lets a concrete ``recurrence_for(self, value, loop: LoopRef)`` still
  structurally satisfy the contract.
"""
from __future__ import annotations

from d810.core.typing import Any, Optional, Protocol, runtime_checkable
from d810.ir.expressions import ExprRef
from d810.ir.value_refs import ValueRef

__all__ = ["ExternalRecurrenceCapability", "RecurrenceAnalysis"]


@runtime_checkable
class RecurrenceAnalysis(Protocol):
    """Capability boundary for recurrence (loop-evolution) analysis."""

    def recurrence_for(self, value: ValueRef, loop: Any) -> Any:
        """Classify how ``value`` evolves across ``loop`` (an analyses ``LoopRef``).

        Returns a ``RecurrenceExpr`` (analyses type -> ``Any``) or ``None``.
        """
        ...

    def step_expression(self, recurrence: Any) -> Optional[ExprRef]:
        """Return the per-iteration step ``ExprRef`` of ``recurrence`` if additive."""
        ...


@runtime_checkable
class ExternalRecurrenceCapability(Protocol):
    """A backend-provided recurrence oracle (e.g. an angr SCEV-style lifter)."""

    def lift_recurrence(self, value: ValueRef, region: Any) -> Any:
        """Lift a backend recurrence for ``value`` within ``region`` (a ``Region``)."""
        ...
