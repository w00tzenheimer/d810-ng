"""Portable recurrence facts (LLVM SCEV-style add-recurrences).

Backend-neutral description of how a value evolves across loop iterations, over
the IR substrate (Landing Sequence LS8).  Net-new and unwired; a future
capability / backend populates these from a reaching-definitions + loop pass.

Minimum viable scope: additive recurrences ``{base, +, step}``.  ``RecurrenceExpr``
is the umbrella (currently a single kind); widen it to a ``Union`` when a second
recurrence kind (e.g. multiplicative) lands.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.control_flow.loops import LoopRef
from d810.ir.confidence import FactConfidence
from d810.ir.expressions import ExprRef
from d810.ir.handles import InsnHandle
from d810.ir.value_refs import ValueRef

__all__ = ["AddRecurrence", "RecurrenceCandidate", "RecurrenceExpr"]


@dataclass(frozen=True)
class AddRecurrence:
    """An additive recurrence ``{base, +, step}`` over a loop (SCEV add-rec)."""

    loop: LoopRef
    base: ExprRef
    step: ExprRef
    update: InsnHandle
    evidence: tuple[InsnHandle, ...] = ()


RecurrenceExpr = AddRecurrence
"""Umbrella for recurrence kinds.

Currently aliases the only kind (``AddRecurrence``); widen to
``Union[AddRecurrence, ...]`` when more recurrence families are modeled.
"""


@dataclass(frozen=True)
class RecurrenceCandidate:
    """A not-yet-confirmed recurrence for a value, carrying a confidence."""

    value: ValueRef
    recurrence: RecurrenceExpr
    confidence: FactConfidence
