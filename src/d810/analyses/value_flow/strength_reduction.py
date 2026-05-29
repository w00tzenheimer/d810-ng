"""Portable strength-reduction candidates.

Backend-neutral description of a loop-variant expression that can be
strength-reduced to an additive recurrence (e.g. ``i * C`` over an induction
variable ``i`` becomes ``t += C`` per iteration).  Net-new and unwired (Landing
Sequence LS8 S6).

Minimum viable scope: linear ``basis * multiplier`` candidates.  Richer forms
(polynomial, pointer scaling) are added on demand.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.ir.confidence import FactConfidence
from d810.ir.value_refs import ValueRef

__all__ = ["StrengthReductionCandidate"]


@dataclass(frozen=True)
class StrengthReductionCandidate:
    """A loop-variant ``value`` equal to ``basis * multiplier`` that can be
    reduced to an additive recurrence over ``basis``."""

    value: ValueRef
    basis: ValueRef
    multiplier: int
    confidence: FactConfidence = FactConfidence(1.0)
