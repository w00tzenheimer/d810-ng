"""Portable value-range checks and proofs.

Backend-neutral description of a value-range bound check and a proof that a value
stays within a range across a region (e.g. a bounded loop induction variable).
Net-new and unwired (Landing Sequence LS8 S6).

Minimum viable scope: inclusive integer ``[lo, hi]`` bounds (``None`` = open on
that side).  Symbolic / modular bounds are added on demand.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Optional
from d810.ir.confidence import FactConfidence
from d810.ir.value_refs import ValueRef

__all__ = ["RangeCheck", "RangeProof"]


@dataclass(frozen=True)
class RangeCheck:
    """A checked bound on a value: ``lo <= value <= hi`` (open side = ``None``)."""

    value: ValueRef
    lo: Optional[int] = None
    hi: Optional[int] = None


@dataclass(frozen=True)
class RangeProof:
    """A proof that ``value`` remains within ``[lo, hi]`` across a region."""

    value: ValueRef
    lo: Optional[int] = None
    hi: Optional[int] = None
    confidence: FactConfidence = FactConfidence(1.0)
