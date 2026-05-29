"""Scalar-promotion fact.

Justifies replacing a memory location whose lifetime is local with a
scalar SSA value. Maps to LLVM ``mem2reg``.

This is the canonical serialized ``FactObservation.kind`` value. The
diagnostic alias registry maps the historical ``CarrierStorePromotionFact``
string to this family.
"""
from __future__ import annotations

SCALAR_PROMOTION_FACT_TYPE = "ScalarPromotionFact"

__all__ = ["SCALAR_PROMOTION_FACT_TYPE"]
