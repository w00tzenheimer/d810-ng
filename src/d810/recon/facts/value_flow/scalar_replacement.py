"""Scalar-replacement fact.

Justifies replacing an aggregate or partially-overlapping local storage
with multiple scalar values. Maps to LLVM SROA; previously
``LocalStorageScalarizationFact``.

This is the canonical serialized ``FactObservation.kind`` value. The
diagnostic alias registry maps the historical
``LocalStorageScalarizationFact`` string to this family.
"""
from __future__ import annotations

SCALAR_REPLACEMENT_FACT_TYPE = "ScalarReplacementFact"

__all__ = ["SCALAR_REPLACEMENT_FACT_TYPE"]
