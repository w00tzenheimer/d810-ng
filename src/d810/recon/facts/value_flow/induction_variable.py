"""Induction-variable fact.

A scalar value that progresses by a fixed pattern across loop iterations
(affine, geometric, etc.). Standard loop-analysis term; previously
``GenericInductionCarrierFact``.

This is the canonical serialized ``FactObservation.kind`` value. The
diagnostic alias registry maps the historical ``GenericInductionCarrierFact``
string to this family.
"""
from __future__ import annotations

INDUCTION_VARIABLE_FACT_TYPE = "InductionVariableFact"

__all__ = ["INDUCTION_VARIABLE_FACT_TYPE"]
