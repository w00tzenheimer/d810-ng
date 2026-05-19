"""Loop-predicate value fact.

The value that drives a loop's termination predicate. Distinct from an
induction variable when the predicate uses a derived expression.

This is the canonical serialized ``FactObservation.kind`` value. The
diagnostic alias registry maps the historical ``LoopPredicateCarrierFact``
string to this family.
"""
from __future__ import annotations

LOOP_PREDICATE_VALUE_FACT_TYPE = "LoopPredicateValueFact"

__all__ = ["LOOP_PREDICATE_VALUE_FACT_TYPE"]
