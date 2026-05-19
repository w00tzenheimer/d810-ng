"""Call return-value fact.

The value produced by a call. Distinct from the call's side effects
(see :data:`CALL_EFFECT_SUMMARY_FACT_TYPE`).

This is the canonical serialized ``FactObservation.kind`` value. The
diagnostic alias registry maps the historical ``CallResultCarrierFact``
string to this family.
"""
from __future__ import annotations

CALL_RETURN_VALUE_FACT_TYPE = "CallReturnValueFact"

__all__ = ["CALL_RETURN_VALUE_FACT_TYPE"]
