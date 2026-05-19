"""Effect-path fact.

An ordered path through which side effects propagate. Distinct from a
single ``MemoryDef`` because it summarizes a sequence; previously
``SideEffectCorridorFact``.

This is the canonical serialized ``FactObservation.kind`` value. The
diagnostic alias registry maps the historical ``SideEffectCorridorFact``
string to this family.
"""
from __future__ import annotations

EFFECT_PATH_FACT_TYPE = "EffectPathFact"

__all__ = ["EFFECT_PATH_FACT_TYPE"]
