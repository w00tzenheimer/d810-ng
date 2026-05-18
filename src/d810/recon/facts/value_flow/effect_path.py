"""Effect-path fact.

An ordered path through which side effects propagate. Distinct from a
single ``MemoryDef`` because it summarizes a sequence; previously
``SideEffectCorridorFact``.

The string value mirrors the legacy serialized ``FactObservation.kind``
during Phase 1 of the value-flow terminology rename; Phase 4 may
introduce a new canonical value behind the diagnostic alias registry.
"""
from __future__ import annotations

from d810.recon.facts.carrier import SIDE_EFFECT_CORRIDOR_FACT_KIND as EFFECT_PATH_FACT_TYPE

__all__ = ["EFFECT_PATH_FACT_TYPE"]
