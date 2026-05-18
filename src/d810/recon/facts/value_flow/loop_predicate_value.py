"""Loop-predicate value fact.

The value that drives a loop's termination predicate. Distinct from an
induction variable when the predicate uses a derived expression.

The string value mirrors the legacy serialized ``FactObservation.kind``
during Phase 1 of the value-flow terminology rename; Phase 4 may
introduce a new canonical value behind the diagnostic alias registry.
"""
from __future__ import annotations

from d810.recon.facts.carrier import LOOP_PREDICATE_CARRIER_FACT_KIND as LOOP_PREDICATE_VALUE_FACT_TYPE

__all__ = ["LOOP_PREDICATE_VALUE_FACT_TYPE"]
