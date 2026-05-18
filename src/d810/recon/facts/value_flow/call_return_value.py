"""Call return-value fact.

The value produced by a call. Distinct from the call's side effects
(see :data:`CALL_EFFECT_SUMMARY_FACT_TYPE`).

The string value mirrors the legacy serialized ``FactObservation.kind``
during Phase 1 of the value-flow terminology rename; Phase 4 may
introduce a new canonical value behind the diagnostic alias registry.
"""
from __future__ import annotations

from d810.recon.facts.carrier import CALL_RESULT_CARRIER_FACT_KIND as CALL_RETURN_VALUE_FACT_TYPE

__all__ = ["CALL_RETURN_VALUE_FACT_TYPE"]
