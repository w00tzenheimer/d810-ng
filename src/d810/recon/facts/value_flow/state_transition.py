"""State-transition fact.

An FSM edge from one state value to another. When the fact represents a
merged memory/state version at a control-flow join, prefer
``MemoryPhi``.

The string value mirrors the legacy serialized ``FactObservation.kind``
during Phase 1 of the value-flow terminology rename; Phase 4 may
introduce a new canonical value behind the diagnostic alias registry.
"""
from __future__ import annotations

from d810.recon.facts.carrier import STATE_TRANSITION_CARRIER_FACT_KIND as STATE_TRANSITION_FACT_TYPE

__all__ = ["STATE_TRANSITION_FACT_TYPE"]
