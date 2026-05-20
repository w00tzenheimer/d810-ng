"""State-transition fact.

An FSM edge from one state value to another. When the fact represents a
merged memory/state version at a control-flow join, prefer
``MemoryPhi``.

This is the canonical serialized ``FactObservation.kind`` value. The
diagnostic alias registry maps the historical ``StateTransitionCarrierFact``
string to this family.
"""
from __future__ import annotations

STATE_TRANSITION_FACT_TYPE = "StateTransitionFact"

__all__ = ["STATE_TRANSITION_FACT_TYPE"]
