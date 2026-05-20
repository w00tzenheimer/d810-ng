"""State-write fact.

A write to a finite-state-machine state variable. Maps to LLVM
``MemoryDef`` / angr store actions while preserving FSM semantics.

This is the canonical serialized ``FactObservation.kind`` value. The
diagnostic alias registry maps the historical ``StateVariableWriteFact``
string to this family.
"""
from __future__ import annotations

STATE_WRITE_FACT_TYPE = "StateWriteFact"

__all__ = ["STATE_WRITE_FACT_TYPE"]
