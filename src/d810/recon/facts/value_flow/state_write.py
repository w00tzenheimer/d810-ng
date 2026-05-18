"""State-write fact.

A write to a finite-state-machine state variable. Maps to LLVM
``MemoryDef`` / angr store actions while preserving FSM semantics.

The string value mirrors the legacy serialized ``FactObservation.kind``
during Phase 1 of the value-flow terminology rename; Phase 4 may
introduce a new canonical value behind the diagnostic alias registry.
"""
from __future__ import annotations

from d810.recon.facts.carrier import STATE_VARIABLE_WRITE_FACT_KIND as STATE_WRITE_FACT_TYPE

__all__ = ["STATE_WRITE_FACT_TYPE"]
