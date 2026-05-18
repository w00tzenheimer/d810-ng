"""Observable memory-def fact.

An externally-visible memory write. Maps to angr store actions and LLVM
``MemoryDef`` with the additional constraint that the write escapes the
function (output buffer, ABI return slot, side-effecting store). The
``observable`` prefix preserves the rewrite-authority distinction tracked by
the legacy ``ObservableStoreFact`` family.

The string value mirrors the legacy serialized ``FactObservation.kind``
during Phase 1 of the value-flow terminology rename; Phase 4 may
introduce a new canonical value behind the diagnostic alias registry.
"""
from __future__ import annotations

from d810.recon.facts.carrier import OBSERVABLE_STORE_FACT_KIND as OBSERVABLE_MEMORY_DEF_FACT_TYPE

__all__ = ["OBSERVABLE_MEMORY_DEF_FACT_TYPE"]
