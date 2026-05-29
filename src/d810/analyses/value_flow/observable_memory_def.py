"""Observable memory-def fact.

An externally-visible memory write. Maps to angr store actions and LLVM
``MemoryDef`` with the additional constraint that the write escapes the
function (output buffer, ABI return slot, side-effecting store). The
``observable`` prefix preserves the rewrite-authority distinction tracked by
the legacy ``ObservableStoreFact`` family.

This is the canonical serialized ``FactObservation.kind`` value. The
diagnostic alias registry maps the historical ``ObservableStoreFact`` string
to this family.
"""
from __future__ import annotations

OBSERVABLE_MEMORY_DEF_FACT_TYPE = "ObservableMemoryDefFact"

__all__ = ["OBSERVABLE_MEMORY_DEF_FACT_TYPE"]
