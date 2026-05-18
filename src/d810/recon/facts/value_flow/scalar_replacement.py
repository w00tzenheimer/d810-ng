"""Scalar-replacement fact.

Justifies replacing an aggregate or partially-overlapping local storage
with multiple scalar values. Maps to LLVM SROA; previously
``LocalStorageScalarizationFact``.

The string value mirrors the legacy serialized ``FactObservation.kind``
during Phase 1 of the value-flow terminology rename; Phase 4 may
introduce a new canonical value behind the diagnostic alias registry.
"""
from __future__ import annotations

from d810.recon.facts.carrier import LOCAL_STORAGE_SCALARIZATION_FACT_KIND as SCALAR_REPLACEMENT_FACT_TYPE

__all__ = ["SCALAR_REPLACEMENT_FACT_TYPE"]
