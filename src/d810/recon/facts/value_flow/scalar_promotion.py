"""Scalar-promotion fact.

Justifies replacing a memory location whose lifetime is local with a
scalar SSA value. Maps to LLVM ``mem2reg``.

The string value mirrors the legacy serialized ``FactObservation.kind``
during Phase 1 of the value-flow terminology rename; Phase 4 may
introduce a new canonical value behind the diagnostic alias registry.
"""
from __future__ import annotations

from d810.recon.facts.carrier import CARRIER_STORE_PROMOTION_FACT_KIND as SCALAR_PROMOTION_FACT_TYPE

__all__ = ["SCALAR_PROMOTION_FACT_TYPE"]
