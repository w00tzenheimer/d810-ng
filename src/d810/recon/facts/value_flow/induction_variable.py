"""Induction-variable fact.

A scalar value that progresses by a fixed pattern across loop iterations
(affine, geometric, etc.). Standard loop-analysis term; previously
``GenericInductionCarrierFact``.

The string value mirrors the legacy serialized ``FactObservation.kind``
during Phase 1 of the value-flow terminology rename; Phase 4 may
introduce a new canonical value behind the diagnostic alias registry.
"""
from __future__ import annotations

from d810.recon.facts.carrier import INDUCTION_CARRIER_FACT_KIND as INDUCTION_VARIABLE_FACT_TYPE

__all__ = ["INDUCTION_VARIABLE_FACT_TYPE"]
