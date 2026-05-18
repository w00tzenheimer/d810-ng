"""Materialization-point fact.

A program point where a previously latent, hidden, indirect, delayed, or
encoded value becomes externally visible or rewrite-critical. Not a
synonym for every memory read; use ``MemoryUse`` for ordinary loads.

The string value mirrors the legacy serialized ``FactObservation.kind``
during Phase 1 of the value-flow terminology rename; Phase 4 may
introduce a new canonical value behind the diagnostic alias registry.
"""
from __future__ import annotations

from d810.recon.facts.carrier import TERMINAL_MATERIALIZATION_FACT_KIND as MATERIALIZATION_POINT_FACT_TYPE

__all__ = ["MATERIALIZATION_POINT_FACT_TYPE"]
