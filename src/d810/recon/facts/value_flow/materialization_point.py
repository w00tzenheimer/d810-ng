"""Materialization-point fact.

A program point where a previously latent, hidden, indirect, delayed, or
encoded value becomes externally visible or rewrite-critical. Not a
synonym for every memory read; use ``MemoryUse`` for ordinary loads.

This is the canonical serialized ``FactObservation.kind`` value. The
diagnostic alias registry maps the historical ``TerminalMaterializationFact``
string to this family.
"""
from __future__ import annotations

MATERIALIZATION_POINT_FACT_TYPE = "MaterializationPointFact"

__all__ = ["MATERIALIZATION_POINT_FACT_TYPE"]
