"""Observable output fact.

An externally-visible output event. This is narrower than an observable memory
definition: it identifies writes that materialize recovered semantics at an
ABI-visible or caller-visible sink such as an output buffer.

This is the canonical serialized ``FactObservation.kind`` value.
"""
from __future__ import annotations

OBSERVABLE_OUTPUT_FACT_TYPE = "ObservableOutputFact"

__all__ = ["OBSERVABLE_OUTPUT_FACT_TYPE"]
