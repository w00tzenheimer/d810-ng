"""Maturity-scoped semantic fact model.

The facts package is intentionally IDA-free.  Collectors can create these
objects at any microcode maturity, while diag writers and later consumers can
serialize them without importing Hex-Rays APIs.
"""
from __future__ import annotations

from d810.recon.facts.model import (
    FactConflict,
    FactConsumerRecord,
    FactMapping,
    FactObservation,
    FactStatus,
    JsonMapping,
    ValidatedFactView,
    canonical_json,
)
from d810.recon.facts.runtime import (
    FactCollectionResult,
    FactCaptureSummary,
    FactCollector,
    FactLifecycleRuntime,
    FactPersistenceCallback,
)

__all__ = [
    "FactConflict",
    "FactConsumerRecord",
    "FactMapping",
    "FactObservation",
    "FactStatus",
    "FactCollectionResult",
    "FactCaptureSummary",
    "FactCollector",
    "FactLifecycleRuntime",
    "FactPersistenceCallback",
    "JsonMapping",
    "ValidatedFactView",
    "canonical_json",
]
