"""Maturity-scoped semantic fact model.

The facts package is intentionally IDA-free.  Collectors can create these
objects at any microcode maturity, while diag writers and later consumers can
serialize them without importing Hex-Rays APIs.
"""
from __future__ import annotations

from d810.analyses.value_flow.facts import (
    FactConflict,
    FactConsumerRecord,
    FactMapping,
    FactObservation,
    FactStatus,
    JsonMapping,
    ValidatedFactView,
    canonical_json,
)

# The fact-lifecycle runtime is a passes-layer module; ``d810.recon.facts.runtime``
# is now a dynamic sys.modules alias to ``d810.passes.fact_runtime`` (resolved via
# importlib so no static recon -> passes upward edge is recorded).  Live importers
# of these runtime names repoint to ``d810.passes.fact_runtime`` directly.
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
