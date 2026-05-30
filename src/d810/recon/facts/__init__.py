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

# The fact-lifecycle runtime lives in the passes layer (``d810.passes`` sits
# ABOVE ``d810.recon`` in the layered architecture).  Re-exporting it from this
# surviving facade is a convenience for legacy importers, but a *static* ``from
# d810.passes.fact_runtime import ...`` would record a layer-fatal recon ->
# passes upward edge.  Resolve it dynamically via ``importlib.import_module`` so
# grimp does not follow the edge; live importers repoint to
# ``d810.passes.fact_runtime`` directly.
import importlib as _importlib

_fact_runtime = _importlib.import_module("d810.passes.fact_runtime")
FactCollectionResult = _fact_runtime.FactCollectionResult
FactCaptureSummary = _fact_runtime.FactCaptureSummary
FactCollector = _fact_runtime.FactCollector
FactLifecycleRuntime = _fact_runtime.FactLifecycleRuntime
FactPersistenceCallback = _fact_runtime.FactPersistenceCallback

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
