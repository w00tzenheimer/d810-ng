"Value-flow fact aggregator (analyses layer).\n\nThis is the analyses-layer half of the former reconnaissance-facts facade,\nwhich aggregated TWO layers: the IDA-free value-flow *model* dataclasses\n(analyses) and the fact-lifecycle *runtime* (passes).  Mixing both in one\nmodule created an ``analyses -> passes`` upward edge, so the facade was split\n(dissolution R2-C2, llr-lyly):\n\n* model / value-flow re-exports live here (:mod:`d810.analyses.value_flow`)\n* the lifecycle runtime re-exports live at :mod:`d810.passes.fact_runtime`\n\nThe former preanalysis-facts facade is now split across the two homes above,\nwhich remain the sole import surfaces.\n"

from __future__ import annotations

from d810.analyses.value_flow.model import (
    FactConflict,
    FactConsumerRecord,
    FactMapping,
    FactObservation,
    FactStatus,
    JsonMapping,
    ValidatedFactView,
    canonical_json,
)

__all__ = [
    "FactConflict",
    "FactConsumerRecord",
    "FactMapping",
    "FactObservation",
    "FactStatus",
    "JsonMapping",
    "ValidatedFactView",
    "canonical_json",
]
