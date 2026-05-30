"""Value-flow fact aggregator (analyses layer).

This is the analyses-layer half of the former ``d810.recon.facts`` facade,
which aggregated TWO layers: the IDA-free value-flow *model* dataclasses
(analyses) and the fact-lifecycle *runtime* (passes).  Mixing both in one
module created an ``analyses -> passes`` upward edge, so the facade was split
(dissolution R2-C2, llr-lyly):

* model / value-flow re-exports live here (:mod:`d810.analyses.value_flow`)
* the lifecycle runtime re-exports live at :mod:`d810.passes.fact_runtime`

The legacy ``d810.recon.facts`` package keeps re-exporting from both for
backward compatibility until the Phase Z shim sweep.
"""
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
