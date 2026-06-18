"""LLVM text emitter backend over portable d810 IR.

This package is intentionally IDA-free.  It consumes ``d810.ir`` records and
emits textual LLVM IR for the narrow M1a supported subset.
"""
from __future__ import annotations

from .emitter import (
    LlvmLiftResult,
    UnsupportedLiftKind,
    UnsupportedLiftReason,
    emit_flowgraph_to_llvm,
)
from .maturity_policy import (
    LLVM_M1_ACCEPTED_MATURITIES,
    LLVM_M1_PREFERRED_MATURITY,
    LlvmMaturityAssessment,
    assess_flowgraph_maturity,
)

__all__ = [
    "LLVM_M1_ACCEPTED_MATURITIES",
    "LLVM_M1_PREFERRED_MATURITY",
    "LlvmLiftResult",
    "LlvmMaturityAssessment",
    "UnsupportedLiftKind",
    "UnsupportedLiftReason",
    "assess_flowgraph_maturity",
    "emit_flowgraph_to_llvm",
]
