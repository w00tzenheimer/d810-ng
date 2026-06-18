"""LLVM text emitter backend over portable d810 IR.

This package is intentionally IDA-free.  It consumes ``d810.ir`` records and
emits textual LLVM IR for the narrow M1a supported subset.
"""
from __future__ import annotations

from .emitter import (
    LlvmLiftResult,
    UnsupportedLiftReason,
    emit_flowgraph_to_llvm,
)

__all__ = [
    "LlvmLiftResult",
    "UnsupportedLiftReason",
    "emit_flowgraph_to_llvm",
]
