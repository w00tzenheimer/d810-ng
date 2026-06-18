"""LLVM text emitter backend over portable d810 IR.

This package is intentionally IDA-free.  It consumes ``d810.ir`` records and
emits textual LLVM IR for the narrow M1a supported subset.
"""
from __future__ import annotations

from .emitter import (
    LlvmIdentityManifest,
    LlvmLiftResult,
    UnsupportedLiftKind,
    UnsupportedLiftReason,
    emit_flowgraph_to_llvm,
)
from .identity_lowering import (
    LlvmIdentityManifestBlock,
    LlvmIdentityManifestControl,
    LlvmIdentityManifestEffect,
    LlvmIdentityManifestInstruction,
    LlvmIdentityManifestMemory,
    LlvmIdentityManifestSwitchCase,
    LlvmIdentityManifestVarnode,
    LlvmIdentityMismatch,
    LlvmIdentityParityResult,
    LlvmIdentityParityStatus,
    check_identity_manifest,
    check_identity_roundtrip,
)
from .maturity_policy import (
    LLVM_M1_ACCEPTED_MATURITIES,
    LLVM_M1_PREFERRED_MATURITY,
    LlvmMaturityAssessment,
    assess_flowgraph_maturity,
)
from .verification import (
    LlvmVerificationResult,
    LlvmVerificationStatus,
    find_llvm_opt,
    verify_llvm_ir,
)

__all__ = [
    "LLVM_M1_ACCEPTED_MATURITIES",
    "LLVM_M1_PREFERRED_MATURITY",
    "LlvmIdentityManifest",
    "LlvmIdentityManifestBlock",
    "LlvmIdentityManifestControl",
    "LlvmIdentityManifestEffect",
    "LlvmIdentityManifestInstruction",
    "LlvmIdentityManifestMemory",
    "LlvmIdentityManifestSwitchCase",
    "LlvmIdentityManifestVarnode",
    "LlvmIdentityMismatch",
    "LlvmIdentityParityResult",
    "LlvmIdentityParityStatus",
    "LlvmLiftResult",
    "LlvmMaturityAssessment",
    "LlvmVerificationResult",
    "LlvmVerificationStatus",
    "UnsupportedLiftKind",
    "UnsupportedLiftReason",
    "assess_flowgraph_maturity",
    "check_identity_manifest",
    "check_identity_roundtrip",
    "emit_flowgraph_to_llvm",
    "find_llvm_opt",
    "verify_llvm_ir",
]
