"Portable transform layer for d810.\n\nPer the LLVM/LiSA-style taxonomy in\n``docs/plans/preanalysis-and-cfg-restructuring.md``, this package hosts\nabstract transform contracts (Protocols) that are backend-neutral --\nthey describe the SHAPE of an optimization, not its Hex-Rays / angr /\nGhidra implementation.\n\nConcrete transform implementations (e.g. Hex-Rays microcode rewrites)\nlive under ``d810.optimizers`` and ``d810.backends.hexrays``; they\nsatisfy the Protocols here structurally.\n\nThis package must remain IDA-free at import time -- enforced by\n``rules/no-live-ida-in-portable-core.yml``.\n"

from __future__ import annotations

from d810.transforms.cfg_transaction import (
    BoundCfgTransaction,
    CfgBlockRef,
    CfgProjection,
    CfgTransactionFailure,
    CfgTransactionParticipant,
    CfgTransactionPhase,
    LogicalBlockRef,
    NativeBlockRef,
    PatchPlanExecutionResult,
    PlanBlockRef,
    PlanInsnRef,
    PreparedCfgTransaction,
    TransactionAttemptId,
)
from d810.transforms.lowering import LoweringMode, LoweringStrategy

__all__ = [
    "BoundCfgTransaction",
    "CfgBlockRef",
    "CfgProjection",
    "CfgTransactionFailure",
    "CfgTransactionParticipant",
    "CfgTransactionPhase",
    "LogicalBlockRef",
    "LoweringMode",
    "LoweringStrategy",
    "NativeBlockRef",
    "PatchPlanExecutionResult",
    "PlanBlockRef",
    "PlanInsnRef",
    "PreparedCfgTransaction",
    "TransactionAttemptId",
]
