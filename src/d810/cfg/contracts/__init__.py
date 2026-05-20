"""Verifier-inspired CFG contract package."""

from __future__ import annotations

import os
from importlib import import_module


def insn_checks_enabled() -> bool:
    """Return True if instruction-level CFG checks are enabled."""
    val = os.environ.get("D810_INSN_CHECKS", "").lower()
    return val in ("1", "true", "yes")


def __getattr__(name: str):
    if name in {
        "BackendContractOracle",
        "CfgContract",
        "CfgContractViolationError",
    }:
        module = import_module("d810.cfg.contracts.contract")
        return getattr(module, name)
    if name in {
        "block_list_consistency",
        "block_type_vs_tail",
        "pred_succ_symmetry",
        "predecessor_uniqueness",
        "successor_set_matches_tail_semantics",
    }:
        module = import_module("d810.cfg.contracts.invariants")
        return getattr(module, name)
    if name in {
        "TRANSACTION_PHASES",
        "TransactionPhase",
        "FailureClassification",
        "classify_failure",
    }:
        module = import_module("d810.cfg.contracts.transaction_policy")
        return getattr(module, name)
    if name in {
        "CfgTransactionEngine",
        "TransactionResult",
    }:
        module = import_module("d810.cfg.contracts.transaction_engine")
        return getattr(module, name)
    raise AttributeError(name)


__all__ = [
    "CfgContractViolationError",
    "BackendContractOracle",
    "CfgContract",
    "CfgTransactionEngine",
    "FailureClassification",
    "TRANSACTION_PHASES",
    "TransactionPhase",
    "TransactionResult",
    "block_list_consistency",
    "block_type_vs_tail",
    "classify_failure",
    "insn_checks_enabled",
    "pred_succ_symmetry",
    "predecessor_uniqueness",
    "successor_set_matches_tail_semantics",
]
