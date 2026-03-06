"""Verifier-inspired CFG contract package."""

from __future__ import annotations

import os
from importlib import import_module


def insn_checks_enabled() -> bool:
    """Return True if instruction-level CFG checks are enabled."""
    val = os.environ.get("D810_INSN_CHECKS", "").lower()
    return val in ("1", "true", "yes")


def __getattr__(name: str):
    if name == "IDACfgContract":
        return import_module("d810.cfg.contracts.ida_contract").IDACfgContract
    if name == "CfgContractViolationError":
        return import_module("d810.cfg.contracts.ida_contract").CfgContractViolationError
    if name == "check_all_insn_invariants":
        return import_module("d810.cfg.contracts.insn_invariants").check_all_insn_invariants
    if name in {
        "NATIVE_ORACLE_AVAILABLE",
        "check_block_native",
        "check_mba_native",
        "oracle_available",
    }:
        module = import_module("d810.cfg.contracts.native_oracle")
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
    raise AttributeError(name)


__all__ = [
    "CfgContractViolationError",
    "FailureClassification",
    "IDACfgContract",
    "NATIVE_ORACLE_AVAILABLE",
    "TRANSACTION_PHASES",
    "TransactionPhase",
    "block_list_consistency",
    "block_type_vs_tail",
    "check_all_insn_invariants",
    "check_block_native",
    "check_mba_native",
    "classify_failure",
    "insn_checks_enabled",
    "oracle_available",
    "pred_succ_symmetry",
    "predecessor_uniqueness",
    "successor_set_matches_tail_semantics",
]
