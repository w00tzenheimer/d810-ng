"""Hex-Rays-backed CFG contract oracle package."""

from __future__ import annotations

from importlib import import_module


def __getattr__(name: str):
    if name in {"CfgContractViolationError", "IDACfgContract"}:
        module = import_module("d810.hexrays.contracts.cfg_contract")
        return getattr(module, name)
    if name in {
        "NATIVE_ORACLE_AVAILABLE",
        "check_block_native",
        "check_mba_native",
        "oracle_available",
    }:
        module = import_module("d810.hexrays.contracts.native_oracle")
        return getattr(module, name)
    raise AttributeError(name)


__all__ = [
    "CfgContractViolationError",
    "IDACfgContract",
    "NATIVE_ORACLE_AVAILABLE",
    "check_block_native",
    "check_mba_native",
    "oracle_available",
]
