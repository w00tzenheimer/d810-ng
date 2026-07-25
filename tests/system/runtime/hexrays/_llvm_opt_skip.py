"""Shared skip policy for LLVM-backed system tests."""

from __future__ import annotations

from d810.backends.llvm import find_llvm_opt


LLVM_OPT_SKIP_REASON = "LLVM opt not found; skipping LLVM-backed system tests"


def llvm_opt_missing() -> bool:
    return find_llvm_opt() is None
