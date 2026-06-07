"""Hex-Rays-backed :class:`d810.ir.expr.mop_ops.MopOpsProvider`.

Implements the live-mop structural comparisons the portable constraint DSL needs at
rule-matching time (``equal_mops`` / ``is_bnot``), wrapping ``hexrays_helpers``.
Registered at the composition root (``D810State.start_d810``), mirroring
``register_bst_walkers`` -- this is what replaces the old
``importlib.import_module("d810.hexrays...")`` dodge inside the (now portable) DSL.
"""
from __future__ import annotations

from d810.hexrays.utils.hexrays_helpers import (
    equal_bnot_mop,
    equal_mops_ignore_size,
)


class HexRaysMopOps:
    """``MopOpsProvider`` impl over live Hex-Rays ``mop_t`` operands."""

    def equal_mops_ignore_size(self, lo: object, ro: object) -> bool:
        return equal_mops_ignore_size(lo, ro)

    def equal_bnot_mop(self, lo: object, ro: object) -> bool:
        return equal_bnot_mop(lo, ro)
