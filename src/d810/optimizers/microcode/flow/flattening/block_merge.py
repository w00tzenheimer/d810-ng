"""Block merge cleanup rule.

``BlockMerger`` preserves the legacy project-config rule name while delegating
the actual work to :class:`BlockMergeTransform`.  The transform analyzes a
FlowGraph snapshot and emits primitive ``NopInstructions`` edits for redundant
linear gotos; lowering those primitives makes the CFG mergeable and Hex-Rays
performs the actual block coalescing during local optimization.
"""
from __future__ import annotations

import ida_hexrays

from d810.optimizers.microcode.flow.handler import FlowOptimizationRule
from d810.optimizers.microcode.handler import DEFAULT_FLOW_MATURITIES


class BlockMerger(FlowOptimizationRule):
    """Run block-merge canonicalization through the primitive CFG pipeline."""

    DESCRIPTION = (
        "Merges artificially split basic blocks by removing "
        "redundant goto instructions"
    )

    USES_DEFERRED_CFG = False
    SAFE_MATURITIES = [
        ida_hexrays.MMAT_CALLS,
        ida_hexrays.MMAT_GLBOPT1,
    ]

    def __init__(self):
        super().__init__()
        self._backend = None
        self._transform = None
        self._last_noop_key: tuple[int, int, int] | None = None

    def optimize(self, blk: ida_hexrays.mblock_t) -> int:
        """Apply primitive block-merge edits for the current MBA snapshot."""
        mba = getattr(blk, "mba", None)
        if mba is None:
            return 0

        key = (
            int(getattr(mba, "entry_ea", 0) or 0),
            int(getattr(mba, "maturity", self.current_maturity)),
            int(self.current_generation),
        )
        if self._last_noop_key == key:
            return 0

        cfg = self._get_backend().lift(mba)
        all_mods = self._get_transform().transform(cfg)
        if not all_mods:
            self._last_noop_key = key
            return 0

        mods = [mod for mod in all_mods if mod.block_serial == blk.serial]
        if not mods:
            return 0

        from d810.hexrays.mutation.cfg_mutations import apply_nop_instructions

        count = 0
        for mod in mods:
            count += apply_nop_instructions(mba, mod.block_serial, mod.insn_eas)
        if count <= 0:
            return 0

        self._last_noop_key = None
        return count

    def configure(self, kwargs):
        super().configure(kwargs)
        if "maturities" not in self.config:
            self.maturities = list(DEFAULT_FLOW_MATURITIES)

    def _get_backend(self):
        if self._backend is None:
            from d810.hexrays.mutation.ir_translator import IDAIRTranslator

            self._backend = IDAIRTranslator()
        return self._backend

    def _get_transform(self):
        if self._transform is None:
            from d810.hexrays.mutation.transform.block_merge import (
                BlockMergeTransform,
            )

            self._transform = BlockMergeTransform()
        return self._transform
