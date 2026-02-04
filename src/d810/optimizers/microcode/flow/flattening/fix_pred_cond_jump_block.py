"""FixPredecessorOfConditionalJumpBlock - optimized with caching.

Detect if a predecessor of a conditional block always takes the same path
and patch it. Works for O-LLVM style control flow flattening.

Performance optimizations (merged from v2):
1. Cache predecessor analysis results - avoids re-tracing same paths
2. Lazy logging - avoid formatting strings when logging disabled
3. State var repr caching - avoid repeated string formatting

Architecture:
Uses deferred CFG modification pattern to avoid race conditions.
All analysis happens first, then modifications are applied atomically.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

import ida_hexrays

from d810.core import getLogger
from d810.core.bits import unsigned_to_signed
from d810.hexrays.cfg_utils import (
    duplicate_block,
    make_2way_block_goto,
    safe_verify,
    update_blk_successor,
)
from d810.hexrays.deferred_modifier import DeferredGraphModifier
from d810.hexrays.hexrays_formatters import dump_microcode_for_debug, format_minsn_t
from d810.hexrays.tracker import MopTracker
from d810.optimizers.microcode.flow.flattening.dispatcher_detection import (
    DispatcherCache,
    DispatcherType,
)
from d810.optimizers.microcode.flow.flattening.generic import GenericUnflatteningRule
from d810.optimizers.microcode.flow.flattening.utils import get_all_possibles_values

unflat_logger = getLogger("D810.unflat")

JMP_OPCODE_HANDLED = [
    ida_hexrays.m_jnz, ida_hexrays.m_jz,
    ida_hexrays.m_jae, ida_hexrays.m_jb,
    ida_hexrays.m_ja, ida_hexrays.m_jbe,
    ida_hexrays.m_jge, ida_hexrays.m_jg,
    ida_hexrays.m_jl, ida_hexrays.m_jle
]


class PredecessorAnalysisCache:
    """Cache for predecessor analysis results.

    Key insight from profiling: The same predecessor paths are traced
    repeatedly across passes. Caching the results provides significant speedup.

    Cache key: (entry_ea, blk_serial, pred_serial, state_var_repr, maturity)
    Cache value: list of possible state values for this predecessor
    """

    def __init__(self, max_size: int = 10000):
        self._cache: dict[tuple, list[int]] = {}
        self._max_size = max_size
        self._hits = 0
        self._misses = 0

    def _make_key(
        self,
        mba: ida_hexrays.mba_t,
        blk_serial: int,
        pred_serial: int,
        state_var_repr: str,
        maturity: int
    ) -> tuple:
        """Create cache key using mba.entry_ea as stable function identifier."""
        return (mba.entry_ea, blk_serial, pred_serial, state_var_repr, maturity)

    def get(
        self,
        mba: ida_hexrays.mba_t,
        blk_serial: int,
        pred_serial: int,
        state_var_repr: str,
        maturity: int
    ) -> Optional[list]:
        """Get cached predecessor values, or None if not cached."""
        key = self._make_key(mba, blk_serial, pred_serial, state_var_repr, maturity)
        result = self._cache.get(key)
        if result is not None:
            self._hits += 1
        else:
            self._misses += 1
        return result

    def put(
        self,
        mba: ida_hexrays.mba_t,
        blk_serial: int,
        pred_serial: int,
        state_var_repr: str,
        maturity: int,
        values: list
    ) -> None:
        """Cache predecessor values."""
        if len(self._cache) >= self._max_size:
            # Simple eviction: clear half the cache
            keys_to_remove = list(self._cache.keys())[:self._max_size // 2]
            for k in keys_to_remove:
                del self._cache[k]

        key = self._make_key(mba, blk_serial, pred_serial, state_var_repr, maturity)
        self._cache[key] = values

    def invalidate_for_mba(self, mba: ida_hexrays.mba_t) -> None:
        """Invalidate all cache entries for a given mba (after CFG modification)."""
        entry_ea = mba.entry_ea
        keys_to_remove = [k for k in self._cache if k[0] == entry_ea]
        for k in keys_to_remove:
            del self._cache[k]

    def stats(self) -> dict:
        """Return cache statistics."""
        total = self._hits + self._misses
        return {
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": self._hits / total if total > 0 else 0,
            "size": len(self._cache),
        }


# Global cache instance (shared across passes for performance)
_pred_analysis_cache = PredecessorAnalysisCache()


def get_cache_stats() -> dict:
    """Get statistics from the global predecessor analysis cache."""
    return _pred_analysis_cache.stats()


def clear_cache() -> None:
    """Clear the global predecessor analysis cache."""
    global _pred_analysis_cache
    _pred_analysis_cache = PredecessorAnalysisCache()


class PredecessorModificationType(Enum):
    """Type of modification to apply to a predecessor."""
    ALWAYS_TAKEN = auto()  # Jump is always taken -> redirect to jump target
    NEVER_TAKEN = auto()   # Jump is never taken -> redirect to fallthrough


@dataclass
class PredecessorModification:
    """Represents a queued modification for a predecessor of a conditional block."""
    mod_type: PredecessorModificationType
    pred_serial: int          # Predecessor block to modify
    cond_block_serial: int    # The conditional block being analyzed
    target_serial: int        # Target serial to redirect to
    description: str = ""


class FixPredecessorOfConditionalJumpBlock(GenericUnflatteningRule):
    """Detect if a predecessor of a conditional block always takes the same path and patch it.

    Works for O-LLVM style control flow flattening.

    Architecture:
    Uses deferred modification pattern:
    1. analyze_blk() queues all needed modifications (stores only serials)
    2. _apply_queued_modifications() applies them after analysis completes
    3. No live pointers stored across CFG modifications
    """

    DESCRIPTION = "Detect if a predecessor of a conditional block always takes the same path and patch it (works for O-LLVM style control flow flattening)"
    DEFAULT_UNFLATTENING_MATURITIES = [
        ida_hexrays.MMAT_CALLS,
        ida_hexrays.MMAT_GLBOPT1,
        ida_hexrays.MMAT_GLBOPT2
    ]
    DEFAULT_MAX_PASSES = 100

    def __init__(self):
        super().__init__()
        self._state_var_repr_cache: dict[int, str] = {}  # blk_serial -> repr
        self._pending_modifications: list[PredecessorModification] = []
        self._modifier: Optional[DeferredGraphModifier] = None

    def _get_state_var_repr(self, blk: ida_hexrays.mblock_t) -> str:
        """Get cached string representation of the state variable being compared."""
        if blk.serial in self._state_var_repr_cache:
            return self._state_var_repr_cache[blk.serial]

        from d810.hexrays.hexrays_formatters import format_mop_t
        rep = format_mop_t(blk.tail.l)
        self._state_var_repr_cache[blk.serial] = rep
        return rep

    def is_jump_taken(
        self,
        jmp_blk: ida_hexrays.mblock_t,
        pred_comparison_values: list[int]
    ) -> tuple[bool, bool]:
        """Determine if jump is always/never taken based on predecessor values.

        Returns: (is_always_taken, is_never_taken)
        """
        if len(pred_comparison_values) == 0:
            return False, False

        jmp_ins = jmp_blk.tail
        compared_value = jmp_ins.r.nnn.value
        compared_value_size = jmp_ins.r.size
        opcode = jmp_ins.opcode

        # Fast path for common opcodes (no signed conversion needed)
        if opcode == ida_hexrays.m_jnz:
            is_always = all(v != compared_value for v in pred_comparison_values)
            is_never = all(v == compared_value for v in pred_comparison_values)
            return is_always, is_never

        if opcode == ida_hexrays.m_jz:
            is_always = all(v == compared_value for v in pred_comparison_values)
            is_never = all(v != compared_value for v in pred_comparison_values)
            return is_always, is_never

        # Unsigned comparisons
        if opcode == ida_hexrays.m_jae:
            is_always = all(v >= compared_value for v in pred_comparison_values)
            is_never = all(v < compared_value for v in pred_comparison_values)
            return is_always, is_never

        if opcode == ida_hexrays.m_jb:
            is_always = all(v < compared_value for v in pred_comparison_values)
            is_never = all(v >= compared_value for v in pred_comparison_values)
            return is_always, is_never

        if opcode == ida_hexrays.m_ja:
            is_always = all(v > compared_value for v in pred_comparison_values)
            is_never = all(v <= compared_value for v in pred_comparison_values)
            return is_always, is_never

        # Signed comparisons - convert values once
        def to_signed(v):
            return unsigned_to_signed(v, compared_value_size)

        signed_compared = to_signed(compared_value)
        signed_values = [to_signed(v) for v in pred_comparison_values]

        if opcode == ida_hexrays.m_jbe:
            is_always = all(sv > signed_compared for sv in signed_values)
            is_never = all(sv <= signed_compared for sv in signed_values)
            return is_always, is_never

        if opcode == ida_hexrays.m_jg:
            is_always = all(sv > signed_compared for sv in signed_values)
            is_never = all(sv <= signed_compared for sv in signed_values)
            return is_always, is_never

        if opcode == ida_hexrays.m_jge:
            is_always = all(sv >= signed_compared for sv in signed_values)
            is_never = all(sv < signed_compared for sv in signed_values)
            return is_always, is_never

        if opcode == ida_hexrays.m_jl:
            is_always = all(sv < signed_compared for sv in signed_values)
            is_never = all(sv >= signed_compared for sv in signed_values)
            return is_always, is_never

        if opcode == ida_hexrays.m_jle:
            is_always = all(sv <= signed_compared for sv in signed_values)
            is_never = all(sv > signed_compared for sv in signed_values)
            return is_always, is_never

        return False, False

    def _analyze_predecessor(
        self,
        blk: ida_hexrays.mblock_t,
        pred_serial: int,
        op_compared: ida_hexrays.mop_t,
        state_var_repr: str,
        dispatcher_info
    ) -> tuple[list, bool]:
        """Analyze a single predecessor to find possible state values.

        Returns: (values_list, has_unknown)
        """
        # Check cache first
        cached = _pred_analysis_cache.get(
            self.mba, blk.serial, pred_serial, state_var_repr, self.mba.maturity
        )
        if cached is not None:
            has_unknown = None in cached
            values = [v for v in cached if v is not None]
            return values, has_unknown

        # Not cached - do the analysis
        cmp_variable_tracker = MopTracker(
            [op_compared], max_nb_block=100, max_path=1000,
            dispatcher_info=dispatcher_info
        )
        cmp_variable_tracker.reset()

        pred_blk = self.mba.get_mblock(pred_serial)
        pred_histories = cmp_variable_tracker.search_backward(
            pred_blk, pred_blk.tail
        )

        pred_values = get_all_possibles_values(pred_histories, [op_compared])
        values = [x[0] for x in pred_values]

        # Cache the result
        _pred_analysis_cache.put(
            self.mba, blk.serial, pred_serial, state_var_repr,
            self.mba.maturity, values
        )

        # Lazy logging - only format if enabled
        if unflat_logger.isEnabledFor(20):  # INFO level
            unflat_logger.info(
                "Pred %d has %d possible paths (%d different cst): %s",
                pred_serial, len(values), len(set(values)), values
            )

        has_unknown = None in values
        return [v for v in values if v is not None], has_unknown

    def sort_predecessors(self, blk: ida_hexrays.mblock_t):
        """Sort predecessors into always-taken, never-taken, and unknown lists."""
        pred_jmp_always_taken = []
        pred_jmp_never_taken = []
        pred_jmp_unk = []

        op_compared = ida_hexrays.mop_t(blk.tail.l)
        state_var_repr = self._get_state_var_repr(blk)
        blk_preset_list = list(blk.predset)

        # Determine dispatcher_info based on dispatcher type.
        # For CONDITIONAL_CHAIN (nested jnz/jz comparisons like Hodur, C2 frameworks):
        #   - DO NOT use dispatcher_info (set to None)
        #   - When MopTracker loops back through the dispatcher, it returns None/"unknown"
        #   - This prevents cascading unreachability where all predecessors get
        #     redirected based on a single initial state value
        #
        # For SWITCH_TABLE (O-LLVM, Tigress switch mode):
        #   - Could potentially use dispatcher_info to resume tracking
        #   - But None also works fine (just skips the resume optimization)
        cache = DispatcherCache.get_or_create(blk.mba)
        analysis = cache.analyze()

        if analysis.dispatcher_type == DispatcherType.CONDITIONAL_CHAIN:
            if unflat_logger.isEnabledFor(10):  # DEBUG level
                unflat_logger.debug(
                    "CONDITIONAL_CHAIN dispatcher detected - using dispatcher_info=None "
                    "to prevent cascading unreachability"
                )
        dispatcher_info = None

        for pred_serial in blk_preset_list:
            pred_values, has_unknown = self._analyze_predecessor(
                blk, pred_serial, op_compared, state_var_repr, dispatcher_info
            )

            pred_blk = self.mba.get_mblock(pred_serial)

            if has_unknown:
                pred_jmp_unk.append(pred_blk)
                continue

            is_jmp_always_taken, is_jmp_never_taken = self.is_jump_taken(
                blk, pred_values
            )

            if is_jmp_always_taken and is_jmp_never_taken:
                # Should never happen
                if unflat_logger.isEnabledFor(40):  # ERROR level
                    unflat_logger.error(
                        "Logic error: '%s' is always taken and never taken from %d: %s",
                        format_minsn_t(blk.tail), pred_serial, pred_values
                    )
                pred_jmp_unk.append(pred_blk)
                continue

            if is_jmp_always_taken:
                if unflat_logger.isEnabledFor(20):  # INFO level
                    unflat_logger.info(
                        "Jump '%s' always taken from pred %d: %s",
                        format_minsn_t(blk.tail), pred_serial, pred_values
                    )
                pred_jmp_always_taken.append(pred_blk)

            if is_jmp_never_taken:
                if unflat_logger.isEnabledFor(20):  # INFO level
                    unflat_logger.info(
                        "Jump '%s' never taken from pred %d: %s",
                        format_minsn_t(blk.tail), pred_serial, pred_values
                    )
                pred_jmp_never_taken.append(pred_blk)

        return pred_jmp_always_taken, pred_jmp_never_taken, pred_jmp_unk

    def analyze_blk(self, blk: ida_hexrays.mblock_t) -> int:
        """Analyze a block and queue modifications for predecessors with known jump outcomes.

        Returns the number of modifications queued.
        """
        if blk.tail is None or blk.tail.opcode not in JMP_OPCODE_HANDLED:
            return 0
        if blk.tail.r.t != ida_hexrays.mop_n:
            return 0

        # NOTE: For CONDITIONAL_CHAIN dispatchers (nested jnz/jz comparisons),
        # this rule uses dispatcher_info=None to avoid cascading unreachability.
        # See sort_predecessors() for details on why this is necessary.
        if unflat_logger.isEnabledFor(20):  # INFO level
            unflat_logger.info(
                "Checking if block %d can be simplified: %s",
                blk.serial, format_minsn_t(blk.tail)
            )

        pred_jmp_always_taken, pred_jmp_never_taken, pred_jmp_unk = (
            self.sort_predecessors(blk)
        )

        if unflat_logger.isEnabledFor(20):  # INFO level
            unflat_logger.info(
                "Block %d has %d preds: %d always jmp, %d never jmp, %d unk",
                blk.serial, blk.npred(),
                len(pred_jmp_always_taken),
                len(pred_jmp_never_taken),
                len(pred_jmp_unk)
            )

        nb_queued = 0

        # Queue modifications for always-taken predecessors
        # Target: conditional jump target (blk.tail.d.b)
        for pred_blk in pred_jmp_always_taken:
            self._pending_modifications.append(PredecessorModification(
                mod_type=PredecessorModificationType.ALWAYS_TAKEN,
                pred_serial=pred_blk.serial,
                cond_block_serial=blk.serial,
                target_serial=blk.tail.d.b,  # Jump target
                description=f"pred {pred_blk.serial} always takes jump in block {blk.serial}"
            ))
            nb_queued += 1

            if unflat_logger.isEnabledFor(10):  # DEBUG level
                unflat_logger.debug(
                    "Queued ALWAYS_TAKEN: pred %d -> cond block %d -> target %d",
                    pred_blk.serial, blk.serial, blk.tail.d.b
                )

        # Queue modifications for never-taken predecessors
        # Target: fallthrough (blk.serial + 1)
        for pred_blk in pred_jmp_never_taken:
            self._pending_modifications.append(PredecessorModification(
                mod_type=PredecessorModificationType.NEVER_TAKEN,
                pred_serial=pred_blk.serial,
                cond_block_serial=blk.serial,
                target_serial=blk.serial + 1,  # Fallthrough
                description=f"pred {pred_blk.serial} never takes jump in block {blk.serial}"
            ))
            nb_queued += 1

            if unflat_logger.isEnabledFor(10):  # DEBUG level
                unflat_logger.debug(
                    "Queued NEVER_TAKEN: pred %d -> cond block %d -> fallthrough %d",
                    pred_blk.serial, blk.serial, blk.serial + 1
                )

        return nb_queued

    def _apply_queued_modifications(self) -> int:
        """Apply all queued predecessor modifications.

        Returns the number of modifications successfully applied.
        """
        if not self._pending_modifications:
            return 0

        if unflat_logger.isEnabledFor(20):  # INFO level
            unflat_logger.info(
                "Applying %d queued predecessor modifications",
                len(self._pending_modifications)
            )

        applied_count = 0

        # Group modifications by conditional block for better debugging
        mods_by_cond_block: dict[int, list[PredecessorModification]] = {}
        for mod in self._pending_modifications:
            if mod.cond_block_serial not in mods_by_cond_block:
                mods_by_cond_block[mod.cond_block_serial] = []
            mods_by_cond_block[mod.cond_block_serial].append(mod)

        # Process each conditional block's modifications
        for cond_block_serial, mods in mods_by_cond_block.items():
            # Re-fetch the conditional block (fresh pointer)
            cond_blk = self.mba.get_mblock(cond_block_serial)
            if cond_blk is None:
                unflat_logger.warning(
                    "Conditional block %d not found, skipping %d modifications",
                    cond_block_serial, len(mods)
                )
                continue

            if self.dump_intermediate_microcode:
                dump_microcode_for_debug(
                    self.mba, self.log_dir,
                    f"{self.cur_maturity_pass}_{cond_block_serial}_before_pred_fix"
                )

            # Apply modifications for this conditional block
            for mod in mods:
                try:
                    if self._apply_single_modification(mod, cond_blk):
                        applied_count += 1
                except Exception as e:
                    unflat_logger.error(
                        "Exception applying modification %s: %s",
                        mod.description, e
                    )
                    import traceback
                    unflat_logger.error("Traceback: %s", traceback.format_exc())

            if self.dump_intermediate_microcode:
                dump_microcode_for_debug(
                    self.mba, self.log_dir,
                    f"{self.cur_maturity_pass}_{cond_block_serial}_after_pred_fix"
                )

        # Clear pending modifications after applying
        self._pending_modifications.clear()

        if unflat_logger.isEnabledFor(20):  # INFO level
            unflat_logger.info(
                "Applied %d predecessor modifications successfully",
                applied_count
            )

        return applied_count

    def _apply_single_modification(
        self,
        mod: PredecessorModification,
        cond_blk: ida_hexrays.mblock_t
    ) -> bool:
        """Apply a single predecessor modification.

        Args:
            mod: The modification to apply
            cond_blk: Fresh pointer to the conditional block

        Returns:
            True if successful, False otherwise
        """
        # Re-fetch predecessor block (fresh pointer)
        pred_blk = self.mba.get_mblock(mod.pred_serial)
        if pred_blk is None:
            unflat_logger.warning(
                "Predecessor block %d not found for modification %s",
                mod.pred_serial, mod.description
            )
            return False

        if unflat_logger.isEnabledFor(10):  # DEBUG level
            unflat_logger.debug(
                "Applying modification: %s (pred %d -> cond %d -> target %d)",
                mod.mod_type.name, mod.pred_serial,
                mod.cond_block_serial, mod.target_serial
            )

        try:
            # Duplicate the conditional block
            new_jmp_block, _ = duplicate_block(cond_blk)

            # Convert 2-way block to 1-way goto pointing to target
            if not make_2way_block_goto(new_jmp_block, mod.target_serial):
                unflat_logger.warning(
                    "Failed to convert block %d to goto %d",
                    new_jmp_block.serial, mod.target_serial
                )
                return False

            # Update predecessor to point to new block instead of original conditional block
            if not update_blk_successor(pred_blk, mod.cond_block_serial, new_jmp_block.serial):
                unflat_logger.warning(
                    "Failed to update predecessor %d: %d -> %d",
                    mod.pred_serial, mod.cond_block_serial, new_jmp_block.serial
                )
                return False

            if unflat_logger.isEnabledFor(10):  # DEBUG level
                unflat_logger.debug(
                    "Successfully applied: created block %d, redirected pred %d",
                    new_jmp_block.serial, mod.pred_serial
                )

            return True

        except Exception as e:
            unflat_logger.error(
                "Exception in _apply_single_modification for %s: %s",
                mod.description, e
            )
            return False

    def optimize(self, blk: ida_hexrays.mblock_t) -> int:
        """Main optimization entry point.

        Architecture:
        1. Clear pending modifications from previous pass
        2. Check if rule should be used
        3. Analyze block and queue modifications
        4. Apply all queued modifications atomically
        5. Clean up and verify
        """
        self.mba = blk.mba

        # Initialize modifier if needed
        if self._modifier is None:
            self._modifier = DeferredGraphModifier(self.mba)

        # Clear pending modifications from previous pass
        self._pending_modifications.clear()

        if not self.check_if_rule_should_be_used(blk):
            return 0

        # Phase 1: Analysis - queue all modifications
        nb_queued = self.analyze_blk(blk)

        if nb_queued == 0:
            return 0

        # Phase 2: Apply - execute all modifications
        self.last_pass_nb_patch_done = self._apply_queued_modifications()

        if self.last_pass_nb_patch_done > 0:
            # Invalidate cache after CFG modification
            _pred_analysis_cache.invalidate_for_mba(self.mba)

            self.mba.mark_chains_dirty()
            self.mba.optimize_local(0)
            safe_verify(
                self.mba,
                "optimizing FixPredecessorOfConditionalJumpBlock",
                logger_func=unflat_logger.error
            )

        return self.last_pass_nb_patch_done

    def check_if_rule_should_be_used(self, blk: ida_hexrays.mblock_t) -> bool:
        """Check if this rule should be applied to the given block."""
        if self.cur_maturity != self.mba.maturity:
            self.cur_maturity = self.mba.maturity
            self.cur_maturity_pass = 0
            self._state_var_repr_cache.clear()  # Clear cache on maturity change

        if self.cur_maturity not in self.maturities:
            return False

        if self.DEFAULT_MAX_PASSES is not None and self.cur_maturity_pass >= self.DEFAULT_MAX_PASSES:
            return False

        if blk.tail is None or blk.tail.opcode not in JMP_OPCODE_HANDLED:
            return False

        if blk.tail.r.t != ida_hexrays.mop_n:
            return False

        self.cur_maturity_pass += 1
        return True
