import ida_hexrays

from d810.core import getLogger
from d810.hexrays.mutation.cfg_mutations import change_1way_block_successor
from d810.hexrays.mutation.cfg_verify import safe_verify
from d810.hexrays.utils.hexrays_formatters import dump_microcode_for_debug, format_minsn_t
from d810.evaluator.hexrays_microcode.tracker import MopTracker
from d810.evaluator.hexrays_microcode.dynamic_state_write_backend import (
    mop_matches_derived_xor_key,
    recognize_derived_xor_dispatcher_models,
)
from d810.optimizers.microcode.flow.flattening.generic import GenericUnflatteningRule
from d810.optimizers.microcode.flow.flattening.strategies.fake_jump import (
    resolve_fake_jump_target,
    should_skip_fake_jump_predecessor,
)
from d810.evaluator.hexrays_microcode.tracker import get_all_possibles_values

unflat_logger = getLogger("D810.unflat")

FAKE_LOOP_OPCODES = [ida_hexrays.m_jz, ida_hexrays.m_jnz]


class UnflattenerFakeJump(GenericUnflatteningRule):
    DESCRIPTION = (
        "Check if a jump is always taken for each father blocks and remove them"
    )
    DEFAULT_UNFLATTENING_MATURITIES = [ida_hexrays.MMAT_CALLS, ida_hexrays.MMAT_GLBOPT1]
    DEFAULT_MAX_PASSES = None

    def __init__(self):
        super().__init__()
        # Set when safe_verify fails -- prevents further processing on a
        # corrupted MBA that would cause IDA hangs.
        self._verify_failed: bool = False

    def _is_derived_xor_dispatch_key(self, mop: ida_hexrays.mop_t) -> bool:
        """Return true when fake-jump would claim a derived-key dispatcher.

        ABC XOR-style dispatchers do not compare the raw state carrier.  They
        compute a transient key, for example ``key = low8(carrier) ^ 0xEF``,
        and handler blocks update the carrier with ``carrier ^= CONST``.  The
        generic fake-jump tracker can then see a constant carrier history and
        incorrectly decide that key comparisons are always taken or never
        taken.  Leave that shape to EmulatedDispatcherUnflattener, which
        recovers the derived-key transitions explicitly.
        """

        mba = getattr(self, "mba", None)
        if mba is None:
            return False
        for model in recognize_derived_xor_dispatcher_models(mba=mba):
            if mop_matches_derived_xor_key(mop, model):
                return True
        return False

    def analyze_blk(self, blk: ida_hexrays.mblock_t) -> int:
        if (blk.tail is None) or blk.tail.opcode not in FAKE_LOOP_OPCODES:
            return 0
        if blk.get_reginsn_qty() != 1:
            return 0
        if blk.tail.r.t != ida_hexrays.mop_n:
            return 0
        unflat_logger.info(
            "Checking if block %s is fake loop: %s",
            blk.serial,
            format_minsn_t(blk.tail),
        )
        op_compared = ida_hexrays.mop_t(blk.tail.l)
        if self._is_derived_xor_dispatch_key(op_compared):
            unflat_logger.info(
                "Skipping fake-jump rewrite for derived-XOR dispatcher key in blk %s",
                blk.serial,
            )
            return 0
        blk_preset_list = [x for x in blk.predset]
        nb_change = 0
        for pred_serial in blk_preset_list:
            cmp_variable_tracker = MopTracker(
                [op_compared], max_nb_block=100, max_path=1000
            )
            cmp_variable_tracker.reset()
            pred_blk = blk.mba.get_mblock(pred_serial)
            pred_histories = cmp_variable_tracker.search_backward(
                pred_blk, pred_blk.tail
            )

            # Filter to resolved histories only - unresolved histories are typically
            # dispatcher back-edges (loops back before finding constant assignments)
            # which are expected in flattened control flow
            resolved_histories = [h for h in pred_histories if h.is_resolved()]
            unresolved_count = len(pred_histories) - len(resolved_histories)

            if len(resolved_histories) == 0:
                # No resolved paths at all - can't determine values for this predecessor
                unflat_logger.debug(
                    "No resolved histories for pred %s, skipping",
                    pred_serial,
                )
                continue  # Try next predecessor instead of failing entirely

            # SAFETY CHECK: If too many unresolved paths, consider skipping.
            # Z3 analysis shows ignoring unresolved paths can be unsafe when they could
            # have different state values leading to different jump outcomes.
            #
            # However, for OLLVM FLA patterns:
            # - Many paths are unresolved due to nested loop back-edges
            # - These back-edges don't set state values, so they don't affect jump direction
            # - The resolved paths still correctly determine if jump is always/never taken
            #
            # Relaxed heuristic: Skip only when unresolved massively outnumber resolved
            # (10x threshold) AND we have very few resolved paths (< 3). This handles:
            # - Simple cases: few paths, strict check (original behavior)
            # - OLLVM FLA: many resolved paths, relax ratio requirement
            if should_skip_fake_jump_predecessor(
                len(resolved_histories),
                unresolved_count,
            ):
                unflat_logger.warning(
                    "Pred %s has extreme unresolved:resolved ratio (%d vs %d) with few resolved - "
                    "unsafe to ignore unresolved, skipping",
                    pred_serial,
                    unresolved_count,
                    len(resolved_histories),
                )
                continue

            if unresolved_count > 0:
                unflat_logger.debug(
                    "Pred %s has %d unresolved and %d resolved paths - using resolved only",
                    pred_serial,
                    unresolved_count,
                    len(resolved_histories),
                )

            pred_values = get_all_possibles_values(resolved_histories, [op_compared])
            pred_values = [x[0] for x in pred_values]
            if None in pred_values:
                unflat_logger.info("Some path are not resolved, can't fix jump")
                return 0
            unflat_logger.info(
                "Pred %s has %s possible path (%s different cst): %s",
                pred_blk.serial,
                len(pred_values),
                len(set(pred_values)),
                pred_values,
            )
            if self.fix_successor(blk, pred_blk, pred_values):
                nb_change += 1
        return nb_change

    def fix_successor(
        self,
        fake_loop_block: ida_hexrays.mblock_t,
        pred: ida_hexrays.mblock_t,
        pred_comparison_values: list[int],
    ) -> bool:
        if len(pred_comparison_values) == 0:
            return False
        jmp_ins = fake_loop_block.tail
        compared_value = jmp_ins.r.nnn.value
        resolution = resolve_fake_jump_target(
            opcode=jmp_ins.opcode,
            compared_value=compared_value,
            pred_comparison_values=pred_comparison_values,
            taken_target=jmp_ins.d.b,
            fallthrough_target=fake_loop_block.nextb.serial,
            jz_opcode=ida_hexrays.m_jz,
            jnz_opcode=ida_hexrays.m_jnz,
        )
        if resolution.always_taken:
            unflat_logger.info(
                "It seems that '%s' is always taken when coming from %s: %s",
                format_minsn_t(jmp_ins),
                pred.serial,
                pred_comparison_values,
            )
        if resolution.always_not_taken:
            unflat_logger.info(
                "It seems that '%s' is never taken when coming from %s: %s",
                format_minsn_t(jmp_ins),
                pred.serial,
                pred_comparison_values,
            )
        if resolution.new_target is None:
            unflat_logger.debug(
                "Jump seems legit '%s' from %s: %s",
                format_minsn_t(jmp_ins),
                pred.serial,
                pred_comparison_values,
            )
            return False
        if self.dump_intermediate_microcode:
            dump_microcode_for_debug(
                self.mba,
                self.log_dir,
                f"{self.cur_maturity_pass}_before_fake_jump",
            )
        unflat_logger.info(
            "Making pred %s with value %s goto %s (%s)",
            pred.serial,
            pred_comparison_values,
            resolution.new_target,
            format_minsn_t(jmp_ins),
        )
        if self.dump_intermediate_microcode:
            dump_microcode_for_debug(
                self.mba,
                self.log_dir,
                f"{self.cur_maturity_pass}_after_fake_jump",
            )
        return change_1way_block_successor(
            pred,
            resolution.new_target,
            verify=False,
        )

    def check_if_rule_should_be_used(self, blk: ida_hexrays.mblock_t) -> bool:
        if self._verify_failed:
            unflat_logger.debug(
                "Skipping UnflattenerFakeJump -- MBA verify previously failed"
            )
            return False
        return super().check_if_rule_should_be_used(blk)

    def optimize(self, blk: ida_hexrays.mblock_t) -> int:
        self.mba = blk.mba
        if not self.check_if_rule_should_be_used(blk):
            return 0
        self.last_pass_nb_patch_done = self.analyze_blk(blk)
        if self.last_pass_nb_patch_done > 0:
            # G2: audit trail only — no safeguard gate. FakeJump makes targeted
            # per-predecessor edge redirects (not bulk CFG rewrites).
            # analyze_blk already applied modifications before returning count.
            unflat_logger.info(
                "fake_jump gate: applied=%d modifications",
                self.last_pass_nb_patch_done,
            )
            self.mba.mark_chains_dirty()
            self.mba.optimize_local(0)
            try:
                safe_verify(
                    self.mba,
                    "optimizing UnflattenerFakeJump",
                    logger_func=unflat_logger.error,
                )
            except RuntimeError:
                self._verify_failed = True
                unflat_logger.warning(
                    "MBA verify failed after UnflattenerFakeJump modifications -- "
                    "aborting future passes to prevent IDA from continuing with "
                    "a corrupted MBA"
                )
                # Return patch count so IDA knows the MBA was touched
                return self.last_pass_nb_patch_done
        return self.last_pass_nb_patch_done
