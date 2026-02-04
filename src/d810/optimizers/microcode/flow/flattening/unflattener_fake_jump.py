import ida_hexrays

from d810.core import getLogger
from d810.hexrays.cfg_utils import change_1way_block_successor, safe_verify
from d810.hexrays.hexrays_formatters import dump_microcode_for_debug, format_minsn_t
from d810.hexrays.tracker import MopTracker
from d810.optimizers.microcode.flow.flattening.generic import GenericUnflatteningRule
from d810.optimizers.microcode.flow.flattening.utils import get_all_possibles_values

unflat_logger = getLogger("D810.unflat")

FAKE_LOOP_OPCODES = [ida_hexrays.m_jz, ida_hexrays.m_jnz]


class UnflattenerFakeJump(GenericUnflatteningRule):
    DESCRIPTION = (
        "Check if a jump is always taken for each father blocks and remove them"
    )
    DEFAULT_UNFLATTENING_MATURITIES = [ida_hexrays.MMAT_CALLS, ida_hexrays.MMAT_GLBOPT1]
    DEFAULT_MAX_PASSES = None

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

            # SAFETY CHECK: If unresolved paths outnumber resolved paths, bail out
            # Z3 analysis shows ignoring unresolved paths is unsafe when they could
            # have different state values leading to different jump outcomes.
            # Conservative heuristic: only trust resolved paths when they're the majority.
            if unresolved_count > len(resolved_histories):
                unflat_logger.warning(
                    "Pred %s has more unresolved (%d) than resolved (%d) paths - "
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
        jmp_taken = False
        jmp_not_taken = False
        dst_serial = None
        if jmp_ins.opcode == ida_hexrays.m_jz:
            jmp_taken = all(
                [
                    possible_value == compared_value
                    for possible_value in pred_comparison_values
                ]
            )

            jmp_not_taken = all(
                [
                    possible_value != compared_value
                    for possible_value in pred_comparison_values
                ]
            )
        elif jmp_ins.opcode == ida_hexrays.m_jnz:
            jmp_taken = all(
                [
                    possible_value != compared_value
                    for possible_value in pred_comparison_values
                ]
            )
            jmp_not_taken = all(
                [
                    possible_value == compared_value
                    for possible_value in pred_comparison_values
                ]
            )
        # TODO: handles other jumps cases
        if jmp_taken:
            unflat_logger.info(
                "It seems that '%s' is always taken when coming from %s: %s",
                format_minsn_t(jmp_ins),
                pred.serial,
                pred_comparison_values,
            )
            dst_serial = jmp_ins.d.b
        if jmp_not_taken:
            unflat_logger.info(
                "It seems that '%s' is never taken when coming from %s: %s",
                format_minsn_t(jmp_ins),
                pred.serial,
                pred_comparison_values,
            )
            dst_serial = fake_loop_block.serial + 1
        if dst_serial is None:
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
            dst_serial,
            format_minsn_t(jmp_ins),
        )
        if self.dump_intermediate_microcode:
            dump_microcode_for_debug(
                self.mba,
                self.log_dir,
                f"{self.cur_maturity_pass}_after_fake_jump",
            )
        return change_1way_block_successor(pred, dst_serial)

    def optimize(self, blk: ida_hexrays.mblock_t) -> int:
        self.mba = blk.mba
        if not self.check_if_rule_should_be_used(blk):
            return 0
        self.last_pass_nb_patch_done = self.analyze_blk(blk)
        if self.last_pass_nb_patch_done > 0:
            self.mba.mark_chains_dirty()
            self.mba.optimize_local(0)
            safe_verify(
                self.mba,
                "optimizing UnflattenerFakeJump",
                logger_func=unflat_logger.error,
            )
        return self.last_pass_nb_patch_done
