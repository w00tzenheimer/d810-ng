from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ida_hexrays import *

from d810.errors import D810Exception
from d810.expr.utils import MOP_CONSTANT_CACHE, MOP_TO_AST_CACHE
from d810.expr.z3_utils import log_z3_instructions
from d810.hexrays.hexrays_formatters import (
    dump_microcode_for_debug,
    format_minsn_t,
    maturity_to_string,
)
from d810.hexrays.hexrays_helpers import check_ins_mop_size_are_ok
from d810.optimizers.microcode.instructions.handler import InstructionOptimizer

if TYPE_CHECKING:
    from d810.manager import D810Manager
    from d810.optimizers.microcode.flow.handler import FlowOptimizationRule
    from d810.optimizers.microcode.instructions.handler import (
        InstructionOptimizationRule,
        InstructionOptimizer,
    )

main_logger = logging.getLogger("D810")
optimizer_logger = logging.getLogger("D810.optimizer")
helper_logger = logging.getLogger("D810.helper")

DEFAULT_OPTIMIZATION_PATTERN_MATURITIES = [
    MMAT_CALLS,
    MMAT_GLBOPT1,
]
DEFAULT_OPTIMIZATION_CHAIN_MATURITIES = [
    MMAT_CALLS,
    MMAT_GLBOPT1,
]
DEFAULT_OPTIMIZATION_Z3_MATURITIES = [MMAT_CALLS, MMAT_GLBOPT1]
DEFAULT_OPTIMIZATION_EARLY_MATURITIES = [MMAT_GENERATED, MMAT_PREOPTIMIZED, MMAT_LOCOPT]
DEFAULT_OPTIMIZATION_PEEPHOLE_MATURITIES = [
    MMAT_GLBOPT1,
    MMAT_GLBOPT2,
    MMAT_GLBOPT3,
    MMAT_LVARS,
]
DEFAULT_ANALYZER_MATURITIES = [
    MMAT_PREOPTIMIZED,
    MMAT_LOCOPT,
    MMAT_CALLS,
    MMAT_GLBOPT1,
    MMAT_GLBOPT2,
    MMAT_GLBOPT3,
    MMAT_LVARS,
]


# from d810.optimizers.microcode.instructions import (
#     ChainOptimizer,
#     EarlyOptimizer,
#     InstructionAnalyzer,
#     PatternOptimizer,
#     PeepholeOptimizer,
#     Z3Optimizer,
# )


class InstructionOptimizerManager(optinsn_t):
    def __init__(self, manager: D810Manager):
        optimizer_logger.debug("Initializing {0}...".format(self.__class__.__name__))
        super().__init__()
        self.manager = manager
        self.instruction_visitor = InstructionVisitorManager(self)
        self._last_optimizer_tried = None
        self.current_maturity = None
        self.current_blk_serial = None
        self.generate_z3_code = False
        self.dump_intermediate_microcode = False

        self.instruction_optimizers = []
        self.optimizer_usage_info = {}
        ChainOptimizer = InstructionOptimizer.get("ChainOptimizer")
        EarlyOptimizer = InstructionOptimizer.get("EarlyOptimizer")
        InstructionAnalyzer = InstructionOptimizer.get("InstructionAnalyzer")
        PatternOptimizer = InstructionOptimizer.get("PatternOptimizer")
        PeepholeOptimizer = InstructionOptimizer.get("PeepholeOptimizer")
        Z3Optimizer = InstructionOptimizer.get("Z3Optimizer")
        self.add_optimizer(
            PatternOptimizer(
                DEFAULT_OPTIMIZATION_PATTERN_MATURITIES, log_dir=self.manager.log_dir
            )
        )
        self.add_optimizer(
            ChainOptimizer(
                DEFAULT_OPTIMIZATION_CHAIN_MATURITIES, log_dir=self.manager.log_dir
            )
        )
        self.add_optimizer(
            Z3Optimizer(
                DEFAULT_OPTIMIZATION_Z3_MATURITIES, log_dir=self.manager.log_dir
            )
        )
        self.add_optimizer(
            EarlyOptimizer(
                DEFAULT_OPTIMIZATION_EARLY_MATURITIES, log_dir=self.manager.log_dir
            )
        )
        self.add_optimizer(
            PeepholeOptimizer(
                DEFAULT_OPTIMIZATION_PEEPHOLE_MATURITIES, log_dir=self.manager.log_dir
            )
        )
        self.analyzer = InstructionAnalyzer(
            DEFAULT_ANALYZER_MATURITIES, log_dir=self.manager.log_dir
        )

    def func(self, blk: mblock_t, ins: minsn_t) -> bool:
        self.log_info_on_input(blk, ins)
        try:
            optimization_performed = self.optimize(blk, ins)

            if not optimization_performed:
                optimization_performed = ins.for_all_insns(self.instruction_visitor)

            if optimization_performed:
                ins.optimize_solo()

                if blk is not None:
                    blk.mark_lists_dirty()
                    blk.mba.verify(True)

            return bool(optimization_performed)
        except RuntimeError as e:
            optimizer_logger.error(
                "RuntimeError while optimizing ins {0} with {1}: {2}".format(
                    format_minsn_t(ins), self._last_optimizer_tried, e
                )
            )
        except D810Exception as e:
            optimizer_logger.error(
                "D810Exception while optimizing ins {0} with {1}: {2}".format(
                    format_minsn_t(ins), self._last_optimizer_tried, e
                )
            )
        return False

    def reset_rule_usage_statistic(self):
        self.optimizer_usage_info = {}
        for ins_optimizer in self.instruction_optimizers:
            self.optimizer_usage_info[ins_optimizer.name] = 0
            ins_optimizer.reset_rule_usage_statistic()

    def show_rule_usage_statistic(self):
        for optimizer_name, optimizer_nb_match in self.optimizer_usage_info.items():
            if optimizer_nb_match > 0:
                main_logger.info(
                    "Instruction optimizer '%s' has been used %d times",
                    optimizer_name,
                    optimizer_nb_match,
                )
        for ins_optimizer in self.instruction_optimizers:
            ins_optimizer.show_rule_usage_statistic()

    def log_info_on_input(self, blk: mblock_t, ins: minsn_t):
        if blk is None:
            return
        mba: mbl_array_t = blk.mba

        if (mba is not None) and (mba.maturity != self.current_maturity):
            self.current_maturity = mba.maturity
            main_logger.debug(
                "Instruction optimization function called at maturity: {0}".format(
                    maturity_to_string(self.current_maturity)
                )
            )
            self.analyzer.set_maturity(self.current_maturity)
            self.current_blk_serial = None

            for ins_optimizer in self.instruction_optimizers:
                ins_optimizer.cur_maturity = self.current_maturity

            if self.dump_intermediate_microcode:
                dump_microcode_for_debug(
                    mba, self.manager.log_dir, "input_instruction_optimizer"
                )

        if blk.serial != self.current_blk_serial:
            self.current_blk_serial = blk.serial

    def add_optimizer(self, optimizer: InstructionOptimizer):
        self.instruction_optimizers.append(optimizer)
        self.optimizer_usage_info[optimizer.name] = 0

    def add_rule(self, rule: InstructionOptimizationRule):
        # optimizer_log.info("Trying to add rule {0}".format(rule))
        for ins_optimizer in self.instruction_optimizers:
            ins_optimizer.add_rule(rule)
        self.analyzer.add_rule(rule)

    def configure(
        self, generate_z3_code=False, dump_intermediate_microcode=False, **kwargs
    ):
        self.generate_z3_code = generate_z3_code
        self.dump_intermediate_microcode = dump_intermediate_microcode

    def optimize(self, blk: mblock_t, ins: minsn_t) -> bool:
        # optimizer_log.info("Trying to optimize {0}".format(format_minsn_t(ins)))
        MOP_TO_AST_CACHE.clear()
        for ins_optimizer in self.instruction_optimizers:
            self._last_optimizer_tried = ins_optimizer
            new_ins = ins_optimizer.get_optimized_instruction(blk, ins)

            if new_ins is not None:
                if not check_ins_mop_size_are_ok(new_ins):
                    if check_ins_mop_size_are_ok(ins):
                        main_logger.error(
                            "Invalid optimized instruction: {0} (original was {1})".format(
                                format_minsn_t(new_ins), format_minsn_t(ins)
                            )
                        )
                    else:
                        main_logger.error(
                            "Invalid original instruction : {0} (original was {1})".format(
                                format_minsn_t(new_ins), format_minsn_t(ins)
                            )
                        )
                else:
                    ins.swap(new_ins)
                    self.optimizer_usage_info[ins_optimizer.name] += 1
                    if self.generate_z3_code:
                        try:
                            log_z3_instructions(new_ins, ins)
                        except KeyError:
                            pass
                    return True

        self.analyzer.analyze(blk, ins)
        return False


class InstructionVisitorManager(minsn_visitor_t):
    def __init__(self, optimizer: InstructionOptimizerManager):
        optimizer_logger.debug("Initializing {0}...".format(self.__class__.__name__))
        super().__init__()
        self.instruction_optimizer = optimizer

    def visit_minsn(self) -> bool:
        return self.instruction_optimizer.optimize(self.blk, self.curins)


class BlockOptimizerManager(optblock_t):
    def __init__(self, manager: D810Manager):
        optimizer_logger.debug("Initializing {0}...".format(self.__class__.__name__))
        super().__init__()
        self.manager = manager
        self.cfg_rules = set()

        self.current_maturity = None
        self.cfg_rules_usage_info = {}

    def func(self, blk: mblock_t):
        self.log_info_on_input(blk)
        nb_patch = self.optimize(blk)
        return nb_patch

    def reset_rule_usage_statistic(self):
        self.cfg_rules_usage_info = {}
        for rule in self.cfg_rules:
            self.cfg_rules_usage_info[rule.name] = []

    def show_rule_usage_statistic(self):
        for rule_name, rule_nb_patch_list in self.cfg_rules_usage_info.items():
            nb_use = len(rule_nb_patch_list)
            if nb_use > 0:
                main_logger.info(
                    "BlkRule '%s' has been used %d times for a total of %d patches",
                    rule_name,
                    nb_use,
                    sum(rule_nb_patch_list),
                )

    def log_info_on_input(self, blk: mblock_t):
        if blk is None:
            return
        mba: mbl_array_t = blk.mba

        if (mba is not None) and (mba.maturity != self.current_maturity):
            main_logger.debug(
                "BlockOptimizer called at maturity: {0}".format(
                    maturity_to_string(mba.maturity)
                )
            )
            self.current_maturity = mba.maturity

    def optimize(self, blk: mblock_t):
        for cfg_rule in self.cfg_rules:
            if (
                blk.mba != None and blk.mba.entry_ea != None
            ) and self.check_if_rule_is_activated_for_address(
                cfg_rule, blk.mba.entry_ea
            ):
                nb_patch = cfg_rule.optimize(blk)
                if nb_patch > 0:
                    optimizer_logger.info(
                        "Rule {0} matched: {1} patches".format(cfg_rule.name, nb_patch)
                    )
                    self.cfg_rules_usage_info[cfg_rule.name].append(nb_patch)
                    return nb_patch
        return 0

    def add_rule(self, cfg_rule: FlowOptimizationRule):
        optimizer_logger.info("Adding cfg rule {0}".format(cfg_rule))
        self.cfg_rules.add(cfg_rule)
        self.cfg_rules_usage_info[cfg_rule.name] = []

    def configure(self, **kwargs):
        pass

    def check_if_rule_is_activated_for_address(
        self, cfg_rule: FlowOptimizationRule, func_entry_ea: int
    ):
        if cfg_rule.use_whitelist and (
            func_entry_ea not in cfg_rule.whitelisted_function_ea_list
        ):
            return False
        if cfg_rule.use_blacklist and (
            func_entry_ea in cfg_rule.blacklisted_function_ea_list
        ):
            return False
        return True


class HexraysDecompilationHook(Hexrays_Hooks):
    def __init__(self, manager):
        super().__init__()
        self.manager = manager

    def prolog(self, mba: mbl_array_t, fc, reachable_blocks, decomp_flags) -> "int":
        main_logger.info("Starting decompilation of function at %s", hex(mba.entry_ea))
        self.manager.start_profiling()
        self.manager.instruction_optimizer.reset_rule_usage_statistic()
        self.manager.block_optimizer.reset_rule_usage_statistic()
        return 0

    def maturity(self, cfunc: "cfunc_t", new_maturity: int) -> int:
        """Ctree maturity level is being changed."""
        # main_logger.info(
        #     "Maturity changed for %s @ %s to %s (ctree maturity: %d)",
        #     cfunc.print_dcl(),
        #     hex(cfunc.entry_ea),
        #     maturity_to_string(cfunc.mba.maturity),
        #     new_maturity,
        # )
        return 0

    def glbopt(self, mba: mbl_array_t) -> "int":
        self.manager.stop_profiling()
        main_logger.info("glbopt finished for function at %s", hex(mba.entry_ea))
        self.manager.instruction_optimizer.show_rule_usage_statistic()
        self.manager.block_optimizer.show_rule_usage_statistic()
        main_logger.info("MOP_CONSTANT_CACHE stats: %s", MOP_CONSTANT_CACHE.stats)
        main_logger.info("MOP_TO_AST_CACHE stats: %s", MOP_TO_AST_CACHE.stats)
        return 0
