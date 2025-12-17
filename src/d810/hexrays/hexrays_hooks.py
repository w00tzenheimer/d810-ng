from __future__ import annotations

import enum
import pathlib
import typing

import ida_hexrays

from d810.core import getLogger
from d810.errors import D810Exception
from d810.expr.z3_utils import log_z3_instructions
from d810.hexrays.cfg_utils import safe_verify
from d810.hexrays.hexrays_formatters import (
    dump_microcode_for_debug,
    format_minsn_t,
    maturity_to_string,
)
from d810.hexrays.hexrays_helpers import check_ins_mop_size_are_ok
# Note: VerifiableRule and adapt_rules are loaded/filtered in manager.py
# Rules are added to PatternOptimizer via add_rule() based on project config

# Import experimental rules that depend on optimizer extensions
# These rules use context-aware features and can't be in mba.rules
from d810.optimizers.microcode.instructions.pattern_matching import experimental  # noqa: F401

# Try to import egglog-based optimizer (optional dependency)
try:
    from d810.mba.backends.egglog_backend import EGGLOG_AVAILABLE
    if EGGLOG_AVAILABLE:
        # Import to trigger auto-registration of EgglogOptimizer
        from d810.optimizers.microcode.instructions.egraph import egglog_handler  # noqa: F401
        # Import to trigger auto-registration of BlockLevelEgglogOptimizer
        from d810.optimizers.microcode.flow.egraph import block_optimizer  # noqa: F401
except ImportError:
    EGGLOG_AVAILABLE = False
from d810.optimizers.microcode.flow.handler import FlowOptimizationRule
from d810.optimizers.microcode.instructions.handler import (
    InstructionOptimizationRule,
    InstructionOptimizer,
)

main_logger = getLogger("D810")
optimizer_logger = getLogger("D810.optimizer")

DEFAULT_OPTIMIZATION_PATTERN_MATURITIES = [
    ida_hexrays.MMAT_PREOPTIMIZED,
    ida_hexrays.MMAT_LOCOPT,
    ida_hexrays.MMAT_CALLS,
    ida_hexrays.MMAT_GLBOPT1,
]
DEFAULT_OPTIMIZATION_CHAIN_MATURITIES = [
    ida_hexrays.MMAT_PREOPTIMIZED,
    ida_hexrays.MMAT_LOCOPT,
    ida_hexrays.MMAT_CALLS,
    ida_hexrays.MMAT_GLBOPT1,
]
DEFAULT_OPTIMIZATION_Z3_MATURITIES = [ida_hexrays.MMAT_LOCOPT, ida_hexrays.MMAT_CALLS, ida_hexrays.MMAT_GLBOPT1]
DEFAULT_OPTIMIZATION_EARLY_MATURITIES = [ida_hexrays.MMAT_GENERATED, ida_hexrays.MMAT_PREOPTIMIZED]
DEFAULT_OPTIMIZATION_PEEPHOLE_MATURITIES = [
    ida_hexrays.MMAT_LOCOPT,
    ida_hexrays.MMAT_CALLS,
    ida_hexrays.MMAT_GLBOPT1,
    ida_hexrays.MMAT_GLBOPT2,
]
DEFAULT_ANALYZER_MATURITIES = [ida_hexrays.MMAT_PREOPTIMIZED, ida_hexrays.MMAT_LOCOPT, ida_hexrays.MMAT_CALLS, ida_hexrays.MMAT_GLBOPT1]


if typing.TYPE_CHECKING:
    from d810.core import OptimizationStatistics
    from d810.optimizers.microcode.instructions.analysis.handler import (
        InstructionAnalyzer,
    )
    from d810.optimizers.microcode.instructions.chain.handler import ChainOptimizer
    from d810.optimizers.microcode.instructions.early.handler import EarlyOptimizer
    from d810.optimizers.microcode.instructions.egraph.egglog_handler import (
        EgglogOptimizer,
    )
    from d810.optimizers.microcode.instructions.pattern_matching.handler import (
        PatternOptimizer,
    )
    from d810.optimizers.microcode.instructions.peephole.handler import (
        PeepholeOptimizer,
    )
    from d810.optimizers.microcode.instructions.z3.handler import Z3Optimizer


class InstructionOptimizerManager(ida_hexrays.optinsn_t):
    def __init__(self, stats: OptimizationStatistics, log_dir: pathlib.Path):
        optimizer_logger.debug("Initializing {0}...".format(self.__class__.__name__))
        super().__init__()
        self.log_dir = log_dir
        self.stats = stats
        self.instruction_visitor = InstructionVisitorManager(self)
        self._last_optimizer_tried = None
        self.current_maturity = None
        self.current_blk_serial = None
        self.generate_z3_code = False
        self.dump_intermediate_microcode = False

        self.instruction_optimizers = []
        # usage tracking moved to centralized statistics object
        ChainOptimizer: type[ChainOptimizer] = InstructionOptimizer.get(
            "ChainOptimizer"
        )
        EarlyOptimizer: type[EarlyOptimizer] = InstructionOptimizer.get(
            "EarlyOptimizer"
        )
        InstructionAnalyzer: type[InstructionAnalyzer] = InstructionOptimizer.get(
            "InstructionAnalyzer"
        )
        PatternOptimizer: type[PatternOptimizer] = InstructionOptimizer.get(
            "PatternOptimizer"
        )
        PeepholeOptimizer: type[PeepholeOptimizer] = InstructionOptimizer.get(
            "PeepholeOptimizer"
        )
        Z3Optimizer: type[Z3Optimizer] = InstructionOptimizer.get("Z3Optimizer")

        # PatternOptimizer: Rules are added via add_rule() from D810Manager based on
        # project configuration. This ensures only rules enabled in the project's
        # ins_rules (with is_activated: true) are loaded.
        # Previously this loaded ALL VerifiableRules, bypassing project config.
        self.add_optimizer(
            PatternOptimizer(
                DEFAULT_OPTIMIZATION_PATTERN_MATURITIES,
                stats=self.stats,
                log_dir=self.log_dir,
            )
        )

        # EXPERIMENTAL: Egglog-based optimizer using equality saturation
        # Currently DISABLED by default because egglog's saturation() is too slow
        # for real-time IDA decompilation. The overhead of running equality saturation
        # on every instruction makes decompilation impractically slow (>100x slower).
        #
        # The egglog backend still works correctly for batch/offline analysis.
        # To enable for testing, set ENABLE_EGGLOG_OPTIMIZER = True below:
        ENABLE_EGGLOG_OPTIMIZER = False  # Set to True to enable (SLOW!)

        if ENABLE_EGGLOG_OPTIMIZER and EGGLOG_AVAILABLE:
            EgglogOptimizer: type[EgglogOptimizer] = InstructionOptimizer.get(
                "EgglogOptimizer"
            )
            if EgglogOptimizer is not None:
                self.add_optimizer(
                    EgglogOptimizer(
                        DEFAULT_OPTIMIZATION_PATTERN_MATURITIES,
                        stats=self.stats,
                        log_dir=self.log_dir,
                    )
                )
                optimizer_logger.warning(
                    "[EgglogOptimizer] ENABLED (experimental) - using equality saturation. "
                    "Expect SLOW decompilation!"
                )
            else:
                optimizer_logger.debug("[EgglogOptimizer] Not registered - skipping")
        elif EGGLOG_AVAILABLE:
            optimizer_logger.debug("[EgglogOptimizer] Disabled (set ENABLE_EGGLOG_OPTIMIZER=True to enable)")
        else:
            optimizer_logger.debug("[EgglogOptimizer] egglog not installed - skipping")

        self.add_optimizer(
            ChainOptimizer(
                DEFAULT_OPTIMIZATION_CHAIN_MATURITIES,
                stats=self.stats,
                log_dir=self.log_dir,
            )
        )
        self.add_optimizer(
            Z3Optimizer(
                DEFAULT_OPTIMIZATION_Z3_MATURITIES,
                stats=self.stats,
                log_dir=self.log_dir,
            )
        )
        self.add_optimizer(
            EarlyOptimizer(
                DEFAULT_OPTIMIZATION_EARLY_MATURITIES,
                stats=self.stats,
                log_dir=self.log_dir,
            )
        )
        self.add_optimizer(
            PeepholeOptimizer(
                DEFAULT_OPTIMIZATION_PEEPHOLE_MATURITIES,
                stats=self.stats,
                log_dir=self.log_dir,
            )
        )
        self.analyzer = InstructionAnalyzer(
            DEFAULT_ANALYZER_MATURITIES,
            stats=self.stats,
            log_dir=self.log_dir,
        )

    def add_optimizer(self, optimizer: InstructionOptimizer):
        self.instruction_optimizers.append(optimizer)

    def add_rule(self, rule: InstructionOptimizationRule):
        # optimizer_log.info("Trying to add rule {0}".format(rule))
        for ins_optimizer in self.instruction_optimizers:
            ins_optimizer.add_rule(rule)
        self.analyzer.add_rule(rule)

    def func(self, blk: ida_hexrays.mblock_t, ins: ida_hexrays.minsn_t) -> bool:
        self.log_info_on_input(blk, ins)
        try:
            optimization_performed = self.optimize(blk, ins)

            if not optimization_performed:
                optimization_performed = ins.for_all_insns(self.instruction_visitor)

            if optimization_performed:
                ins.optimize_solo()

                if blk is not None:
                    blk.mark_lists_dirty()
                    safe_verify(
                        blk.mba, "rewriting", logger_func=optimizer_logger.error
                    )

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

    # statistics are managed centrally via the stats object

    def log_info_on_input(self, blk: ida_hexrays.mblock_t, ins: ida_hexrays.minsn_t):
        mba: ida_hexrays.mbl_array_t = blk.mba

        if (mba is not None) and (mba.maturity != self.current_maturity):
            self.current_maturity = mba.maturity
            main_logger.update_maturity(maturity_to_string(self.current_maturity))
            if main_logger.debug_on:
                main_logger.debug(
                    "Instruction optimization function called at maturity: %s",
                    maturity_to_string(self.current_maturity),
                )
            self.analyzer.set_maturity(self.current_maturity)
            self.current_blk_serial = None

            for ins_optimizer in self.instruction_optimizers:
                ins_optimizer.cur_maturity = self.current_maturity

            if self.dump_intermediate_microcode:
                dump_microcode_for_debug(
                    mba, self.log_dir, "input_instruction_optimizer"
                )

        if blk.serial != self.current_blk_serial:
            self.current_blk_serial = blk.serial

    def configure(
        self, generate_z3_code=False, dump_intermediate_microcode=False, **kwargs
    ):
        self.generate_z3_code = generate_z3_code
        self.dump_intermediate_microcode = dump_intermediate_microcode

    def optimize(self, blk: ida_hexrays.mblock_t, ins: ida_hexrays.minsn_t) -> bool:
        # optimizer_log.info("Trying to optimize {0}".format(format_minsn_t(ins)))
        for ins_optimizer in self.instruction_optimizers:
            self._last_optimizer_tried = ins_optimizer
            new_ins = ins_optimizer.get_optimized_instruction(blk, ins)

            if new_ins is not None:
                if not check_ins_mop_size_are_ok(new_ins):
                    if check_ins_mop_size_are_ok(ins):
                        main_logger.error(
                            "Invalid optimized instruction (%s) for maturity %s:\n\toptimized: %s\n\toriginal: %s",
                            ins_optimizer.name,
                            maturity_to_string(self.current_maturity),  # type: ignore
                            format_minsn_t(new_ins),
                            format_minsn_t(ins),
                        )
                    else:
                        main_logger.error(
                            "Invalid original instruction (%s) for maturity %s:\n\toptimized: %s\n\toriginal: %s",
                            ins_optimizer.name,
                            maturity_to_string(self.current_maturity),  # type: ignore
                            format_minsn_t(new_ins),
                            format_minsn_t(ins),
                        )
                else:
                    ins.swap(new_ins)
                    if self.stats is not None:
                        self.stats.record_optimizer_match(ins_optimizer.name)

                    if self.generate_z3_code:
                        try:
                            log_z3_instructions(new_ins, ins)
                        except KeyError:
                            pass
                    return True

        self.analyzer.analyze(blk, ins)
        return False


class InstructionVisitorManager(ida_hexrays.minsn_visitor_t):
    def __init__(self, optimizer: InstructionOptimizerManager):
        optimizer_logger.debug("Initializing {0}...".format(self.__class__.__name__))
        super().__init__()
        self.instruction_optimizer = optimizer

    def visit_minsn(self) -> bool:
        return self.instruction_optimizer.optimize(self.blk, self.curins)


class BlockOptimizerManager(ida_hexrays.optblock_t):
    def __init__(self, stats: OptimizationStatistics, log_dir: pathlib.Path):
        optimizer_logger.debug("Initializing {0}...".format(self.__class__.__name__))
        super().__init__()
        self.log_dir = log_dir
        self.stats = stats
        self.cfg_rules = set()

        self.current_maturity = None
        # usage tracking moved to centralized statistics object

    def func(self, blk: ida_hexrays.mblock_t):
        self.log_info_on_input(blk)
        nb_patch = self.optimize(blk)
        return nb_patch

    def log_info_on_input(self, blk: ida_hexrays.mblock_t):
        mba: ida_hexrays.mbl_array_t = blk.mba

        if (mba is not None) and (mba.maturity != self.current_maturity):
            if main_logger.debug_on:
                main_logger.debug(
                    "BlockOptimizer called at maturity: %s",
                    maturity_to_string(mba.maturity),
                )

            self.current_maturity = mba.maturity

    # statistics are managed centrally via the stats object

    def optimize(self, blk: ida_hexrays.mblock_t):
        for cfg_rule in self.cfg_rules:
            cfg_rule.current_maturity = self.current_maturity
            guard = blk.mba is not None and blk.mba.entry_ea is not None
            guard &= self.check_if_rule_is_activated_for_address(
                cfg_rule, blk.mba.entry_ea
            )
            if guard:
                nb_patch = cfg_rule.optimize(blk)
                if nb_patch > 0:
                    optimizer_logger.info(
                        "Rule {0} matched: {1} patches".format(cfg_rule.name, nb_patch)
                    )
                    if self.stats is not None:
                        self.stats.record_cfg_rule_patches(cfg_rule.name, nb_patch)

                    return nb_patch
        return 0

    def add_rule(self, cfg_rule: FlowOptimizationRule):
        optimizer_logger.info("Adding cfg rule {0}".format(cfg_rule))
        self.cfg_rules.add(cfg_rule)

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


class DecompilationEvent(enum.Enum):
    STARTED = "decompilation_started"
    FINISHED = "decompilation_finished"


class HexraysDecompilationHook(ida_hexrays.Hexrays_Hooks):
    def __init__(self, callback: typing.Callable):
        super().__init__()
        self.callback = callback

    def prolog(self, mba: ida_hexrays.mbl_array_t, fc, reachable_blocks, decomp_flags) -> "int":
        main_logger.info("Starting decompilation of function at %s", hex(mba.entry_ea))
        self.callback(DecompilationEvent.STARTED)
        # self.manager.start_profiling()
        # self.manager.instruction_optimizer.reset_rule_usage_statistic()
        # self.manager.block_optimizer.reset_rule_usage_statistic()
        return 0

    # def maturity(self, cfunc: "cfunc_t", new_maturity: int) -> int:
    #     """Ctree maturity level is being changed."""
    #     # main_logger.info(
    #     #     "Maturity changed for %s @ %s to %s (ctree maturity: %d)",
    #     #     cfunc.print_dcl(),
    #     #     hex(cfunc.entry_ea),
    #     #     maturity_to_string(cfunc.mba.maturity),
    #     #     new_maturity,
    #     # )
    #     return 0

    def glbopt(self, mba: ida_hexrays.mbl_array_t) -> "int":
        main_logger.info("glbopt finished for function at %s", hex(mba.entry_ea))
        main_logger.reset_maturity()
        return 0

    def structural(self, ct: "control_graph_t") -> int:  # type: ignore
        """Structural analysis has been finished.

        @param ct: (control_graph_t *)"""
        main_logger.info("Structural analysis has been finished")
        self.callback(DecompilationEvent.FINISHED)
        return 0

    def func_printed(self, cfunc: "cfunc_t") -> int:
        """Function text has been generated. Plugins may modify the text in cfunc_t::sv. However, it is too late to modify the ctree or microcode. The text uses regular color codes (see lines.hpp) COLOR_ADDR is used to store pointers to ctree items.

        @param cfunc: (cfunc_t *)"""
        main_logger.info("Function text has been generated")
        return 0
