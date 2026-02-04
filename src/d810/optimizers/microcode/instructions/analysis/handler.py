import abc

import ida_hexrays

from d810.core import getLogger
from d810.hexrays.hexrays_formatters import format_minsn_t
from d810.optimizers.microcode.instructions.handler import (
    InstructionOptimizationRule,
    InstructionOptimizer,
)

optimizer_logger = getLogger("D810.optimizer")


class InstructionAnalysisRule(InstructionOptimizationRule):
    @abc.abstractmethod
    def analyze_instruction(self, blk: ida_hexrays.mblock_t, ins: ida_hexrays.minsn_t):
        """Analyze the instruction and return a replacement instruction if the rule matches, otherwise None."""
        ...

    @abc.abstractmethod
    def set_maturity(self, maturity: int): ...


class InstructionAnalyzer(InstructionOptimizer):
    RULE_CLASSES = [InstructionAnalysisRule]

    def set_maturity(self, maturity: int):
        self.cur_maturity = maturity
        for rule in self.rules:
            rule.set_maturity(self.cur_maturity)

    def analyze(self, blk: ida_hexrays.mblock_t, ins: ida_hexrays.minsn_t):
        if blk is not None:
            self.cur_maturity = blk.mba.maturity

        if self.cur_maturity not in self.maturities:
            return None

        for rule in self.rules:
            try:
                rule.analyze_instruction(blk, ins)
            except RuntimeError:
                optimizer_logger.error(
                    "error during rule {0} for instruction {1}".format(
                        rule, format_minsn_t(ins)
                    )
                )

    @property
    def name(self):
        if self.NAME is not None:
            return self.NAME
        return self.__class__.__name__
