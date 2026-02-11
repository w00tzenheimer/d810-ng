import abc

from d810.optimizers.microcode.instructions.handler import (
    InstructionOptimizationRule,
    InstructionOptimizer,
)


class PeepholeSimplificationRule(InstructionOptimizationRule):

    CATEGORY = "Peephole Simplification"

    @abc.abstractmethod
    def check_and_replace(self, blk, ins):
        """Return a replacement instruction if the rule matches, otherwise None."""


class PeepholeOptimizer(InstructionOptimizer):
    RULE_CLASSES = [PeepholeSimplificationRule]
