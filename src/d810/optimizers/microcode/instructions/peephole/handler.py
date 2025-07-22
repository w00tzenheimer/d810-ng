import abc

from d810.optimizers.microcode.instructions.handler import (
    InstructionOptimizationRule,
    InstructionOptimizer,
)


class PeepholeSimplificationRule(InstructionOptimizationRule, abc.ABC):
    pass


class PeepholeOptimizer(InstructionOptimizer):
    RULE_CLASSES = [PeepholeSimplificationRule]
