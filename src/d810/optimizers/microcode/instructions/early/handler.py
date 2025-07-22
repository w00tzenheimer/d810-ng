import abc

from d810.optimizers.microcode.instructions.handler import (
    GenericPatternRule,
    InstructionOptimizer,
)


class EarlyRule(GenericPatternRule, abc.ABC):
    pass


class EarlyOptimizer(InstructionOptimizer):
    RULE_CLASSES = [EarlyRule]
