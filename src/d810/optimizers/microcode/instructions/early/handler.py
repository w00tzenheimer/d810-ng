from d810.optimizers.microcode.instructions.handler import (
    GenericPatternRule,
    InstructionOptimizer,
)


class EarlyRule(GenericPatternRule):
    pass


class EarlyOptimizer(InstructionOptimizer):
    RULE_CLASSES = [EarlyRule]
