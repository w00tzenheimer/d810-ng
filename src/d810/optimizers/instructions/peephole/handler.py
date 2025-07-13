from d810.optimizers.instructions.handler import (
    InstructionOptimizationRule,
    InstructionOptimizer,
)


class PeepholeSimplificationRule(InstructionOptimizationRule):
    pass


class PeepholeOptimizer(InstructionOptimizer):
    RULE_CLASSES = [PeepholeSimplificationRule]
