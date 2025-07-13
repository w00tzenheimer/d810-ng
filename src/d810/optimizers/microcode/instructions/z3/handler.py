from d810.optimizers.microcode.instructions.handler import (
    GenericPatternRule,
    InstructionOptimizer,
)


class Z3Rule(GenericPatternRule):
    pass


class Z3Optimizer(InstructionOptimizer):
    RULE_CLASSES = [Z3Rule]
