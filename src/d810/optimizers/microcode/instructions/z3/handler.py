import abc

from d810.expr.ast import AstNode
from d810.optimizers.microcode.instructions.handler import (
    GenericPatternRule,
    InstructionOptimizer,
)


class Z3Rule(GenericPatternRule):

    @property
    @abc.abstractmethod
    def PATTERN(self) -> AstNode:
        """Return the pattern to match."""

    @property
    @abc.abstractmethod
    def REPLACEMENT_PATTERN(self) -> AstNode:
        """Return the replacement pattern."""


class Z3Optimizer(InstructionOptimizer):
    RULE_CLASSES = [Z3Rule]
