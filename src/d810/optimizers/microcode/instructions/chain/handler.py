import abc

from d810.optimizers.microcode.instructions.handler import (
    InstructionOptimizationRule,
    InstructionOptimizer,
)


class ChainSimplificationRule(InstructionOptimizationRule):

    @abc.abstractmethod
    def check_and_replace(self, blk, ins):
        """Return a replacement instruction if the rule matches, otherwise None."""


class ChainOptimizer(InstructionOptimizer):
    RULE_CLASSES = [ChainSimplificationRule]

    def __init__(self, maturities, stats, log_dir=None):
        super().__init__(maturities, stats, log_dir)
        # Only consider binary associative ops chains
        import ida_hexrays

        self._allowed_root_opcodes = {ida_hexrays.m_xor, ida_hexrays.m_and, ida_hexrays.m_or, ida_hexrays.m_add, ida_hexrays.m_sub}
