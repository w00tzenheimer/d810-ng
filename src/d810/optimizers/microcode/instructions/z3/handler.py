import abc
import typing

import ida_hexrays

from d810.expr.ast import AstNode, AstNodeProtocol
from d810.optimizers.microcode.instructions.handler import (
    GenericPatternRule,
    InstructionOptimizer,
)


class Z3Rule(GenericPatternRule):
    """Base class for Z3-based optimization rules.

    Z3 rules can prove properties about expressions (e.g., always zero, always equal)
    using Z3 theorem proving. They have access to the current block and instruction
    context for backward tracking of register/stack variable definitions.
    """

    def __init__(self):
        super().__init__()
        # Context for backward tracking (set during check_and_replace)
        self._current_blk: ida_hexrays.mblock_t | None = None
        self._current_ins: ida_hexrays.minsn_t | None = None

    @property
    @abc.abstractmethod
    def PATTERN(self) -> AstNode:
        """Return the pattern to match."""

    @property
    @abc.abstractmethod
    def REPLACEMENT_PATTERN(self) -> AstNode:
        """Return the replacement pattern."""

    @typing.override
    def check_and_replace(
        self, blk: ida_hexrays.mblock_t, instruction: ida_hexrays.minsn_t
    ) -> ida_hexrays.minsn_t | None:
        """Override to store context for backward tracking."""
        # Store context so check_candidate can access blk/ins for MopTracker
        self._current_blk = blk
        self._current_ins = instruction
        try:
            return super().check_and_replace(blk, instruction)
        finally:
            # Clear context after use
            self._current_blk = None
            self._current_ins = None


class Z3Optimizer(InstructionOptimizer):
    RULE_CLASSES = [Z3Rule]

    def __init__(self, maturities, stats, log_dir=None):
        super().__init__(maturities, stats, log_dir)
        self._allowed_root_opcodes: set[int] = set()
        # Track if any rule has no PATTERN (pattern-less rules match any opcode)
        self._has_patternless_rule: bool = False

    def add_rule(self, rule: Z3Rule) -> bool:  # type: ignore[override]
        ok = super().add_rule(rule)
        if not ok:
            return False
        try:
            pat = rule.PATTERN
            if pat is None:
                # Rule has no PATTERN - it uses custom check_and_replace logic
                # and can match any opcode, so disable the pre-filter entirely
                # by clearing _allowed_root_opcodes (also checked by base class)
                self._has_patternless_rule = True
                self._allowed_root_opcodes.clear()
            # Use Protocol for hot-reload safety
            elif isinstance(pat, AstNodeProtocol) and pat.opcode is not None:
                # Only add to filter if we haven't disabled it
                if not self._has_patternless_rule:
                    self._allowed_root_opcodes.add(int(pat.opcode))
        except Exception:
            pass
        return True

    def get_optimized_instruction(self, blk: ida_hexrays.mblock_t, ins: ida_hexrays.minsn_t):  # type: ignore[override]
        # The opcode pre-filter is now handled by clearing _allowed_root_opcodes
        # when a patternless rule is added, which also disables the base class filter.
        return super().get_optimized_instruction(blk, ins)
