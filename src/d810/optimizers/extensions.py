"""Context-aware DSL extensions for advanced pattern matching rules.

This module provides declarative helpers for rules that need to inspect or modify
the instruction context (destination registers, operand sizes, etc.) without
requiring direct manipulation of IDA's internal C++ API.

The goal is to make complex rules accessible to users who understand the mathematics
but not IDA's internals.

NOTE: This module requires IDA Pro and should only be loaded in system tests,
not unit tests. All IDA imports are at module level.

Example usage:
    ```python
    from d810.mba.dsl import Var, Const
    from d810.mba.rules import VerifiableRule
    from d810.optimizers.extensions import when, context

    class FixHighMov(VerifiableRule):
        PATTERN = c0
        REPLACEMENT = (full_reg & 0xFFFF) | (c0 << 16)

        CONSTRAINTS = [when.dst.is_high_half]
        CONTEXT_VARS = {"full_reg": context.dst.parent_register}
        UPDATE_DESTINATION = "full_reg"
    ```
"""

from typing import Any, Dict, Optional

import ida_hexrays

from d810.expr.ast import AstLeaf
from d810.hexrays.hexrays_formatters import format_mop_t


class DestinationHelpers:
    """Helpers for inspecting the destination operand of an instruction.

    These are used in CONSTRAINTS to declaratively check properties of the
    instruction's destination without writing custom check_candidate() methods.
    """

    @staticmethod
    def is_high_half(ctx: Dict[str, Any]) -> bool:
        """Constraint: Check if destination is the high 16-bits of a 32-bit register.

        In IDA, high-half registers are denoted with "^2" suffix (e.g., r6^2).
        This pattern appears in some architectures where you can separately
        address the high and low words of a register.

        Args:
            ctx: Context dictionary containing "_candidate" key with matched instruction

        Returns:
            True if destination is a 2-byte register with "^2" in its name
        """
        candidate = ctx.get("_candidate")
        if not candidate:
            return False

        dst = candidate.dst_mop

        # Must be a register
        if dst.t != ida_hexrays.mop_r:
            return False

        # Must be 2 bytes (high word of 32-bit register)
        if dst.size != 2:
            return False

        # Check name convention (IDA uses "^2" for high words)
        name = format_mop_t(dst)
        return name is not None and "^2" in name

    @staticmethod
    def is_register(ctx: Dict[str, Any]) -> bool:
        """Constraint: Check if destination is a register.

        Args:
            ctx: Context dictionary containing "_candidate" key

        Returns:
            True if destination is a register operand
        """
        candidate = ctx.get("_candidate")
        if not candidate:
            return False

        return candidate.dst_mop.t == ida_hexrays.mop_r

    @staticmethod
    def is_memory(ctx: Dict[str, Any]) -> bool:
        """Constraint: Check if destination is a memory location.

        Args:
            ctx: Context dictionary containing "_candidate" key

        Returns:
            True if destination is a memory operand
        """
        candidate = ctx.get("_candidate")
        if not candidate:
            return False

        # Memory can be: address (mop_a), stack var (mop_S), or global var (mop_v)
        return candidate.dst_mop.t in (ida_hexrays.mop_a, ida_hexrays.mop_S, ida_hexrays.mop_v)


class ContextProviders:
    """Providers for extracting values from the instruction context.

    These are used in CONTEXT_VARS to declaratively bind variables from the
    instruction context (e.g., parent register, operand sizes) without writing
    custom check_candidate() methods.
    """

    @staticmethod
    def parent_register(ctx: Dict[str, Any]) -> Optional[AstLeaf]:
        """Provider: Returns the 32-bit parent register of a high-half destination.

        For high-half registers like r6^2, this returns the full 32-bit register r6.
        The relationship is: r6^2 has register index (r6 + 2).

        Args:
            ctx: Context dictionary containing "_candidate" key

        Returns:
            AstLeaf representing the parent register, or None if not applicable
        """
        candidate = ctx.get("_candidate")
        if not candidate:
            return None

        dst = candidate.dst_mop

        # Must be a register
        if dst.t != ida_hexrays.mop_r:
            return None

        # IDA Logic: rX^2 has index (rX + 2)
        # So to get rX from rX^2, we subtract 2
        base_reg_idx = dst.r - 2

        # Create a new mop_t for the full 32-bit register
        new_mop = ida_hexrays.mop_t()
        new_mop.make_reg(base_reg_idx, 4)  # 4 bytes = 32-bit

        # Create an AstLeaf and attach the mop
        leaf = AstLeaf("parent_reg")
        leaf.mop = new_mop
        return leaf

    @staticmethod
    def operand_size(ctx: Dict[str, Any]) -> Optional[int]:
        """Provider: Returns the size in bytes of the destination operand.

        Args:
            ctx: Context dictionary containing "_candidate" key

        Returns:
            Size in bytes, or None if not available
        """
        candidate = ctx.get("_candidate")
        if not candidate:
            return None

        return candidate.dst_mop.size


class ContextBuilder:
    """Builder for context providers (accessible via `context.dst.*`)."""

    dst = ContextProviders()


class WhenBuilder:
    """Builder for destination constraints (accessible via `when.dst.*`)."""

    dst = DestinationHelpers()


# Singleton instances for clean syntax
context = ContextBuilder()
when = WhenBuilder()


# Export public API
__all__ = [
    'context',
    'when',
    'ContextProviders',
    'DestinationHelpers',
    'ContextBuilder',
    'WhenBuilder',
]
