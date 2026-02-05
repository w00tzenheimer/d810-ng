"""Core abstractions for d810 optimization rules.

This module defines the fundamental interfaces and data structures used throughout
the d810 optimization framework. It promotes composition over inheritance by using
Protocol-based interfaces instead of deep inheritance hierarchies.
"""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass
from typing import Any, Dict, Protocol

import ida_hexrays


@dataclass(frozen=True)
class OptimizationContext:
    """A context object holding all necessary data for an optimization pass.

    This immutable context is passed to optimization rules, eliminating the need
    for rules to maintain mutable state. All information needed for optimization
    is explicitly provided.

    Attributes:
        mba: The microcode array being optimized.
        maturity: The current maturity level of the microcode.
        config: Configuration dictionary for optimization behavior.
        logger: Logger instance for the optimization pass.
        log_dir: Directory path for debug logs and artifacts.
    """
    mba: ida_hexrays.mba_t
    maturity: int
    config: Dict[str, Any]
    logger: logging.Logger
    log_dir: str


class OptimizationRule(Protocol):
    """A protocol defining the contract for any optimization rule.

    This protocol-based interface decouples rules from their execution engine,
    making it easy to test rules in isolation and compose different optimization
    strategies.

    Any class implementing this protocol can be used as an optimization rule,
    regardless of its inheritance hierarchy.
    """

    @property
    def name(self) -> str:
        """A unique identifier for this rule.

        Returns:
            A string uniquely identifying this optimization rule.
        """
        ...

    def apply(self, context: OptimizationContext, element: Any) -> int:
        """Applies the optimization to a program element.

        This method is the main entry point for rule execution. It receives
        an immutable context and a program element to optimize.

        Args:
            context: The current optimization context containing mba, maturity, etc.
            element: The program element to optimize. This could be:
                - mblock_t for flow-level optimizations
                - minsn_t for instruction-level optimizations
                - Any other program element the rule operates on

        Returns:
            The number of changes made by this rule. Return 0 if no changes were made.
            This allows the optimizer to track progress and decide when to stop iterating.
        """
        ...


class PatternMatchingRule(abc.ABC):
    """An abstract base class for rules that match and replace AST patterns.

    This class provides a common structure for pattern-based optimization rules.
    Subclasses define a pattern to match and a replacement pattern, along with
    optional validation logic.

    This approach separates the pattern definition (declarative) from the matching
    and replacement logic (imperative), improving maintainability.
    """

    @property
    @abc.abstractmethod
    def pattern(self) -> "AstNode":
        """The AST pattern to match against microcode instructions.

        Returns:
            An AstNode representing the pattern to search for.
        """
        ...

    @property
    @abc.abstractmethod
    def replacement(self) -> "AstNode":
        """The AST pattern to substitute when a match is found.

        Returns:
            An AstNode representing the replacement pattern.
        """
        ...

    @abc.abstractmethod
    def check_candidate(self, candidate: "AstNode") -> bool:
        """Performs rule-specific validation on a matched pattern.

        After the pattern is matched, this method can perform additional checks
        to ensure the transformation is valid and beneficial. For example, it might
        verify that certain constants have specific relationships.

        Args:
            candidate: The matched AST node that satisfies the pattern.

        Returns:
            True if the transformation should proceed, False otherwise.
        """
        ...

    def apply(self, context: OptimizationContext, ins: ida_hexrays.minsn_t) -> int:
        """Applies the pattern matching rule to a single instruction.

        This method implements the common pattern matching and replacement logic
        that all pattern-based rules share. Subclasses typically don't need to
        override this.

        Args:
            context: The optimization context.
            ins: The microcode instruction to potentially optimize.

        Returns:
            1 if the instruction was modified, 0 otherwise.
        """
        # This will be implemented as part of the pattern matching refactoring
        # For now, this is a placeholder showing the intended interface
        raise NotImplementedError("Pattern matching logic will be refactored")
