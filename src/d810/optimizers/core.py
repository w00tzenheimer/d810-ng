"""Core abstractions for d810 optimization rules.

This module defines the fundamental interfaces and data structures used throughout
the d810 optimization framework. It promotes composition over inheritance by using
Protocol-based interfaces instead of deep inheritance hierarchies.

Slice 7 (llvm-lisa-restructure) note: this module previously imported
``ida_hexrays`` solely to type-annotate ``OptimizationContext.mba`` as
``ida_hexrays.mba_t`` and ``PatternMatchingRule.apply``'s ``ins``
parameter as ``ida_hexrays.minsn_t``.  Audit found that
``OptimizationContext`` is never instantiated anywhere in the codebase
(zero ``OptimizationContext(...)`` call sites) and ``PatternMatchingRule``
is abstract -- both annotations are purely Protocol-contract surface,
not runtime-consumed types.  The annotations have been widened to
``object`` / ``Any`` so this module is IDA-free at import time and the
``OptimizationRule`` Protocol can be moved to a portable home (e.g.
``d810.transforms/protocols.py``) in a sibling slice without dragging
``import ida_hexrays`` into the portable layer.

Concrete rule implementations (e.g. Hex-Rays microcode flow / instruction
rules) continue to accept ``mba_t`` / ``minsn_t`` in their own
narrower-typed methods; Protocol satisfaction is structural so the
widening here does not constrain those implementations.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from d810.core.logging import D810Logger
from d810.core.typing import Any, Dict, Protocol


@dataclass(frozen=True)
class OptimizationContext:
    """A context object holding all necessary data for an optimization pass.

    This immutable context is passed to optimization rules, eliminating the need
    for rules to maintain mutable state. All information needed for optimization
    is explicitly provided.

    Attributes:
        mba: The microcode array being optimized.  Annotated as ``object``
            to keep the contract IDA-free; concrete callers pass an
            ``ida_hexrays.mba_t`` in the Hex-Rays integration path and
            an angr ``AILGraph`` / Ghidra graph in future backend paths.
        maturity: The current maturity level of the microcode.
        config: Configuration dictionary for optimization behavior.
        logger: Logger instance for the optimization pass.
        log_dir: Directory path for debug logs and artifacts.
    """
    mba: object
    maturity: int
    config: Dict[str, Any]
    logger: D810Logger
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

    def apply(self, context: OptimizationContext, ins: Any) -> int:
        """Applies the pattern matching rule to a single instruction.

        This method implements the common pattern matching and replacement logic
        that all pattern-based rules share. Subclasses typically don't need to
        override this.

        Args:
            context: The optimization context.
            ins: The microcode instruction to potentially optimize.
                Annotated as ``Any`` to keep the contract IDA-free;
                concrete Hex-Rays subclasses narrow this to
                ``ida_hexrays.minsn_t`` in their own override signatures.

        Returns:
            1 if the instruction was modified, 0 otherwise.
        """
        # This will be implemented as part of the pattern matching refactoring
        # For now, this is a placeholder showing the intended interface
        raise NotImplementedError("Pattern matching logic will be refactored")
