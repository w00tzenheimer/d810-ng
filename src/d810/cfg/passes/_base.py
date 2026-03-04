"""Abstract base class for CFG transformation passes.

A CFGPass analyzes a PortableCFG and returns a list of GraphModification
intents describing desired changes. Passes are backend-agnostic and operate
only on the portable IR.

Example:
    >>> class RemoveDeadBlocks(CFGPass):
    ...     name = "remove_dead_blocks"
    ...     tags = frozenset({"optimization", "cleanup"})
    ...
    ...     def transform(self, cfg: PortableCFG) -> list[GraphModification]:
    ...         # Analyze cfg, find dead blocks, return removal intents
    ...         return [RemoveBlock(serial=5)]
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from d810.core.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from d810.cfg.flowgraph import PortableCFG
    from d810.cfg.graph_modification import GraphModification


class CFGPass(ABC):
    """Abstract base class for CFG transformation passes.

    A CFGPass analyzes a PortableCFG and returns a list of
    GraphModification intents describing desired changes.

    Subclasses must define:
        - `name` (str): Unique identifier for the pass
        - `transform(cfg)`: Main transformation logic

    Optionally override:
        - `tags` (frozenset[str]): Pass categories (e.g., "optimization")
        - `is_applicable(cfg)`: Pre-check if pass should run

    Attributes:
        name: Unique identifier for the pass (must be defined in subclass).
        tags: Frozen set of category tags (default: empty frozenset).

    Example:
        >>> class NoOpPass(CFGPass):
        ...     name = "noop"
        ...     def transform(self, cfg: PortableCFG) -> list[GraphModification]:
        ...         return []
    """

    name: str
    tags: frozenset[str] = frozenset()

    def __init_subclass__(cls, **kwargs):
        """Enforce that subclasses define 'name' class attribute."""
        super().__init_subclass__(**kwargs)
        if not hasattr(cls, 'name') or cls.name is NotImplemented:
            raise TypeError(f"{cls.__name__} must define 'name' class attribute")

    @abstractmethod
    def transform(self, cfg: "PortableCFG") -> list["GraphModification"]:
        """Analyze portable CFG, return modification intents.

        Args:
            cfg: Portable CFG snapshot to analyze.

        Returns:
            List of GraphModification intents describing desired changes.
            Empty list if no changes needed.
        """
        ...

    def is_applicable(self, cfg: "PortableCFG") -> bool:
        """Check if this pass should run on the given CFG.

        Default implementation always returns True. Override to add
        pre-conditions (e.g., skip if CFG has no blocks).

        Args:
            cfg: Portable CFG snapshot to check.

        Returns:
            True if pass should run, False to skip.
        """
        return True

    def __repr__(self) -> str:
        """String representation of the pass."""
        return f"{type(self).__name__}(name={self.name!r})"


__all__ = ["CFGPass"]
