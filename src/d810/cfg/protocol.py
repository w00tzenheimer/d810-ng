"""Protocol for CFG backends that can lift, lower, and verify modifications.

CFGBackend defines the interface between backend-agnostic passes (operating
on FlowGraph) and concrete backend implementations (IDA mba_t, in-memory
graphs, etc.).

Example:
    >>> backend = HexRaysBackend()
    >>> cfg = backend.lift(mba)
    >>> modifications = some_pass.transform(cfg)
    >>> count = backend.lower(modifications, mba)
    >>> backend.verify(mba)
    True
"""
from __future__ import annotations

from d810.core.typing import Any, Protocol, runtime_checkable

from d810.cfg.flowgraph import FlowGraph
from d810.cfg.graph_modification import GraphModification


@runtime_checkable
class IRTranslator(Protocol):
    """Protocol for intermediate representation translators that can lift,
    lower, and verify modifications.

    An IRTranslator provides three core operations:
        - lift: Convert ir-specific state to FlowGraph
        - lower: Apply GraphModifications to ir state
        - verify: Check ir state consistency after modifications

    IRTranslators are responsible for:
        - Translating IR state to/from portable IR
        - Applying modification intents to mutable IR state
        - Validating state consistency (e.g., no dangling edges)

    The Protocol is runtime_checkable, so you can use isinstance() to verify
    conformance without explicit inheritance.

    Example:
        >>> class InMemoryBackend:
        ...     name = "in_memory"
        ...     def lift(self, state): ...
        ...     def lower(self, modifications, state): ...
        ...     def verify(self, state): ...
        >>> backend = InMemoryBackend()
        >>> isinstance(backend, IRTranslator)
        True
    """

    @property
    def name(self) -> str:
        """Unique identifier for the backend (e.g., 'hexrays', 'in_memory')."""
        ...

    def lift(self, state: Any) -> FlowGraph:
        """Convert backend-specific state to FlowGraph.

        Args:
            state: Backend-specific mutable state (e.g., mba_t, networkx graph).

        Returns:
            FlowGraph snapshot capturing current state topology.

        Example:
            >>> cfg = backend.lift(mba)
            >>> cfg.num_blocks
            5
        """
        ...

    def lower(self, modifications: list[GraphModification], state: Any) -> int:
        """Apply GraphModifications to backend state.

        Mutates the backend state according to the modification intents.
        Returns the count of successfully applied modifications.

        Args:
            modifications: List of modification intents to apply.
            state: Backend-specific mutable state to modify.

        Returns:
            Number of modifications successfully applied (0 to len(modifications)).

        Example:
            >>> mods = [ConvertToGoto(serial=3), RemoveBlock(serial=5)]
            >>> count = backend.lower(mods, mba)
            >>> count
            2
        """
        ...

    def verify(self, state: Any) -> bool:
        """Check backend state consistency after modifications.

        Validates invariants like:
            - No dangling edges (successors/predecessors point to valid blocks)
            - Entry block exists
            - Block topology matches block_type (e.g., 2WAY has exactly 2 successors)

        Args:
            state: Backend-specific state to verify.

        Returns:
            True if state is consistent, False if corruption detected.

        Example:
            >>> backend.verify(mba)
            True
        """
        ...


__all__ = ["IRTranslator"]
