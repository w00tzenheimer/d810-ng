"""Shared pytest fixtures for hexrays unit tests.

Provides InMemoryBackend as a module-level helper so it can be imported
by multiple test modules without duplication.
"""
from __future__ import annotations

from d810.cfg.graph_modification import GraphModification
from d810.cfg.flowgraph import BlockSnapshot, FlowGraph


class InMemoryBackend:
    """Mock backend operating on synthetic PortableCFG.

    Implements CFGBackend protocol without IDA dependency.
    Used for testing CFGPass instances and PassPipeline in isolation.
    """

    def __init__(self, blocks: dict[int, BlockSnapshot] | None = None):
        """Initialize with optional block dict.

        Args:
            blocks: Dict mapping serial to BlockSnapshot (default: empty).
        """
        self.blocks = blocks or {}
        self.applied_modifications: list[GraphModification] = []
        self.lift_count = 0

    @property
    def name(self) -> str:
        """Backend identifier."""
        return "in_memory"

    def lift(self, state: dict[int, BlockSnapshot] | None = None) -> FlowGraph:
        """Lift blocks dict to PortableCFG.

        Args:
            state: Optional blocks dict (uses self.blocks if None).

        Returns:
            PortableCFG with blocks from state or self.blocks.
        """
        self.lift_count += 1
        blocks = state if state is not None else self.blocks
        # If empty, return minimal CFG with entry_serial=0
        if not blocks:
            return FlowGraph(blocks={}, entry_serial=0, func_ea=0)
        # Otherwise use first block as entry
        entry_serial = min(blocks.keys())
        return FlowGraph(
            blocks=blocks,
            entry_serial=entry_serial,
            func_ea=blocks[entry_serial].start_ea
        )

    def lower(
        self,
        modifications: list[GraphModification],
        state: dict[int, BlockSnapshot] | None = None
    ) -> int:
        """Record modifications and return count.

        Args:
            modifications: List of modification intents.
            state: Optional state (ignored, uses self.applied_modifications).

        Returns:
            Number of modifications (always len(modifications)).
        """
        self.applied_modifications.extend(modifications)
        return len(modifications)

    def verify(self, state: dict[int, BlockSnapshot] | None = None) -> bool:
        """Always returns True (no validation logic in mock).

        Args:
            state: Optional state (ignored).

        Returns:
            True (always valid).
        """
        return True


__all__ = ["InMemoryBackend"]
