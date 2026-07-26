"""Shared pytest fixtures for hexrays unit tests.

Provides InMemoryBackend as a module-level helper so it can be imported
by multiple test modules without duplication.
"""

from __future__ import annotations

from d810.ir.flowgraph import BlockSnapshot, FlowGraph
from d810.transforms.cfg_transaction import PatchPlanExecutionResult
from d810.transforms.plan import PatchPlan, PatchStep


class InMemoryBackend:
    """Mock backend operating on synthetic FlowGraph.

    Implements the PatchPlan runtime port without an IDA dependency.
    Used for testing FlowGraphTransform instances and PassPipeline in isolation.
    """

    def __init__(self, blocks: dict[int, BlockSnapshot] | None = None):
        """Initialize with optional block dict.

        Args:
            blocks: Dict mapping serial to BlockSnapshot (default: empty).
        """
        self.blocks = blocks or {}
        self.applied_steps: list[PatchStep] = []
        self.applied_patch_plans: list[PatchPlan] = []
        self.lift_count = 0

    @property
    def name(self) -> str:
        """Backend identifier."""
        return "in_memory"

    def lift(self, state: dict[int, BlockSnapshot] | None = None) -> FlowGraph:
        """Lift blocks dict to FlowGraph.

        Args:
            state: Optional blocks dict (uses self.blocks if None).

        Returns:
            FlowGraph with blocks from state or self.blocks.
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
            func_ea=blocks[entry_serial].start_ea,
        )

    def lower(
        self,
        lowering_input: PatchPlan,
        state: dict[int, BlockSnapshot] | None = None,
        *,
        mutation_gateway: object,
    ) -> int:
        """Record modifications and return count.

        Args:
            lowering_input: Finalized PatchPlan authority.
            state: Optional state (ignored, uses self.applied_steps).

        Returns:
            Number of graph modifications represented by the plan.
        """
        if not isinstance(lowering_input, PatchPlan):
            raise TypeError("InMemoryBackend.lower requires PatchPlan")
        self.applied_patch_plans.append(lowering_input)
        self.applied_steps.extend(lowering_input.steps)
        return len(lowering_input.steps)

    def verify(self, state: dict[int, BlockSnapshot] | None = None) -> bool:
        """Always returns True (no validation logic in mock).

        Args:
            state: Optional state (ignored).

        Returns:
            True (always valid).
        """
        return True

    def execute_patch_plan(
        self,
        plan: PatchPlan,
        state: dict[int, BlockSnapshot] | None = None,
        *,
        mutation_gateway: object,
        pre_cfg: FlowGraph,
    ) -> PatchPlanExecutionResult:
        """Test runtime mirroring commit-or-zero pipeline semantics."""
        count = self.lower(plan, state, mutation_gateway=mutation_gateway)
        if count <= 0 or not self.verify(state):
            return PatchPlanExecutionResult(applied_count=0, graph=pre_cfg)
        return PatchPlanExecutionResult(
            applied_count=count,
            graph=self.lift(state),
        )


__all__ = ["InMemoryBackend"]
