"""Shared fixtures/helpers for hexrays runtime tests.

TODO:
- This helper is currently only used by goto-chain-removal runtime tests and
  could be inlined there (or this file deleted) if no other runtime tests use it.
- Longer-term, replace this synthetic in-memory backend with tests that run
  against a real IDA database/microcode context.
"""

from __future__ import annotations

from d810.transforms.graph_modification import GraphModification
from d810.ir.flowgraph import BlockSnapshot, FlowGraph
from d810.transforms.cfg_transaction import PatchPlanExecutionResult
from d810.transforms.plan import LoweringInput, PatchPlan, ensure_patch_plan
from tests.typed_patch_authority import graph_modifications


class InMemoryBackend:
    """Mock backend operating on synthetic FlowGraph for pass tests."""

    def __init__(self, blocks: dict[int, BlockSnapshot] | None = None):
        self.blocks = blocks or {}
        self.applied_modifications: list[GraphModification] = []
        self.applied_patch_plans: list[PatchPlan] = []
        self.lift_count = 0

    @property
    def name(self) -> str:
        return "in_memory"

    def lift(self, state: dict[int, BlockSnapshot] | None = None) -> FlowGraph:
        self.lift_count += 1
        blocks = state if state is not None else self.blocks
        if not blocks:
            return FlowGraph(blocks={}, entry_serial=0, func_ea=0)
        entry_serial = min(blocks.keys())
        return FlowGraph(
            blocks=blocks,
            entry_serial=entry_serial,
            func_ea=blocks[entry_serial].start_ea,
        )

    def lower(
        self,
        lowering_input: LoweringInput,
        state: dict[int, BlockSnapshot] | None = None,
        *,
        mutation_gateway: object,
    ) -> int:
        patch_plan = ensure_patch_plan(lowering_input)
        self.applied_patch_plans.append(patch_plan)
        modifications = graph_modifications(patch_plan)
        self.applied_modifications.extend(modifications)
        return len(modifications)

    def verify(self, state: dict[int, BlockSnapshot] | None = None) -> bool:
        return True

    def execute_patch_plan(
        self,
        plan: PatchPlan,
        state: dict[int, BlockSnapshot] | None = None,
        *,
        mutation_gateway: object,
        pre_cfg: FlowGraph,
    ) -> PatchPlanExecutionResult:
        count = self.lower(plan, state, mutation_gateway=mutation_gateway)
        if count <= 0 or not self.verify(state):
            return PatchPlanExecutionResult(applied_count=0, graph=pre_cfg)
        return PatchPlanExecutionResult(
            applied_count=count,
            graph=self.lift(state),
        )


__all__ = ["InMemoryBackend"]
