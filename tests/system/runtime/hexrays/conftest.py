"""Shared fixtures/helpers for hexrays runtime tests.

TODO:
- This helper is currently only used by goto-chain-removal runtime tests and
  could be inlined there (or this file deleted) if no other runtime tests use it.
- Longer-term, replace this synthetic in-memory backend with tests that run
  against a real IDA database/microcode context.
"""
from __future__ import annotations

from d810.cfg.graph_modification import GraphModification
from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.cfg.plan import LoweringInput, PatchPlan, ensure_patch_plan


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
    ) -> int:
        patch_plan = ensure_patch_plan(lowering_input)
        self.applied_patch_plans.append(patch_plan)
        modifications = patch_plan.as_graph_modifications()
        self.applied_modifications.extend(modifications)
        return len(modifications)

    def verify(self, state: dict[int, BlockSnapshot] | None = None) -> bool:
        return True


__all__ = ["InMemoryBackend"]
