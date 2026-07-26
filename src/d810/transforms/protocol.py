"""Portable runtime port for lifting and executing typed PatchPlans."""

from __future__ import annotations

from d810.core.typing import Any, Protocol, runtime_checkable
from d810.ir.flowgraph import FlowGraph
from d810.transforms.cfg_transaction import PatchPlanExecutionResult
from d810.transforms.plan import PatchPlan


@runtime_checkable
class PatchPlanRuntime(Protocol):
    """Lift immutable snapshots and execute plans through one owned gateway."""

    @property
    def name(self) -> str: ...

    def lift(self, state: Any) -> FlowGraph: ...

    def execute_patch_plan(
        self,
        plan: PatchPlan,
        state: Any,
        *,
        mutation_gateway: object,
        pre_cfg: FlowGraph,
    ) -> PatchPlanExecutionResult: ...


__all__ = ["PatchPlanRuntime"]
