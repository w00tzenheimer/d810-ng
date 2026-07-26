"""PassPipeline orchestrator for running FlowGraphTransform transforms through a CFGBackend.

The pipeline lifts backend state to FlowGraph, runs each pass's transform,
compiles the resulting modifications to PatchPlan, and delegates the complete
transaction to one runtime port.
"""

from __future__ import annotations

from d810.core.logging import getLogger
from d810.core.typing import Any

from d810.transforms.cfg_transaction import PatchPlanExecutionResult
from d810.transforms.plan import compile_patch_plan
from d810.transforms._base import FlowGraphTransform
from d810.transforms.protocol import PatchPlanRuntime

logger = getLogger(__name__, default_level=0)  # NOTSET: inherit from parent


class FlowGraphTransformPipeline:
    """Run a sequence of FlowGraphTransform transforms through a CFGBackend.

    Usage:
        pipeline = PassPipeline(backend, [pass1, pass2, pass3])
        total_changes = pipeline.run(
            backend_state,
            mutation_gateway=mutation_gateway,
        )
    """

    def __init__(
        self,
        backend: PatchPlanRuntime,
        passes: list[FlowGraphTransform],
    ) -> None:
        if not isinstance(backend, PatchPlanRuntime):
            raise TypeError("FlowGraphTransformPipeline requires PatchPlanRuntime")
        self.backend = backend
        self.passes = list(passes)  # defensive copy

    def run(self, backend_state: Any, *, mutation_gateway: object) -> int:
        """Execute all transform against backend_state.

        Returns total count of applied modifications across all transform.
        """
        total = 0
        cfg = self.backend.lift(backend_state)

        for pass_ in self.passes:
            if not pass_.is_applicable(cfg):
                logger.debug("Pass %s not applicable, skipping", pass_.name)
                continue

            mods = pass_.transform(cfg)
            if not mods:
                logger.debug("Pass %s produced no modifications", pass_.name)
                continue

            identity_index = getattr(mutation_gateway, "identity_index", None)
            if identity_index is None:
                raise TypeError(
                    "FlowGraph transform compilation requires exact block authority"
                )
            patch_plan = compile_patch_plan(
                mods,
                cfg,
                snapshot_id=identity_index.snapshot_id,
                source_generation=identity_index.generation,
                block_refs_by_serial=identity_index.plan_refs_by_serial(),
            )
            execution = self.backend.execute_patch_plan(
                patch_plan,
                backend_state,
                mutation_gateway=mutation_gateway,
                pre_cfg=cfg,
            )
            if not isinstance(execution, PatchPlanExecutionResult):
                raise TypeError("PatchPlan runtime returned invalid execution authority")
            count = execution.applied_count
            if count <= 0:
                logger.debug(
                    "Pass %s: transaction committed no operations", pass_.name
                )
                continue

            cfg = execution.graph
            total += count
            logger.debug(
                "Pass %s applied %d modifications (total: %d)", pass_.name, count, total
            )

        return total

    def __repr__(self) -> str:
        pass_names = [p.name for p in self.passes]
        return f"PassPipeline(backend={self.backend.name!r}, transform={pass_names})"


__all__ = ["FlowGraphTransformPipeline"]
