"""Hex-Rays runtime adapter for portable pass-pipeline specs."""
from __future__ import annotations

from d810.core.typing import Callable
from d810.passes.pass_pipeline_factory import (
    PASS_ID_GOTO_CHAIN_REMOVAL,
    PASS_ID_LOOP_CARRIER_BACKEDGE_REFRESH,
    PASS_ID_SIMPLIFY_IDENTICAL_BRANCH,
    PassPipelineSpec,
)


def _build_transform(pass_id: str, fact_view_provider: Callable | None):
    if pass_id == PASS_ID_SIMPLIFY_IDENTICAL_BRANCH:
        from d810.transforms.simplify_identical_branch import (
            SimplifyIdenticalBranchPass,
        )

        return SimplifyIdenticalBranchPass()
    if pass_id == PASS_ID_GOTO_CHAIN_REMOVAL:
        from d810.hexrays.mutation.transform.goto_chain_removal import (
            GotoChainRemovalPass,
        )

        return GotoChainRemovalPass()
    if pass_id == PASS_ID_LOOP_CARRIER_BACKEDGE_REFRESH:
        from d810.transforms.loop_carrier_backedge_refresh import (
            LoopCarrierBackedgeRefreshPass,
        )

        return LoopCarrierBackedgeRefreshPass(
            fact_view_provider=fact_view_provider,
        )
    raise ValueError(f"Unknown pass pipeline pass id: {pass_id}")


def build_hexrays_flowgraph_pipeline(
    spec: PassPipelineSpec,
    *,
    fact_view_provider: Callable | None = None,
):
    """Lower a portable pass spec to the current Hex-Rays FlowGraph pipeline."""
    from d810.hexrays.mutation.ir_translator import IDAIRTranslator
    from d810.passes.pipeline import FlowGraphTransformPipeline

    passes = [
        _build_transform(pass_id, fact_view_provider)
        for pass_id in spec.pass_ids
    ]
    return FlowGraphTransformPipeline(IDAIRTranslator(), passes)
