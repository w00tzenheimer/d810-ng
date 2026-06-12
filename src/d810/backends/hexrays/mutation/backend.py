"""Hex-Rays mutation backend — the unflatten ``MutationBackend.apply`` boundary.

The ONLY place a unflatten ``PatchPlan`` becomes live ``mba`` edits. ``apply`` lowers the plan through the
existing ``IDAIRTranslator`` (PatchPlan -> DeferredGraphModifier queue) and then RE-LIFTS the
post-apply ``mba`` to a fresh ``FlowGraph`` snapshot — the new snapshot identity is the sound
invalidation epoch (Hex-Rays re-runs its own optimizer during/after apply, so the re-lift captures
the vendor's re-optimization, per unflatten / the LLVM AnalysisManager invalidation model).

Structurally satisfies the ``MutationBackend`` protocol (``passes.pass_pipeline``) without importing
it (upward edge); duck-typing suffices.
"""
from __future__ import annotations

from d810.analyses.control_flow.graph_checks import (
    check_entry_reachability_not_collapsed,
    check_terminal_reachability_preserved,
)
from d810.analyses.control_flow.edit_simulation import simulate_edits
from d810.core.logging import getLogger
from d810.core.typing import TYPE_CHECKING
from d810.ir.flowgraph import FlowGraph
from d810.transforms.plan import PatchPlan
from d810.transforms.edit_simulator import patch_plan_to_simulated_edits


logger = getLogger(__name__)

if TYPE_CHECKING:
    from d810.hexrays.mutation.ir_translator import IDAIRTranslator


class HexRaysMutationBackend:
    """Apply unflatten PatchPlans to a live ``mba`` and return the re-lifted FlowGraph."""

    def __init__(self, translator: "IDAIRTranslator | None" = None) -> None:
        if translator is None:
            from d810.hexrays.mutation.ir_translator import IDAIRTranslator

            translator = IDAIRTranslator()
        self._translator = translator

    def capabilities(self) -> frozenset[str]:
        # "emulation" advertises the concolic block-emulator the unflatten entry registers as
        # the EmulationCapability (llr-11du). ADDITIVE: no standard pass requires it, so
        # advertising it is behaviour-neutral; only the INDIRECT pipeline (slice 2) reads
        # it, and there is no live indirect detector yet.
        return frozenset({"live_mba", "emulation"})

    def apply(
        self,
        rewrite_plan: PatchPlan,
        live_source: object,
        safety_policy: object = None,
    ) -> FlowGraph:
        """Lower the plan to live edits, then re-lift to a fresh snapshot (the new epoch)."""
        pre_cfg = self._translator.lift(live_source)
        simulation = simulate_edits(
            pre_cfg.as_adjacency_dict(),
            patch_plan_to_simulated_edits(rewrite_plan),
        )
        terminal_reachability = check_terminal_reachability_preserved(
            pre_cfg,
            post_adj=simulation.adj,
        )
        entry_reachability = check_entry_reachability_not_collapsed(
            pre_cfg,
            post_adj=simulation.adj,
        )
        if not terminal_reachability.passed or not entry_reachability.passed:
            logger.warning(
                "Rejecting Hex-Rays mutation plan: terminal_ok=%s entry_ok=%s "
                "pre_reach=%d post_reach=%d pre_terminals=%s post_terminals=%s "
                "entry_retained=%.2f reason=%s/%s steps=%d",
                terminal_reachability.passed,
                entry_reachability.passed,
                terminal_reachability.pre_reachable_count,
                terminal_reachability.post_reachable_count,
                sorted(terminal_reachability.pre_reachable_terminals),
                sorted(terminal_reachability.post_reachable_terminals),
                entry_reachability.retained_ratio,
                terminal_reachability.reason,
                entry_reachability.reason,
                len(rewrite_plan.steps),
            )
            return pre_cfg

        self._translator.lower(rewrite_plan, live_source)
        return self._translator.lift(live_source)
