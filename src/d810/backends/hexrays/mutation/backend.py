"""Hex-Rays mutation and semantic-fragment publication backend.

The ONLY place a unflatten ``PatchPlan`` becomes live ``mba`` edits. ``apply`` lowers the plan through the
existing ``IDAIRTranslator`` (PatchPlan -> DeferredGraphModifier queue) and then RE-LIFTS the
post-apply ``mba`` to a fresh ``FlowGraph`` snapshot — the new snapshot identity is the sound
invalidation epoch (Hex-Rays re-runs its own optimizer during/after apply, so the re-lift captures
the vendor's re-optimization, per unflatten / the LLVM AnalysisManager invalidation model).

``publish_fragment`` uses a fresh receipt-backed gateway transaction and
re-lifts only after semantic postvalidation commits. The class structurally
satisfies both portable backend protocols without importing either upward.
"""

from __future__ import annotations

from d810.analyses.control_flow.graph_checks import (
    check_entry_reachability_not_collapsed,
    check_terminal_reachability_preserved,
)
from d810.analyses.control_flow.edit_simulation import simulate_edits
from d810.core.logging import getLogger
from d810.core.typing import Callable, TYPE_CHECKING
from d810.ir.block_identity import CurrentMbaIdentityBindingSnapshot
from d810.ir.flowgraph import FlowGraph
from d810.transforms.fragment_plan import FragmentPlan
from d810.transforms.plan import PatchPlan
from d810.transforms.edit_simulator import patch_plan_to_simulated_edits


logger = getLogger(__name__)

if TYPE_CHECKING:
    from d810.hexrays.mutation.ir_translator import IDAIRTranslator
    from d810.hexrays.mutation.mba_mutation_events import MbaMutationGateway
    from d810.hexrays.mutation.semantic_fragment_backend import (
        SemanticNativeBodyMaterializer,
    )


class HexRaysMutationBackend:
    """Apply unflatten PatchPlans to a live ``mba`` and return the re-lifted FlowGraph."""

    def __init__(
        self,
        *,
        mutation_gateway: "MbaMutationGateway",
        translator: "IDAIRTranslator | None" = None,
        fragment_backend_factory: Callable[[object, object], object] | None = None,
        semantic_native_body_materializer: (
            "SemanticNativeBodyMaterializer | None"
        ) = None,
    ) -> None:
        if translator is None:
            from d810.hexrays.mutation.ir_translator import IDAIRTranslator

            translator = IDAIRTranslator()
        self._translator = translator
        self._mutation_gateway = mutation_gateway
        self._semantic_native_body_materializer = semantic_native_body_materializer
        self._committed_fragment_receipt: object | None = None
        self._fragment_backend_factory = (
            fragment_backend_factory
            if fragment_backend_factory is not None
            else self._new_fragment_backend
        )

    def committed_current_mba_identity_binding(
        self,
    ) -> CurrentMbaIdentityBindingSnapshot | None:
        """Return only the last successfully committed fragment's live binding."""
        receipt = self._committed_fragment_receipt
        if receipt is None:
            return None
        binding = getattr(receipt, "current_mba_identity_binding", None)
        if not isinstance(binding, CurrentMbaIdentityBindingSnapshot):
            raise TypeError(
                "committed fragment receipt has invalid current-MBA identity binding"
            )
        return binding

    def _new_fragment_backend(self, live_source: object, gateway: object) -> object:
        from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier

        return DeferredGraphModifier(
            live_source,
            mutation_gateway=gateway,
            semantic_native_body_materializer=(self._semantic_native_body_materializer),
        )

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

        self._translator.lower(
            rewrite_plan,
            live_source,
            mutation_gateway=self._mutation_gateway,
        )
        return self._translator.lift(live_source)

    def publish_fragment(
        self,
        fragment_plan: FragmentPlan,
        live_source: object,
        safety_policy: object = None,
    ) -> FlowGraph:
        """Publish one complete fragment through an independent gateway batch."""
        del safety_policy
        self._committed_fragment_receipt = None
        gateway = self._mutation_gateway.new_transaction()
        fragment_backend = self._fragment_backend_factory(live_source, gateway)
        self._committed_fragment_receipt = gateway.publish_semantic_fragment(
            fragment_backend,
            fragment_plan,
        )
        return self._translator.lift(live_source)
