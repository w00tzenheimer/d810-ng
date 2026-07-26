"""Hex-Rays mutation backend for typed patch and semantic-fragment plans.

The ONLY place a unflatten ``PatchPlan`` becomes live ``mba`` edits. ``apply`` lowers the plan through the
existing ``IDAIRTranslator`` (PatchPlan -> DeferredGraphModifier queue) and then RE-LIFTS the
post-apply ``mba`` to a fresh ``FlowGraph`` snapshot — the new snapshot identity is the sound
invalidation epoch (Hex-Rays re-runs its own optimizer during/after apply, so the re-lift captures
the vendor's re-optimization, per unflatten / the LLVM AnalysisManager invalidation model).

Semantic fragments use a fresh receipt-backed gateway transaction and re-lift
only after semantic postvalidation commits. ``apply`` is the sole live entry.
"""

from __future__ import annotations

from d810.core.logging import getLogger
from d810.core.typing import Callable, TYPE_CHECKING
from d810.ir.block_identity import CurrentMbaIdentityBindingSnapshot
from d810.ir.flowgraph import FlowGraph
from d810.transforms.fragment_plan import FragmentPlan
from d810.transforms.plan import PatchPlan


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
            from d810.hexrays.contracts.cfg_contract import IDACfgContract
            from d810.hexrays.mutation.ir_translator import IDAIRTranslator

            translator = IDAIRTranslator(contract=IDACfgContract())
        self._translator = translator
        self._mutation_gateway = mutation_gateway
        self._semantic_native_body_materializer = semantic_native_body_materializer
        self._committed_fragment_receipt: object | None = None
        self._last_patch_execution: object | None = None
        self._last_patch_failure: Exception | None = None
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

    @property
    def last_patch_execution(self) -> object | None:
        return self._last_patch_execution

    @property
    def last_patch_failure(self) -> Exception | None:
        return self._last_patch_failure

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
        rewrite_plan: PatchPlan | FragmentPlan,
        live_source: object,
        safety_policy: object = None,
    ) -> FlowGraph:
        """The sole live transaction entry point for PatchPlan and FragmentPlan."""
        if isinstance(rewrite_plan, FragmentPlan):
            return self._apply_fragment(rewrite_plan, live_source, safety_policy)
        if not isinstance(rewrite_plan, PatchPlan):
            raise TypeError("HexRaysMutationBackend.apply requires a typed plan")
        return self._apply_patch_plan(rewrite_plan, live_source, safety_policy)

    def _apply_patch_plan(
        self,
        rewrite_plan: PatchPlan,
        live_source: object,
        safety_policy: object = None,
    ) -> FlowGraph:
        """Execute one already-lowered PatchPlan through the shared coordinator."""
        del safety_policy
        from d810.hexrays.mutation.patch_transaction import (
            PatchTransactionPreflightRejected,
            execute_patch_transaction,
        )

        pre_cfg = self._translator.lift(live_source)
        self._last_patch_execution = None
        self._last_patch_failure = None
        try:
            self._last_patch_execution = execute_patch_transaction(
                self._mutation_gateway,
                self._translator,
                rewrite_plan,
                live_source,
                pre_cfg=pre_cfg,
                contract=getattr(self._translator, "contract", None),
            )
        except PatchTransactionPreflightRejected as error:
            self._last_patch_failure = error
            logger.warning("Rejecting Hex-Rays PatchPlan preflight: %s", error)
            return pre_cfg
        return self._last_patch_execution.graph

    def _apply_fragment(
        self,
        fragment_plan: FragmentPlan,
        live_source: object,
        safety_policy: object = None,
    ) -> FlowGraph:
        """Prepare and execute a fragment through the shared ``apply`` entry."""
        del safety_policy
        self._committed_fragment_receipt = None
        gateway = self._mutation_gateway.new_transaction()
        fragment_backend = self._fragment_backend_factory(live_source, gateway)
        self._committed_fragment_receipt = gateway.execute_patch_transaction(
            fragment_backend,
            fragment_plan,
        )
        return self._translator.lift(live_source)
