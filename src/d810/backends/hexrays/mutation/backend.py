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
from d810.hexrays.mutation.semantic_fragment_profile import (
    SemanticFragmentPublicationProfile,
)
from d810.transforms.cfg_transaction import (
    PatchPlanExecutionResult,
    TransactionAttemptId,
)
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
        fragment_backend_factory: (
            Callable[[object, object, SemanticFragmentPublicationProfile], object]
            | None
        ) = None,
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
        self._committed_fragment_operation_count = 0
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

    @property
    def committed_fragment_operation_count(self) -> int:
        """Return receipt-proven fragment operations committed this callback."""
        return self._committed_fragment_operation_count

    def _new_fragment_backend(
        self,
        live_source: object,
        gateway: object,
        publication_profile: SemanticFragmentPublicationProfile,
    ) -> object:
        from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier

        return DeferredGraphModifier(
            live_source,
            mutation_gateway=gateway,
            semantic_native_body_materializer=(self._semantic_native_body_materializer),
            semantic_fragment_publication_profile=publication_profile,
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
        *,
        pre_cfg: FlowGraph | None = None,
        publication_profile: SemanticFragmentPublicationProfile = (
            SemanticFragmentPublicationProfile.CFG_READY
        ),
    ) -> FlowGraph | object:
        """The sole live transaction entry point for PatchPlan and FragmentPlan."""
        if isinstance(rewrite_plan, FragmentPlan):
            if not isinstance(
                publication_profile,
                SemanticFragmentPublicationProfile,
            ):
                raise TypeError(
                    "fragment publication requires a typed publication profile"
                )
            return self._apply_fragment(
                rewrite_plan,
                live_source,
                safety_policy,
                publication_profile=publication_profile,
            )
        if not isinstance(rewrite_plan, PatchPlan):
            raise TypeError("HexRaysMutationBackend.apply requires a typed plan")
        return self._apply_patch_plan(
            rewrite_plan,
            live_source,
            safety_policy,
            pre_cfg=pre_cfg,
        )

    def execute_patch_plan(
        self,
        plan: PatchPlan,
        live_source: object,
        *,
        pre_cfg: FlowGraph,
    ) -> PatchPlanExecutionResult:
        """Return typed commit authority for the portable pipeline port."""
        graph = self.apply(plan, live_source, pre_cfg=pre_cfg)
        execution = self.last_patch_execution
        if execution is None:
            return PatchPlanExecutionResult(applied_count=0, graph=graph)
        if not isinstance(execution, PatchPlanExecutionResult):
            raise TypeError("Hex-Rays backend produced invalid patch execution")
        return execution

    def _apply_patch_plan(
        self,
        rewrite_plan: PatchPlan,
        live_source: object,
        safety_policy: object = None,
        *,
        pre_cfg: FlowGraph | None = None,
    ) -> FlowGraph:
        """Execute one already-lowered PatchPlan through the shared coordinator."""
        del safety_policy
        from d810.hexrays.mutation.patch_transaction import (
            PatchTransactionPostObservationRejected,
            PatchTransactionPreflightRejected,
            execute_patch_transaction,
        )
        from d810.transforms.cfg_transaction import CfgGenerationPoisoned

        if pre_cfg is None:
            pre_cfg = self._translator.lift(live_source)
        elif not isinstance(pre_cfg, FlowGraph):
            raise TypeError("PatchPlan execution requires an immutable pre-CFG")
        identity_index = getattr(self._mutation_gateway, "identity_index", None)
        if identity_index is None:
            raise TypeError("Hex-Rays mutation backend requires an identity index")
        attempt_authority = TransactionAttemptId.new(
            rewrite_plan.plan_id,
            str(identity_index.session_id),
            int(identity_index.generation),
        )
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
                attempt_id=attempt_authority,
            )
        except PatchTransactionPreflightRejected as error:
            self._last_patch_failure = error
            self._observe_dispatcher_transaction_outcome(
                rewrite_plan,
                pre_cfg=pre_cfg,
                application_status="rejected_preflight",
                outcome_reason=str(error),
                attempt_id=attempt_authority.attempt_id,
                projected_validation=(
                    error.projected_dispatcher_removal_validation
                ),
                projected_coverage_validation=(
                    error.projected_dispatcher_coverage_validation
                ),
            )
            logger.warning("Rejecting Hex-Rays PatchPlan preflight: %s", error)
            return pre_cfg
        except CfgGenerationPoisoned as error:
            self._last_patch_failure = error
            observed_validation = getattr(
                error,
                "observed_dispatcher_removal_validation",
                None,
            )
            observed_coverage_validation = getattr(
                error,
                "observed_dispatcher_coverage_validation",
                None,
            )
            cause = error.__cause__
            if isinstance(cause, PatchTransactionPostObservationRejected):
                observed_validation = cause.observed_dispatcher_removal_validation
                observed_coverage_validation = (
                    cause.observed_dispatcher_coverage_validation
                )
            self._observe_dispatcher_transaction_outcome(
                rewrite_plan,
                pre_cfg=pre_cfg,
                application_status="poisoned_restart_required",
                outcome_reason=str(error.failure.reason),
                attempt_id=attempt_authority.attempt_id,
                observed_validation=observed_validation,
                observed_coverage_validation=observed_coverage_validation,
            )
            raise
        except Exception as error:
            # Projection/contract/binding failures happen before mutation, but
            # a coverage-bearing plan still needs a terminal diagnostic record
            # rather than a permanently pending corridor fact.  Preserve the
            # original exception contract for callers.
            self._last_patch_failure = error
            self._observe_dispatcher_transaction_outcome(
                rewrite_plan,
                pre_cfg=pre_cfg,
                application_status="rejected_clean",
                outcome_reason=str(error) or type(error).__name__,
                attempt_id=attempt_authority.attempt_id,
                projected_validation=getattr(
                    error,
                    "projected_dispatcher_removal_validation",
                    None,
                ),
                projected_coverage_validation=getattr(
                    error,
                    "projected_dispatcher_coverage_validation",
                    None,
                ),
            )
            raise
        self._observe_dispatcher_transaction_outcome(
            rewrite_plan,
            pre_cfg=pre_cfg,
            application_status="applied",
            attempt_id=attempt_authority.attempt_id,
            projected_validation=getattr(
                self._last_patch_execution,
                "projected_dispatcher_removal_validation",
                None,
            ),
            projected_coverage_validation=getattr(
                self._last_patch_execution,
                "projected_dispatcher_coverage_validation",
                None,
            ),
            observed_validation=getattr(
                self._last_patch_execution,
                "observed_dispatcher_removal_validation",
                None,
            ),
            observed_coverage_validation=getattr(
                self._last_patch_execution,
                "observed_dispatcher_coverage_validation",
                None,
            ),
        )
        return self._last_patch_execution.graph

    @staticmethod
    def _observe_dispatcher_transaction_outcome(
        rewrite_plan: PatchPlan,
        *,
        pre_cfg: FlowGraph,
        application_status: str,
        outcome_reason: str | None = None,
        attempt_id: str | None = None,
        observed_validation: object | None = None,
        observed_coverage_validation: object | None = None,
        projected_validation: object | None = None,
        projected_coverage_validation: object | None = None,
    ) -> None:
        """Publish immutable plan outcome facts; SQLite remains subscriber-owned."""
        try:
            from d810.core.observability_preanalysis import (
                observe_unflatten_dispatcher_corridor_coverage,
            )
            from d810.transforms.dispatcher_corridor_coverage import (
                collect_unflatten_dispatcher_outcome_observations_from_metadata,
            )

            envelope = rewrite_plan.source_maturity
            ir = None if envelope is None else getattr(envelope, "ir", None)
            maturity = str(getattr(ir, "value", None) or ir or "unknown")
            observations = collect_unflatten_dispatcher_outcome_observations_from_metadata(
                rewrite_plan.metadata_dict(),
                maturity=maturity,
                phase="patch_transaction",
                application_status=application_status,
                outcome_reason=outcome_reason,
                observed_validation=observed_validation,
                observed_coverage_validation=observed_coverage_validation,
                projected_validation=projected_validation,
                projected_coverage_validation=projected_coverage_validation,
                plan_id=rewrite_plan.plan_id,
                attempt_id=attempt_id,
            )
            if observations:
                observe_unflatten_dispatcher_corridor_coverage(
                    func_ea=int(pre_cfg.func_ea),
                    observations=observations,
                )
        except Exception:  # noqa: BLE001 - diagnostics must not mask transaction state
            try:
                logger.exception("Failed to publish dispatcher transaction outcome")
            except Exception:
                pass

    def _apply_fragment(
        self,
        fragment_plan: FragmentPlan,
        live_source: object,
        safety_policy: object = None,
        *,
        publication_profile: SemanticFragmentPublicationProfile,
    ) -> FlowGraph | object:
        """Prepare and execute a fragment through the shared ``apply`` entry."""
        del safety_policy
        self._committed_fragment_receipt = None
        gateway = self._mutation_gateway.new_transaction()
        fragment_backend = self._fragment_backend_factory(
            live_source,
            gateway,
            publication_profile,
        )
        receipt = gateway.execute_patch_transaction(
            fragment_backend,
            fragment_plan,
            publication_profile,
        )
        operation_count = getattr(receipt, "operation_count", None)
        if isinstance(operation_count, bool) or not isinstance(operation_count, int):
            raise TypeError("committed fragment receipt requires an operation count")
        if operation_count <= 0:
            raise ValueError("committed fragment receipt requires applied operations")
        self._committed_fragment_receipt = receipt
        self._committed_fragment_operation_count += operation_count
        if publication_profile.graph_free:
            return live_source
        return self._translator.lift(live_source)


class HexRaysPatchPlanRuntime:
    """Hex-Rays implementation of the portable pass-pipeline runtime port."""

    def __init__(self, translator: "IDAIRTranslator | None" = None) -> None:
        if translator is None:
            from d810.hexrays.contracts.cfg_contract import IDACfgContract
            from d810.hexrays.mutation.ir_translator import IDAIRTranslator

            translator = IDAIRTranslator(contract=IDACfgContract())
        self._translator = translator

    @property
    def name(self) -> str:
        return "hexrays"

    def lift(self, state: object) -> FlowGraph:
        return self._translator.lift(state)

    def execute_patch_plan(
        self,
        plan: PatchPlan,
        state: object,
        *,
        mutation_gateway: object,
        pre_cfg: FlowGraph,
    ) -> PatchPlanExecutionResult:
        return HexRaysMutationBackend(
            mutation_gateway=mutation_gateway,
            translator=self._translator,
        ).execute_patch_plan(plan, state, pre_cfg=pre_cfg)


__all__ = ["HexRaysMutationBackend", "HexRaysPatchPlanRuntime"]
