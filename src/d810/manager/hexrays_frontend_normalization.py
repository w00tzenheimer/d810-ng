"""Thin Hex-Rays adapter for manager-owned PREOPT normalization."""

from __future__ import annotations

from collections.abc import MutableMapping
import json

from d810.analyses.control_flow.frontend_normalization import (
    FrontendNormalizationEvidenceRejected,
)
from d810.core.logging import getLogger
from d810.core.observability import emit as emit_diagnostic
from d810.core.observability_events import (
    FrontendNormalizationPlanIntentObserved,
    LifecycleEventObserved,
)
from d810.ir.block_identity import CurrentMbaIdentityBindingSnapshot
from d810.manager.decompilation_lifecycle import DecompilationSessionContext
from d810.manager.frontend_normalization import (
    FrontendNormalizationPublicationError,
    SessionFrontendNormalizationEvidenceProvider,
    run_frontend_normalization_pipeline,
)
from d810.manager.pass_contract_evidence import SessionPassContractEvidenceObserver
from d810.transforms.fragment_plan import (
    FragmentBlockRole,
    FragmentPlanRejected,
    fragment_plan_to_dict,
)
from d810.transforms.cfg_transaction import CfgGenerationPoisoned


logger = getLogger("d810.manager.frontend_normalization")
_HANDLER_NAME = "manager.frontend_normalization"


def _lift_live_function(mba: object) -> object:
    from d810.backends.hexrays.lifter import lift_function

    return lift_function(mba)


def _new_live_backend(
    *,
    mutation_gateway: object,
    semantic_native_body_materializer: object,
) -> object:
    from d810.backends.hexrays.mutation.backend import HexRaysMutationBackend

    return HexRaysMutationBackend(
        mutation_gateway=mutation_gateway,
        semantic_native_body_materializer=semantic_native_body_materializer,
    )


def _receipt_committed_live_import_identity(
    *,
    session: DecompilationSessionContext,
    mba: object,
    backend: object,
) -> CurrentMbaIdentityBindingSnapshot:
    """Read the committed audit snapshot without activating producer coordinates."""
    del session, mba
    binding_provider = getattr(
        backend,
        "committed_current_mba_identity_binding",
        None,
    )
    if not callable(binding_provider):
        raise TypeError(
            "frontend normalization backend lacks committed identity authority"
        )
    binding = binding_provider()
    if not isinstance(binding, CurrentMbaIdentityBindingSnapshot):
        raise TypeError(
            "frontend normalization backend returned invalid committed identity"
        )
    return binding


def _emit_receipted_complete_plan_intent(
    *,
    session: DecompilationSessionContext,
    function_ea: int,
    evidence_generation: int,
) -> None:
    """Persist complete detached intent before reporting its live identity."""
    receipted = session.frontend_normalization_plan_authority.plan_for(
        int(function_ea),
        int(evidence_generation),
    )
    if receipted is None:
        raise FrontendNormalizationPublicationError(
            "modified frontend normalization lacks receipt-backed complete intent"
        )
    plan, authority = receipted
    imported_blocks = tuple(
        block for block in plan.blocks if block.role is FragmentBlockRole.IMPORTED
    )
    emit_diagnostic(
        FrontendNormalizationPlanIntentObserved(
            session_id=session.identity_key,
            func_ea=int(function_ea),
            evidence_generation=int(evidence_generation),
            work_item_id=authority.work_item_id,
            plan_id=plan.plan_id,
            atomic_group_id=plan.atomic_group_id,
            publication_revision=int(authority.publication_revision),
            block_count=len(plan.blocks),
            operation_count=len(plan.operations),
            imported_block_count=len(imported_blocks),
            native_body_count=len(plan.native_bodies),
            published_operation_ids=tuple(authority.published_operation_ids),
            selected_obligation_ids=tuple(authority.selected_obligation_ids),
            remaining_obligation_ids=tuple(authority.remaining_obligation_ids),
            unreachable_obligation_ids=tuple(authority.unreachable_obligation_ids),
            complete_plan_json=json.dumps(
                fragment_plan_to_dict(plan),
                sort_keys=True,
                separators=(",", ":"),
            ),
        )
    )


def run_live_frontend_normalization(
    *,
    function_ea: int,
    mba: object,
    decision: MutableMapping[str, object],
) -> None:
    """Publish one portable PREOPT generation through the fragment gateway."""
    session = decision.get("session")
    mutation_gateway = decision.get("mutation_gateway")
    semantic_native_body_materializer = decision.get(
        "semantic_native_body_materializer"
    )
    if not isinstance(session, DecompilationSessionContext):
        logger.debug(
            "frontend normalization abstained for 0x%X: no lifecycle session",
            int(function_ea),
        )
        return
    if mutation_gateway is None:
        logger.debug(
            "frontend normalization abstained for 0x%X: no mutation gateway",
            int(function_ea),
        )
        return
    if semantic_native_body_materializer is None:
        logger.debug(
            "frontend normalization abstained for 0x%X: "
            "no semantic native-body materializer",
            int(function_ea),
        )
        return
    if int(session.function_ea) != int(function_ea):
        raise ValueError(
            "frontend normalization event belongs to another lifecycle session"
        )
    if int(session.native_preanalysis_depth) > 0:
        return

    source = _lift_live_function(mba)
    backend = _new_live_backend(
        mutation_gateway=mutation_gateway,
        semantic_native_body_materializer=(semantic_native_body_materializer),
    )
    from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
        resolver_session_state,
    )

    resolver_state = resolver_session_state(session)
    try:
        result = run_frontend_normalization_pipeline(
            source=source,
            backend=backend,
            evidence_provider=SessionFrontendNormalizationEvidenceProvider(
                function_ea=int(function_ea),
                native_key=session.native_key,
                state=session.native_preanalysis,
            ),
            plan_authority=(session.frontend_normalization_plan_authority),
            lifecycle_state=session.native_preanalysis,
            native_key=session.native_key,
            reference_oracle_provider=(
                resolver_state.semantic_route_reference_oracle_provider
            ),
            pass_contract_evidence_observer=SessionPassContractEvidenceObserver(
                session_id=session.identity_key,
                function_ea=int(function_ea),
                evidence_generation=int(session.native_preanalysis.evidence_generation),
            ),
        )
    except CfgGenerationPoisoned as exc:
        emit_diagnostic(
            LifecycleEventObserved(
                session_id=session.identity_key,
                func_ea=int(function_ea),
                event_kind="frontend_normalization_generation_poisoned",
                provider=_HANDLER_NAME,
                phase=exc.failure.failure_phase,
                evidence_generation=int(session.native_preanalysis.evidence_generation),
                summary="frontend normalization poisoned the live MBA generation",
                payload={
                    "outcome": exc.failure.phase.value,
                    "reason": exc.failure.reason,
                    "interr_code": exc.failure.interr_code,
                    "attempt_id": exc.failure.attempt_id.attempt_id,
                },
            )
        )
        raise
    except (FrontendNormalizationEvidenceRejected, FragmentPlanRejected) as exc:
        reason = str(exc)
        emit_diagnostic(
            LifecycleEventObserved(
                session_id=session.identity_key,
                func_ea=int(function_ea),
                event_kind="frontend_normalization_rejected",
                provider=_HANDLER_NAME,
                phase="frontend_normalization",
                evidence_generation=int(session.native_preanalysis.evidence_generation),
                summary="frontend normalization planning rejected",
                payload={
                    "outcome": "rejected",
                    "reason": reason,
                },
            )
        )
        raise
    if not result.microcode_modified:
        return

    _emit_receipted_complete_plan_intent(
        session=session,
        function_ea=int(function_ea),
        evidence_generation=int(session.native_preanalysis.evidence_generation),
    )

    details = decision.setdefault("details", {})
    if not isinstance(details, MutableMapping):
        raise TypeError("PREOPT decision details must be a mutable mapping")
    details["frontend_normalization"] = {
        "authority": "fragment_receipt",
        "published_generation": result.published_generation,
        "published_work_item_id": result.published_work_item_id,
        "remaining_obligation_count": result.remaining_obligation_count,
    }
    decision["microcode_modified"] = True
    committed_identity = _receipt_committed_live_import_identity(
        session=session,
        mba=mba,
        backend=backend,
    )
    committed_origins = committed_identity.instruction_origins
    emit_diagnostic(
        LifecycleEventObserved(
            session_id=session.identity_key,
            func_ea=int(function_ea),
            event_kind="current_mba_import_identity_receipted",
            provider=_HANDLER_NAME,
            phase="frontend_normalization",
            evidence_generation=int(session.native_preanalysis.evidence_generation),
            summary="receipt-backed current-MBA import identity recorded",
            payload={
                "outcome": "receipted",
                "resolver_activation": "not_bound_in_producer_callback",
                "origin_count": len(committed_origins),
                "native_ea_count": len(
                    {int(native_ea) for _live_ea, native_ea in committed_origins}
                ),
                "native_eas": sorted(
                    {int(native_ea) for _live_ea, native_ea in committed_origins}
                ),
                "block_binding_count": len(committed_identity.block_bindings),
                "block_bindings": [
                    {
                        "live_instruction_eas": sorted(binding.live_instruction_eas),
                        "exact_instruction_eas": sorted(
                            binding.stable_identity.exact_instruction_eas
                        ),
                        "native_ranges": [
                            {
                                "start_ea": interval.start_ea,
                                "end_ea": interval.end_ea,
                            }
                            for interval in (
                                binding.stable_identity.native_ranges.intervals
                            )
                        ],
                    }
                    for binding in committed_identity.block_bindings
                ],
            },
        )
    )


def install_live_frontend_normalization() -> None:
    """Install the sole PREOPT semantic-fragment publication handler."""
    from d810.hexrays.preanalysis.preopt_preanalysis import (
        register_preopt_preanalysis_handler,
    )

    register_preopt_preanalysis_handler(
        _HANDLER_NAME,
        run_live_frontend_normalization,
    )


def uninstall_live_frontend_normalization() -> None:
    """Remove the manager-owned PREOPT publication handler."""
    from d810.hexrays.preanalysis.preopt_preanalysis import (
        unregister_preopt_preanalysis_handler,
    )

    unregister_preopt_preanalysis_handler(_HANDLER_NAME)


__all__ = [
    "install_live_frontend_normalization",
    "run_live_frontend_normalization",
    "uninstall_live_frontend_normalization",
]
