"""Thin Hex-Rays adapter for manager-owned PREOPT normalization."""

from __future__ import annotations

from collections.abc import MutableMapping

from d810.analyses.control_flow.frontend_normalization import (
    FrontendNormalizationEvidenceRejected,
)
from d810.core.logging import getLogger
from d810.core.observability import emit as emit_diagnostic
from d810.core.observability_events import LifecycleEventObserved
from d810.ir.block_identity import CurrentMbaIdentityBindingSnapshot
from d810.manager.decompilation_lifecycle import DecompilationSessionContext
from d810.manager.frontend_normalization import (
    SessionFrontendNormalizationEvidenceProvider,
    run_frontend_normalization_pipeline,
)
from d810.transforms.fragment_plan import FragmentPlanRejected


logger = getLogger("D810.manager.frontend_normalization")
_HANDLER_NAME = "manager.frontend_normalization"


def _lift_live_function(mba: object) -> object:
    from d810.backends.hexrays.lifter import lift_function

    return lift_function(mba)


def _new_live_backend(
    *,
    mba: object,
    function_ea: int,
    mutation_gateway: object,
) -> object:
    from d810.backends.hexrays.mutation.backend import HexRaysMutationBackend
    from d810.hexrays.mutation.detached_handler_island import (
        PreoptUnionSemanticNativeBodyMaterializer,
    )

    return HexRaysMutationBackend(
        mutation_gateway=mutation_gateway,
        semantic_native_body_materializer=(
            PreoptUnionSemanticNativeBodyMaterializer(
                mba=mba,
                function_ea=int(function_ea),
            )
        ),
    )


def _bind_committed_live_import_identity(
    *,
    session: DecompilationSessionContext,
    mba: object,
    backend: object,
) -> CurrentMbaIdentityBindingSnapshot:
    """Bind one receipt-backed imported identity snapshot to this live MBA."""
    from d810.hexrays.mutation.detached_handler_island import (
        stable_mba_identity,
    )
    from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
        resolver_session_state,
    )

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
    resolver_session_state(session).bind_current_imported_publication(
        stable_mba_identity(mba),
        binding,
    )
    return binding


def run_live_frontend_normalization(
    *,
    function_ea: int,
    mba: object,
    decision: MutableMapping[str, object],
) -> None:
    """Publish one portable PREOPT generation through the fragment gateway."""
    session = decision.get("session")
    mutation_gateway = decision.get("mutation_gateway")
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
    if int(session.function_ea) != int(function_ea):
        raise ValueError(
            "frontend normalization event belongs to another lifecycle session"
        )
    if int(session.native_preanalysis_depth) > 0:
        return

    source = _lift_live_function(mba)
    backend = _new_live_backend(
        mba=mba,
        function_ea=int(function_ea),
        mutation_gateway=mutation_gateway,
    )
    try:
        result = run_frontend_normalization_pipeline(
            source=source,
            backend=backend,
            evidence_provider=SessionFrontendNormalizationEvidenceProvider(
                function_ea=int(function_ea),
                native_key=session.native_key,
                state=session.native_preanalysis,
            ),
            lifecycle_state=session.native_preanalysis,
            native_key=session.native_key,
        )
    except (FrontendNormalizationEvidenceRejected, FragmentPlanRejected) as exc:
        reason = str(exc)
        emit_diagnostic(
            LifecycleEventObserved(
                session_id=session.identity_key,
                func_ea=int(function_ea),
                event_kind="frontend_normalization_rejected",
                provider=_HANDLER_NAME,
                phase="frontend_normalization",
                evidence_generation=int(
                    session.native_preanalysis.evidence_generation
                ),
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
    committed_identity = _bind_committed_live_import_identity(
        session=session,
        mba=mba,
        backend=backend,
    )
    committed_origins = committed_identity.instruction_origins
    emit_diagnostic(
        LifecycleEventObserved(
            session_id=session.identity_key,
            func_ea=int(function_ea),
            event_kind="current_mba_import_identity_bound",
            provider=_HANDLER_NAME,
            phase="frontend_normalization",
            evidence_generation=int(
                session.native_preanalysis.evidence_generation
            ),
            summary="receipt-backed current-MBA import identity bound",
            payload={
                "outcome": "bound",
                "origin_count": len(committed_origins),
                "native_ea_count": len(
                    {int(native_ea) for _live_ea, native_ea in committed_origins}
                ),
                "native_eas": sorted(
                    {
                        int(native_ea)
                        for _live_ea, native_ea in committed_origins
                    }
                ),
                "block_binding_count": len(
                    committed_identity.block_bindings
                ),
                "block_bindings": [
                    {
                        "live_instruction_eas": sorted(
                            binding.live_instruction_eas
                        ),
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
