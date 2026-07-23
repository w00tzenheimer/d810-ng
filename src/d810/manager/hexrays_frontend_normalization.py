"""Thin Hex-Rays adapter for manager-owned PREOPT normalization."""

from __future__ import annotations

from collections.abc import MutableMapping

from d810.core.logging import getLogger
from d810.manager.decompilation_lifecycle import DecompilationSessionContext
from d810.manager.frontend_normalization import (
    SessionFrontendNormalizationEvidenceProvider,
    run_frontend_normalization_pipeline,
)


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
    if not result.microcode_modified:
        return

    details = decision.setdefault("details", {})
    if not isinstance(details, MutableMapping):
        raise TypeError("PREOPT decision details must be a mutable mapping")
    details["frontend_normalization"] = {
        "authority": "fragment_receipt",
        "published_generation": result.published_generation,
    }
    decision["microcode_modified"] = True


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
