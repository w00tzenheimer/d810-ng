"""Generic CALLS-maturity preanalysis event dispatcher."""

from __future__ import annotations

from collections.abc import Callable, MutableMapping

from d810.core.logging import getLogger
from d810.core.normalization_policy import Seam
from d810.hexrays.preanalysis._seam_gate import (
    RegisteredSeamHandler,
    permitted_seam_handlers,
)

logger = getLogger("d810.hexrays.preanalysis.calls_done")

CallsDonePreanalysisHandler = Callable[..., None]

_SEAM = Seam.CALLS_DONE

_CALLS_DONE_PREANALYSIS_HANDLERS: dict[str, RegisteredSeamHandler] = {}


def register_calls_done_preanalysis_handler(
    name: str,
    handler: CallsDonePreanalysisHandler,
    *,
    read_only: bool = False,
) -> None:
    """Register a named handler for the live MMAT_CALLS MBA."""
    _CALLS_DONE_PREANALYSIS_HANDLERS[str(name)] = RegisteredSeamHandler(
        handler, read_only
    )


def unregister_calls_done_preanalysis_handler(name: str) -> None:
    """Remove a named CALLS-maturity handler."""
    _CALLS_DONE_PREANALYSIS_HANDLERS.pop(str(name), None)


def run_calls_done_preanalysis_handlers(
    *,
    function_ea: int,
    mba: object,
    decision: MutableMapping[str, object],
    **_kwargs: object,
) -> None:
    """Run handlers over the live MBA after call analysis is complete."""
    for name, handler in permitted_seam_handlers(
        _SEAM, int(function_ea), _CALLS_DONE_PREANALYSIS_HANDLERS
    ):
        try:
            handler(
                function_ea=int(function_ea),
                mba=mba,
                decision=decision,
            )
        except Exception:  # noqa: BLE001 - preanalysis must fail open
            logger.debug(
                "CALLS preanalysis handler %s failed for 0x%X",
                name,
                int(function_ea),
                exc_info=True,
            )


__all__ = [
    "register_calls_done_preanalysis_handler",
    "run_calls_done_preanalysis_handlers",
    "unregister_calls_done_preanalysis_handler",
]
