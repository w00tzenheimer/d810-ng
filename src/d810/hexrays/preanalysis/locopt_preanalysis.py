"""Generic Hex-Rays LOCOPT-maturity preanalysis event dispatcher."""

from __future__ import annotations

from collections.abc import Callable, MutableMapping

from d810.core.logging import getLogger
from d810.core.normalization_policy import Seam
from d810.hexrays.preanalysis._seam_gate import (
    RegisteredSeamHandler,
    permitted_seam_handlers,
)

logger = getLogger("d810.hexrays.preanalysis.locopt")

LocoptPreanalysisHandler = Callable[..., None]

_SEAM = Seam.LOCOPT

_LOCOPT_PREANALYSIS_HANDLERS: dict[str, RegisteredSeamHandler] = {}


def register_locopt_preanalysis_handler(
    name: str,
    handler: LocoptPreanalysisHandler,
    *,
    read_only: bool = False,
) -> None:
    """Register a named handler for the live MMAT_LOCOPT MBA."""
    _LOCOPT_PREANALYSIS_HANDLERS[str(name)] = RegisteredSeamHandler(handler, read_only)


def unregister_locopt_preanalysis_handler(name: str) -> None:
    """Remove a named LOCOPT-maturity handler."""
    _LOCOPT_PREANALYSIS_HANDLERS.pop(str(name), None)


def run_locopt_preanalysis_handlers(
    *,
    function_ea: int,
    mba: object,
    decision: MutableMapping[str, object],
    **_kwargs: object,
) -> None:
    """Run handlers after LOCOPT and before Hex-Rays analyzes calls."""
    for name, handler in permitted_seam_handlers(
        _SEAM, int(function_ea), _LOCOPT_PREANALYSIS_HANDLERS
    ):
        try:
            handler(
                function_ea=int(function_ea),
                mba=mba,
                decision=decision,
            )
        except Exception:  # noqa: BLE001 - preanalysis must fail open
            logger.debug(
                "LOCOPT preanalysis handler %s failed for 0x%X",
                name,
                int(function_ea),
                exc_info=True,
            )


__all__ = [
    "register_locopt_preanalysis_handler",
    "run_locopt_preanalysis_handlers",
    "unregister_locopt_preanalysis_handler",
]
