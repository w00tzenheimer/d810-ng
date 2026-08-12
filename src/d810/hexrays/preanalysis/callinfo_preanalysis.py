"""Generic Hex-Rays call-prototype preanalysis event dispatcher."""

from __future__ import annotations

from collections.abc import Callable, MutableMapping

from d810.core.logging import getLogger
from d810.core.normalization_policy import Seam
from d810.hexrays.preanalysis._seam_gate import (
    RegisteredSeamHandler,
    permitted_seam_handlers,
)

logger = getLogger("d810.hexrays.preanalysis.callinfo")

CallinfoPreanalysisHandler = Callable[..., None]

_SEAM = Seam.CALLINFO

_CALLINFO_PREANALYSIS_HANDLERS: dict[str, RegisteredSeamHandler] = {}


def register_callinfo_preanalysis_handler(
    name: str,
    handler: CallinfoPreanalysisHandler,
    *,
    read_only: bool = False,
) -> None:
    """Register a named provider for ``hxe_build_callinfo``."""
    _CALLINFO_PREANALYSIS_HANDLERS[str(name)] = RegisteredSeamHandler(
        handler, read_only
    )


def unregister_callinfo_preanalysis_handler(name: str) -> None:
    """Remove a named call-prototype provider."""
    _CALLINFO_PREANALYSIS_HANDLERS.pop(str(name), None)


def run_callinfo_preanalysis_handlers(
    *,
    function_ea: int,
    block: object,
    call_type: object,
    decision: MutableMapping[str, object],
    **_kwargs: object,
) -> None:
    """Run providers before Hex-Rays guesses one call's prototype."""
    for name, handler in permitted_seam_handlers(
        _SEAM, int(function_ea), _CALLINFO_PREANALYSIS_HANDLERS
    ):
        try:
            handler(
                function_ea=int(function_ea),
                block=block,
                call_type=call_type,
                decision=decision,
            )
        except Exception:  # noqa: BLE001 - preanalysis must fail open
            logger.debug(
                "callinfo preanalysis handler %s failed for 0x%X",
                name,
                int(function_ea),
                exc_info=True,
            )


__all__ = [
    "register_callinfo_preanalysis_handler",
    "run_callinfo_preanalysis_handlers",
    "unregister_callinfo_preanalysis_handler",
]
