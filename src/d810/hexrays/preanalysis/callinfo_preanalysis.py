"""Generic Hex-Rays call-prototype preanalysis event dispatcher."""
from __future__ import annotations

from collections.abc import Callable, MutableMapping

from d810.core.logging import getLogger

logger = getLogger("D810.hexrays.preanalysis.callinfo")

CallinfoPreanalysisHandler = Callable[..., None]

_CALLINFO_PREANALYSIS_HANDLERS: dict[str, CallinfoPreanalysisHandler] = {}


def register_callinfo_preanalysis_handler(
    name: str,
    handler: CallinfoPreanalysisHandler,
) -> None:
    """Register a named provider for ``hxe_build_callinfo``."""
    _CALLINFO_PREANALYSIS_HANDLERS[str(name)] = handler


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
    for name, handler in tuple(_CALLINFO_PREANALYSIS_HANDLERS.items()):
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
