"""Generic Hex-Rays transient stack-point preanalysis dispatcher."""

from __future__ import annotations

from collections.abc import Callable, MutableMapping

from d810.core.logging import getLogger

logger = getLogger("D810.hexrays.preanalysis.stkpnts")

StkpntsPreanalysisHandler = Callable[..., None]

_STKPNTS_PREANALYSIS_HANDLERS: dict[str, StkpntsPreanalysisHandler] = {}


def register_stkpnts_preanalysis_handler(
    name: str,
    handler: StkpntsPreanalysisHandler,
) -> None:
    """Register a named provider for ``hxe_stkpnts``."""
    _STKPNTS_PREANALYSIS_HANDLERS[str(name)] = handler


def unregister_stkpnts_preanalysis_handler(name: str) -> None:
    """Remove a named transient stack-point provider."""
    _STKPNTS_PREANALYSIS_HANDLERS.pop(str(name), None)


def run_stkpnts_preanalysis_handlers(
    *,
    function_ea: int,
    mba: object,
    stack_points: object,
    decision: MutableMapping[str, object],
    **_kwargs: object,
) -> None:
    """Run providers while Hex-Rays' transient ``stkpnts_t`` is mutable."""
    for name, handler in tuple(_STKPNTS_PREANALYSIS_HANDLERS.items()):
        try:
            handler(
                function_ea=int(function_ea),
                mba=mba,
                stack_points=stack_points,
                decision=decision,
            )
        except Exception:  # noqa: BLE001 - preanalysis must fail open
            logger.debug(
                "stack-point preanalysis handler %s failed for 0x%X",
                name,
                int(function_ea),
                exc_info=True,
            )


__all__ = [
    "register_stkpnts_preanalysis_handler",
    "run_stkpnts_preanalysis_handlers",
    "unregister_stkpnts_preanalysis_handler",
]
