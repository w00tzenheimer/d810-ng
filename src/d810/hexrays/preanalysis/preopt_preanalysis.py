"""Generic Hex-Rays PREOPT-maturity preanalysis event dispatcher."""

from __future__ import annotations

from collections.abc import Callable, MutableMapping

from d810.core.logging import getLogger
from d810.transforms.cfg_transaction import CfgGenerationPoisoned

logger = getLogger("D810.hexrays.preanalysis.preopt")

PreoptPreanalysisHandler = Callable[..., None]

_PREOPT_PREANALYSIS_HANDLERS: dict[str, PreoptPreanalysisHandler] = {}


def register_preopt_preanalysis_handler(
    name: str,
    handler: PreoptPreanalysisHandler,
) -> None:
    """Register a named handler for the live MMAT_PREOPTIMIZED MBA."""
    _PREOPT_PREANALYSIS_HANDLERS[str(name)] = handler


def unregister_preopt_preanalysis_handler(name: str) -> None:
    """Remove a named PREOPT-maturity handler."""
    _PREOPT_PREANALYSIS_HANDLERS.pop(str(name), None)


def run_preopt_preanalysis_handlers(
    *,
    function_ea: int,
    mba: object,
    decision: MutableMapping[str, object],
    **_kwargs: object,
) -> None:
    """Run handlers after PREOPT and before local and call analysis."""
    for name, handler in tuple(_PREOPT_PREANALYSIS_HANDLERS.items()):
        try:
            handler(
                function_ea=int(function_ea),
                mba=mba,
                decision=decision,
            )
        except CfgGenerationPoisoned:
            raise
        except Exception:  # noqa: BLE001 - non-mutation preanalysis fails open
            logger.debug(
                "PREOPT preanalysis handler %s failed for 0x%X",
                name,
                int(function_ea),
                exc_info=True,
            )


__all__ = [
    "register_preopt_preanalysis_handler",
    "run_preopt_preanalysis_handlers",
    "unregister_preopt_preanalysis_handler",
]
