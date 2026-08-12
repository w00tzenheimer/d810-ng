"""Generic Hex-Rays PREOPT-maturity preanalysis event dispatcher."""

from __future__ import annotations

from collections.abc import Callable, MutableMapping

from d810.core.logging import getLogger
from d810.core.normalization_policy import Seam
from d810.hexrays.preanalysis._seam_gate import (
    RegisteredSeamHandler,
    permitted_seam_handlers,
)
from d810.transforms.cfg_transaction import CfgGenerationPoisoned

logger = getLogger("d810.hexrays.preanalysis.preopt")

PreoptPreanalysisHandler = Callable[..., None]

_SEAM = Seam.PREOPT

_PREOPT_PREANALYSIS_HANDLERS: dict[str, RegisteredSeamHandler] = {}


def register_preopt_preanalysis_handler(
    name: str,
    handler: PreoptPreanalysisHandler,
    *,
    read_only: bool = False,
) -> None:
    """Register a named handler for the live MMAT_PREOPTIMIZED MBA."""
    _PREOPT_PREANALYSIS_HANDLERS[str(name)] = RegisteredSeamHandler(handler, read_only)


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
    for name, handler in permitted_seam_handlers(
        _SEAM, int(function_ea), _PREOPT_PREANALYSIS_HANDLERS
    ):
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
