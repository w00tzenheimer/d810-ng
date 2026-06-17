"""Generic Hex-Rays flowchart-stage preanalysis event dispatcher."""
from __future__ import annotations

from collections.abc import Callable, MutableMapping

from d810.core.logging import getLogger

logger = getLogger("D810.hexrays.preanalysis.flowchart")

FlowchartPreanalysisHandler = Callable[..., None]

_FLOWCHART_PREANALYSIS_HANDLERS: dict[str, FlowchartPreanalysisHandler] = {}


def register_flowchart_preanalysis_handler(
    name: str,
    handler: FlowchartPreanalysisHandler,
) -> None:
    """Register a named flowchart-stage preanalysis handler."""
    _FLOWCHART_PREANALYSIS_HANDLERS[str(name)] = handler


def unregister_flowchart_preanalysis_handler(name: str) -> None:
    """Remove a named flowchart-stage preanalysis handler."""
    _FLOWCHART_PREANALYSIS_HANDLERS.pop(str(name), None)


def request_hexrays_redo(
    decision: MutableMapping[str, object],
    reason: str,
    **details: object,
) -> None:
    """Mark the current flowchart event as requiring a Hex-Rays rebuild."""
    decision["request_redo"] = True
    decision["reason"] = str(reason)
    if details:
        payload = decision.setdefault("details", {})
        if isinstance(payload, dict):
            payload.update(details)


def run_flowchart_preanalysis_handlers(
    *,
    function_ea: int,
    mba: object,
    decision: MutableMapping[str, object],
    **_kwargs: object,
) -> None:
    """Run registered flowchart preanalysis handlers for one decompilation."""
    for name, handler in tuple(_FLOWCHART_PREANALYSIS_HANDLERS.items()):
        try:
            handler(
                function_ea=int(function_ea),
                mba=mba,
                decision=decision,
            )
        except Exception:  # noqa: BLE001 - preanalysis must not gate decompile
            logger.debug(
                "flowchart preanalysis handler %s failed for 0x%X",
                name,
                int(function_ea),
                exc_info=True,
            )


__all__ = [
    "register_flowchart_preanalysis_handler",
    "request_hexrays_redo",
    "run_flowchart_preanalysis_handlers",
    "unregister_flowchart_preanalysis_handler",
]
