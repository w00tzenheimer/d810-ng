"""Use-def-safe redirect filtering — veto spine redirects that orphan non-state-var uses.

Mirrors the legacy ``LinearizedFlowGraph`` postprocess: a redirect that severs a use-def dominance
chain for a NON-state variable would orphan handler-body data (the over-redirect that DCEs handler
bodies and collapses the function).  The state variable itself is *meant* to be severed -- that is
the unflattening -- so violations on ``state_var_stkoff`` are ignored.

Portable: the live use-def query is the injected :class:`d810.capabilities.UseDefSafetyCapability`;
the caller passes the opaque live function (``ida_hexrays.mba_t``) and the pre-modification
``FlowGraph``.  When no capability / live function is available the redirects pass through unfiltered
(the portable/test path).
"""
from __future__ import annotations

from d810.core import logging
from d810.transforms.graph_modification import (
    RedirectBranch,
    RedirectGoto,
    to_redirect_intent,
)

logger = logging.getLogger("D810.transforms.use_def_filter")

__all__ = ["filter_use_def_severing_redirects"]


def filter_use_def_severing_redirects(
    mods,
    *,
    use_def_safety,
    live_function,
    pre_cfg,
    state_var_stkoff=None,
):
    """Drop redirects whose application would orphan a non-state-variable use.

    Args:
        mods: Iterable of ``GraphModification`` (only ``RedirectGoto`` / ``RedirectBranch`` are
            checked; everything else passes through).
        use_def_safety: An injected ``UseDefSafetyCapability`` (or ``None`` -> no filtering).
        live_function: Opaque live backend function the capability queries (``mba_t``); ``None`` ->
            no filtering.
        pre_cfg: Pre-modification ``FlowGraph`` snapshot the capability reads.
        state_var_stkoff: Stack offset of the state variable; violations on it are the intended
            unflattening and are ignored.

    Returns:
        The kept modifications (a list), in input order.
    """
    if use_def_safety is None or live_function is None:
        return list(mods)
    kept: list = []
    vetoed = 0
    for mod in mods:
        if not isinstance(mod, (RedirectGoto, RedirectBranch)):
            kept.append(mod)
            continue
        try:
            violations = use_def_safety.redirect_use_def_violations(
                to_redirect_intent(mod), live_function, pre_cfg
            )
        except Exception:  # noqa: BLE001 — a failed safety check must not drop a redirect
            logger.debug("use-def veto check raised for %r", mod, exc_info=True)
            kept.append(mod)
            continue
        if not violations:
            kept.append(mod)
            continue
        real_violations = [
            v
            for v in violations
            if state_var_stkoff is None or int(v.var_stkoff) != int(state_var_stkoff)
        ]
        if not real_violations:
            # Only the dispatcher state variable would be severed -- that is the unflattening.
            kept.append(mod)
            continue
        vetoed += 1  # would orphan non-state-var (handler body) uses -> drop
    if vetoed:
        logger.info("use-def veto filtered %d redirect(s)", vetoed)
    return kept
