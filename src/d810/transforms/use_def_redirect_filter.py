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

import os

from d810.core import logging
from d810.transforms.graph_modification import (
    RedirectBranch,
    RedirectGoto,
    to_redirect_intent,
)

logger = logging.getLogger("D810.transforms.use_def_filter")


def _veto_enabled() -> bool:
    """The use-def severance veto is OFF by default; opt in with
    ``D810_USE_DEF_VETO=1``.

    Empirically (sub_7FFD, §1a and HCC) the veto is not load-bearing: with it
    disabled the redirects apply without INTERR, carriers (e.g. ``a5+0xD0``) are
    preserved, and the dispatcher output is no worse — the veto's dominance-only
    check mostly produces *false* severances (see d81-7zf7).  It stays available
    as an opt-in safety gate for functions where genuine non-state severances
    must be blocked."""
    return os.environ.get("D810_USE_DEF_VETO", "0").strip() == "1"

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
    if use_def_safety is None or live_function is None or not _veto_enabled():
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
        if logger.debug_on:
            intent = to_redirect_intent(mod)
            detail = ", ".join(
                "var_stkoff=0x{:x} size={} use_blk={} use_ea=0x{:x}".format(
                    int(v.var_stkoff), int(v.var_size), int(v.use_block), int(v.use_ea)
                )
                for v in real_violations[:6]
            )
            logger.debug(
                "USE_DEF_VETO_DETAIL: redirect src=%s old=%s new=%s would-veto by %d "
                "real violation(s): %s",
                getattr(intent, "from_serial", "?"),
                getattr(intent, "old_target", "?"),
                getattr(intent, "new_target", "?"),
                len(real_violations),
                detail,
            )
    if vetoed:
        logger.info("use-def veto filtered %d redirect(s)", vetoed)
    return kept
