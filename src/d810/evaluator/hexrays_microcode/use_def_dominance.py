"""Use-def dominance severance detector for CFG redirect safety.

This module detects when a proposed redirect intent (CFG-layer
``RedirectGoto`` / ``RedirectBranch`` lifted to the portable
``d810.ir.redirect.RedirectIntent`` shape at the capability boundary)
would sever a use-def dominance chain, i.e., move a definition of a stack
variable out of a position where it dominated its uses.

The first deployment used this as observer-only telemetry.  State-dispatcher
reconstruction now also uses it as a safety gate before applying redirects that
would bypass semantic payload blocks.  Callers decide whether a reported
violation is fatal for their strategy.

Slice 5 of the llvm-lisa-restructure plan: the abstract capability Protocol
``UseDefSafetyCapability`` and the portable result type
``SeveranceViolation`` were moved to ``d810.capabilities.use_def_safety``.
This module keeps:

  * the Hex-Rays concrete implementation (``HexRaysUseDefSafetyBackend``)
  * the live ``ida_hexrays`` algorithm helpers
    (``_collect_stkvar_defs_in_block``, ``_build_post_mod_adjacency``,
    ``check_redirect_severs_use_def``)
  * back-compat re-exports of ``SeveranceViolation`` and the legacy
    name ``UseDefSafetyBackend`` (alias of ``UseDefSafetyCapability``)
    so the two existing Hodur consumers
    (``hodur/strategies/handler_chain_composer.py``,
    ``hodur/strategies/linearized_flow_graph.py``) do not need to update.

Algorithm
---------

1. Walk the source block's live ``minsn_t`` stream and collect every
   ``(stkoff, size)`` written by an instruction with a ``mop_S``
   destination.
2. For each defined stack variable, query the DU chains via
   :func:`find_all_uses_of_stkvar` to enumerate uses across the MBA.
3. Build the *post-modification* adjacency by copying the pre-mod CFG
   adjacency, removing the old target from the source's successor list,
   and appending the new target.
4. Compute the dominator tree of the post-mod adjacency rooted at
   the entry block (serial 0 by Hex-Rays convention).
5. For every use, if the source block does **not** dominate the use
   block in the post-mod tree, record a :class:`SeveranceViolation`.

Returns an empty tuple when no violations exist.
"""

from __future__ import annotations

import ida_hexrays

# Canonical home for the abstract capability + portable result type;
# re-exported below for back-compat with the existing Hodur consumers.
from d810.capabilities.use_def_safety import (
    SeveranceViolation,
    UseDefSafetyCapability,
)
from d810.analyses.control_flow.dominator import compute_dom_tree
from d810.ir.flowgraph import FlowGraph
from d810.core.logging import getLogger
from d810.evaluator.hexrays_microcode.chains import (
    UseSite,
    find_all_uses_of_stkvar,
)
from d810.ir.redirect import RedirectIntent

logger = getLogger(__name__)


# Back-compat alias for the pre-slice-5 name.  New code should import
# ``UseDefSafetyCapability`` from ``d810.capabilities.use_def_safety``
# directly.  This alias preserves the import path used by Hodur
# strategies (``hodur/strategies/handler_chain_composer.py`` etc.) so
# they do not need to be updated in the same slice.
UseDefSafetyBackend = UseDefSafetyCapability


class HexRaysUseDefSafetyBackend:
    """Use Hex-Rays live microcode to answer redirect use-def safety queries.

    Concrete implementation of :class:`UseDefSafetyCapability` for the
    Hex-Rays backend.  Stays in ``evaluator/hexrays_microcode/``
    because the algorithm requires live ``ida_hexrays`` access (DU
    chains via ``find_all_uses_of_stkvar``, live ``minsn_t`` stream,
    dominator tree over the post-modification adjacency).
    """

    def redirect_use_def_violations(
        self,
        mod: RedirectIntent,
        live_function: object,
        pre_cfg: FlowGraph,
    ) -> tuple[SeveranceViolation, ...]:
        return check_redirect_severs_use_def(mod, live_function, pre_cfg)


def _collect_stkvar_defs_in_block(
    mba: object, blk_serial: int
) -> list[tuple[int, int]]:
    """Return ``(stkoff, size)`` pairs written by the block's live insns.

    Iterates the MBA's live ``minsn_t`` stream (not the snapshot) so
    that ``stkoff`` is read straight from ``mop_t.s.off`` without
    risking lossy snapshot capture.

    Duplicates are de-duplicated.
    """

    blk = mba.get_mblock(blk_serial)  # type: ignore[attr-defined]
    if blk is None:
        return []

    seen: set[tuple[int, int]] = set()
    cur = blk.head
    while cur is not None:
        d = cur.d
        if (
            d is not None
            and d.t == ida_hexrays.mop_S
            and d.s is not None
        ):
            key = (int(d.s.off), int(d.size))
            if key not in seen:
                seen.add(key)
        cur = cur.next
    return list(seen)


def _build_post_mod_adjacency(
    pre_cfg: FlowGraph, mod: RedirectIntent
) -> dict[int, list[int]]:
    """Return adjacency dict reflecting *mod* applied to *pre_cfg*.

    The pre-mod adjacency is copied verbatim; only ``mod.from_serial``'s
    successor list is rewritten — ``mod.old_target`` is removed (first
    occurrence) and ``mod.new_target`` is appended.
    """
    adj: dict[int, list[int]] = pre_cfg.as_adjacency_dict()
    succs = list(adj.get(mod.from_serial, ()))
    try:
        succs.remove(mod.old_target)
    except ValueError:
        # old_target not in successors — leave the list as-is.  The
        # detector still runs against the (possibly stale) post-mod
        # graph; downstream gates handle structural mismatches.
        pass
    succs.append(mod.new_target)
    adj[mod.from_serial] = succs
    return adj


def check_redirect_severs_use_def(
    mod: RedirectIntent,
    mba: object,
    pre_cfg: FlowGraph,
) -> tuple[SeveranceViolation, ...]:
    """Detect use-def chains that would be severed by *mod*.

    Args:
        mod: The proposed redirect intent (``RedirectGotoIntent`` or
            ``RedirectBranchIntent`` from ``d810.ir.redirect``).
        mba: An ``ida_hexrays.mba_t`` instance used to query DU chains
            and walk the source block's live instruction stream.
        pre_cfg: The pre-modification CFG snapshot.

    Returns:
        A (possibly empty) tuple of :class:`SeveranceViolation`s.
    """

    src = int(mod.from_serial)
    new_target = int(mod.new_target)

    defs = _collect_stkvar_defs_in_block(mba, src)
    if not defs:
        return ()

    post_adj = _build_post_mod_adjacency(pre_cfg, mod)
    entry = int(getattr(pre_cfg, "entry_serial", 0))
    dom_tree = compute_dom_tree(post_adj, entry=entry)

    violations: list[SeveranceViolation] = []
    for stkoff, size in defs:
        uses: list[UseSite] = find_all_uses_of_stkvar(mba, stkoff, size)
        for use in uses:
            if use.block_serial == src:
                # In-block use — trivially dominated by src.
                continue
            if dom_tree.dominates(src, use.block_serial):
                continue
            violations.append(
                SeveranceViolation(
                    src_block=src,
                    new_target=new_target,
                    var_stkoff=stkoff,
                    var_size=size,
                    use_block=use.block_serial,
                    use_ea=use.ins_ea,
                )
            )
    return tuple(violations)


__all__ = [
    "HexRaysUseDefSafetyBackend",
    "SeveranceViolation",
    "UseDefSafetyBackend",  # back-compat alias of UseDefSafetyCapability
    "UseDefSafetyCapability",  # re-export of canonical capability
    "check_redirect_severs_use_def",
]
