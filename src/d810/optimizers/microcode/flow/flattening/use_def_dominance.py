"""Use-def dominance severance detector (ticket ``uee-b7ze``).

This module detects when a proposed ``RedirectGoto`` would sever a
use-def dominance chain, i.e., move a definition of a stack variable
out of a position where it dominated its uses.

Callers may pass ``exclude_stkoffs`` (typically the dispatcher state
variable's stack offset) to suppress violations whose only "uses"
are BST comparisons that are *expected* to die when the dispatcher
collapses.  The remaining violations represent real cross-handler
def/use chains (e.g. byte-buffer writes consumed by a later block)
and are intended for refusal by the executor (Phase 2).

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

from dataclasses import dataclass

import ida_hexrays

from d810.cfg.dominator import compute_dom_tree
from d810.cfg.flowgraph import FlowGraph
from d810.cfg.graph_modification import RedirectGoto
from d810.core.logging import getLogger
from d810.evaluator.hexrays_microcode.chains import (
    UseSite,
    find_all_uses_of_stkvar,
)

logger = getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SeveranceViolation:
    """A single use-def dominance severance.

    A violation indicates that after applying the proposed redirect,
    a definition in :attr:`src_block` would no longer dominate a use
    at :attr:`use_block` for the stack variable identified by
    ``(var_stkoff, var_size)``.

    Attributes:
        src_block: Block serial that defines the stack variable.
        new_target: New successor target after the redirect.
        var_stkoff: Stack offset of the affected variable.
        var_size: Operand size in bytes.
        use_block: Block serial of the orphaned use.
        use_ea: Effective address of the orphaned use instruction.
    """

    src_block: int
    new_target: int
    var_stkoff: int
    var_size: int
    use_block: int
    use_ea: int


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
    pre_cfg: FlowGraph, mod: RedirectGoto
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
    mod: RedirectGoto,
    mba: object,
    pre_cfg: FlowGraph,
    exclude_stkoffs: tuple[int, ...] = (),
) -> tuple[SeveranceViolation, ...]:
    """Detect use-def chains that would be severed by *mod*.

    Args:
        mod: The proposed :class:`RedirectGoto` modification.
        mba: An ``ida_hexrays.mba_t`` instance used to query DU chains
            and walk the source block's live instruction stream.
        pre_cfg: The pre-modification CFG snapshot.
        exclude_stkoffs: Stack offsets to ignore when reporting
            violations.  The dispatcher state variable's offset belongs
            here — its uses are the BST comparisons that we *want* to
            die after linearization, so they are not real severances.

    Returns:
        A (possibly empty) tuple of :class:`SeveranceViolation`s.
    """

    src = int(mod.from_serial)
    new_target = int(mod.new_target)

    defs = _collect_stkvar_defs_in_block(mba, src)
    if not defs:
        return ()

    excluded: frozenset[int] = frozenset(int(off) for off in exclude_stkoffs)

    post_adj = _build_post_mod_adjacency(pre_cfg, mod)
    entry = int(getattr(pre_cfg, "entry_serial", 0))
    dom_tree = compute_dom_tree(post_adj, entry=entry)

    violations: list[SeveranceViolation] = []
    for stkoff, size in defs:
        if stkoff in excluded:
            # Filtered out — typically the dispatcher state variable.
            continue
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
    "SeveranceViolation",
    "check_redirect_severs_use_def",
]
