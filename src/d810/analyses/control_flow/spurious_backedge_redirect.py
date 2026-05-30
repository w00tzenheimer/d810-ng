"""Plan disconnect-redirects for spurious back-edges (Piece 3a of uee-32r3).

Composes ``compute_live_cfg_sccs`` (Piece 1) and ``classify_backedges``
(Piece 2). For each cyclic SCC, finds SPURIOUS back-edges and proposes
forward-redirects on the small subset that are safely actionable.

Actionable subset: source is ``BLT_2WAY`` with exactly two successors
where one is the SPURIOUS edge's target. The "other" successor is the
safe-alternative redirect target — converting the conditional tail to
``goto safe_alternative`` removes the back-edge while preserving control
flow that would otherwise have fallen through the predicate's
true/false branch.

Conservative skips
------------------
- ``BLT_1WAY`` sources: target resolution requires reaching-def-based
  predicate simulation (a later piece of work), so we leave them alone.
- ``BLT_NWAY`` / ``BLT_STOP`` / unknown types: same reason.
- Edges where the "other" successor would still keep the source inside
  the SCC are still emitted — IDA's structurer reasons about *which*
  back-edges close cycles, and even reducing one back-edge often shifts
  rendering toward a cleaner ``while``/``do-while`` shape.

Caller responsibilities
-----------------------
The planner is pure-Python and namespace-agnostic. The caller extracts
``block_writes`` / ``block_predicate_reads`` from a live ``mba_t`` and
populates ``block_types`` from ``mblock_t.type`` (mapped to the names
``BLT_1WAY``/``BLT_2WAY``/etc.). The Hodur-strategy wrapper handles all
of that.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.control_flow.backedge_classifier import (
    BackedgeClassification,
    classify_backedges,
)
from d810.analyses.control_flow.dominator import compute_dom_tree
from d810.analyses.control_flow.scc import compute_live_cfg_sccs, nontrivial_sccs
from d810.core.logging import getLogger
from d810.core.typing import Mapping, Sequence

logger = getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SpuriousRedirectPlan:
    """One actionable spurious-back-edge redirect.

    Parameters
    ----------
    src_serial : int
        Block whose tail is being rewritten.
    old_target : int
        SPURIOUS back-edge target; will be removed from src's successors.
    new_target : int
        Safe-alternative successor that becomes src's sole successor
        after the rewrite.
    reason : str
        Human-readable explanation copied from the underlying
        BackedgeClassification.reason.
    """

    src_serial: int
    old_target: int
    new_target: int
    reason: str


def plan_spurious_backedge_redirects(
    *,
    block_succs: Mapping[int, tuple[int, ...]],
    block_types: Mapping[int, str],
    block_writes: Mapping[int, frozenset[str]],
    block_predicate_reads: Mapping[int, frozenset[str]],
) -> tuple[SpuriousRedirectPlan, ...]:
    """Compose Pieces 1 + 2 and return the actionable redirect set.

    Returns plans in deterministic order: SCC reverse-topological, then
    by ``(src_serial, old_target)``.
    """
    sccs = compute_live_cfg_sccs(block_succs)
    dom_backedges = _dominator_backedges(block_succs)
    plans: list[SpuriousRedirectPlan] = []
    seen: set[tuple[int, int]] = set()

    for scc in nontrivial_sccs(sccs):
        edges = sorted(
            edge
            for edge in scc.cyclic_edges
            if edge in dom_backedges
        )
        if not edges:
            continue
        classifications = classify_backedges(
            edges,
            block_writes=block_writes,
            block_predicate_reads=block_predicate_reads,
        )
        for c in classifications:
            plan = _try_make_plan(
                c,
                block_succs=block_succs,
                block_types=block_types,
            )
            if plan is None:
                continue
            key = (plan.src_serial, plan.old_target)
            if key in seen:
                continue
            seen.add(key)
            plans.append(plan)

    return tuple(plans)


def _graph_nodes_and_roots(
    block_succs: Mapping[int, Sequence[int]],
) -> tuple[set[int], list[int]]:
    nodes: set[int] = set()
    preds: dict[int, set[int]] = {}
    for src, succs in block_succs.items():
        src_i = int(src)
        nodes.add(src_i)
        preds.setdefault(src_i, set())
        for succ in succs:
            succ_i = int(succ)
            nodes.add(succ_i)
            preds.setdefault(succ_i, set()).add(src_i)
    if not nodes:
        return set(), []
    roots = sorted(node for node in nodes if not preds.get(node))
    if 0 in nodes:
        roots = [0] + [node for node in roots if node != 0]
    return nodes, roots


def _dominator_backedges(
    block_succs: Mapping[int, Sequence[int]],
) -> frozenset[tuple[int, int]]:
    """Return edges whose target dominates their source."""

    nodes, roots = _graph_nodes_and_roots(block_succs)
    if not nodes:
        return frozenset()
    edges: set[tuple[int, int]] = set()
    covered: set[int] = set()
    entries = list(roots)
    if not entries:
        entries.append(min(nodes))

    while entries:
        entry = entries.pop(0)
        if entry in covered:
            continue
        dom_tree = compute_dom_tree(block_succs, entry=entry)
        reachable = set(dom_tree.idom)
        covered.update(reachable)
        for src, succs in block_succs.items():
            src_i = int(src)
            if src_i not in reachable:
                continue
            for succ in succs:
                succ_i = int(succ)
                if succ_i not in reachable:
                    continue
                if dom_tree.dominates(succ_i, src_i):
                    edges.add((src_i, succ_i))

        remaining_roots = [
            node for node in sorted(nodes - covered) if node not in entries
        ]
        if remaining_roots and not entries:
            entries.append(remaining_roots[0])
    return frozenset(edges)


def _try_make_plan(
    c: BackedgeClassification,
    *,
    block_succs: Mapping[int, tuple[int, ...]],
    block_types: Mapping[int, str],
) -> SpuriousRedirectPlan | None:
    """Decide whether ``c`` is actionable; return a plan or None."""
    if not c.is_spurious:
        return None

    src_type = block_types.get(c.src_serial, "")
    if src_type != "BLT_2WAY":
        return None

    succs = tuple(int(s) for s in block_succs.get(c.src_serial, ()))
    if len(succs) != 2:
        return None

    if c.tgt_serial not in succs:
        # Inconsistent inputs; skip rather than synthesize a plan.
        return None

    other_candidates = [s for s in succs if s != c.tgt_serial]
    if len(other_candidates) != 1:
        return None
    other = int(other_candidates[0])

    if other == c.src_serial:
        # Refuse to create a self-loop in a redirect.
        return None

    return SpuriousRedirectPlan(
        src_serial=int(c.src_serial),
        old_target=int(c.tgt_serial),
        new_target=other,
        reason=c.reason,
    )


def log_plans(plans: tuple[SpuriousRedirectPlan, ...]) -> None:
    """One INFO line per planned redirect."""
    if not plans:
        return
    logger.info("spurious back-edge redirect plans: %d", len(plans))
    for p in plans:
        logger.info(
            "spurious redirect: blk[%d] %d -> %d (was %d) — %s",
            p.src_serial,
            p.old_target,
            p.new_target,
            p.old_target,
            p.reason,
        )


__all__ = [
    "SpuriousRedirectPlan",
    "log_plans",
    "plan_spurious_backedge_redirects",
]
