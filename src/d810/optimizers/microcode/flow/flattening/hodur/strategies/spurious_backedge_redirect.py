"""SpuriousBackedgeRedirectStrategy — smoke-test SCC normalization.

Composes Pieces 1 (live-CFG SCC analysis), 2 (back-edge classification)
and 3a (redirect planner) into a Hodur strategy that emits
``ConvertToGoto`` modifications for actionable SPURIOUS back-edges.

Status: **MEASUREMENT smoke test, not "the fix"**.

Scope is intentionally narrow: only ``BLT_2WAY``-source SPURIOUS
back-edges with two successors are redirected. ``BLT_1WAY`` SPURIOUS
edges and ``UNKNOWN`` classifications are left untouched — they need
register-token support and reaching-def-based forward-target resolution
that lives in future pieces of the SCC normalization plan.

Default-OFF. Opt-in via ``D810_HODUR_ENABLE_SPURIOUS_REDIRECT=1``. The
strategy logs topology metrics (SCC count/sizes, within-SCC back-edge
count) before AND after planning so the operator can see the effect
empirically without the strategy being on by default.
"""
from __future__ import annotations

import os

from d810.transforms.modification_builder import ModificationBuilder
from d810.analyses.control_flow.scc import compute_live_cfg_sccs, nontrivial_sccs
from d810.analyses.control_flow.spurious_backedge_redirect import (
    plan_spurious_backedge_redirects,
)
from d810.core import logging
from d810.core.typing import TYPE_CHECKING
from d810.evaluator.hexrays_microcode.live_analysis_backend import (
    HexRaysLiveAnalysisBackend,
)
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    FAMILY_CLEANUP,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger(
    "D810.hodur.strategy.spurious_backedge_redirect", logging.INFO
)

__all__ = ["SpuriousBackedgeRedirectStrategy"]

_GATE_ENV = "D810_HODUR_ENABLE_SPURIOUS_REDIRECT"
_LIVE_ANALYSIS_BACKEND = HexRaysLiveAnalysisBackend()


class SpuriousBackedgeRedirectStrategy:
    """Convert spurious BLT_2WAY back-edges to forward gotos.

    Family: ``FAMILY_CLEANUP`` — runs after all other Hodur reconstruction
    passes when enabled.
    """

    @property
    def name(self) -> str:
        return "spurious_backedge_redirect"

    @property
    def family(self) -> str:
        return FAMILY_CLEANUP

    def is_applicable(self, snapshot: "AnalysisSnapshot") -> bool:
        if os.environ.get(_GATE_ENV, "").strip() != "1":
            return False
        if snapshot.mba is None:
            return False
        return True

    def plan(self, snapshot: "AnalysisSnapshot") -> PlanFragment | None:
        if not self.is_applicable(snapshot):
            return None

        mba = snapshot.mba
        topology_evidence = _LIVE_ANALYSIS_BACKEND.collect_block_topology(mba)
        predicate_evidence = (
            _LIVE_ANALYSIS_BACKEND.collect_predicate_read_write_evidence(mba)
        )
        block_succs = {
            int(evidence.serial): tuple(int(succ) for succ in evidence.succs)
            for evidence in topology_evidence
        }
        block_types = {
            int(evidence.serial): str(evidence.block_type)
            for evidence in topology_evidence
        }
        block_writes = {
            int(evidence.block_serial): frozenset(evidence.writes)
            for evidence in predicate_evidence
        }
        block_predicate_reads = {
            int(evidence.block_serial): frozenset(evidence.predicate_reads)
            for evidence in predicate_evidence
        }

        # Pre-plan topology snapshot.
        sccs_before = compute_live_cfg_sccs(block_succs)
        cyclic_before = nontrivial_sccs(sccs_before)
        biggest_before = max((s.size for s in cyclic_before), default=0)
        backedges_before = sum(len(s.cyclic_edges) for s in cyclic_before)
        logger.info(
            "SpuriousBackedgeRedirect: pre-plan topology — sccs=%d "
            "biggest_size=%d backedges=%d",
            len(cyclic_before),
            biggest_before,
            backedges_before,
        )

        plans = plan_spurious_backedge_redirects(
            block_succs=block_succs,
            block_types=block_types,
            block_writes=block_writes,
            block_predicate_reads=block_predicate_reads,
        )

        if not plans:
            logger.info("SpuriousBackedgeRedirect: no actionable plans")
            return None

        builder = ModificationBuilder.from_snapshot(snapshot)
        modifications: list = []
        owned_blocks: set[int] = set()
        for plan in plans:
            modifications.append(
                builder.convert_to_goto(plan.src_serial, plan.new_target)
            )
            owned_blocks.add(plan.src_serial)
            logger.info(
                "SpuriousBackedgeRedirect: blk[%d] %d -> %d (was conditional "
                "back-edge to %d) — %s",
                plan.src_serial,
                plan.new_target,
                plan.new_target,
                plan.old_target,
                plan.reason,
            )

        # Simulated post-plan topology (succs map after applying redirects).
        simulated_succs = dict(block_succs)
        for plan in plans:
            simulated_succs[plan.src_serial] = (plan.new_target,)
        sccs_after = compute_live_cfg_sccs(simulated_succs)
        cyclic_after = nontrivial_sccs(sccs_after)
        biggest_after = max((s.size for s in cyclic_after), default=0)
        backedges_after = sum(len(s.cyclic_edges) for s in cyclic_after)
        logger.info(
            "SpuriousBackedgeRedirect: simulated post-plan topology — "
            "sccs=%d biggest_size=%d backedges=%d (delta sccs=%+d "
            "biggest=%+d backedges=%+d)",
            len(cyclic_after),
            biggest_after,
            backedges_after,
            len(cyclic_after) - len(cyclic_before),
            biggest_after - biggest_before,
            backedges_after - backedges_before,
        )

        ownership = OwnershipScope(
            blocks=frozenset(owned_blocks),
            edges=frozenset(),
            transitions=frozenset(),
        )
        benefit = BenefitMetrics(
            handlers_resolved=0,
            transitions_resolved=len(plans),
            blocks_freed=0,
            conflict_density=0.0,
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=modifications,
            ownership=ownership,
            prerequisites=["handler_chain_composer", "dispatcher_trampoline_skip"],
            expected_benefit=benefit,
            risk_score=0.30,
            metadata={
                "execution_policy": "spurious_backedge_redirect",
                "smoke_test": True,
            },
        )
