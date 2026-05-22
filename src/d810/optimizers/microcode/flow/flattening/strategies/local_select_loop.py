"""Cleanup strategy wrapper for local_select_loop facts."""
from __future__ import annotations

from collections.abc import Sequence

from d810.cfg.graph_modification import (
    ConvertToGoto,
    DuplicateBlock,
    GraphModification,
    RedirectBranch,
    RedirectGoto,
)
from d810.cfg.local_select_loop_planning import build_local_select_loop_modifications
from d810.core.typing import TYPE_CHECKING
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    FAMILY_CLEANUP,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.recon.flow.local_select_loop import (
    LOCAL_SELECT_LOOP_FIXES_METADATA_KEY,
    LocalSelectConvergenceLoopFix,
    LocalSelectDirectExitLoopFix,
    LocalSelectLoopCandidate,
    LocalSelectLoopFix,
    LocalSelectTerminalLoopFix,
    collect_local_select_loop_fixes,
    extract_local_select_loop_fixes,
    serialize_local_select_loop_fixes,
)

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
        AnalysisSnapshot,
    )


def _build_ownership(modifications: Sequence[GraphModification]) -> OwnershipScope:
    blocks: set[int] = set()
    edges: set[tuple[int, int]] = set()
    for mod in modifications:
        if isinstance(mod, (RedirectBranch, RedirectGoto)):
            blocks.add(int(mod.from_serial))
            edges.add((int(mod.from_serial), int(mod.old_target)))
        elif isinstance(mod, ConvertToGoto):
            blocks.add(int(mod.block_serial))
        elif isinstance(mod, DuplicateBlock):
            blocks.add(int(mod.source_block))
            if mod.pred_serial is not None:
                edges.add((int(mod.pred_serial), int(mod.source_block)))
    return OwnershipScope(
        blocks=frozenset(blocks),
        edges=frozenset(edges),
        transitions=frozenset(),
    )


class LocalSelectLoopStrategy:
    """Engine strategy for validated local_select_loop facts."""

    name = "local_select_loop"
    family = FAMILY_CLEANUP

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        return bool(extract_local_select_loop_fixes(snapshot.flow_graph))

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        fixes = extract_local_select_loop_fixes(snapshot.flow_graph)
        if not fixes:
            return None
        modifications = build_local_select_loop_modifications(fixes)
        if not modifications:
            return None
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            ownership=_build_ownership(modifications),
            prerequisites=[],
            expected_benefit=BenefitMetrics(
                handlers_resolved=0,
                transitions_resolved=0,
                blocks_freed=len(modifications),
                conflict_density=0.0,
            ),
            risk_score=0.2,
            metadata={
                LOCAL_SELECT_LOOP_FIXES_METADATA_KEY: (
                    serialize_local_select_loop_fixes(fixes)
                ),
                "safeguard_min_required": 1,
            },
            modifications=list(modifications),
        )


__all__ = [
    "LOCAL_SELECT_LOOP_FIXES_METADATA_KEY",
    "LocalSelectConvergenceLoopFix",
    "LocalSelectDirectExitLoopFix",
    "LocalSelectLoopCandidate",
    "LocalSelectLoopFix",
    "LocalSelectTerminalLoopFix",
    "LocalSelectLoopStrategy",
    "build_local_select_loop_modifications",
    "collect_local_select_loop_fixes",
    "extract_local_select_loop_fixes",
    "serialize_local_select_loop_fixes",
]
