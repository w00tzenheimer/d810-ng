"""Engine strategy for proven selector/state-machine shell facts."""
from __future__ import annotations

from collections.abc import Sequence

from d810.transforms.graph_modification import GraphModification, RedirectBranch, RedirectGoto
from d810.transforms.selector_shell_planning import plan_selector_shell_cleanup
from d810.core.typing import TYPE_CHECKING
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    FAMILY_CLEANUP,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.analyses.control_flow.selector_shell import (
    SELECTOR_SHELL_FACTS_METADATA_KEY,
    extract_selector_shell_facts,
    serialize_selector_shell_facts,
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
    return OwnershipScope(
        blocks=frozenset(blocks),
        edges=frozenset(edges),
        transitions=frozenset(),
    )


class SelectorShellStrategy:
    """Materialize CFG redirects from normalized selector-shell evidence."""

    name = "selector_shell"
    family = FAMILY_CLEANUP

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        return bool(extract_selector_shell_facts(snapshot.flow_graph))

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        if snapshot.flow_graph is None:
            return None
        facts = extract_selector_shell_facts(snapshot.flow_graph)
        if not facts:
            return None
        modifications = plan_selector_shell_cleanup(facts, snapshot.flow_graph)
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
                SELECTOR_SHELL_FACTS_METADATA_KEY: serialize_selector_shell_facts(
                    facts
                ),
                "safeguard_min_required": 1,
            },
            modifications=list(modifications),
        )


__all__ = ["SelectorShellStrategy"]
