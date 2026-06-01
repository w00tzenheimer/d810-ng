"""Unit tests for shared engine planner exports and pure-Python behavior."""
from __future__ import annotations

from d810.transforms.graph_modification import RedirectGoto
from d810.optimizers.microcode.flow.flattening import engine
from d810.optimizers.microcode.flow.flattening.engine.planner import (
    PipelinePolicy,
    PlannerHintSignals,
    UnflatteningPlanner,
    compute_hint_adjustment,
)
from d810.transforms.plan_fragment import (
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
    FAMILY_DIRECT,
)
from d810.optimizers.microcode.flow.flattening.engine import planner as hodur_planner


def _fragment(
    name: str,
    *,
    prereqs: list[str] | None = None,
    handlers: int = 1,
) -> PlanFragment:
    return PlanFragment(
        strategy_name=name,
        family=FAMILY_DIRECT,
        ownership=OwnershipScope(
            blocks=frozenset(),
            edges=frozenset(),
            transitions=frozenset(),
        ),
        prerequisites=prereqs or [],
        expected_benefit=BenefitMetrics(
            handlers_resolved=handlers,
            transitions_resolved=handlers,
            blocks_freed=0,
            conflict_density=0.0,
        ),
        risk_score=0.0,
        modifications=[RedirectGoto(from_serial=1, old_target=2, new_target=3)],
    )


def test_engine_package_re_exports_planner_types() -> None:
    assert engine.UnflatteningPlanner is UnflatteningPlanner
    assert engine.PipelinePolicy is PipelinePolicy
    assert engine.PlannerHintSignals is PlannerHintSignals


def test_hodur_planner_shim_points_to_engine_symbols() -> None:
    assert hodur_planner.UnflatteningPlanner is UnflatteningPlanner
    assert hodur_planner.PipelinePolicy is PipelinePolicy
    assert hodur_planner.compute_hint_adjustment is compute_hint_adjustment


def test_order_fragments_respects_prerequisites() -> None:
    planner = UnflatteningPlanner()
    first = _fragment("first")
    second = _fragment("second", prereqs=["first"], handlers=10)

    ordered = planner.order_fragments([second, first])

    assert [fragment.strategy_name for fragment in ordered] == ["first", "second"]


def test_compute_hint_adjustment_boosts_direct_fragments() -> None:
    adjustment = compute_hint_adjustment(
        _fragment("direct"),
        PlannerHintSignals(transition_confidence=0.75),
    )

    assert adjustment.score_delta > 0.0
    assert "transition_report_boost" in adjustment.reasons
