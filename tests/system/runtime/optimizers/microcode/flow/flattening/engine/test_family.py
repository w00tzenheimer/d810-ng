"""Tests for the CFF strategy family abstraction."""
from __future__ import annotations

from d810.optimizers.microcode.flow.flattening import engine
from d810.optimizers.microcode.flow.flattening.engine.family import (
    CFFStrategyFamily,
    DetectionResult,
)
from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
    AnalysisSnapshot,
)
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
    UnflatteningStrategy,
    FAMILY_DIRECT,
)


class StubDetectionResult:
    @property
    def detected(self) -> bool:
        return True

    @property
    def description(self) -> str:
        return "stub"


class StubStrategy:
    name = "stub"
    family = FAMILY_DIRECT

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        return True

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            ownership=OwnershipScope(
                blocks=frozenset(),
                edges=frozenset(),
                transitions=frozenset(),
            ),
            prerequisites=[],
            expected_benefit=BenefitMetrics(
                handlers_resolved=1,
                transitions_resolved=1,
                blocks_freed=0,
                conflict_density=0.0,
            ),
            risk_score=0.0,
            modifications=[],
        )


class StubFamily(CFFStrategyFamily):
    @property
    def name(self) -> str:
        return "stub_family"

    def detect(self, mba: object) -> DetectionResult:
        return StubDetectionResult()

    def build_snapshot(
        self,
        mba: object,
        detection: DetectionResult,
    ) -> AnalysisSnapshot:
        return AnalysisSnapshot(mba=mba)

    @property
    def strategies(self) -> list[UnflatteningStrategy]:
        return [StubStrategy()]  # type: ignore[list-item]


def test_engine_package_re_exports_family_types() -> None:
    assert engine.CFFStrategyFamily is CFFStrategyFamily
    assert engine.DetectionResult is DetectionResult


def test_detection_result_protocol_shape() -> None:
    result = StubDetectionResult()
    assert isinstance(result, DetectionResult)
    assert result.detected is True
    assert result.description == "stub"


def test_strategy_family_provides_snapshot_and_strategies() -> None:
    family = StubFamily()
    detection = family.detect(object())
    snapshot = family.build_snapshot(object(), detection)

    assert family.name == "stub_family"
    assert detection.detected is True
    assert isinstance(snapshot, AnalysisSnapshot)
    assert len(family.strategies) == 1
    assert family.strategies[0].name == "stub"
