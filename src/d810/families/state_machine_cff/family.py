"""Reusable family orchestrator for detect -> snapshot -> plan -> execute."""
from __future__ import annotations

import abc

from d810.core.typing import TYPE_CHECKING
from d810.families.protocols import DetectionResult

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
        AnalysisSnapshot,
    )
    # Canonical home (same families layer); engine.strategy only re-exports it.
    from d810.families.state_machine_cff.protocols import UnflatteningStrategy

__all__ = ["CFFStrategyFamily", "DetectionResult"]


class CFFStrategyFamily(abc.ABC):
    """Base class for CFF unflattening strategy families."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Unique name for this strategy family."""
        ...

    @abc.abstractmethod
    def detect(self, mba: object) -> DetectionResult:
        """Run family-specific detection on the microcode."""
        ...

    @abc.abstractmethod
    def build_snapshot(
        self,
        mba: object,
        detection: DetectionResult,
    ) -> AnalysisSnapshot:
        """Construct the immutable analysis snapshot from detection results."""
        ...

    @property
    @abc.abstractmethod
    def strategies(self) -> list[UnflatteningStrategy]:
        """Ordered list of strategies to poll during planning."""
        ...

    def post_execute_cleanup(
        self,
        mba: object,
        *,
        snapshot: AnalysisSnapshot,
        total_changes: int,
    ) -> int:
        """Run optional family-specific cleanup after successful execution.

        Families that need legacy post-apply cleanup can override this hook.
        The default implementation is a no-op.
        """
        return 0
