"""Fixpoint solver configuration."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Direction(Enum):
    """Direction in which a fixpoint analysis propagates state."""

    FORWARD = "forward"
    BACKWARD = "backward"


@dataclass(frozen=True)
class FixpointConfiguration:
    """Tunable knobs for a fixpoint run.

    Attributes:
        max_iterations: Hard cap on worklist iterations before the run is
            declared non-convergent.
        widening_threshold: Number of times a node may be revisited before
            :meth:`~d810.analyses.data_flow.domain.FlowDomain.widen` is
            applied instead of ``meet`` (ascending-chain acceleration).
        descending_iterations: Optional narrowing passes after the ascending
            fixpoint, to recover precision lost to widening.
        direction: Propagation direction (forward or backward).
    """

    max_iterations: int = 1000
    widening_threshold: int = 4
    descending_iterations: int = 0
    direction: Direction = Direction.FORWARD
