"""Hex-Rays composition root for portable GLBOPT2 dead-store liveness."""

from __future__ import annotations

from d810.backends.hexrays.evidence.instruction_value_flow_live import (
    build_live_instruction_flow,
)
from d810.evaluator.hexrays_microcode.dead_store_liveness import (
    HexRaysDeadStoreLivenessBackend as _PortableDeadStoreLivenessEvaluator,
)

__all__ = ["HexRaysDeadStoreLivenessBackend"]


class HexRaysDeadStoreLivenessBackend(_PortableDeadStoreLivenessEvaluator):
    """Bind the portable DSE evaluator to live Hex-Rays instruction facts."""

    def __init__(self) -> None:
        super().__init__(build_live_instruction_flow)
