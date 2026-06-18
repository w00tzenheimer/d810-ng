"""LLVM M1 front-lift maturity policy over portable FlowGraph metadata."""
from __future__ import annotations

from dataclasses import dataclass

from d810.ir.flowgraph import FlowGraph
from d810.ir.maturity import IRMaturity

__all__ = [
    "LLVM_M1_ACCEPTED_MATURITIES",
    "LLVM_M1_PREFERRED_MATURITY",
    "LlvmMaturityAssessment",
    "assess_flowgraph_maturity",
]


LLVM_M1_ACCEPTED_MATURITIES = frozenset(
    {
        IRMaturity.CALL_MODELED,
        IRMaturity.GLOBAL_ANALYZED,
        IRMaturity.GLOBAL_OPTIMIZED,
    }
)
LLVM_M1_PREFERRED_MATURITY = IRMaturity.GLOBAL_ANALYZED


@dataclass(frozen=True, slots=True)
class LlvmMaturityAssessment:
    """Readiness decision for the LLVM M1 front-lift route."""

    observed: IRMaturity | None
    accepted: bool
    preferred: bool
    reason: str = ""


def _coerce_maturity(value: object) -> IRMaturity | None:
    if isinstance(value, IRMaturity):
        return value
    if isinstance(value, str):
        try:
            return IRMaturity(value)
        except ValueError:
            try:
                return IRMaturity[value]
            except KeyError:
                return None
    return None


def assess_flowgraph_maturity(flow_graph: FlowGraph) -> LlvmMaturityAssessment:
    """Assess whether a portable ``FlowGraph`` is at an M1 candidate maturity.

    This function is intentionally backend-agnostic: it reads the canonical
    ``ir_maturity`` value published into ``FlowGraph.metadata`` by a producer.
    It never imports Hex-Rays or inspects raw backend maturity integers.
    """

    observed = _coerce_maturity(flow_graph.metadata.get("ir_maturity"))
    if observed is None:
        return LlvmMaturityAssessment(
            observed=None,
            accepted=False,
            preferred=False,
            reason="FlowGraph metadata does not carry a recognized ir_maturity",
        )
    if observed not in LLVM_M1_ACCEPTED_MATURITIES:
        return LlvmMaturityAssessment(
            observed=observed,
            accepted=False,
            preferred=False,
            reason=f"{observed.value} is outside the LLVM M1 candidate range",
        )
    return LlvmMaturityAssessment(
        observed=observed,
        accepted=True,
        preferred=observed is LLVM_M1_PREFERRED_MATURITY,
        reason=(
            "preferred provisional LLVM M1 freeze point"
            if observed is LLVM_M1_PREFERRED_MATURITY
            else "accepted LLVM M1 candidate maturity"
        ),
    )
