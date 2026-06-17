"""Hex-Rays backend provider registration."""
from __future__ import annotations

from d810.backends.hexrays.evidence import condition_chain_analysis
from d810.capabilities.providers import (
    register_condition_chain_walkers,
    register_microcode_evidence,
)
from d810.hexrays.expr_mop_ops import HexRaysMopOps
from d810.ir.expr.mop_ops import register_mop_ops


def ensure_hexrays_fact_lifter_registered() -> None:
    """Ensure the Hex-Rays live fact lifter is installed."""
    from d810.backends.facts.ida import ensure_hexrays_lifter_registered

    ensure_hexrays_lifter_registered()


def register_hexrays_backend_providers() -> None:
    """Push Hex-Rays supplied providers into portable registries."""
    register_condition_chain_walkers(
        condition_chain_analysis.build_condition_chain_walker_provider()
    )
    register_microcode_evidence(
        condition_chain_analysis.build_microcode_evidence_provider()
    )
    register_mop_ops(HexRaysMopOps())
    ensure_hexrays_fact_lifter_registered()
