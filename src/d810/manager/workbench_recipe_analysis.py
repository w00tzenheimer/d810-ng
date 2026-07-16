"""Mutation-free live fact capture for Recipe Composer preflight."""

from __future__ import annotations

from d810.passes.analysis_manager import AnalysisManager
from d810.passes.function_pass_manager import DEFAULT_ANALYSIS_PROVIDERS


def collect_recipe_preflight_facts(
    recon_runtime: object | None,
    *,
    function_ea: int,
    target: object,
    provider_phase: object,
) -> AnalysisManager:
    """Capture current evidence and expose it through the contract facts API.

    This boundary invokes only the recon fact lifecycle.  It never constructs a
    pass, a mutation backend, or a decompilation request.
    """
    if recon_runtime is None:
        raise RuntimeError("Recon runtime is not available")
    capture = getattr(recon_runtime, "capture_maturity_facts", None)
    validated_view = getattr(recon_runtime, "validated_fact_view", None)
    if not callable(capture) or not callable(validated_view):
        raise RuntimeError("Recon runtime does not support recipe preflight")

    func_ea = int(function_ea)
    capture(
        target,
        func_ea=func_ea,
        provider_phase=provider_phase,
        phase="recipe_preflight",
    )
    provider_level = int(getattr(provider_phase, "provider_level"))
    input_facts = validated_view(func_ea, provider_level)
    return AnalysisManager(
        target,
        input_facts=input_facts,
        providers=DEFAULT_ANALYSIS_PROVIDERS,
    )


__all__ = ["collect_recipe_preflight_facts"]
