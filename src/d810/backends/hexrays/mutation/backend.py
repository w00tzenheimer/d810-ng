"""Hex-Rays mutation backend — the unflatten ``MutationBackend.apply`` boundary.

The ONLY place a unflatten ``PatchPlan`` becomes live ``mba`` edits. ``apply`` lowers the plan through the
existing ``IDAIRTranslator`` (PatchPlan -> DeferredGraphModifier queue) and then RE-LIFTS the
post-apply ``mba`` to a fresh ``FlowGraph`` snapshot — the new snapshot identity is the sound
invalidation epoch (Hex-Rays re-runs its own optimizer during/after apply, so the re-lift captures
the vendor's re-optimization, per unflatten / the LLVM AnalysisManager invalidation model).

Structurally satisfies the ``MutationBackend`` protocol (``passes.pass_pipeline``) without importing
it (upward edge); duck-typing suffices.
"""
from __future__ import annotations

from d810.ir.flowgraph import FlowGraph
from d810.hexrays.mutation.ir_translator import IDAIRTranslator
from d810.transforms.plan import PatchPlan


class HexRaysMutationBackend:
    """Apply unflatten PatchPlans to a live ``mba`` and return the re-lifted FlowGraph."""

    def __init__(self, translator: IDAIRTranslator | None = None) -> None:
        self._translator = translator or IDAIRTranslator()

    def capabilities(self) -> frozenset[str]:
        # "emulation" advertises the concolic block-emulator the unflatten entry registers as
        # the EmulationCapability (llr-11du). ADDITIVE: no standard pass requires it, so
        # advertising it is behaviour-neutral; only the INDIRECT pipeline (slice 2) reads
        # it, and there is no live indirect detector yet.
        return frozenset({"live_mba", "emulation"})

    def apply(
        self,
        rewrite_plan: PatchPlan,
        live_source: object,
        safety_policy: object = None,
    ) -> FlowGraph:
        """Lower the plan to live edits, then re-lift to a fresh snapshot (the new epoch)."""
        self._translator.lower(rewrite_plan, live_source)
        return self._translator.lift(live_source)
