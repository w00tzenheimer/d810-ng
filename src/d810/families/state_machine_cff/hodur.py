"""Hodur family: the §1a Family profile + the legacy strategy-selection policy.

Two backend-neutral Hodur-family concerns live here:

* :class:`HodurFamily` — the §1a ``Family`` profile (``detect`` + ``pipeline_for``):
  recognizes the state-variable CFF (Hodur) shape over a portable ``FlowGraph`` and
  declares the five-pass pipeline on the shared spine. Auto-registers via
  :class:`StateMachineCffFamily` / ``Registrant`` so the scanner discovers it on load.
* :class:`HodurUnflatteningProfile` — the runtime strategy-ordering policy (the POLICY
  half of the former ``optimizers/.../hodur/profile.py``) + the env-var helpers that
  select / filter strategy classes. The strategy *classes* themselves (which import
  ``ida_hexrays``) and ``default_hodur_profile()`` stay in ``profile.py``, which
  re-imports these names back (reverse-shim).

Both halves are hexrays-free (the §1a passes/analyses are portable); no microcode
patching happens here.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from d810.ir.flowgraph import FlowGraph
from d810.passes.pass_pipeline import PassSpec
from d810.analyses.control_flow.dispatcher_recovery import build_state_dispatcher_map_from_flow_graph
from d810.families.state_machine_cff.base import StateMachineCffFamily
from d810.families.state_machine_cff.pipeline import standard_state_machine_passes

__all__ = ["HodurFamily", "HodurUnflatteningProfile"]


class HodurFamily(StateMachineCffFamily):
    """State-variable CFF (Hodur) family: detection + pipeline shape. No microcode patching."""

    name = "hodur"

    def detect(self, graph: FlowGraph, capabilities, context=None):
        """Recognize the equality-chain (``CONDITIONAL_CHAIN``) Hodur state machine.

        Claims ONLY the equality-chain dispatcher shape via
        ``build_state_dispatcher_map_from_flow_graph`` — DISJOINT from ``ApproovFamily``'s
        switch/indirect, so at most one profile claims any graph and ``select_family`` is
        order-independent. The match IS the recovered ``StateDispatcherMap`` (truthy), so
        the pipeline only runs where a real equality-chain dispatcher is present.

        (Switch/masked detection briefly lived here as an M1 stopgap so abc could unflatten
        on §1a-portable; that now belongs to ``ApproovFamily``. The live entry still
        hardcodes ``HodurFamily()`` and never calls ``select_family``, so abc on the
        portable path awaits the cutover; production abc is unaffected — it runs via HCC.)
        """
        if graph is None or not hasattr(graph, "blocks"):
            return None
        return build_state_dispatcher_map_from_flow_graph(graph)

    def pipeline_for(self, match, context) -> "tuple[PassSpec, ...]":
        # DRY: the canonical five-pass spine lives in ``pipeline``; this family's
        # equality-chain shape runs it unchanged.
        return standard_state_machine_passes()


@dataclass(frozen=True, slots=True)
class HodurUnflatteningProfile:
    """Runtime policy and strategy ordering for the Hodur profile."""

    strategy_classes: tuple[type, ...]
    entrypoint_strategy_classes: tuple[type, ...]
    experimental_strategy_classes: tuple[type, ...]
    legacy_strategy_classes: tuple[type, ...]
    detector: str
    evidence_adapters: tuple[str, ...]
    audit_hooks: tuple[str, ...]
    post_apply_hooks: tuple[str, ...]
    executor_safeguard_profile: str = "hodur"

    def uses_evidence_adapter(self, name: str) -> bool:
        """Return whether this profile declares a named evidence adapter."""
        return name in self.evidence_adapters

    def enables_audit_hook(self, name: str) -> bool:
        """Return whether this profile declares a named audit hook."""
        return name in self.audit_hooks

    def enables_post_apply_hook(self, name: str) -> bool:
        """Return whether this profile declares a named post-apply hook."""
        return name in self.post_apply_hooks


def _env_name_set(name: str) -> set[str]:
    return {
        value.strip()
        for value in os.environ.get(name, "").split(",")
        if value.strip()
    }


def _filter_strategies(strategies: tuple[type, ...]) -> tuple[type, ...]:
    """Filter strategies via env vars D810_HODUR_ONLY / D810_HODUR_SKIP."""
    only = _env_name_set("D810_HODUR_ONLY")
    skip = _env_name_set("D810_HODUR_SKIP")
    out = tuple(strategies)
    if only:
        out = tuple(strategy for strategy in out if strategy.__name__ in only)
    if skip:
        out = tuple(strategy for strategy in out if strategy.__name__ not in skip)
    return out


def _legacy_semantic_region_enabled() -> bool:
    return (
        os.getenv("D810_HODUR_ENABLE_SEMANTIC_STRUCTURED_REGION", "").strip() == "1"
        or "SemanticStructuredRegionStrategy" in _env_name_set("D810_HODUR_ONLY")
    )


def _standalone_srw_enabled() -> bool:
    return (
        os.getenv("D810_RECON_ENABLE_STANDALONE_SRW", "").strip() == "1"
        and os.getenv("D810_RECON_SKIP_SRW_STRATEGY", "").strip() != "1"
    )
