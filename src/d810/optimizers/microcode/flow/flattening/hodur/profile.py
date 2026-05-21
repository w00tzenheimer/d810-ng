"""Hodur profile strategy ordering for the shared unflattening engine."""
from __future__ import annotations

from dataclasses import dataclass
import os

from d810.optimizers.microcode.flow.flattening.hodur.strategies.valrange_resolution import (
    ValrangeResolutionStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.terminal_loop_cleanup import (
    TerminalLoopCleanupStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.dead_state_variable_elimination import (
    DeadStateVariableEliminationStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.state_constant_return_fixup import (
    StateConstantReturnFixupStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.linearized_flow_graph import (
    SemanticStructuredRegionStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.reconstruction import (
    StateWriteReconstructionStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.handler_chain_composer import (
    HandlerChainComposerStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.dispatcher_trampoline_skip import (
    DispatcherTrampolineSkipStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.counter_hoist import (
    CounterHoistStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.return_frontier_carrier_preserve import (
    ReturnFrontierCarrierPreserveStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.spurious_backedge_redirect import (
    SpuriousBackedgeRedirectStrategy,
)


__all__ = [
    "HodurUnflatteningProfile",
    "default_hodur_profile",
    "ALL_STRATEGIES",
    "EXPERIMENTAL_STRATEGIES",
    "LEGACY_STRATEGIES",
]


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


def default_hodur_profile() -> HodurUnflatteningProfile:
    """Build the default Hodur profile from current environment gates."""
    legacy_region_prefix = (
        (SemanticStructuredRegionStrategy,) if _legacy_semantic_region_enabled() else ()
    )
    experimental = _filter_strategies((
        *legacy_region_prefix,
        HandlerChainComposerStrategy,
        DispatcherTrampolineSkipStrategy,
        CounterHoistStrategy,
        ReturnFrontierCarrierPreserveStrategy,
        SpuriousBackedgeRedirectStrategy,
    ))
    entrypoint = _filter_strategies((
        *legacy_region_prefix,
        HandlerChainComposerStrategy,
        DispatcherTrampolineSkipStrategy,
        CounterHoistStrategy,
        ReturnFrontierCarrierPreserveStrategy,
        SpuriousBackedgeRedirectStrategy,
        *(
            (StateWriteReconstructionStrategy,)
            if _standalone_srw_enabled()
            else ()
        ),
    ))
    strategies = _filter_strategies((
        *legacy_region_prefix,
        HandlerChainComposerStrategy,
        DispatcherTrampolineSkipStrategy,
        CounterHoistStrategy,
        ReturnFrontierCarrierPreserveStrategy,
        StateConstantReturnFixupStrategy,
        DeadStateVariableEliminationStrategy,
        *(
            (StateWriteReconstructionStrategy,)
            if _standalone_srw_enabled()
            else ()
        ),
    ))
    legacy = (
        ValrangeResolutionStrategy,
        TerminalLoopCleanupStrategy,
        StateConstantReturnFixupStrategy,
        DeadStateVariableEliminationStrategy,
    )
    return HodurUnflatteningProfile(
        strategy_classes=strategies,
        entrypoint_strategy_classes=entrypoint,
        experimental_strategy_classes=experimental,
        legacy_strategy_classes=legacy,
        detector="hodur_state_machine",
        evidence_adapters=(
            "transition_report_store",
            "return_frontier_audit_store",
            "terminal_return_audit_store",
            "induction_fact_view",
        ),
        audit_hooks=(
            "return_frontier_pre_plan",
            "return_frontier_post_plan",
            "return_frontier_post_apply",
            "return_frontier_post_pipeline",
            "return_frontier_carrier_post_pipeline",
            "terminal_return_persistence",
        ),
        post_apply_hooks=(
            "bst_cleanup",
            "reachability_snapshot",
            "dispatcher_residue_cache",
            "sub7ffd_bundle_stabilization",
            "inline_add_stkvar_canonicalization",
            "terminal_byte_mbl_keep",
            "tail_shaping",
            "may_only_probe",
            "reachable_mbl_keep",
        ),
    )


_DEFAULT_PROFILE = default_hodur_profile()
ALL_STRATEGIES: list[type] = list(_DEFAULT_PROFILE.strategy_classes)
EXPERIMENTAL_STRATEGIES: list[type] = list(_DEFAULT_PROFILE.experimental_strategy_classes)
LEGACY_STRATEGIES: list[type] = list(_DEFAULT_PROFILE.legacy_strategy_classes)
