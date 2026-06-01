"""Hodur profile strategy ordering for the shared unflattening engine."""
from __future__ import annotations

from d810.backends.hexrays.evidence.valrange_resolution import (
    ValrangeResolutionStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.terminal_loop_cleanup import (
    TerminalLoopCleanupStrategy,
)
from d810.backends.hexrays.evidence.dead_state_variable_elimination import (
    DeadStateVariableEliminationStrategy,
)
from d810.backends.hexrays.evidence.state_constant_return_fixup import (
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
from d810.backends.hexrays.evidence.counter_hoist import (
    CounterHoistStrategy,
)
from d810.backends.hexrays.mutation.return_frontier_carrier_preserve import (
    ReturnFrontierCarrierPreserveStrategy,
)
from d810.backends.hexrays.evidence.spurious_backedge_redirect import (
    SpuriousBackedgeRedirectStrategy,
)


# Reverse-shim (LS13 C3): the policy half (dataclass + env helpers) now lives in
# the backend-neutral d810.families.state_machine_cff.hodur; re-import it here so
# default_hodur_profile() + the 11 ida_hexrays-importing strategy classes (which
# MUST stay in optimizers) keep working. optimizers->families is downward-legal.
from d810.families.state_machine_cff.hodur import (  # noqa: E402
    HodurUnflatteningProfile,
    _env_name_set,
    _filter_strategies,
    _legacy_semantic_region_enabled,
    _standalone_srw_enabled,
)

__all__ = [
    "HodurUnflatteningProfile",
    "default_hodur_profile",
    "ALL_STRATEGIES",
    "EXPERIMENTAL_STRATEGIES",
    "LEGACY_STRATEGIES",
]


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
            "pipeline_summary",
            "post_pipeline_audit",
            "reachability_snapshot",
            "dispatcher_residue_cache",
            "post_pipeline_diagnostic_snapshot",
            "inline_add_stkvar_canonicalization",
            "terminal_byte_mbl_keep",
            "tag_all_mbl_keep",
            "tail_shaping",
            "may_only_probe",
            "bst_cleanup_reiteration_suppression",
            "may_only_probe_rerun",
            "reachable_mbl_keep",
        ),
    )


_DEFAULT_PROFILE = default_hodur_profile()
ALL_STRATEGIES: list[type] = list(_DEFAULT_PROFILE.strategy_classes)
EXPERIMENTAL_STRATEGIES: list[type] = list(_DEFAULT_PROFILE.experimental_strategy_classes)
LEGACY_STRATEGIES: list[type] = list(_DEFAULT_PROFILE.legacy_strategy_classes)
