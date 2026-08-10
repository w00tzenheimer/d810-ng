"""Portable unflatten pass shape: the canonical five-pass state-machine spine.

The five-pass spine is dispatcher-shape neutral: every standard kind (equality-chain, condition-chain,
switch-table) runs the SAME passes, which re-derive their own evidence from ``ctx.graph``.
This module owns the canonical 5-tuple — the DRY source consumed by the family
``pipeline_for`` implementations and config-v2 shadow migration.
"""

from __future__ import annotations

import dataclasses

from d810.core.deobfuscation_case import StrategyWorkflowStage
from d810.core.pass_editor_spec import (
    FieldControlKind,
    FieldEditorSpec,
    PassEditorSpec,
)
from d810.passes.pass_pipeline import (
    AnalysisContract,
    BackendRoute,
    FactRequirement,
    MaturityRange,
    PassContract,
    PassInvalidates,
    PassOutputs,
    PassPreserves,
    PassRequires,
    PassSafety,
    PassScope,
    PassSpec,
    default,
    live_mba,
    no_caps,
)
from d810.passes.registry import PassRegistry
from d810.passes.execution_stages import ExecutionPipeline, ExecutionStageDescriptor
from d810.passes.state_machine_options import (
    StateMachineCffOptions,
    state_machine_cff_options_from_config,
)
from d810.ir.maturity import IRMaturity
from d810.passes.unflatten.state_machine import (
    BOUND_CANONICAL_SEMANTIC_EVIDENCE,
    CANONICAL_SEMANTIC_EVIDENCE,
    CleanupResidualDispatcher,
    LowerCanonicalSemanticFragment,
    LowerStateMachine,
    PlanSemanticRegions,
    RecoverDispatcher,
    RecoverStateTransitions,
)

__all__ = [
    "CLEANUP_ANALYSES",
    "DISPATCHER_ANALYSES",
    "LOWER_ANALYSES",
    "SEMANTIC_LOWER_ANALYSES",
    "REGION_ANALYSES",
    "TRANSITION_ANALYSES",
    "register_state_machine_passes",
    "state_machine_pass_spec",
    "semantic_evidence_state_machine_passes",
    "standard_state_machine_passes",
    "state_machine_pass_registry",
]

DISPATCHER_ANALYSES = AnalysisContract(
    provided=frozenset(
        {
            "dispatcher_model",
            "recover_dispatcher",
            "recovered_machine",
        }
    )
)
TRANSITION_ANALYSES = AnalysisContract(
    required=frozenset({"recover_dispatcher"}),
    provided=frozenset(
        {
            "recover_state_transitions",
            "transition_result",
            "valrange_confirmable_count",
            CANONICAL_SEMANTIC_EVIDENCE,
            BOUND_CANONICAL_SEMANTIC_EVIDENCE,
        }
    ),
)
REGION_ANALYSES = AnalysisContract(
    required=frozenset({"recover_dispatcher", "transition_result"}),
    provided=frozenset({"plan_semantic_regions"}),
)
LOWER_ANALYSES = AnalysisContract(
    required=frozenset(
        {
            "plan_semantic_regions",
            "recover_dispatcher",
            "transition_result",
        }
    ),
    provided=frozenset({"lower_state_machine_plan_metadata"}),
)
SEMANTIC_LOWER_ANALYSES = AnalysisContract(
    required=LOWER_ANALYSES.required,
    provided=LOWER_ANALYSES.provided,
)
CLEANUP_ANALYSES = AnalysisContract()

STATE_MACHINE_MATURITY = MaturityRange(
    min=IRMaturity.CALL_MODELED,
    max=IRMaturity.GLOBAL_ANALYZED,
    preferred=IRMaturity.GLOBAL_ANALYZED,
)
ROLE_DISPATCHER_FACT = "role.dispatcher"
IR_BRANCH_TARGET_EVIDENCE = "ir.branch_target"
IR_STATE_VARIABLE_WRITE_EVIDENCE = "ir.state_variable_write"
RECOVERED_STATE_TRANSITION_FACT = "recovered.state_transition"
RECOVERED_REGION_FACT = "recovered.region"
RECOVERED_CFG_EDGE_FACT = "recovered.cfg_edge"
STALE_CFG_SHAPE_FACT = "ir.cfg_shape.stale"


def _state_machine_contract(
    *,
    requires_analyses: frozenset[str] = frozenset(),
    requires_evidence: frozenset[str] = frozenset(),
    requires_facts: frozenset[str] = frozenset(),
    outputs_facts: frozenset[str] = frozenset(),
    preserves_analyses: frozenset[str] = frozenset(),
    preserves_facts: frozenset[str] = frozenset(),
    invalidates_analyses: frozenset[str] = frozenset(),
    invalidates_facts: frozenset[str] = frozenset(),
    safety: PassSafety = PassSafety(),
) -> PassContract:
    return PassContract(
        scope=PassScope.FUNCTION,
        # Standard CFF families declare GLOBAL_ANALYZED; indirect-table variants can
        # enter at CALL_MODELED, so the native contract records the full supported range.
        maturity=STATE_MACHINE_MATURITY,
        requires=PassRequires(
            analyses=requires_analyses,
            evidence=requires_evidence,
            facts=FactRequirement(required=requires_facts),
        ),
        outputs=PassOutputs(facts=outputs_facts),
        preserves=PassPreserves(
            analyses=preserves_analyses,
            facts=preserves_facts,
        ),
        invalidates=PassInvalidates(
            analyses=invalidates_analyses,
            facts=invalidates_facts,
        ),
        safety=safety,
    )


DISPATCHER_CONTRACT = _state_machine_contract(
    outputs_facts=frozenset({ROLE_DISPATCHER_FACT}),
)
TRANSITION_CONTRACT = _state_machine_contract(
    requires_analyses=TRANSITION_ANALYSES.required,
    requires_evidence=frozenset(
        {IR_BRANCH_TARGET_EVIDENCE, IR_STATE_VARIABLE_WRITE_EVIDENCE}
    ),
    requires_facts=frozenset({ROLE_DISPATCHER_FACT}),
    outputs_facts=frozenset({RECOVERED_STATE_TRANSITION_FACT}),
)
REGION_CONTRACT = _state_machine_contract(
    requires_analyses=REGION_ANALYSES.required,
    requires_facts=frozenset({ROLE_DISPATCHER_FACT, RECOVERED_STATE_TRANSITION_FACT}),
    outputs_facts=frozenset({RECOVERED_REGION_FACT}),
)
MUTATING_STATE_MACHINE_PRESERVED_ANALYSES = frozenset({"function_boundaries"})
MUTATING_STATE_MACHINE_INVALIDATED_ANALYSES = frozenset(
    {"dominators", "loop_info", "postdominators", "regions"}
)
MUTATING_STATE_MACHINE_PRESERVED_FACTS = frozenset(
    {"raw_instruction_addresses", RECOVERED_CFG_EDGE_FACT}
)
MUTATING_STATE_MACHINE_INVALIDATED_FACTS = frozenset({STALE_CFG_SHAPE_FACT})
MUTATING_STATE_MACHINE_SAFETY = PassSafety(policy="golden", requires_oracle=True)

LOWER_CONTRACT = _state_machine_contract(
    requires_analyses=LOWER_ANALYSES.required,
    requires_facts=frozenset(
        {
            ROLE_DISPATCHER_FACT,
            RECOVERED_REGION_FACT,
            RECOVERED_STATE_TRANSITION_FACT,
        }
    ),
    outputs_facts=frozenset({RECOVERED_CFG_EDGE_FACT}),
    preserves_analyses=MUTATING_STATE_MACHINE_PRESERVED_ANALYSES,
    preserves_facts=MUTATING_STATE_MACHINE_PRESERVED_FACTS,
    invalidates_analyses=MUTATING_STATE_MACHINE_INVALIDATED_ANALYSES,
    invalidates_facts=MUTATING_STATE_MACHINE_INVALIDATED_FACTS,
    safety=MUTATING_STATE_MACHINE_SAFETY,
)
CLEANUP_CONTRACT = _state_machine_contract(
    preserves_analyses=MUTATING_STATE_MACHINE_PRESERVED_ANALYSES,
    preserves_facts=MUTATING_STATE_MACHINE_PRESERVED_FACTS,
    invalidates_analyses=MUTATING_STATE_MACHINE_INVALIDATED_ANALYSES,
    invalidates_facts=MUTATING_STATE_MACHINE_INVALIDATED_FACTS,
    safety=MUTATING_STATE_MACHINE_SAFETY,
)


_CONTRACTS_BY_PASS_ID = {
    "recover_dispatcher": DISPATCHER_CONTRACT,
    "recover_state_transitions": TRANSITION_CONTRACT,
    "plan_semantic_regions": REGION_CONTRACT,
    "lower_state_machine": LOWER_CONTRACT,
    "cleanup_residual_dispatcher": CLEANUP_CONTRACT,
}

_WORKFLOW_STAGE_BY_PASS_ID = {
    "recover_dispatcher": StrategyWorkflowStage.CANONICAL_ANALYSIS,
    "recover_state_transitions": StrategyWorkflowStage.CANONICAL_ANALYSIS,
    "plan_semantic_regions": StrategyWorkflowStage.CANONICAL_ANALYSIS,
    "lower_state_machine": StrategyWorkflowStage.CANONICAL_TRANSFORM,
    "cleanup_residual_dispatcher": StrategyWorkflowStage.BACKEND_PUBLICATION,
}

_STATE_MACHINE_EDITOR_SPEC = PassEditorSpec.fields_editor(
    (
        FieldEditorSpec(
            field_id="min_state_constant",
            label="Minimum state constant",
            path=("min_state_constant",),
            control=FieldControlKind.INTEGER,
            description="Minimum value accepted as a dispatcher state constant.",
            minimum=0,
            maximum=(1 << 64) - 1,
            default=StateMachineCffOptions().min_state_constant,
        ),
        FieldEditorSpec(
            field_id="family",
            label="Protection family",
            path=("family",),
            control=FieldControlKind.ENUM,
            description="Select the state-machine recovery family.",
            choices=("auto", "tigress-indirect"),
            default=StateMachineCffOptions().family.value,
        ),
        FieldEditorSpec(
            field_id="recovery_strategy",
            label="Recovery strategy",
            path=("recovery_strategy",),
            control=FieldControlKind.ENUM,
            description="Select the typed dispatcher-recovery strategy.",
            choices=("family", "reduced-product"),
            default=StateMachineCffOptions().recovery_strategy.value,
        ),
    )
)


def state_machine_pass_spec(
    pass_id: str,
    pass_factory,
    requirements,
    safety_policy,
    *,
    analyses: AnalysisContract,
    backend_route: BackendRoute = BackendRoute.MUTATION_BACKEND,
    workflow_stage: StrategyWorkflowStage | None = None,
) -> PassSpec:
    """Build a canonical state-machine pass spec with native contract metadata."""
    return PassSpec(
        pass_id,
        pass_factory,
        requirements,
        safety_policy,
        analyses=analyses,
        backend_route=backend_route,
        contract=_CONTRACTS_BY_PASS_ID[pass_id],
        workflow_stage=workflow_stage or _WORKFLOW_STAGE_BY_PASS_ID[pass_id],
    )


def register_state_machine_passes(registry: PassRegistry) -> PassRegistry:
    """Register the canonical state-machine CFF pass factories."""
    for spec in standard_state_machine_passes():
        def build(config, *, factory=spec.pass_factory):
            options = state_machine_cff_options_from_config(config)
            if factory is RecoverDispatcher:
                return factory(options=options)
            return factory()

        registry.register_configured(
            spec.pass_id,
            build,
            config_template=dataclasses.replace(
                spec.config,
                options=_STATE_MACHINE_EDITOR_SPEC.default_options(),
            ),
            stages=(
                ExecutionStageDescriptor(
                    spec.pass_id,
                    spec.pass_id,
                    ExecutionPipeline.FLOW,
                    spec.pass_factory.__name__,
                ),
            ),
            editor_spec=_STATE_MACHINE_EDITOR_SPEC,
        )
    return registry


def state_machine_pass_registry() -> PassRegistry:
    """Return a registry populated with the canonical state-machine pass ids."""
    return register_state_machine_passes(PassRegistry())


def standard_state_machine_passes() -> tuple[PassSpec, ...]:
    """Return the canonical five-pass unflatten state-machine spine, in order."""
    return (
        state_machine_pass_spec(
            "recover_dispatcher",
            RecoverDispatcher,
            live_mba,
            default,
            analyses=DISPATCHER_ANALYSES,
        ),
        state_machine_pass_spec(
            "recover_state_transitions",
            RecoverStateTransitions,
            live_mba,
            default,
            analyses=TRANSITION_ANALYSES,
        ),
        state_machine_pass_spec(
            "plan_semantic_regions",
            PlanSemanticRegions,
            no_caps,
            default,
            analyses=REGION_ANALYSES,
        ),
        state_machine_pass_spec(
            "lower_state_machine",
            LowerStateMachine,
            no_caps,
            default,
            analyses=LOWER_ANALYSES,
        ),
        state_machine_pass_spec(
            "cleanup_residual_dispatcher",
            CleanupResidualDispatcher,
            no_caps,
            default,
            analyses=CLEANUP_ANALYSES,
        ),
    )


def semantic_evidence_state_machine_passes() -> tuple[PassSpec, ...]:
    """Return the canonical evidence spine with one atomic publication owner."""
    standard = standard_state_machine_passes()
    return (
        standard[0],
        standard[1],
        standard[2],
        state_machine_pass_spec(
            "lower_state_machine",
            LowerCanonicalSemanticFragment,
            no_caps,
            default,
            analyses=SEMANTIC_LOWER_ANALYSES,
            backend_route=BackendRoute.FRAGMENT_PUBLICATION,
        ),
    )
