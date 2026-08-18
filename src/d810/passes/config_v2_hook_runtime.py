"""Compile typed config-v2 pipelines into live Hex-Rays hook bindings.

The project-facing input is the typed ``pipeline_v2`` pass sequence.  This
module owns the unavoidable adapter boundary between those portable pass
declarations and Hex-Rays' instruction/block callback registrations.  It does
not inspect execution modes or legacy rule arrays: a project either contains a
non-empty v2 pipeline and produces one schedule, or fails before runtime state
is changed.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace

from d810.core.config import RuleConfiguration
from d810.core.execution_scope import ExecutionPipeline
from d810.ir.maturity import IRMaturity
from d810.passes.cleanup_family_adapter import (
    SIMPLE_FLATTENING_CLEANUP_PASS_ID,
    build_cleanup_family_adapter_pass,
)
from d810.passes.constant_simplification import (
    CONSTANT_SIMPLIFICATION_PASS_ID,
    build_constant_simplification_pass,
    constant_simplification_hook_rules,
)
from d810.passes.constant_simplification_options import (
    CompiledConstantSimplificationSchedule,
)
from d810.passes.hook_transform_passes import build_hook_transform_pass
from d810.passes.mba_simplify import (
    MBA_SIMPLIFY_PASS_ID,
    build_mba_simplify_pass,
    materialize_mba_transform_options,
)
from d810.passes.mba_transform_options import mba_transform_stages
from d810.passes.mba_solve import (
    MBA_SOLVE_PASS_ID,
    build_mba_solve_pass,
    mba_solve_implementation,
)
from d810.passes.mba_egraph import (
    MBA_EGRAPH_PASS_ID,
    build_mba_egraph_pass,
)
from d810.passes.rotate_idiom_recovery import (
    ROTATE_IDIOM_RECOVERY_IMPLEMENTATION,
    ROTATE_IDIOM_RECOVERY_PASS_ID,
    build_rotate_idiom_recovery_pass,
)
from d810.passes.pass_pipeline import PipelineConfig, PipelineConfigError
from d810.passes.pipeline_config_parser import (
    pipeline_configs_from_project_config,
)
from d810.passes.state_machine_options import (
    STATE_MACHINE_NATIVE_PASS_IDS,
    StateMachineCffFamily,
    StateMachineRecoveryStrategy,
    state_machine_cff_options_from_config,
)

STATE_MACHINE_UNFLATTENER_RULE = "StateMachineCffUnflattener"
STATE_MACHINE_RUNTIME_HOST = STATE_MACHINE_UNFLATTENER_RULE


def _migration_message(project_path: object) -> str:
    path = str(project_path) if project_path is not None else "PROJECT"
    return (
        f"project {path} has no non-empty additional_configuration.pipeline_v2; "
        "migrate it with: python tools/migrations/migrate_project_config_v2.py "
        f"{path} --in-place"
    )


@dataclass(frozen=True, slots=True)
class ConfigV2HookSchedule:
    """Live callback bindings compiled from one valid config-v2 pipeline."""

    configured_pass_ids: tuple[str, ...]
    instruction_bindings: tuple[RuleConfiguration, ...] = ()
    block_bindings: tuple[RuleConfiguration, ...] = ()
    native_state_machine_pass_ids: tuple[str, ...] = ()
    global_const_persistence_enabled: bool = False
    constant_simplification_schedule: CompiledConstantSimplificationSchedule | None = None

    @property
    def instruction_rules(self) -> tuple[RuleConfiguration, ...]:
        return self.instruction_bindings

    @property
    def block_rules(self) -> tuple[RuleConfiguration, ...]:
        return self.block_bindings


def requires_native_preanalysis_handlers(
    schedule: ConfigV2HookSchedule,
) -> bool:
    """Whether this schedule needs generated-restart consumption.

    The complete native state-machine spine can stage dispatcher-recovery
    evidence after the first generated MBA.  Its controller-owned retry must
    reach the flowchart handler that consumes that evidence exactly once.
    """
    return bool(
        schedule.native_state_machine_pass_ids == STATE_MACHINE_NATIVE_PASS_IDS
    )


def _rule_config(name: str, config: object) -> RuleConfiguration:
    if config is None:
        config = {}
    if not isinstance(config, Mapping):
        raise PipelineConfigError(f"{name} runtime hook options must be a mapping")
    return RuleConfiguration(
        name=name,
        is_activated=True,
        config=dict(config),
    )


def _state_machine_rule_config(
    configs: tuple[PipelineConfig, ...],
) -> RuleConfiguration:
    native_configs = tuple(
        config for config in configs if config.pass_id in STATE_MACHINE_NATIVE_PASS_IDS
    )
    if not native_configs:
        raise PipelineConfigError("state-machine native spine is empty")
    pass_ids = tuple(config.pass_id for config in native_configs)
    if pass_ids != STATE_MACHINE_NATIVE_PASS_IDS:
        raise PipelineConfigError(
            "config-v2 state-machine spine must contain the complete native pass "
            f"sequence: {list(STATE_MACHINE_NATIVE_PASS_IDS)}"
        )

    options = tuple(
        state_machine_cff_options_from_config(config) for config in native_configs
    )
    first = options[0]
    if any(value != first for value in options[1:]):
        raise PipelineConfigError(
            "state-machine native spine entries disagree on typed options"
        )
    hook_options: dict[str, object] = {"min_state_constant": first.min_state_constant}
    if first.family is StateMachineCffFamily.TIGRESS_INDIRECT:
        hook_options["profile"] = "tigress_indirect"
    if first.recovery_strategy is StateMachineRecoveryStrategy.REDUCED_PRODUCT:
        hook_options["recovery_engine"] = "reduced_product"
    return _rule_config(
        STATE_MACHINE_RUNTIME_HOST,
        hook_options,
    )


def _mba_simplify_rules_from(
    config: PipelineConfig,
) -> tuple[tuple[RuleConfiguration, ...], tuple[RuleConfiguration, ...]]:
    """Route selected MBA transforms through their declared execution pipeline."""
    adapter = build_mba_simplify_pass(config)
    stages_by_id = {stage.stage_id: stage for stage in mba_transform_stages()}
    instruction_bindings: list[RuleConfiguration] = []
    block_bindings: list[RuleConfiguration] = []
    for transform_id, implementation_name in zip(
        adapter.transform_ids,
        adapter.implementation_names,
        strict=True,
    ):
        stage = stages_by_id[transform_id]
        if stage.pipeline is ExecutionPipeline.INSTRUCTION:
            instruction_bindings.append(
                _rule_config(
                    implementation_name,
                    {
                        **materialize_mba_transform_options(
                            transform_id,
                            adapter.transform_options.get(transform_id, {}),
                        ),
                        "generate_commutative_permutations": (
                            adapter.generate_commutative_permutations
                        ),
                    },
                )
            )
        elif stage.pipeline is ExecutionPipeline.FLOW:
            block_bindings.append(
                _rule_config(
                    implementation_name,
                    materialize_mba_transform_options(
                        transform_id,
                        adapter.transform_options.get(transform_id, {}),
                    ),
                )
            )
        else:
            raise PipelineConfigError(
                f"mba-simplify transform {transform_id!r} has unsupported pipeline "
                f"{stage.pipeline.value!r}"
            )
    return tuple(instruction_bindings), tuple(block_bindings)


# The rule implementing ``mba-solve`` is declared by whichever extension
# provides it; d810 ships no solver. See ``mba_solve.mba_solve_implementation``.


def _mba_solve_options(config: PipelineConfig) -> dict[str, object]:
    """Validate ``mba-solve`` options through its pass and pass them to the rule."""
    adapter = build_mba_solve_pass(config)
    return {
        "max_leaves": adapter.max_leaves,
        "require_proof": adapter.require_proof,
        # Portable IRMaturity names; the rule maps them to MMAT_* so this layer
        # stays hexrays-agnostic.
        "maturities": list(adapter.maturities),
        # The rule sees only what is forwarded here, so anything the pass
        # validates and the editor offers must appear in this dict or it is a
        # setting that looks configurable and silently does nothing.
        "auto_install_solver": adapter.auto_install_solver,
    }


def _mba_egraph_options(config: PipelineConfig) -> dict[str, object]:
    adapter = build_mba_egraph_pass(config)
    return {
        "max_leaves": adapter.max_leaves,
        "max_operator_nodes": adapter.max_operator_nodes,
        "max_degree": adapter.max_degree,
        "saturation_rounds": adapter.saturation_rounds,
        "max_eclasses": adapter.max_eclasses,
        "max_enodes": adapter.max_enodes,
        "max_rule_firings": adapter.max_rule_firings,
        "cross_block_constant_preparation": (
            adapter.cross_block_constant_preparation
        ),
        "cross_block_def_use_preparation": (
            adapter.cross_block_def_use_preparation
        ),
        "learned_replay_enabled": adapter.learned_replay_enabled,
        "learned_replay_max_entries": adapter.learned_replay_max_entries,
        "learned_replay_max_bytes": adapter.learned_replay_max_bytes,
        "time_budget_ms": adapter.time_budget_ms,
        "function_time_budget_ms": adapter.function_time_budget_ms,
        "residual_only": adapter.residual_only,
        "require_proof": adapter.require_proof,
        "collect_stage_timings": adapter.collect_stage_timings,
        "execution_mode": adapter.execution_mode,
        "native_proof_mode": adapter.native_proof_mode,
        "families": list(adapter.families),
        # Keep portable maturity vocabulary across the config-v2 boundary.
        # The live e-graph rule resolves it through d810.hexrays.ir_maturity.
        "maturities": list(adapter.maturities),
    }


def _rotate_idiom_recovery_options(config: PipelineConfig) -> dict[str, object]:
    adapter = build_rotate_idiom_recovery_pass(config)
    return {"maturities": list(adapter.maturities)}


def _flow_rule_from(config: PipelineConfig) -> RuleConfiguration:
    adapter = build_hook_transform_pass(config)
    return _rule_config(adapter.implementation_name, adapter.transform_options)


def _cleanup_family_rule_from(config: PipelineConfig) -> RuleConfiguration:
    adapter = build_cleanup_family_adapter_pass(config)
    return _rule_config(adapter.implementation_name, adapter.transform_options)


def _dedupe_rule_configs(
    rules: list[RuleConfiguration],
    *,
    field_name: str,
) -> tuple[RuleConfiguration, ...]:
    seen: dict[str, dict[str, object]] = {}
    ordered: list[RuleConfiguration] = []
    for rule in rules:
        name = str(rule.name or "")
        if not name:
            raise PipelineConfigError(f"{field_name} contains an empty rule name")
        config = dict(rule.config)
        if name in seen:
            if seen[name] != config:
                raise PipelineConfigError(
                    f"{field_name} contains conflicting duplicate config for {name}"
                )
            continue
        seen[name] = config
        ordered.append(rule)
    return tuple(ordered)


def _validate_constant_simplification_ownership(
    configs: tuple[PipelineConfig, ...],
) -> None:
    bundles = tuple(
        config
        for config in configs
        if config.pass_id == CONSTANT_SIMPLIFICATION_PASS_ID
    )
    if not bundles:
        return
    if len(bundles) != 1:
        raise PipelineConfigError(
            "constant-simplification may appear at most once in pipeline_v2"
        )
    conflicting_passes = {"forward-constant-propagation"}
    for config in configs:
        if config.pass_id in conflicting_passes:
            raise PipelineConfigError(
                "constant-simplification cannot coexist with legacy constant pass "
                f"{config.pass_id!r}"
            )


def _constrain_state_machine_constant_schedule(
    schedule: CompiledConstantSimplificationSchedule,
) -> CompiledConstantSimplificationSchedule:
    """Keep state-machine forward propagation in its post-recovery window."""
    forward = schedule.stage("forward-constants")
    if not forward.enabled:
        return schedule
    effective = tuple(
        maturity
        for maturity in forward.effective_maturities
        if maturity is IRMaturity.GLOBAL_OPTIMIZED
    )
    if not effective:
        raise PipelineConfigError(
            "state-machine constant-simplification requires forward-constants "
            "to include GLOBAL_OPTIMIZED, or the stage must be disabled"
        )
    constrained = replace(forward, effective_maturities=effective)
    return replace(
        schedule,
        stages=tuple(
            constrained if stage.stage_id == forward.stage_id else stage
            for stage in schedule.stages
        ),
    )


def _runtime_pipeline_configs(project_config) -> tuple[PipelineConfig, ...]:
    """Parse the required v2 payload and attach the offline migration remedy."""
    try:
        configs = pipeline_configs_from_project_config(project_config)
    except PipelineConfigError as exc:
        if "pipeline_v2 must contain at least one pass config" in str(exc):
            raise PipelineConfigError(
                _migration_message(getattr(project_config, "path", None))
            ) from exc
        raise
    if not configs:
        raise PipelineConfigError(
            _migration_message(getattr(project_config, "path", None))
        )
    return configs


def compile_config_v2_hook_schedule(project_config) -> ConfigV2HookSchedule:
    """Compile one non-empty typed v2 pipeline into callback bindings.

    ``pipeline_configs_from_project_config`` intentionally remains a permissive
    parser for the migration release.  This runtime boundary is stricter: a
    missing or empty pipeline is never treated as an inert activation and gets
    a copyable offline migration command instead.
    """
    configs = _runtime_pipeline_configs(project_config)
    _validate_constant_simplification_ownership(configs)

    instruction_bindings: list[RuleConfiguration] = []
    block_bindings: list[RuleConfiguration] = []
    global_const_persistence_enabled = False
    constant_simplification_schedule = None
    native_present = any(
        config.pass_id in STATE_MACHINE_NATIVE_PASS_IDS for config in configs
    )
    if native_present:
        block_bindings.append(_state_machine_rule_config(configs))

    for config in configs:
        pass_id = config.pass_id
        if pass_id == CONSTANT_SIMPLIFICATION_PASS_ID:
            constant_simplification_schedule = build_constant_simplification_pass(
                config
            ).options
            if native_present:
                constant_simplification_schedule = (
                    _constrain_state_machine_constant_schedule(
                        constant_simplification_schedule
                    )
                )
            global_const_persistence_enabled = bool(
                constant_simplification_schedule.preparation.enabled
            )
            bundle = constant_simplification_hook_rules(
                config,
                forward_constant_options=(
                    {
                        # The accelerated path still identifies stack cells by
                        # SSA valnum.  State-machine recovery creates the
                        # post-recovery cross-block storage identity this pass
                        # needs, so use the equivalent Python evaluator here.
                        "cython_enabled": False,
                    }
                    if native_present
                    else None
                ),
                schedule=constant_simplification_schedule,
            )
            instruction_bindings.extend(bundle.instruction_rules)
            block_bindings.extend(bundle.block_rules)
            continue
        if pass_id == MBA_SIMPLIFY_PASS_ID:
            mba_instruction_bindings, mba_block_bindings = _mba_simplify_rules_from(
                config
            )
            instruction_bindings.extend(mba_instruction_bindings)
            block_bindings.extend(mba_block_bindings)
            continue
        if pass_id == MBA_SOLVE_PASS_ID:
            # Solver-backed simplification is a single instruction rule rather
            # than a transform list, so it needs its own branch: without one it
            # falls through to _flow_rule_from below and is misfiled as a block
            # rule, which silently never runs.
            rule_name = mba_solve_implementation()
            if rule_name is None:
                # Nothing installed implements it. Emitting a rule config for a
                # class that will never register would put an unresolvable name
                # into the hook pipeline; skipping leaves mba-solve simply
                # absent, which is what "no solver installed" means.
                continue
            instruction_bindings.append(
                _rule_config(rule_name, _mba_solve_options(config))
            )
            continue
        if pass_id == MBA_EGRAPH_PASS_ID:
            from d810.backends import registry

            backend_registry = registry()
            candidate = backend_registry.require_unique_implementation(
                MBA_EGRAPH_PASS_ID,
                install_hint="d810-egglog",
            )
            backend_registry.activate_implementation(candidate)
            instruction_bindings.append(
                _rule_config(candidate.rule_name, _mba_egraph_options(config))
            )
            continue
        if pass_id == ROTATE_IDIOM_RECOVERY_PASS_ID:
            block_bindings.append(
                _rule_config(
                    ROTATE_IDIOM_RECOVERY_IMPLEMENTATION,
                    _rotate_idiom_recovery_options(config),
                )
            )
            continue
        if pass_id in STATE_MACHINE_NATIVE_PASS_IDS:
            continue
        if pass_id == SIMPLE_FLATTENING_CLEANUP_PASS_ID:
            block_bindings.append(_cleanup_family_rule_from(config))
            continue
        block_bindings.append(_flow_rule_from(config))

    return ConfigV2HookSchedule(
        configured_pass_ids=tuple(config.pass_id for config in configs),
        instruction_bindings=_dedupe_rule_configs(
            instruction_bindings,
            field_name="pipeline_v2 instruction rules",
        ),
        block_bindings=_dedupe_rule_configs(
            block_bindings,
            field_name="pipeline_v2 block rules",
        ),
        native_state_machine_pass_ids=(
            STATE_MACHINE_NATIVE_PASS_IDS if native_present else ()
        ),
        global_const_persistence_enabled=global_const_persistence_enabled,
        constant_simplification_schedule=constant_simplification_schedule,
    )


def config_v2_native_state_machine_configs(
    project_config,
) -> tuple[PipelineConfig, ...]:
    """Return only native state-machine spine configs from a v2 payload."""
    configs = _runtime_pipeline_configs(project_config)
    return tuple(
        config
        for config in configs
        if config.pass_id in STATE_MACHINE_NATIVE_PASS_IDS
    )


__all__ = [
    "ConfigV2HookSchedule",
    "STATE_MACHINE_NATIVE_PASS_IDS",
    "STATE_MACHINE_RUNTIME_HOST",
    "STATE_MACHINE_UNFLATTENER_RULE",
    "compile_config_v2_hook_schedule",
    "config_v2_native_state_machine_configs",
    "requires_native_preanalysis_handlers",
]
