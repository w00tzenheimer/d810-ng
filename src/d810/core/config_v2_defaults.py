"""Supported config-v2 default routing policy.

This module is deliberately about selection policy only. The config-v2 hook
bridge still derives executable hook rules from an explicit runtime
``ProjectConfiguration``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from d810.core.config import ProjectConfiguration


class ConfigV2DefaultRoutingError(RuntimeError):
    """Raised when supported config-v2 default routing is configured unsafely."""


@dataclass(frozen=True)
class ConfigV2DefaultMapping:
    source_config: str
    runtime_config: str
    expected_pass_ids: tuple[str, ...]


@dataclass(frozen=True)
class ConfigV2DefaultSelection:
    source_project: ProjectConfiguration
    runtime_project: ProjectConfiguration
    mapping: ConfigV2DefaultMapping
    routed: bool

    @property
    def source_config(self) -> str:
        return self.source_project.path.name

    @property
    def runtime_config(self) -> str:
        return self.runtime_project.path.name

    @property
    def expected_pass_ids(self) -> tuple[str, ...]:
        return self.mapping.expected_pass_ids


CONFIG_V2_SUPPORTED_DEFAULT_MAPPINGS: tuple[ConfigV2DefaultMapping, ...] = (
    ConfigV2DefaultMapping(
        source_config="default_instruction_only.json",
        runtime_config="default_instruction_only_config_v2_canary.json",
        expected_pass_ids=(
            "mba-simplify",
            "global-constant-inliner",
            "jump-fixer",
        ),
    ),
    ConfigV2DefaultMapping(
        source_config="default_unflattening_tigress_engine.json",
        runtime_config="default_unflattening_tigress_engine_config_v2_canary.json",
        expected_pass_ids=(
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
        ),
    ),
    ConfigV2DefaultMapping(
        source_config="hodur_flag2.json",
        runtime_config="hodur_flag2_config_v2_canary.json",
        expected_pass_ids=(
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
            "jump-fixer",
        ),
    ),
    ConfigV2DefaultMapping(
        source_config="hodur_glbopt2_only.json",
        runtime_config="hodur_glbopt2_only_config_v2_canary.json",
        expected_pass_ids=(
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
        ),
    ),
    ConfigV2DefaultMapping(
        source_config="eidolon.json",
        runtime_config="eidolon_config_v2_canary.json",
        expected_pass_ids=("mba-simplify",),
    ),
    ConfigV2DefaultMapping(
        source_config="default_unflattening_approov.json",
        runtime_config="default_unflattening_approov_config_v2_canary.json",
        expected_pass_ids=(
            "mba-simplify",
            "mba-state-preconditioner",
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
            "jump-fixer",
        ),
    ),
    ConfigV2DefaultMapping(
        source_config="default_unflattening_approov_s1a.json",
        runtime_config="default_unflattening_approov_s1a_config_v2_canary.json",
        expected_pass_ids=(
            "mba-simplify",
            "mba-state-preconditioner",
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
            "jump-fixer",
        ),
    ),
    ConfigV2DefaultMapping(
        source_config="hodur_flag2_s1a.json",
        runtime_config="hodur_flag2_s1a_config_v2_canary.json",
        expected_pass_ids=(
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
            "jump-fixer",
        ),
    ),
    ConfigV2DefaultMapping(
        source_config="hodur_flag2_with_fcp.json",
        runtime_config="hodur_flag2_with_fcp_config_v2_canary.json",
        expected_pass_ids=(
            "mba-simplify",
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
            "jump-fixer",
            "forward-constant-propagation",
        ),
    ),
    ConfigV2DefaultMapping(
        source_config="identity_call.json",
        runtime_config="identity_call_config_v2_canary.json",
        expected_pass_ids=("identity-call-resolver",),
    ),
    ConfigV2DefaultMapping(
        source_config="default_unflattening_tigress_engine_transition_facts.json",
        runtime_config=(
            "default_unflattening_tigress_engine_transition_facts_config_v2_canary.json"
        ),
        expected_pass_ids=(
            "mba-simplify",
            "forward-constant-propagation",
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
        ),
    ),
    ConfigV2DefaultMapping(
        source_config="example_libobfuscated_abc.json",
        runtime_config="example_libobfuscated_abc_config_v2_canary.json",
        expected_pass_ids=(
            "mba-simplify",
            "forward-constant-propagation",
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
            "jump-fixer",
        ),
    ),
    ConfigV2DefaultMapping(
        source_config="flatfold.json",
        runtime_config="flatfold_config_v2_canary.json",
        expected_pass_ids=(
            "mba-simplify",
            "mba-state-preconditioner",
            "global-constant-inliner",
            "jump-fixer",
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
        ),
    ),
    ConfigV2DefaultMapping(
        source_config="example_hodur.json",
        runtime_config="example_hodur_config_v2_canary.json",
        expected_pass_ids=(
            "mba-simplify",
            "forward-constant-propagation",
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
            "jump-fixer",
        ),
    ),
    # Fence lifted (d81-xkw8): OLLVM + indirect were fenced by policy, not
    # technical blocker -- their canaries + parity rows are already proven green.
    ConfigV2DefaultMapping(
        source_config="default_unflattening_ollvm.json",
        runtime_config="default_unflattening_ollvm_config_v2_canary.json",
        expected_pass_ids=(
            "mba-simplify",
            "indirect-call-resolver",
            "mba-state-preconditioner",
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
            "simple-flattening-cleanup-unflattener",
            "jump-fixer",
        ),
    ),
    ConfigV2DefaultMapping(
        source_config="default_indirect_resolution.json",
        runtime_config="default_indirect_resolution_config_v2_canary.json",
        expected_pass_ids=(
            "indirect-branch-resolver",
            "indirect-call-resolver",
        ),
    ),
    ConfigV2DefaultMapping(
        source_config="default_unflattening_tigress_indirect.json",
        runtime_config="default_unflattening_tigress_indirect_config_v2_canary.json",
        expected_pass_ids=(
            "mba-simplify",
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
            "jump-fixer",
        ),
    ),
    ConfigV2DefaultMapping(
        source_config="default.json",
        runtime_config="default_config_v2_canary.json",
        expected_pass_ids=(
            "indirect-branch-resolver",
            "indirect-call-resolver",
        ),
    ),
    ConfigV2DefaultMapping(
        source_config="example_libobfuscated_no_fixprecedessor.json",
        runtime_config="example_libobfuscated_no_fixprecedessor_config_v2_canary.json",
        expected_pass_ids=(
            "mba-simplify",
            "forward-constant-propagation",
            "simple-flattening-cleanup-unflattener",
            "jump-fixer",
        ),
    ),
    ConfigV2DefaultMapping(
        source_config="bogus_loops.json",
        runtime_config="bogus_loops_config_v2_canary.json",
        expected_pass_ids=(
            "single-trip-loop-peel",
            "mba-state-preconditioner",
            "jump-fixer",
        ),
    ),
    ConfigV2DefaultMapping(
        source_config="example_libobfuscated.json",
        runtime_config="example_libobfuscated_config_v2_canary.json",
        expected_pass_ids=(
            "mba-simplify",
            "global-constant-inliner",
            "forward-constant-propagation",
            "mba-state-preconditioner",
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
            "jump-fixer",
        ),
    ),
)

_MAPPINGS_BY_SOURCE = {
    mapping.source_config: mapping for mapping in CONFIG_V2_SUPPORTED_DEFAULT_MAPPINGS
}
_MAPPINGS_BY_RUNTIME = {
    mapping.runtime_config: mapping for mapping in CONFIG_V2_SUPPORTED_DEFAULT_MAPPINGS
}


def bundled_config_dir() -> Path:
    """Return the built-in project configuration directory."""
    return Path(__file__).resolve().parent.parent / "conf"


def bundled_config_path(config_name: str) -> Path:
    return bundled_config_dir() / config_name


def is_bundled_project_config(project: ProjectConfiguration) -> bool:
    """Return true only for checked-in bundled project configs.

    User configs intentionally override bundled configs by basename elsewhere in
    the configuration loader. Default routing must therefore verify provenance
    by path, not by filename alone.
    """
    try:
        project_path = project.path.resolve()
        conf_dir = bundled_config_dir().resolve()
    except Exception:
        project_path = Path(project.path)
        conf_dir = bundled_config_dir()
    return project_path.parent == conf_dir and project_path.exists()


def select_config_v2_default_project(
    source_project: ProjectConfiguration,
) -> ConfigV2DefaultSelection | None:
    """Select a bundled config-v2 canary for supported bundled source configs.

    Config-v2 is the runtime for every bundled project config: routing is
    unconditional. User-provided configs (not bundled) are never routed and run
    their own rules unchanged.
    """
    project_name = source_project.path.name
    mapping = _MAPPINGS_BY_SOURCE.get(project_name)
    if mapping is not None:
        if not is_bundled_project_config(source_project):
            return None
        runtime_project = ProjectConfiguration.from_file(
            bundled_config_path(mapping.runtime_config)
        )
        if not is_bundled_project_config(runtime_project):
            raise ConfigV2DefaultRoutingError(
                "supported config-v2 default routing requires bundled canary "
                f"{mapping.runtime_config!r}"
            )
        return ConfigV2DefaultSelection(
            source_project=source_project,
            runtime_project=runtime_project,
            mapping=mapping,
            routed=True,
        )

    mapping = _MAPPINGS_BY_RUNTIME.get(project_name)
    if mapping is None:
        return None
    if not is_bundled_project_config(source_project):
        return None
    return ConfigV2DefaultSelection(
        source_project=source_project,
        runtime_project=source_project,
        mapping=mapping,
        routed=False,
    )


def format_config_v2_default_selection_status(
    *,
    selection: ConfigV2DefaultSelection,
) -> str:
    return (
        "CONFIG_V2_SUPPORTED_DEFAULT "
        f"source_project={selection.source_config!r} "
        f"runtime_project={selection.runtime_config!r} "
        f"routed={selection.routed!r} "
        "pipeline_v2_mode='config-v2' "
        f"expected_pass_ids={selection.expected_pass_ids!r}"
    )
