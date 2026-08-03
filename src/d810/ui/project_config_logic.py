"""Pure presentation and edit policy for project configuration UI."""
from __future__ import annotations

import dataclasses
import enum
import pathlib
from collections.abc import Sequence

from d810.manager.project_runtime import (
    ProjectConfigMode,
    ProjectRuntimeSnapshot,
    RuleProjectionKind,
)
from d810.ui.rule_tree_logic import RuleTreeContextTarget


V2_STRUCTURED_EDIT_EXPLANATION = (
    "Edit with the structured config-v2 editor; unsupported fields remain "
    "read-only and survive lossless save."
)
V2_CLONE_EXPLANATION = (
    "Duplicate will copy the complete effective runtime config-v2 document; "
    "the flat rule tree remains read-only."
)


class ConfigEditMode(str, enum.Enum):
    NEW = "new"
    DUPLICATE = "duplicate"
    EDIT = "edit"


class ConfigSaveStrategy(enum.Enum):
    CREATE_LEGACY = "create-legacy"
    SAVE_LEGACY_COPY = "save-legacy-copy"
    CLONE_RUNTIME_V2 = "clone-runtime-v2"
    STRUCTURED_V2 = "structured-v2"
    REFUSE = "refuse"


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigEditPolicy:
    allowed: bool
    rules_editable: bool
    save_strategy: ConfigSaveStrategy
    explanation: str


@dataclasses.dataclass(frozen=True, slots=True)
class ProjectConfigView:
    mode_text: str
    source_text: str
    source_tooltip: str
    runtime_text: str
    runtime_tooltip: str
    effective_passes_text: str
    rules_title: str
    enabled_rule_names: frozenset[str]
    edit_enabled: bool
    edit_tooltip: str


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2FocusTarget:
    """Conservative focus information for the structured config-v2 editor."""

    pass_id: str | None
    rule_name: str | None
    message: str
    unambiguous: bool


def resolve_config_v2_focus_target(
    target: RuleTreeContextTarget,
    pipeline_pass_ids: Sequence[str],
    catalog: Sequence[object],
) -> ConfigV2FocusTarget:
    """Resolve a displayed runtime target to one configured pipeline pass.

    Catalog-owned rules and transforms are the authoritative mappings. MBA
    instruction rules are the one deliberate special case because that pass's
    template has no static ``owned_rules`` list; its configured rule selection
    is still the owner of every instruction-optimizer rule.
    """

    pass_ids = tuple(str(pass_id) for pass_id in pipeline_pass_ids)
    catalog_by_id = {
        str(getattr(entry, "pass_id", "")): entry
        for entry in catalog
        if getattr(entry, "pass_id", "")
    }
    candidates: set[tuple[int, str]] = set()
    for index, pass_id in enumerate(pass_ids):
        entry = catalog_by_id.get(pass_id)
        if entry is None:
            continue
        owned = {
            str(name)
            for name in (
                *getattr(entry, "owned_rules", ()),
                *getattr(entry, "transforms", ()),
            )
            if str(name)
        }
        if owned.intersection(target.rule_names):
            candidates.add((index, pass_id))
        if (
            target.optimizer_type == "Instruction Optimizers"
            and pass_id == "mba-simplify"
        ):
            candidates.add((index, pass_id))

    rule_name = target.rule_name
    if len(candidates) == 1:
        _index, pass_id = next(iter(candidates))
        subject = f" for {rule_name}" if rule_name else ""
        return ConfigV2FocusTarget(
            pass_id=pass_id,
            rule_name=rule_name,
            message=f"Editing config-v2 pass {pass_id!r}{subject}.",
            unambiguous=True,
        )
    if len(candidates) > 1:
        names = ", ".join(sorted(pass_id for _index, pass_id in candidates))
        return ConfigV2FocusTarget(
            pass_id=None,
            rule_name=rule_name,
            message=(
                "The selected runtime rule maps to multiple configured passes "
                f"({names}); choose the owning pass explicitly."
            ),
            unambiguous=False,
        )
    return ConfigV2FocusTarget(
        pass_id=None,
        rule_name=rule_name,
        message=(
            "No configured config-v2 pass owns the selected runtime rule; "
            "review the pipeline explicitly."
        ),
        unambiguous=False,
    )


def config_v2_user_destination(
    config_dir: pathlib.Path,
    runtime_path: pathlib.Path,
) -> pathlib.Path:
    """Return the ordinary writable destination for config-v2 edits."""

    config_dir = pathlib.Path(config_dir).expanduser()
    runtime_path = pathlib.Path(runtime_path).expanduser()
    if runtime_path.parent == config_dir:
        return runtime_path
    return config_dir / runtime_path.name


def select_config_edit_policy(
    mode: ConfigEditMode,
    snapshot: ProjectRuntimeSnapshot | None,
) -> ConfigEditPolicy:
    if mode is ConfigEditMode.NEW:
        return ConfigEditPolicy(
            True,
            True,
            ConfigSaveStrategy.CREATE_LEGACY,
            "",
        )
    if snapshot is None:
        return ConfigEditPolicy(
            False,
            False,
            ConfigSaveStrategy.REFUSE,
            "No active project",
        )
    if mode is ConfigEditMode.EDIT and snapshot.mode is ProjectConfigMode.CONFIG_V2:
        return ConfigEditPolicy(
            True,
            False,
            ConfigSaveStrategy.STRUCTURED_V2,
            V2_STRUCTURED_EDIT_EXPLANATION,
        )
    if (
        mode is ConfigEditMode.DUPLICATE
        and snapshot.mode is ProjectConfigMode.CONFIG_V2
    ):
        return ConfigEditPolicy(
            True,
            False,
            ConfigSaveStrategy.STRUCTURED_V2,
            V2_CLONE_EXPLANATION,
        )
    return ConfigEditPolicy(
        True,
        True,
        ConfigSaveStrategy.SAVE_LEGACY_COPY,
        "",
    )


def build_project_config_view(
    snapshot: ProjectRuntimeSnapshot,
) -> ProjectConfigView:
    if snapshot.mode is ProjectConfigMode.LEGACY:
        mode_text = "Legacy"
        effective_passes_text = "Legacy rule policy"
    else:
        mode_text = "Config v2 (routed)" if snapshot.routed else "Config v2"
        effective_passes_text = (
            f"{len(snapshot.effective_pass_ids)} passes: "
            + ", ".join(snapshot.effective_pass_ids)
        )

    projection_text = (
        "runtime expansion"
        if snapshot.rule_projection is RuleProjectionKind.RUNTIME_EXPANSION
        else "source policy"
    )
    instruction_count = len(snapshot.effective_instruction_rule_names)
    block_count = len(snapshot.effective_block_rule_names)
    edit_policy = select_config_edit_policy(ConfigEditMode.EDIT, snapshot)
    return ProjectConfigView(
        mode_text=mode_text,
        source_text=snapshot.source.basename,
        source_tooltip=str(snapshot.source.path),
        runtime_text=snapshot.runtime.basename,
        runtime_tooltip=str(snapshot.runtime.path),
        effective_passes_text=effective_passes_text,
        rules_title=(
            f"Rules ({projection_text}: {instruction_count} instruction, "
            f"{block_count} block)"
        ),
        enabled_rule_names=frozenset(
            (
                *snapshot.effective_instruction_rule_names,
                *snapshot.effective_block_rule_names,
            )
        ),
        edit_enabled=edit_policy.allowed,
        edit_tooltip=edit_policy.explanation or "Edit legacy rule configuration",
    )


__all__ = [
    "ConfigV2FocusTarget",
    "ConfigEditMode",
    "ConfigEditPolicy",
    "ConfigSaveStrategy",
    "ProjectConfigView",
    "V2_CLONE_EXPLANATION",
    "V2_STRUCTURED_EDIT_EXPLANATION",
    "build_project_config_view",
    "config_v2_user_destination",
    "resolve_config_v2_focus_target",
    "select_config_edit_policy",
]
