"""Pure presentation and config-v2 edit policy for the project UI."""

from __future__ import annotations

import dataclasses
import enum
import pathlib

from d810.manager.project_runtime import ProjectConfigMode, ProjectRuntimeSnapshot


V2_STRUCTURED_EDIT_EXPLANATION = (
    "Edit the ordered pass pipeline and typed pass options with the structured "
    "config-v2 editor."
)
V2_CLONE_EXPLANATION = (
    "Duplicate the complete effective config-v2 document before editing it."
)
STRICT_V2_EXPLANATION = (
    "This project does not expose a config-v2 pass pipeline and cannot be edited "
    "with the strict project editor."
)


class ConfigEditMode(str, enum.Enum):
    NEW = "new"
    DUPLICATE = "duplicate"
    EDIT = "edit"


class ConfigSaveStrategy(str, enum.Enum):
    STRUCTURED_V2 = "structured-v2"
    REFUSE = "refuse"


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigEditPolicy:
    allowed: bool
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
    pass_tree_title: str
    header_summary_text: str
    identity_is_divergent: bool
    effective_pass_ids: tuple[str, ...]
    edit_enabled: bool
    edit_tooltip: str


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2FocusTarget:
    """Stable pass focus for the structured config-v2 editor."""

    pass_id: str | None
    pass_index: int | None
    message: str
    unambiguous: bool


def resolve_config_v2_focus_target(
    pass_id: str,
    pipeline_pass_ids: tuple[str, ...],
    pass_index: int | None = None,
) -> ConfigV2FocusTarget:
    normalized = str(pass_id).strip()
    if pass_index is not None:
        if (
            0 <= pass_index < len(pipeline_pass_ids)
            and pipeline_pass_ids[pass_index] == normalized
        ):
            return ConfigV2FocusTarget(
                pass_id=normalized,
                pass_index=pass_index,
                message=f"Editing config-v2 pass {normalized!r} at row {pass_index}.",
                unambiguous=True,
            )
        return ConfigV2FocusTarget(
            pass_id=None,
            pass_index=None,
            message=(
                f"Pass {normalized!r} is not present at pipeline row {pass_index}."
            ),
            unambiguous=False,
        )
    matches = tuple(
        index for index, candidate in enumerate(pipeline_pass_ids) if candidate == normalized
    )
    if len(matches) == 1:
        return ConfigV2FocusTarget(
            pass_id=normalized,
            pass_index=matches[0],
            message=f"Editing config-v2 pass {normalized!r}.",
            unambiguous=True,
        )
    if len(matches) > 1:
        return ConfigV2FocusTarget(
            pass_id=None,
            pass_index=None,
            message=(
                f"Pass {normalized!r} occurs more than once in the effective pipeline; "
                "select a pipeline row."
            ),
            unambiguous=False,
        )
    return ConfigV2FocusTarget(
        pass_id=None,
        pass_index=None,
        message=f"Pass {normalized!r} is not present in the effective pipeline.",
        unambiguous=False,
    )


def config_v2_user_destination(
    config_dir: pathlib.Path,
    runtime_path: pathlib.Path,
) -> pathlib.Path:
    config_dir = pathlib.Path(config_dir).expanduser()
    runtime_path = pathlib.Path(runtime_path).expanduser()
    if runtime_path.parent == config_dir:
        return runtime_path
    return config_dir / runtime_path.name


def select_config_edit_policy(
    mode: ConfigEditMode,
    snapshot: ProjectRuntimeSnapshot | None,
) -> ConfigEditPolicy:
    if snapshot is None or snapshot.mode is not ProjectConfigMode.CONFIG_V2:
        return ConfigEditPolicy(False, ConfigSaveStrategy.REFUSE, STRICT_V2_EXPLANATION)
    explanation = (
        V2_CLONE_EXPLANATION
        if mode is ConfigEditMode.DUPLICATE
        else V2_STRUCTURED_EDIT_EXPLANATION
    )
    return ConfigEditPolicy(True, ConfigSaveStrategy.STRUCTURED_V2, explanation)


def build_project_config_view(snapshot: ProjectRuntimeSnapshot) -> ProjectConfigView:
    is_v2 = snapshot.mode is ProjectConfigMode.CONFIG_V2
    mode_text = (
        "Config v2 (routed)"
        if is_v2 and snapshot.routed
        else "Config v2"
        if is_v2
        else "Unsupported project format"
    )
    pass_ids = tuple(snapshot.effective_pass_ids) if is_v2 else ()
    passes_text = (
        f"{len(pass_ids)} passes: " + ", ".join(pass_ids)
        if pass_ids
        else "No executable config-v2 pass pipeline"
    )
    policy = select_config_edit_policy(ConfigEditMode.EDIT, snapshot)
    # Compare resolved paths, not the routed flag and not basenames: two
    # projects in different directories can share a filename.
    divergent = snapshot.source.path != snapshot.runtime.path
    summary_text = f"{mode_text} . {len(pass_ids)} passes" if pass_ids else mode_text
    return ProjectConfigView(
        mode_text=mode_text,
        source_text=snapshot.source.basename,
        source_tooltip=str(snapshot.source.path),
        runtime_text=snapshot.runtime.basename,
        runtime_tooltip=str(snapshot.runtime.path),
        effective_passes_text=passes_text,
        pass_tree_title=f"Pass pipeline ({len(pass_ids)} active)",
        header_summary_text=summary_text,
        identity_is_divergent=divergent,
        effective_pass_ids=pass_ids,
        edit_enabled=policy.allowed,
        edit_tooltip=policy.explanation,
    )


__all__ = [
    "ConfigEditMode",
    "ConfigEditPolicy",
    "ConfigSaveStrategy",
    "ConfigV2FocusTarget",
    "ProjectConfigView",
    "STRICT_V2_EXPLANATION",
    "V2_CLONE_EXPLANATION",
    "V2_STRUCTURED_EDIT_EXPLANATION",
    "build_project_config_view",
    "config_v2_user_destination",
    "resolve_config_v2_focus_target",
    "select_config_edit_policy",
]
