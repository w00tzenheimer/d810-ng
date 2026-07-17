"""Pure catalog projection for the native D-810 configuration picker."""

from __future__ import annotations

import dataclasses
from collections.abc import Sequence

from d810.core.config import ProjectConfiguration
from d810.core.config_v2_defaults import CONFIG_V2_SUPPORTED_DEFAULT_MAPPINGS


@dataclasses.dataclass(frozen=True, slots=True)
class ProjectPickerEntry:
    """One directly-selectable project with its stable manager identity."""

    project_index: int
    filename: str
    behavior: str
    description: str
    search_text: str


def _normalized_text(*values: str) -> str:
    return " ".join(" ".join(value.split()) for value in values).casefold()


def _supported_routing(
    filenames: frozenset[str],
) -> tuple[dict[str, str], dict[str, str]]:
    source_to_runtime: dict[str, str] = {}
    runtime_to_source: dict[str, str] = {}
    for mapping in CONFIG_V2_SUPPORTED_DEFAULT_MAPPINGS:
        if {
            mapping.source_config,
            mapping.runtime_config,
        }.issubset(filenames):
            source_to_runtime[mapping.source_config] = mapping.runtime_config
            runtime_to_source[mapping.runtime_config] = mapping.source_config
    return source_to_runtime, runtime_to_source


def build_project_picker_entries(
    projects: Sequence[ProjectConfiguration],
) -> tuple[ProjectPickerEntry, ...]:
    """Describe every project without altering its original manager index."""

    filenames = frozenset(project.path.name for project in projects)
    source_to_runtime, runtime_to_source = _supported_routing(filenames)
    entries: list[ProjectPickerEntry] = []
    for project_index, project in enumerate(projects):
        filename = project.path.name
        description = project.description.strip()
        if runtime := source_to_runtime.get(filename):
            behavior = f"Config v2 -> {runtime}"
            search_text = _normalized_text(
                filename,
                behavior,
                description,
                "config v2 runtime",
                runtime,
            )
        elif filename in runtime_to_source:
            behavior = "Config v2 runtime (direct)"
            search_text = _normalized_text(
                filename,
                behavior,
                description,
                runtime_to_source[filename],
            )
        else:
            behavior = "Direct project"
            search_text = _normalized_text(filename, behavior, description)
        entries.append(
            ProjectPickerEntry(
                project_index=project_index,
                filename=filename,
                behavior=behavior,
                description=description,
                search_text=search_text,
            )
        )
    return tuple(entries)


def filter_project_picker_entries(
    entries: Sequence[ProjectPickerEntry], query: str
) -> tuple[ProjectPickerEntry, ...]:
    """Filter catalog entries while retaining their original identities."""

    normalized_query = _normalized_text(query)
    if not normalized_query:
        return tuple(entries)
    query_terms = tuple(normalized_query.split())
    return tuple(
        entry
        for entry in entries
        if all(term in entry.search_text for term in query_terms)
    )


__all__ = [
    "ProjectPickerEntry",
    "build_project_picker_entries",
    "filter_project_picker_entries",
]
