"""Pure catalog projection for the native D-810 configuration picker."""

from __future__ import annotations

import dataclasses
from collections.abc import Sequence

from d810.core.config import ProjectConfiguration


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


def build_project_picker_entries(
    projects: Sequence[ProjectConfiguration],
) -> tuple[ProjectPickerEntry, ...]:
    """Describe every project without altering its original manager index."""

    entries: list[ProjectPickerEntry] = []
    for project_index, project in enumerate(projects):
        filename = project.path.name
        description = project.description.strip()
        behavior = "Config v2 project"
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
