"""Strict project-relative registration of trusted preparation scripts."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from d810.capabilities.idb_preparation import PreparationScriptDescriptor

__all__ = [
    "PreparationScriptConfigurationError",
    "PreparationScriptRegistry",
]

_SCRIPT_ID = re.compile(r"^[a-z][a-z0-9_-]*$")


class PreparationScriptConfigurationError(ValueError):
    """The project's preparation script configuration is malformed."""


def _source_sha256(path: Path) -> str:
    try:
        source = path.read_bytes()
    except OSError as error:
        raise PreparationScriptConfigurationError(
            f"preparation script {path} is not readable: {error}"
        ) from error
    return hashlib.sha256(source).hexdigest()


@dataclass(frozen=True, slots=True)
class PreparationScriptRegistry:
    """Ordered, source-attested preparation scripts for one project."""

    descriptors: tuple[PreparationScriptDescriptor, ...]

    @classmethod
    def from_project(
        cls,
        project_path: str | Path,
        payload: Mapping[str, object],
    ) -> PreparationScriptRegistry:
        if not isinstance(payload, Mapping):
            raise PreparationScriptConfigurationError(
                "project configuration payload must be an object"
            )
        pre_hexrays = payload.get("pre_hexrays", {})
        if not isinstance(pre_hexrays, Mapping):
            raise PreparationScriptConfigurationError("pre_hexrays must be an object")
        entries = pre_hexrays.get("scripts", [])
        if not isinstance(entries, list):
            raise PreparationScriptConfigurationError(
                "pre_hexrays.scripts must be an ordered list"
            )

        project = Path(project_path).resolve()
        descriptors: list[PreparationScriptDescriptor] = []
        seen_ids: set[str] = set()
        for index, entry in enumerate(entries):
            if not isinstance(entry, Mapping):
                raise PreparationScriptConfigurationError(
                    f"pre_hexrays.scripts[{index}] must be an object"
                )
            script_id = entry.get("id")
            if (
                not isinstance(script_id, str)
                or _SCRIPT_ID.fullmatch(script_id) is None
            ):
                raise PreparationScriptConfigurationError(
                    f"pre_hexrays.scripts[{index}].id must be a stable identifier"
                )
            if script_id in seen_ids:
                raise PreparationScriptConfigurationError(
                    f"duplicate script id {script_id!r}"
                )
            seen_ids.add(script_id)

            configured_path = entry.get("path")
            if not isinstance(configured_path, str) or not configured_path.strip():
                raise PreparationScriptConfigurationError(
                    f"pre_hexrays.scripts[{index}].path must be a non-empty string"
                )
            raw_path = Path(configured_path)
            portable = not raw_path.is_absolute()
            path = (
                (project.parent / raw_path).resolve()
                if portable
                else raw_path.resolve()
            )
            if path.suffix.lower() != ".py":
                raise PreparationScriptConfigurationError(
                    f"preparation script path must end in .py: {configured_path}"
                )
            if not path.is_file():
                raise PreparationScriptConfigurationError(
                    f"preparation script is not a regular file: {path}"
                )

            enabled = entry.get("enabled", True)
            if not isinstance(enabled, bool):
                raise PreparationScriptConfigurationError(
                    f"pre_hexrays.scripts[{index}].enabled must be a bool"
                )
            display_name = entry.get("display_name", script_id)
            if not isinstance(display_name, str) or not display_name.strip():
                raise PreparationScriptConfigurationError(
                    f"pre_hexrays.scripts[{index}].display_name must be non-empty"
                )

            descriptors.append(
                PreparationScriptDescriptor(
                    script_id=script_id,
                    display_name=display_name,
                    path=str(path),
                    source_sha256=_source_sha256(path),
                    enabled=enabled,
                    portable=portable,
                )
            )
        return cls(descriptors=tuple(descriptors))

    @property
    def enabled_descriptors(self) -> tuple[PreparationScriptDescriptor, ...]:
        return tuple(
            descriptor for descriptor in self.descriptors if descriptor.enabled
        )

    def require(self, script_id: str) -> PreparationScriptDescriptor:
        for descriptor in self.descriptors:
            if descriptor.script_id == script_id:
                return descriptor
        raise KeyError(f"unknown preparation script {script_id!r}")
