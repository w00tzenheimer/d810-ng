from __future__ import annotations

import json
import os
import pathlib
import tempfile
from collections.abc import Callable

from d810.core import typing
from d810.core.config import ProjectConfiguration


class ProjectConfigurationWriteError(RuntimeError):
    """A complete project document could not be validated and committed."""


def _read_complete_document(path: pathlib.Path) -> dict[str, typing.Any]:
    try:
        with path.open("r", encoding="utf-8") as fp:
            return typing.cast(dict[str, typing.Any], json.load(fp))
    except Exception as exc:
        raise ProjectConfigurationWriteError(
            f"Could not read complete project configuration {path}"
        ) from exc


def write_project_document_atomically(
    destination: pathlib.Path,
    document: dict[str, typing.Any],
    *,
    validator: Callable[[ProjectConfiguration], None] | None = None,
) -> ProjectConfiguration:
    destination = pathlib.Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_path: pathlib.Path | None = None
    try:
        fd, temp_name = tempfile.mkstemp(
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
        )
        temp_path = pathlib.Path(temp_name)
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            json.dump(document, fp, indent=2)
            fp.write("\n")
            fp.flush()
            os.fsync(fp.fileno())
        validated = ProjectConfiguration.from_file(temp_path)
        if validator is not None:
            validator(validated)
        # Re-serialize through the typed project model after validation.  This
        # is where config-v2 documents lose transitional legacy arrays and the
        # compatibility mode marker while unknown non-rule fields remain in
        # the complete document.  Legacy/malformed documents retain their raw
        # shape so the offline migration tool can still inspect them.
        canonical_document = validated.to_document()
        with temp_path.open("w", encoding="utf-8") as fp:
            json.dump(
                canonical_document,
                fp,
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
            fp.write("\n")
            fp.flush()
            os.fsync(fp.fileno())
        validated = ProjectConfiguration.from_file(temp_path)
        if validator is not None:
            validator(validated)
        os.replace(temp_path, destination)
        temp_path = None
        validated.path = destination
        return validated
    except Exception as exc:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        raise ProjectConfigurationWriteError(
            f"Could not atomically write project configuration {destination}"
        ) from exc


def clone_project_configuration(
    *,
    source: ProjectConfiguration,
    destination: pathlib.Path,
    description: str,
    validator: Callable[[ProjectConfiguration], None] | None = None,
) -> ProjectConfiguration:
    document = _read_complete_document(source.path)
    document["description"] = description
    return write_project_document_atomically(
        destination,
        document,
        validator=validator,
    )
