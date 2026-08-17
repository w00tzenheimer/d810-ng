"""IDA-free policy shared by directory and clipboard path controls."""

from __future__ import annotations

import pathlib


def directory_chooser_initial_path(current_path: str) -> str:
    """Return a stable initial directory for every D810 directory picker."""
    normalized = str(current_path).strip()
    if normalized:
        return str(pathlib.Path(normalized).expanduser())
    return str(pathlib.Path.home())


def file_chooser_initial_path(
    current_path: str,
    *,
    suggested_filename: str = "",
) -> str:
    """Return the shared initial target for a save-file chooser."""
    normalized = str(current_path).strip()
    if normalized:
        return str(pathlib.Path(normalized).expanduser())
    return str(pathlib.Path.home() / suggested_filename)


__all__ = ["directory_chooser_initial_path"]
