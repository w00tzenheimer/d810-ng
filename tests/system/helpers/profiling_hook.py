"""Pure helpers for the env-gated ``ProfilingController`` system-test hook.

This module is intentionally IDA-free so it can be exercised by
``tests/unit/helpers/test_profiling_hook.py`` without an IDA runtime. The
IDA-dependent wiring (resolving the live ``D810State``/``D810Manager`` and
pointing ``ProfilingController.log_dir`` at the resolved directory) lives in
the ``_profile_controller_hook`` autouse fixture in ``tests/system/conftest.py``.

Env vars (see ``PROFILING.md``):

- ``D810_PROFILE_CONTROLLER``: ``"on"`` enables the hook for the test, unset
  or ``""`` disables it (the default). Any other value is a hard error.
- ``D810_PROFILE_LABEL``: a basename used as the profile run's label
  directory. Defaults to :data:`DEFAULT_PROFILE_LABEL`.

Output convention: ``<worktree>/.tmp/profiles/<label>/<sanitised nodeid>/``.
"""

from __future__ import annotations

import pathlib
import re

DEFAULT_PROFILE_LABEL = "system-profile"

_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9_.-]+")


def profiling_hook_enabled(value: str | None) -> bool:
    """Return whether the profiling hook should activate.

    ``None``/empty-string means "unset" and is treated as disabled without
    error, matching an opt-in env var. Any other value must be exactly
    ``"on"`` or ``"off"``.
    """
    if value is None or value == "":
        return False
    if value not in ("on", "off"):
        raise ValueError(
            f"D810_PROFILE_CONTROLLER must be 'on' or 'off', got {value!r}"
        )
    return value == "on"


def validate_profile_label(label: str | None) -> str:
    """Validate ``D810_PROFILE_LABEL``, returning the default when unset."""
    if not label:
        return DEFAULT_PROFILE_LABEL
    if label in (".", "..") or pathlib.Path(label).name != label:
        raise ValueError(
            f"D810_PROFILE_LABEL must be a basename (no path separators or "
            f"parent traversal), got {label!r}"
        )
    return label


def sanitize_nodeid(nodeid: str) -> str:
    """Convert a pytest nodeid into a single filesystem-safe path component.

    ``::`` and ``/`` separators are flattened to ``__`` so the result never
    contains a path separator, and every other unsafe character (brackets
    from parametrize ids, spaces, etc.) is collapsed to ``_``.
    """
    if not nodeid:
        raise ValueError("nodeid must be non-empty")
    cleaned = nodeid.replace("::", "__").replace("/", "__").replace("\\", "__")
    cleaned = _UNSAFE_CHARS.sub("_", cleaned)
    cleaned = cleaned.strip("_")
    if not cleaned:
        raise ValueError(f"nodeid sanitized to an empty string: {nodeid!r}")
    return cleaned


def resolve_profile_output_dir(
    base_dir: pathlib.Path, label: str | None, nodeid: str
) -> pathlib.Path:
    """Resolve the per-test profile output directory.

    Layout: ``<base_dir>/.tmp/profiles/<validated label>/<sanitised nodeid>/``
    """
    validated_label = validate_profile_label(label)
    sanitized = sanitize_nodeid(nodeid)
    return pathlib.Path(base_dir) / ".tmp" / "profiles" / validated_label / sanitized
