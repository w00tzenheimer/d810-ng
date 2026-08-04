"""Strict application-level configuration for function recipe persistence.

This value object lives in the portable core so both application state and
manager orchestration can consume it without introducing a manager package
cycle.
"""

from __future__ import annotations

import enum
import pathlib
from collections.abc import Mapping
from dataclasses import dataclass


class FunctionStorageConfigurationError(ValueError):
    """The application recipe-storage setting is malformed or unsafe."""


class FunctionRecipeStorageBackend(str, enum.Enum):
    NETNODE = "netnode"
    SQLITE = "sqlite"


@dataclass(frozen=True, slots=True)
class FunctionRecipeStorageConfig:
    backend: FunctionRecipeStorageBackend
    path: pathlib.Path | None


def parse_function_recipe_storage(
    payload: object,
    *,
    log_dir: pathlib.Path,
) -> FunctionRecipeStorageConfig:
    """Parse the one supported application-level storage configuration shape."""

    if payload is None:
        return FunctionRecipeStorageConfig(
            backend=FunctionRecipeStorageBackend.NETNODE,
            path=None,
        )
    if not isinstance(payload, Mapping):
        raise FunctionStorageConfigurationError(
            "function_recipe_storage must be an object"
        )

    backend_value = payload.get("backend")
    if not isinstance(backend_value, str):
        raise FunctionStorageConfigurationError(
            "function_recipe_storage.backend must be a string"
        )
    try:
        backend = FunctionRecipeStorageBackend(backend_value)
    except ValueError as exc:
        raise FunctionStorageConfigurationError(
            "function_recipe_storage.backend must be 'netnode' or 'sqlite'"
        ) from exc

    allowed_keys = {"backend"} if backend is FunctionRecipeStorageBackend.NETNODE else {
        "backend",
        "path",
    }
    unknown_keys = tuple(sorted(str(key) for key in set(payload) - allowed_keys))
    if unknown_keys:
        raise FunctionStorageConfigurationError(
            "function_recipe_storage has unknown fields: " + ", ".join(unknown_keys)
        )

    if backend is FunctionRecipeStorageBackend.NETNODE:
        return FunctionRecipeStorageConfig(backend=backend, path=None)

    path_value = payload.get("path")
    if not isinstance(path_value, str) or not path_value.strip():
        raise FunctionStorageConfigurationError(
            "function_recipe_storage.path must be a non-empty absolute path"
        )
    candidate = pathlib.Path(path_value).expanduser()
    if not candidate.is_absolute():
        raise FunctionStorageConfigurationError(
            "function_recipe_storage.path must be absolute"
        )

    resolved_path = candidate.resolve(strict=False)
    resolved_log_dir = pathlib.Path(log_dir).expanduser().resolve(strict=False)
    if resolved_path == resolved_log_dir or resolved_path.is_relative_to(
        resolved_log_dir
    ):
        raise FunctionStorageConfigurationError(
            "function_recipe_storage.path must be outside the log directory"
        )
    return FunctionRecipeStorageConfig(backend=backend, path=resolved_path)


__all__ = [
    "FunctionRecipeStorageBackend",
    "FunctionRecipeStorageConfig",
    "FunctionStorageConfigurationError",
    "parse_function_recipe_storage",
]
