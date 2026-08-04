from __future__ import annotations

import pathlib

import pytest

from d810.core.function_storage_config import (
    FunctionRecipeStorageBackend,
    FunctionRecipeStorageConfig,
    FunctionStorageConfigurationError,
    parse_function_recipe_storage,
)


def test_missing_storage_setting_uses_netnode(tmp_path: pathlib.Path) -> None:
    parsed = parse_function_recipe_storage(None, log_dir=tmp_path / "logs")

    assert parsed == FunctionRecipeStorageConfig(
        FunctionRecipeStorageBackend.NETNODE,
        None,
    )


def test_sqlite_accepts_absolute_path_outside_log_directory(
    tmp_path: pathlib.Path,
) -> None:
    log_dir = tmp_path / "logs"
    database_path = tmp_path / "state" / "recipes.sqlite3"

    parsed = parse_function_recipe_storage(
        {"backend": "sqlite", "path": str(database_path)},
        log_dir=log_dir,
    )

    assert parsed == FunctionRecipeStorageConfig(
        FunctionRecipeStorageBackend.SQLITE,
        database_path.resolve(),
    )


def test_sqlite_rejects_relative_path(tmp_path: pathlib.Path) -> None:
    with pytest.raises(FunctionStorageConfigurationError, match="absolute"):
        parse_function_recipe_storage(
            {"backend": "sqlite", "path": "recipes.sqlite3"},
            log_dir=tmp_path / "logs",
        )


@pytest.mark.parametrize("relative_path", ("recipes.sqlite3", "nested/recipes.db"))
def test_sqlite_rejects_log_directory_and_descendants(
    tmp_path: pathlib.Path,
    relative_path: str,
) -> None:
    log_dir = tmp_path / "logs"

    with pytest.raises(FunctionStorageConfigurationError, match="log directory"):
        parse_function_recipe_storage(
            {"backend": "sqlite", "path": str(log_dir / relative_path)},
            log_dir=log_dir,
        )


@pytest.mark.parametrize(
    "payload",
    (
        "/tmp/recipes.sqlite3",
        {"backend": "sqlite"},
        {"backend": "netnode", "path": "/tmp/recipes.sqlite3"},
        {"backend": "netnode", "unexpected": True},
        {"backend": "unknown"},
    ),
)
def test_partial_former_or_unknown_storage_shapes_are_rejected(
    payload: object,
    tmp_path: pathlib.Path,
) -> None:
    with pytest.raises(FunctionStorageConfigurationError):
        parse_function_recipe_storage(payload, log_dir=tmp_path / "logs")
