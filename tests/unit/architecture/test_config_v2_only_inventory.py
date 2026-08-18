"""Fail-closed inventory for the config-v2-only project boundary."""

from __future__ import annotations

import json
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[3]
_CONF_DIR = _REPO_ROOT / "src" / "d810" / "conf"

# Keep this surface explicit.  In particular, ``docs/plans`` is not product
# documentation, and must not become an accidental compatibility allowlist.
_SURFACE_ROOTS = (
    _REPO_ROOT / "src",
    _REPO_ROOT / "tests",
    _REPO_ROOT / "tools",
    _REPO_ROOT / "samples",
    _REPO_ROOT / "README.md",
    _REPO_ROOT / "HEADLESS.md",
)
_DOC_PATHS = (
    _REPO_ROOT / "README.md",
    _REPO_ROOT / "HEADLESS.md",
    _REPO_ROOT / "samples" / "src" / "masm" / "README.md",
    _REPO_ROOT / "tests" / "README.md",
)
_MIGRATION_ROOT = _REPO_ROOT / "tools" / "migrations"
_MIGRATION_TEST_PATHS = frozenset(
    {
        _REPO_ROOT / "tests" / "unit" / "tools" / "test_migrate_project_config_v2.py",
        _REPO_ROOT
        / "tests"
        / "unit"
        / "tools"
        / "test_migrate_config_v2_transform_options.py",
    }
)
_TEXT_SUFFIXES = frozenset({".json", ".md", ".py", ".toml", ".yaml", ".yml"})


def _legacy_runtime_tokens() -> tuple[str, ...]:
    """Build retired names without making this ratchet match itself."""

    return (
        "config_v2_" + "defaults",
        "select_config_v2_" + "default_project",
        "CONFIG_V2_" + "SUPPORTED_" + "DEFAULT",
        "PipelineV2" + "Mode",
        "pipeline_v2_" + "hook_bridge",
        "STATE_MACHINE_" + "UNFLATTENER_RULE",
        "require_" + "pipeline_v2_" + "shadow_match",
        "pipeline_v2_" + "shadow_registry",
        "_config_v2_" + "canary",
    )


def _legacy_class_name() -> str:
    """Return the retired implementation-name spelling at runtime only."""

    return "StateMachineCff" + "Unflattener"


def _cleanup_implementation_name() -> str:
    """Return the cleanup implementation spelling at runtime only."""

    return "SimpleFlatteningCleanup" + "Unflattener"


def _relative(path: Path) -> str:
    return path.relative_to(_REPO_ROOT).as_posix()


def _is_offline_migration_path(path: Path) -> bool:
    """Allow historical vocabulary only at the offline migration boundary."""

    return (
        path == _MIGRATION_ROOT
        or _MIGRATION_ROOT in path.parents
        or path in _MIGRATION_TEST_PATHS
    )


def _surface_files() -> tuple[Path, ...]:
    files: set[Path] = set()
    for root in _SURFACE_ROOTS:
        if root.is_file():
            files.add(root)
            continue
        files.update(
            path
            for path in root.rglob("*")
            if path.is_file() and path.suffix in _TEXT_SUFFIXES
        )
    return tuple(sorted(files))


def _text_violations(
    tokens: tuple[str, ...],
    *,
    paths: tuple[Path, ...] | None = None,
    allow_migration: bool = True,
) -> list[str]:
    violations: list[str] = []
    for path in _surface_files() if paths is None else paths:
        if allow_migration and _is_offline_migration_path(path):
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError as exc:
            violations.append(f"{_relative(path)}: unreadable UTF-8 ({exc})")
            continue
        for line_number, line in enumerate(lines, start=1):
            for token in tokens:
                if token in line:
                    violations.append(
                        f"{_relative(path)}:{line_number}: forbidden {token!r}"
                    )
    return violations


def _mapping_keys(value: object) -> tuple[str, ...]:
    if isinstance(value, dict):
        keys = [str(key) for key in value]
        for child in value.values():
            keys.extend(_mapping_keys(child))
        return tuple(keys)
    if isinstance(value, list):
        return tuple(key for child in value for key in _mapping_keys(child))
    return ()


def test_runtime_has_no_retired_config_v2_symbols() -> None:
    violations = _text_violations(_legacy_runtime_tokens())

    assert not violations, "config-v2 runtime inventory violations:\n" + "\n".join(
        violations
    )


def test_bundled_configs_have_canonical_v2_metadata() -> None:
    legacy_arrays = ("ins_" + "rules", "blk_" + "rules")
    retired_metadata = (
        "pipeline_v2_" + "mode",
        "require_" + "pipeline_v2_" + "shadow_match",
        "pipeline_v2_" + "shadow_registry",
    )
    class_name = _legacy_class_name()
    violations: list[str] = []

    for path in sorted(_CONF_DIR.glob("*.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            violations.append(f"{_relative(path)}: invalid JSON ({exc})")
            continue
        document_keys = frozenset(_mapping_keys(document))
        for key in legacy_arrays:
            if key in document_keys:
                violations.append(
                    f"{_relative(path)}: legacy key {key!r} must be absent"
                )
        additional = document.get("additional_configuration", {})
        for key in retired_metadata:
            if key in document_keys:
                violations.append(
                    f"{_relative(path)}: retired metadata {key!r} is present"
                )
        if class_name in json.dumps(document, sort_keys=True):
            violations.append(
                f"{_relative(path)}: direct legacy class-name registration"
            )
        pipeline = (
            additional.get("pipeline_v2") if isinstance(additional, dict) else None
        )
        if isinstance(pipeline, list):
            for index, entry in enumerate(pipeline):
                if isinstance(entry, dict) and "name" in entry:
                    violations.append(
                        f"{_relative(path)}: pipeline_v2[{index}] uses a class-name field"
                    )

    assert not violations, "bundled config-v2 inventory violations:\n" + "\n".join(
        violations
    )


def test_production_execution_does_not_route_by_legacy_class_name() -> None:
    execution_roots = tuple(
        root
        for root in (
            _REPO_ROOT / "src" / "d810" / "manager",
            _REPO_ROOT / "src" / "d810" / "ui",
            _REPO_ROOT / "src" / "d810" / "passes",
        )
        if root.exists()
    )
    paths = tuple(
        sorted(
            path
            for root in execution_roots
            for path in root.rglob("*.py")
            if path.is_file()
        )
    )
    violations = _text_violations(
        (_legacy_class_name(),), paths=paths, allow_migration=False
    )

    assert not violations, "production class-name routing violations:\n" + "\n".join(
        violations
    )


def test_user_facing_docs_describe_pass_ids_not_legacy_configuration() -> None:
    legacy_doc_tokens = (
        _legacy_class_name(),
        _cleanup_implementation_name(),
        "ins_" + "rules",
        "blk_" + "rules",
        "pipeline_v2_" + "mode",
    )
    paths = tuple(path for path in _DOC_PATHS if path.is_file())
    violations = _text_violations(legacy_doc_tokens, paths=paths, allow_migration=False)

    assert not violations, (
        "user-facing config-v2 documentation violations:\n" + "\n".join(violations)
    )
