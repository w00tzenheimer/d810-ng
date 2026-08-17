"""Offline command-line migration for legacy D-810 project documents.

This module is intentionally outside ``src/d810``.  It is the compatibility
boundary for users with legacy project JSON; the plugin runtime does not import
it and never rewrites a project implicitly.

Exit status is stable and deliberately small:

``0``
    The requested conversion/check completed successfully.
``1``
    A project was invalid, a directory check found files requiring migration,
    or an explicit write failed.
``2``
    Command-line usage is invalid (argparse's standard error status).
"""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from collections.abc import Sequence
from pathlib import Path

if __package__ in {None, ""}:  # pragma: no cover - exercised by subprocess tests
    # Running ``python tools/migrations/migrate_project_config_v2.py`` places
    # ``tools/migrations`` rather than the repository root on sys.path.
    # Bootstrap the repository and source roots so the tool works from a fresh
    # checkout without requiring an editable installation.
    _repository_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(_repository_root / "src"))
    sys.path.insert(0, str(_repository_root))

from d810.core.project_config_persistence import (
    ProjectConfigurationWriteError,
    write_project_document_atomically,
)
from tools.migrations.legacy_project_config import (
    LegacyMigrationError,
    is_canonical_v2_document,
    migrate_legacy_document,
)


EXIT_SUCCESS = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2

_SCRIPT_COMMAND = "python tools/migrations/migrate_project_config_v2.py"


class MigrationCliError(ValueError):
    """An expected input, migration, or output error for the command line."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Convert one legacy D-810 project JSON to canonical config-v2 "
            "without involving IDA."
        )
    )
    parser.add_argument("input", type=Path, help="project JSON file or --check directory")
    parser.add_argument(
        "--output",
        type=Path,
        help="write a new destination file; an existing destination is refused",
    )
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="atomically replace the input file",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="inspect every JSON file in an input directory without writing",
    )
    return parser


def _validate_arguments(
    parser: argparse.ArgumentParser, *, input_path: Path, output: Path | None, in_place: bool, check: bool
) -> None:
    if output is not None and in_place:
        parser.error("--output cannot be combined with --in-place")
    if output is not None and check:
        parser.error("--output cannot be combined with --check")
    if in_place and check:
        parser.error("--in-place cannot be combined with --check")
    if not input_path.exists():
        parser.error(f"input path does not exist: {input_path}")
    if input_path.is_dir():
        if not check and output is None:
            parser.error("directory input requires --check")
        if output is not None:
            parser.error("--output cannot be used with directory input")
        if in_place:
            parser.error("--in-place cannot be used with directory input")
    elif check:
        parser.error("--check requires a directory input")


def _read_json(path: Path) -> dict[str, object]:
    try:
        with path.open("r", encoding="utf-8") as stream:
            value = json.load(stream)
    except json.JSONDecodeError as exc:
        raise MigrationCliError(f"{path}: invalid JSON: {exc.msg}") from exc
    except OSError as exc:
        raise MigrationCliError(f"{path}: could not read project: {exc}") from exc
    if not isinstance(value, dict):
        raise MigrationCliError(f"{path}: project JSON root must be an object")
    return value


def _migrate_path(path: Path) -> dict[str, object]:
    document = _read_json(path)
    try:
        return migrate_legacy_document(document, source_name=path.name)
    except LegacyMigrationError as exc:
        raise MigrationCliError(f"{path}: {exc}") from exc


def _canonical_json(document: dict[str, object]) -> str:
    """Serialize with the same two-space/newline policy as project persistence."""

    try:
        return (
            json.dumps(
                document,
                ensure_ascii=True,
                allow_nan=False,
                indent=2,
            )
            + "\n"
        )
    except (TypeError, ValueError) as exc:
        raise MigrationCliError(f"canonical serialization failed: {exc}") from exc


def _write_atomically(
    destination: Path, document: dict[str, object], *, refuse_existing: bool
) -> None:
    if refuse_existing and destination.exists():
        raise MigrationCliError(f"{destination}: destination already exists")
    try:
        # This shared persistence helper owns mkstemp(dir=parent), fsync,
        # validation of the staged JSON, os.replace, and failure cleanup.
        write_project_document_atomically(destination, document)
    except ProjectConfigurationWriteError as exc:
        raise MigrationCliError(str(exc)) from exc
    except OSError as exc:
        raise MigrationCliError(f"{destination}: atomic write failed: {exc}") from exc


def _migration_command(path: Path) -> str:
    return shlex.join(("python", *_SCRIPT_COMMAND.split(), str(path), "--in-place"))


def _check_directory(directory: Path) -> int:
    findings: list[str] = []
    for path in sorted(directory.glob("*.json"), key=lambda item: item.name):
        if not path.is_file():
            continue
        try:
            document = _read_json(path)
        except MigrationCliError as exc:
            findings.append(f"{path}: invalid project: {exc}; migrate with: {_migration_command(path)}")
            continue

        if is_canonical_v2_document(document):
            continue
        try:
            migrate_legacy_document(document, source_name=path.name)
        except LegacyMigrationError as exc:
            findings.append(
                f"{path}: cannot migrate legacy/invalid project: {exc}; "
                f"migrate with: {_migration_command(path)}"
            )
        else:
            findings.append(
                f"{path}: legacy project requires migration; "
                f"migrate with: {_migration_command(path)}"
            )

    for finding in findings:
        print(finding, file=sys.stderr)
    return EXIT_FINDINGS if findings else EXIT_SUCCESS


def main(argv: Sequence[str] | None = None) -> int:
    """Run the offline migration command and return its stable status code."""

    parser = _parser()
    args = parser.parse_args(argv)
    _validate_arguments(
        parser,
        input_path=args.input,
        output=args.output,
        in_place=args.in_place,
        check=args.check,
    )

    if args.check:
        return _check_directory(args.input)

    try:
        migrated = _migrate_path(args.input)
        if args.in_place:
            _write_atomically(args.input, migrated, refuse_existing=False)
        elif args.output is not None:
            _write_atomically(args.output, migrated, refuse_existing=True)
        else:
            sys.stdout.write(_canonical_json(migrated))
    except MigrationCliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FINDINGS
    return EXIT_SUCCESS


if __name__ == "__main__":  # pragma: no cover - subprocess entry point
    raise SystemExit(main())


__all__ = [
    "EXIT_FINDINGS",
    "EXIT_SUCCESS",
    "EXIT_USAGE",
    "MigrationCliError",
    "main",
]
