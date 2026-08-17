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
import os
import shlex
import stat
import sys
import tempfile
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
from d810.core.config import ProjectConfiguration
from tools.migrations.legacy_project_config import (
    LegacyMigrationError,
    is_canonical_v2_document,
    migrate_legacy_document,
)


EXIT_SUCCESS = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2

_SCRIPT_COMMAND = (
    "python",
    "tools/migrations/migrate_project_config_v2.py",
)


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
    try:
        input_mode = input_path.lstat().st_mode
    except FileNotFoundError:
        parser.error(f"input path does not exist: {input_path}")
    except OSError as exc:
        parser.error(f"could not inspect input path {input_path}: {exc}")
    if stat.S_ISLNK(input_mode):
        parser.error(f"input path must not be a symlink: {input_path}")
    if stat.S_ISDIR(input_mode):
        if not check and output is None:
            parser.error("directory input requires --check")
        if output is not None:
            parser.error("--output cannot be used with directory input")
        if in_place:
            parser.error("--in-place cannot be used with directory input")
    elif check:
        parser.error("--check requires a directory input")
    elif not stat.S_ISREG(input_mode):
        parser.error(f"input path must be a regular file: {input_path}")


def _require_regular_file(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as exc:
        raise MigrationCliError(f"{path}: input path disappeared before reading") from exc
    except OSError as exc:
        raise MigrationCliError(f"{path}: could not inspect input path: {exc}") from exc
    if stat.S_ISLNK(mode):
        raise MigrationCliError(f"{path}: input path must not be a symlink")
    if not stat.S_ISREG(mode):
        raise MigrationCliError(f"{path}: input path must be a regular file")


def _read_json(path: Path) -> dict[str, object]:
    _require_regular_file(path)
    try:
        with path.open("r", encoding="utf-8") as stream:
            value = json.load(stream)
    except json.JSONDecodeError as exc:
        raise MigrationCliError(f"{path}: invalid JSON: {exc.msg}") from exc
    except UnicodeDecodeError as exc:
        raise MigrationCliError(f"{path}: invalid UTF-8: {exc}") from exc
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
    if refuse_existing:
        _write_new_no_clobber(destination, document)
        return
    try:
        # This shared persistence helper owns mkstemp(dir=parent), fsync,
        # validation of the staged JSON, os.replace, and failure cleanup.
        write_project_document_atomically(destination, document)
    except ProjectConfigurationWriteError as exc:
        raise MigrationCliError(str(exc)) from exc
    except OSError as exc:
        raise MigrationCliError(f"{destination}: atomic write failed: {exc}") from exc


def _write_new_no_clobber(destination: Path, document: dict[str, object]) -> None:
    """Publish a new destination without ever replacing a directory entry.

    The staged file is written and validated in the destination directory.  A
    same-filesystem hard link is an atomic create-if-absent operation: it fails
    for regular files, directories, dangling symlinks, and a creator that wins
    a race after staging.  The in-place path intentionally remains on the
    shared persistence helper's replace semantics.
    """

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise MigrationCliError(
            f"{destination}: could not prepare destination directory: {exc}"
        ) from exc

    file_descriptor: int | None = None
    staged_path: Path | None = None
    try:
        file_descriptor, staged_name = tempfile.mkstemp(
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
        )
        staged_path = Path(staged_name)
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as stream:
            file_descriptor = None
            stream.write(_canonical_json(document))
            stream.flush()
            os.fsync(stream.fileno())

        try:
            ProjectConfiguration.from_file(staged_path)
        except (OSError, UnicodeError, ValueError) as exc:
            raise MigrationCliError(
                f"{destination}: staged output validation failed: {exc}"
            ) from exc

        try:
            os.link(staged_path, destination)
        except FileExistsError as exc:
            raise MigrationCliError(
                f"{destination}: destination already exists"
            ) from exc
        except OSError as exc:
            raise MigrationCliError(
                f"{destination}: atomic no-clobber publish failed: {exc}"
            ) from exc

        staged_path.unlink()
        staged_path = None
    except MigrationCliError:
        raise
    except (OSError, UnicodeError, ValueError) as exc:
        raise MigrationCliError(f"{destination}: atomic output failed: {exc}") from exc
    finally:
        if file_descriptor is not None:
            try:
                os.close(file_descriptor)
            except OSError:
                pass
        if staged_path is not None:
            try:
                staged_path.unlink()
            except OSError:
                pass


def _migration_command(path: Path) -> str:
    return shlex.join((*_SCRIPT_COMMAND, str(path), "--in-place"))


def _directory_entries(directory: Path) -> list[os.DirEntry[str]]:
    try:
        mode = directory.lstat().st_mode
    except OSError as exc:
        raise MigrationCliError(f"{directory}: could not inspect directory: {exc}") from exc
    if not stat.S_ISDIR(mode):
        raise MigrationCliError(f"{directory}: input path is not a directory")
    if not mode & (stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH):
        raise MigrationCliError(
            f"{directory}: directory has no read/search permission bits"
        )
    if not mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        raise MigrationCliError(
            f"{directory}: directory has no read/search permission bits"
        )

    try:
        with os.scandir(directory) as iterator:
            entries = [entry for entry in iterator if entry.name.endswith(".json")]
    except (OSError, UnicodeError) as exc:
        raise MigrationCliError(f"{directory}: could not enumerate directory: {exc}") from exc
    return sorted(entries, key=lambda entry: entry.name)


def _check_directory(directory: Path) -> int:
    findings: list[str] = []
    try:
        entries = _directory_entries(directory)
    except MigrationCliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FINDINGS

    for entry in entries:
        path = Path(entry.path)
        try:
            entry_mode = entry.stat(follow_symlinks=False).st_mode
        except (OSError, UnicodeError) as exc:
            findings.append(
                f"{path}: could not inspect JSON directory entry: {exc}; "
                "migration command is not applicable"
            )
            continue
        if stat.S_ISLNK(entry_mode) or not stat.S_ISREG(entry_mode):
            findings.append(
                f"{path}: special/non-regular JSON directory entry; "
                "migration command is not applicable"
            )
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
