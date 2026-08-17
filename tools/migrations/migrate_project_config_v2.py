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
import errno
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


def _remove_staged_path(path: Path) -> None:
    """Remove one staged path; kept as a narrow seam for cleanup testing."""

    path.unlink()


def _cleanup_staged_path(path: Path, *, attempts: int = 2) -> tuple[bool, int]:
    """Retry staged cleanup and return ``(removed, attempts_used)``."""

    for attempt in range(1, attempts + 1):
        try:
            _remove_staged_path(path)
        except FileNotFoundError:
            return True, attempt
        except OSError:
            continue
        else:
            return True, attempt
    return False, attempts


def _cleanup_failure_message(primary: str, path: Path, attempts: int) -> str:
    return (
        f"{primary}; staged cleanup failed after {attempts} attempts; "
        f"leaked staging path: {path}"
    )


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
) -> os.stat_result:
    if output is not None and in_place:
        parser.error("--output cannot be combined with --in-place")
    if output is not None and check:
        parser.error("--output cannot be combined with --check")
    if in_place and check:
        parser.error("--in-place cannot be combined with --check")
    try:
        input_stat = input_path.lstat()
        input_mode = input_stat.st_mode
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
    return input_stat


def _file_identity(file_stat: os.stat_result) -> tuple[int, int, int]:
    """Return the identity used to prove that a path was not replaced."""

    return (
        file_stat.st_dev,
        file_stat.st_ino,
        stat.S_IFMT(file_stat.st_mode),
    )


def _regular_file_error(path: Path, file_stat: os.stat_result) -> str | None:
    mode = file_stat.st_mode
    if stat.S_ISLNK(mode):
        return f"{path}: input path must not be a symlink"
    if not stat.S_ISREG(mode):
        return f"{path}: input path must be a regular file"
    return None


def _open_single_file_descriptor(path: Path) -> int:
    """Open one input without following replacement or symlink paths.

    The pre/post identity checks are retained even when ``O_NOFOLLOW`` is
    available.  They reject a regular-file replacement race as well as a
    symlink race, and the parser consumes only the descriptor that was checked.
    """

    try:
        before = path.lstat()
    except FileNotFoundError as exc:
        raise MigrationCliError(f"{path}: input path disappeared before reading") from exc
    except OSError as exc:
        raise MigrationCliError(f"{path}: could not inspect input path: {exc}") from exc
    error = _regular_file_error(path, before)
    if error is not None:
        raise MigrationCliError(error)

    flags = os.O_RDONLY
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if no_follow:
        flags |= no_follow
    elif not before.st_dev or not before.st_ino:
        raise MigrationCliError(
            f"{path}: stable file-handle read is unsupported on this platform"
        )

    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        if no_follow and exc.errno == errno.ELOOP:
            raise MigrationCliError(f"{path}: input path must not be a symlink") from exc
        raise MigrationCliError(f"{path}: could not open input: {exc}") from exc

    try:
        opened = os.fstat(descriptor)
        error = _regular_file_error(path, opened)
        if error is not None:
            raise MigrationCliError(error)
        after = path.lstat()
        if _file_identity(before) != _file_identity(opened) or _file_identity(opened) != _file_identity(after):
            if stat.S_ISLNK(after.st_mode):
                raise MigrationCliError(f"{path}: input path must not be a symlink")
            raise MigrationCliError(f"{path}: input path changed during read")
    except MigrationCliError:
        os.close(descriptor)
        raise
    except FileNotFoundError as exc:
        os.close(descriptor)
        raise MigrationCliError(f"{path}: input path changed during read") from exc
    except OSError as exc:
        os.close(descriptor)
        raise MigrationCliError(f"{path}: could not verify input: {exc}") from exc
    return descriptor


def _read_json_from_descriptor(descriptor: int, path: Path) -> dict[str, object]:
    stream = None
    try:
        stream = os.fdopen(descriptor, "r", encoding="utf-8")
        with stream:
            value = json.load(stream)
    except json.JSONDecodeError as exc:
        raise MigrationCliError(f"{path}: invalid JSON: {exc.msg}") from exc
    except UnicodeDecodeError as exc:
        raise MigrationCliError(f"{path}: invalid UTF-8: {exc}") from exc
    except (OSError, ValueError) as exc:
        raise MigrationCliError(f"{path}: could not read project: {exc}") from exc
    finally:
        if stream is None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if not isinstance(value, dict):
        raise MigrationCliError(f"{path}: project JSON root must be an object")
    return value


def _open_directory_child_descriptor(
    directory_descriptor: int,
    name: str,
    expected_stat: os.stat_result,
) -> int:
    """Open a checked directory member relative to its stable directory fd."""

    if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
        raise MigrationCliError(
            "stable directory child opening is unsupported on this platform"
        )
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(name, flags, dir_fd=directory_descriptor)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise MigrationCliError(f"{name}: symlink or path changed during directory check") from exc
        raise MigrationCliError(f"{name}: could not open during directory check: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        error = _regular_file_error(Path(name), opened)
        if error is not None:
            raise MigrationCliError(f"{name}: file changed during directory check")
        if _file_identity(expected_stat) != _file_identity(opened):
            raise MigrationCliError(f"{name}: file changed during directory check")
    except MigrationCliError:
        os.close(descriptor)
        raise
    except OSError as exc:
        os.close(descriptor)
        raise MigrationCliError(f"{name}: could not verify during directory check: {exc}") from exc
    return descriptor


def _read_json(
    path: Path,
    *,
    directory_descriptor: int | None = None,
    entry_name: str | None = None,
    expected_stat: os.stat_result | None = None,
    expected_path_stat: os.stat_result | None = None,
) -> dict[str, object]:
    if directory_descriptor is None:
        if entry_name is not None or expected_stat is not None:
            raise MigrationCliError("directory entry descriptor arguments require a directory")
        descriptor = _open_single_file_descriptor(path)
        if expected_path_stat is not None:
            try:
                opened = os.fstat(descriptor)
            except OSError as exc:
                os.close(descriptor)
                raise MigrationCliError(f"{path}: could not verify input: {exc}") from exc
            if _file_identity(expected_path_stat) != _file_identity(opened):
                os.close(descriptor)
                raise MigrationCliError(f"{path}: input path changed during read")
    else:
        if entry_name is None or expected_stat is None:
            raise MigrationCliError("directory entry descriptor arguments are incomplete")
        descriptor = _open_directory_child_descriptor(
            directory_descriptor, entry_name, expected_stat
        )
    return _read_json_from_descriptor(descriptor, path)


def _migrate_path(
    path: Path, *, expected_path_stat: os.stat_result | None = None
) -> dict[str, object]:
    document = _read_json(path, expected_path_stat=expected_path_stat)
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
) -> str | None:
    if refuse_existing:
        return _write_new_no_clobber(destination, document)
    try:
        # This shared persistence helper owns mkstemp(dir=parent), fsync,
        # validation of the staged JSON, os.replace, and failure cleanup.
        write_project_document_atomically(destination, document)
    except ProjectConfigurationWriteError as exc:
        raise MigrationCliError(str(exc)) from exc
    except OSError as exc:
        raise MigrationCliError(f"{destination}: atomic write failed: {exc}") from exc


def _write_new_no_clobber(
    destination: Path, document: dict[str, object]
) -> str | None:
    """Publish a new destination without ever replacing a directory entry.

    The staged file is written and validated in the destination directory.  A
    same-filesystem hard link is an atomic create-if-absent operation: it fails
    for regular files, directories, dangling symlinks, and a creator that wins
    a race after staging.  Explicit ``--output`` therefore requires hard-link
    support and a destination on the same filesystem as the staging directory.
    The in-place path intentionally remains on the shared persistence helper's
    portable ``os.replace`` semantics.

    The hard link is the commit point.  If staged cleanup fails after that
    point, the destination remains committed and this function returns a
    warning rather than claiming that migration failed.  Before the commit
    point, cleanup failure is appended to the primary error with the leaked
    staging path.
    """

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise MigrationCliError(
            f"{destination}: could not prepare destination directory: {exc}"
        ) from exc

    file_descriptor: int | None = None
    staged_path: Path | None = None
    def fail_before_commit(primary: str) -> None:
        if staged_path is None:
            raise MigrationCliError(primary)
        removed, attempts = _cleanup_staged_path(staged_path)
        if not removed:
            primary = _cleanup_failure_message(primary, staged_path, attempts)
        raise MigrationCliError(primary)

    try:
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
        except MigrationCliError as exc:
            fail_before_commit(f"{destination}: atomic output failed: {exc}")
        except (OSError, UnicodeError, ValueError) as exc:
            fail_before_commit(f"{destination}: atomic output failed: {exc}")

        assert staged_path is not None
        try:
            ProjectConfiguration.from_file(staged_path)
        except Exception as exc:
            fail_before_commit(f"{destination}: staged output validation failed: {exc}")

        try:
            os.link(staged_path, destination)
        except FileExistsError:
            fail_before_commit(f"{destination}: destination already exists")
        except OSError as exc:
            fail_before_commit(f"{destination}: atomic no-clobber publish failed: {exc}")

        # os.link succeeded: the destination is committed, even if cleanup of
        # the second hard link is refused by the filesystem.
        removed, attempts = _cleanup_staged_path(staged_path)
        if removed:
            return None
        return (
            f"destination committed at {destination}; staged cleanup failed "
            f"after {attempts} attempts; leaked staging path: {staged_path}"
        )
    finally:
        if file_descriptor is not None:
            try:
                os.close(file_descriptor)
            except OSError:
                pass


def _migration_command(path: Path) -> str:
    return shlex.join((*_SCRIPT_COMMAND, str(path), "--in-place"))


def _open_directory_handle(directory: Path) -> int:
    """Open a real directory for stable descriptor-relative enumeration."""

    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise MigrationCliError(
            f"{directory}: stable directory-handle enumeration is unsupported on this platform"
        )
    if os.open not in os.supports_dir_fd or os.stat not in os.supports_dir_fd:
        raise MigrationCliError(
            f"{directory}: stable directory-handle enumeration is unsupported on this platform"
        )

    try:
        before = directory.lstat()
    except FileNotFoundError as exc:
        raise MigrationCliError(f"{directory}: input path disappeared before checking") from exc
    except OSError as exc:
        raise MigrationCliError(f"{directory}: could not inspect directory: {exc}") from exc
    if stat.S_ISLNK(before.st_mode):
        raise MigrationCliError(f"{directory}: input path must not be a symlink")
    if not stat.S_ISDIR(before.st_mode):
        raise MigrationCliError(f"{directory}: input path is not a directory")
    if not before.st_mode & (stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH) or not before.st_mode & (
        stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    ):
        raise MigrationCliError(
            f"{directory}: directory has no read/search permission bits"
        )

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(directory, flags)
    except OSError as exc:
        raise MigrationCliError(f"{directory}: could not open directory: {exc}") from exc
    try:
        directory_stat = os.fstat(descriptor)
        if not stat.S_ISDIR(directory_stat.st_mode):
            raise MigrationCliError(f"{directory}: input path is not a directory")
        if not directory_stat.st_mode & (
            stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
        ) or not directory_stat.st_mode & (
            stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        ):
            raise MigrationCliError(
                f"{directory}: directory has no read/search permission bits"
            )
        if _file_identity(before) != _file_identity(directory_stat):
            raise MigrationCliError(f"{directory}: input path changed during directory check")
    except MigrationCliError:
        os.close(descriptor)
        raise
    except OSError as exc:
        os.close(descriptor)
        raise MigrationCliError(f"{directory}: could not inspect directory: {exc}") from exc
    return descriptor


def _directory_entries(
    directory_descriptor: int,
) -> list[tuple[os.DirEntry[str], os.stat_result | None]]:
    try:
        with os.scandir(directory_descriptor) as iterator:
            entries: list[tuple[os.DirEntry[str], os.stat_result | None]] = []
            for entry in iterator:
                if not entry.name.endswith(".json"):
                    continue
                try:
                    entry_stat = entry.stat(follow_symlinks=False)
                    # inode() is the directory-entry identity captured by
                    # readdir.  A mismatch means the name was replaced before
                    # its stat was obtained, so do not consume it.
                    entry_inode = entry.inode()
                    if entry_inode and entry_inode != entry_stat.st_ino:
                        entry_stat = None
                except (OSError, UnicodeError):
                    entry_stat = None
                entries.append((entry, entry_stat))
    except (TypeError, NotImplementedError) as exc:
        raise MigrationCliError(
            "stable directory-handle enumeration is unsupported on this platform"
        ) from exc
    except (OSError, UnicodeError) as exc:
        raise MigrationCliError(f"could not enumerate directory: {exc}") from exc
    return sorted(entries, key=lambda item: item[0].name)


def _check_directory(
    directory: Path, *, expected_path_stat: os.stat_result | None = None
) -> int:
    findings: list[str] = []
    try:
        directory_descriptor = _open_directory_handle(directory)
    except MigrationCliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FINDINGS
    if expected_path_stat is not None:
        try:
            opened_directory_stat = os.fstat(directory_descriptor)
        except OSError as exc:
            os.close(directory_descriptor)
            print(f"error: {directory}: could not verify directory: {exc}", file=sys.stderr)
            return EXIT_FINDINGS
        if _file_identity(expected_path_stat) != _file_identity(opened_directory_stat):
            os.close(directory_descriptor)
            print(
                f"error: {directory}: input path changed during directory check",
                file=sys.stderr,
            )
            return EXIT_FINDINGS

    try:
        try:
            entries = _directory_entries(directory_descriptor)
        except MigrationCliError as exc:
            print(f"error: {directory}: {exc}", file=sys.stderr)
            return EXIT_FINDINGS

        for entry, entry_stat in entries:
            path = directory / entry.name
            if entry_stat is None:
                findings.append(
                    f"{path}: file changed during directory check; "
                    "migration command is not applicable"
                )
                continue
            if stat.S_ISLNK(entry_stat.st_mode) or not stat.S_ISREG(entry_stat.st_mode):
                findings.append(
                    f"{path}: special/non-regular JSON directory entry; "
                    "migration command is not applicable"
                )
                continue
            try:
                document = _read_json(
                    path,
                    directory_descriptor=directory_descriptor,
                    entry_name=entry.name,
                    expected_stat=entry_stat,
                )
            except MigrationCliError as exc:
                findings.append(
                    f"{path}: invalid project: {exc}; "
                    f"migrate with: {_migration_command(path)}"
                )
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
    finally:
        try:
            os.close(directory_descriptor)
        except OSError:
            pass

    for finding in findings:
        print(finding, file=sys.stderr)
    return EXIT_FINDINGS if findings else EXIT_SUCCESS


def main(argv: Sequence[str] | None = None) -> int:
    """Run the offline migration command and return its stable status code."""

    parser = _parser()
    args = parser.parse_args(argv)
    input_stat = _validate_arguments(
        parser,
        input_path=args.input,
        output=args.output,
        in_place=args.in_place,
        check=args.check,
    )

    if args.check:
        return _check_directory(args.input, expected_path_stat=input_stat)

    try:
        migrated = _migrate_path(args.input, expected_path_stat=input_stat)
        cleanup_warning: str | None = None
        if args.in_place:
            cleanup_warning = _write_atomically(
                args.input, migrated, refuse_existing=False
            )
        elif args.output is not None:
            cleanup_warning = _write_atomically(
                args.output, migrated, refuse_existing=True
            )
        else:
            sys.stdout.write(_canonical_json(migrated))
    except MigrationCliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FINDINGS
    if cleanup_warning is not None:
        print(f"warning: {cleanup_warning}", file=sys.stderr)
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
