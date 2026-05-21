"""Check repository compatibility with IDA-supported Python runtimes."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


DEFAULT_PATHS = ("src", "tools", "tests", "setup.py")
DEFAULT_TARGET = "3.10-"
SUPPORTED_SYNTAX_VERSIONS = ((3, 10), (3, 11), (3, 12))
VERMIN_EXCLUDES = (
    "typing.Self",
    "typing.NotRequired",
    "typing.LiteralString",
    "typing.TypeAliasType",
    "typing.override",
)
SKIP_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
}


def _repo_root() -> Path:
    return Path.cwd()


def _iter_python_files(paths: tuple[str, ...]) -> tuple[Path, ...]:
    root = _repo_root()
    files: list[Path] = []
    for raw_path in paths:
        path = Path(raw_path)
        if not path.exists():
            continue
        if path.is_file():
            if path.suffix == ".py":
                files.append(path)
            continue
        for candidate in path.rglob("*.py"):
            rel_parts = candidate.relative_to(root).parts if candidate.is_absolute() else candidate.parts
            if any(part in SKIP_DIRS for part in rel_parts):
                continue
            files.append(candidate)
    return tuple(sorted(files))


def _run_vermin(paths: tuple[str, ...], *, target: str) -> int:
    vermin = shutil.which("vermin")
    if vermin is None:
        print("error: vermin is not installed; run `python -m pip install -e .[dev]`", file=sys.stderr)
        return 127

    cmd = [
        vermin,
        f"--target={target}",
        "--violations",
        "--no-tips",
        "--no-make-paths-absolute",
        "--backport",
        "typing_extensions",
        "--exclude-regex",
        r"^src/d810/_vendor($|/)",
    ]
    for symbol in VERMIN_EXCLUDES:
        cmd.extend(["--exclude", symbol])
    cmd.extend(paths)
    return subprocess.run(cmd, check=False).returncode


def _candidate_interpreters(
    explicit: str | None,
    *,
    target_versions: tuple[tuple[int, int], ...],
) -> tuple[tuple[str, ...], ...]:
    if explicit:
        return (tuple(explicit.split()),)

    candidates: list[tuple[str, ...]] = []
    for major, minor in target_versions:
        name = f"python{major}.{minor}"
        resolved = shutil.which(name)
        if resolved:
            candidates.append((resolved,))
    for name in ("python3", "python"):
        resolved = shutil.which(name)
        if resolved:
            candidates.append((resolved,))
    py_launcher = shutil.which("py")
    if py_launcher:
        for major, minor in target_versions:
            candidates.append((py_launcher, f"-{major}.{minor}"))
    return tuple(candidates)


def _interpreter_version(command: tuple[str, ...]) -> tuple[int, int] | None:
    code = "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
    proc = subprocess.run([*command, "-c", code], text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        return None
    try:
        major, minor = proc.stdout.strip().split(".", 1)
        return int(major), int(minor)
    except ValueError:
        return None


def _select_syntax_interpreter(
    explicit: str | None,
    *,
    target_versions: tuple[tuple[int, int], ...] = SUPPORTED_SYNTAX_VERSIONS,
) -> tuple[str, ...] | None:
    for command in _candidate_interpreters(explicit, target_versions=target_versions):
        version = _interpreter_version(command)
        if version in target_versions:
            return command
    return None


def _run_supported_python_syntax_check(paths: tuple[str, ...], *, interpreter: str | None) -> int:
    command = _select_syntax_interpreter(interpreter)
    if command is None:
        versions = ", ".join(f"{major}.{minor}" for major, minor in SUPPORTED_SYNTAX_VERSIONS)
        print(
            f"warning: no supported Python syntax interpreter found ({versions}); skipped target parser syntax check",
            file=sys.stderr,
        )
        return 0

    files = _iter_python_files(paths)
    if not files:
        return 0

    checker = (
        "import pathlib, sys\n"
        "failed = False\n"
        "for raw in sys.argv[1:]:\n"
        "    path = pathlib.Path(raw)\n"
        "    try:\n"
        "        source = path.read_text(encoding='utf-8')\n"
        "        compile(source, str(path), 'exec')\n"
        "    except SyntaxError as exc:\n"
        "        failed = True\n"
        "        print(f'{path}:{exc.lineno}:{exc.offset}: SyntaxError: {exc.msg}', file=sys.stderr)\n"
        "    except UnicodeDecodeError as exc:\n"
        "        failed = True\n"
        "        print(f'{path}: UnicodeDecodeError: {exc}', file=sys.stderr)\n"
        "sys.exit(1 if failed else 0)\n"
    )

    overall = 0
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    for index in range(0, len(files), 200):
        chunk = [str(path) for path in files[index : index + 200]]
        proc = subprocess.run([*command, "-c", checker, *chunk], env=env, check=False)
        if proc.returncode != 0:
            overall = proc.returncode
    return overall


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check d810 source syntax and language-version compatibility.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=list(DEFAULT_PATHS),
        help="source paths to check (default: src/d810 tools tests)",
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help="vermin target version expression (default: 3.10-)",
    )
    parser.add_argument(
        "--python310",
        dest="syntax_python",
        default=os.environ.get("D810_PYTHON_SYNTAX") or os.environ.get("D810_PYTHON310"),
        help="Python interpreter command for parser syntax checks",
    )
    parser.add_argument(
        "--skip-vermin",
        action="store_true",
        help="skip vermin feature-version analysis",
    )
    parser.add_argument(
        "--skip-syntax",
        action="store_true",
        help="skip supported-Python parser syntax check",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    paths = tuple(args.paths)

    results: list[int] = []
    if not args.skip_vermin:
        results.append(_run_vermin(paths, target=args.target))
    if not args.skip_syntax:
        results.append(_run_supported_python_syntax_check(paths, interpreter=args.syntax_python))
    return 1 if any(result != 0 for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
