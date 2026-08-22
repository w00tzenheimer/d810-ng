#!/usr/bin/env python3
"""Reject local-only work artifacts from a Git index or tree."""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path


FORBIDDEN_TRACKED_PREFIXES = (
    ".superpowers/sdd",
    "docs/plans",
    "docs/superpowers",
)


def _normalize_git_path(path: str) -> str:
    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.rstrip("/")


def forbidden_tracked_paths(paths: Iterable[str]) -> tuple[str, ...]:
    """Return tracked paths owned by one of the local-only prefixes."""

    forbidden: list[str] = []
    for raw_path in paths:
        path = _normalize_git_path(raw_path)
        if not path:
            continue
        if any(
            path == prefix or path.startswith(f"{prefix}/")
            for prefix in FORBIDDEN_TRACKED_PREFIXES
        ):
            forbidden.append(path)
    return tuple(dict.fromkeys(forbidden))


def _git_paths(
    repo_root: Path,
    *,
    staged: bool,
    tree: str | None,
) -> tuple[str, ...]:
    if staged:
        command = (
            "git",
            "diff",
            "--cached",
            "--name-only",
            "--diff-filter=ACMR",
            "-z",
            "--",
        )
    elif tree is not None:
        command = ("git", "ls-tree", "-r", "--name-only", "-z", tree, "--")
    else:
        command = ("git", "ls-files", "-z")
    output = subprocess.run(
        command,
        cwd=repo_root,
        check=True,
        capture_output=True,
    ).stdout.decode("utf-8")
    return tuple(path for path in output.split("\0") if path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Reject tracked local-only planning and SDD artifacts."
    )
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument(
        "--staged",
        action="store_true",
        help="inspect added, copied, modified, or renamed paths in the index",
    )
    scope.add_argument(
        "--tree",
        metavar="TREEISH",
        help="inspect the complete Git tree at TREEISH",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="repository checkout to inspect (default: current directory)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repo_root = args.repo_root.resolve()
    forbidden = forbidden_tracked_paths(
        _git_paths(repo_root, staged=args.staged, tree=args.tree)
    )
    if not forbidden:
        return 0

    scope = "staged paths" if args.staged else (
        f"tree {args.tree}" if args.tree is not None else "tracked paths"
    )
    print(
        f"[forbidden-tracked-paths] BLOCKED: {scope} contain local-only artifacts:",
        file=sys.stderr,
    )
    for path in forbidden:
        print(f"[forbidden-tracked-paths]   {path}", file=sys.stderr)
    print(
        "[forbidden-tracked-paths] Move these files under _gitless/ and untrack "
        "their original paths.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
