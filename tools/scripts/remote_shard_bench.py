#!/usr/bin/env python3
"""Measure what remote offload actually buys on wall time.

``run_system_tests_docker.sh --remote`` is an *offload* runner: it moves one
container to another machine.  Running several worktrees at once on that
machine is what turns it into a sharded runner, and the only honest way to
claim a speedup is to measure both arms.

This script launches one container per shard (one worktree each, which is what
the runner's per-worktree lock allows), waits for all of them, then runs the
same test ids once as a sequential baseline, and prints the measured table.
Every number it prints is measured here; nothing is estimated.

Example::

    python3 tools/scripts/remote_shard_bench.py --remote remote-engine.example \\
        --shard 'perf-canonical-stamp-reviewed=tests/system/e2e/x.py::a' \\
        --shard 'ctrl-w7=tests/system/e2e/x.py::b'
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

DEFAULT_BASELINE = "remote-sequential"
SUMMARY_PATTERN = re.compile(
    r"^.*?\b\d+ (?:passed|failed|error|errors|skipped|xfailed|xpassed)\b"
    r".*?\bin \d+(?:\.\d+)?s.*$",
    re.MULTILINE,
)


@dataclass(frozen=True)
class Shard:
    """One worktree and the test ids assigned to it."""

    index: int
    worktree: str
    test_ids: tuple[str, ...]

    @property
    def output_name(self) -> str:
        return f"shard-{self.index}.txt"


@dataclass(frozen=True)
class ShardResult:
    shard: Shard
    seconds: float
    returncode: int
    summary: str | None
    revision: str | None = None


@dataclass(frozen=True)
class BenchSummary:
    results: tuple[ShardResult, ...]
    parallel_wall: float
    slowest_shard: float
    launch_overhead: float
    baseline_wall: float | None
    baseline_label: str
    baseline_summary: str | None
    speedup: float | None
    baseline_returncode: int | None = None
    baseline_revision: str | None = None


def default_runner() -> Path:
    """The runner shipped beside this script.

    ``-w`` mounts a worktree's sources but the wrapper that runs is always the
    one invoked, so the bench must not resolve the runner from ``--repo-root``:
    the root checkout's copy can predate ``--remote`` entirely.
    """
    return Path(__file__).resolve().parent / "run_system_tests_docker.sh"


def parse_shard_assignment(specification: str) -> tuple[str, tuple[str, ...]]:
    """Split ``WORKTREE=ID[,ID...]`` into its worktree and test ids.

    >>> parse_shard_assignment("wt=a::b,c::d")
    ('wt', ('a::b', 'c::d'))
    """
    worktree, separator, joined = specification.partition("=")
    if not separator or not worktree.strip():
        raise ValueError(f"--shard needs WORKTREE=TEST_ID[,TEST_ID...], got {specification!r}")
    test_ids = tuple(part.strip() for part in joined.split(",") if part.strip())
    if not test_ids:
        raise ValueError(f"--shard {worktree!r} lists no test ids")
    return worktree.strip(), test_ids


def build_shards(specifications: Sequence[str]) -> tuple[Shard, ...]:
    """Turn --shard specifications into numbered shards, one worktree each.

    >>> [shard.worktree for shard in build_shards(["a=t::1", "b=t::2"])]
    ['a', 'b']
    """
    shards: list[Shard] = []
    seen: set[str] = set()
    for index, specification in enumerate(specifications):
        worktree, test_ids = parse_shard_assignment(specification)
        if worktree in seen:
            raise ValueError(
                f"worktree {worktree!r} is used twice; one run per worktree is enforced by the runner lock"
            )
        seen.add(worktree)
        shards.append(Shard(index=index, worktree=worktree, test_ids=test_ids))
    if not shards:
        raise ValueError("at least one --shard is required")
    return tuple(shards)


def build_shard_command(
    runner: str,
    *,
    remote: str | None,
    worktree: str,
    output_name: str,
    test_ids: Sequence[str],
) -> list[str]:
    """Build one runner invocation.

    >>> build_shard_command("r.sh", remote="h", worktree="w", output_name="o.txt",
    ...                     test_ids=["t::1"])
    ['r.sh', 'test', '--remote', 'h', '-w', 'w', '-o', 'o.txt', '--', 't::1', '-q']
    """
    command = [runner, "test"]
    if remote:
        command += ["--remote", remote]
    command += ["-w", worktree, "-o", output_name, "--", *test_ids, "-q"]
    return command


def extract_pytest_summary(text: str) -> str | None:
    """Return the last pytest summary line in a captured output file.

    >>> extract_pytest_summary("collecting\\n1 passed in 12.34s\\n")
    '1 passed in 12.34s'
    >>> extract_pytest_summary("=== 2 passed, 1 warning in 3.00s ===")
    '2 passed, 1 warning in 3.00s'
    >>> extract_pytest_summary("nothing here") is None
    True
    """
    matches = SUMMARY_PATTERN.findall(text)
    if not matches:
        return None
    return matches[-1].strip().strip("=").strip()


def parse_summary_counts(summary: str) -> dict[str, int]:
    """Parse the ``N outcome`` pairs out of a pytest summary line.

    >>> parse_summary_counts("2 passed, 1 warning in 3.00s") == {
    ...     "passed": 2, "warning": 1}
    True
    >>> parse_summary_counts("1 failed, 1 passed in 9.0s") == {
    ...     "failed": 1, "passed": 1}
    True
    """
    counts: dict[str, int] = {}
    for amount, outcome in re.findall(r"(\d+) ([a-z]+)", summary):
        if outcome == "s":  # the trailing "in 3.00s" duration
            continue
        counts[outcome] = counts.get(outcome, 0) + int(amount)
    return counts


def summary_is_green(summary: str | None) -> bool:
    """A shard counts only when its output reports passes and no failures.

    >>> summary_is_green("1 passed in 1.0s"), summary_is_green("1 failed in 1.0s")
    (True, False)
    >>> summary_is_green("1 failed, 1 passed in 1.0s")
    False
    >>> summary_is_green("2 errors in 1.0s"), summary_is_green(None)
    (False, False)
    """
    if summary is None:
        return False
    counts = parse_summary_counts(summary)
    if any(counts.get(bad) for bad in ("failed", "error", "errors")):
        return False
    return counts.get("passed", 0) > 0


def build_revision_argv(worktree_dir: Path) -> list[str]:
    """Build the argv that reads a worktree's checked-out revision.

    >>> build_revision_argv(Path("/w"))[:3]
    ['git', '-C', '/w']
    """
    return ["git", "-C", str(worktree_dir), "rev-parse", "HEAD"]


def revision_conflict(revisions: Sequence[str | None], allow_mixed: bool) -> str | None:
    """Report when shards did not all run the same source revision.

    >>> revision_conflict(["a", "a"], False) is None
    True
    >>> revision_conflict(["a", "b"], False)
    'shards ran mixed revisions: a, b'
    >>> revision_conflict(["a", "b"], True) is None
    True
    >>> revision_conflict(["a", None], False)
    'shard revision could not be determined'
    """
    if allow_mixed:
        return None
    if any(revision is None for revision in revisions):
        return "shard revision could not be determined"
    distinct = sorted(set(revision for revision in revisions if revision))
    if len(distinct) > 1:
        return "shards ran mixed revisions: " + ", ".join(distinct)
    return None


def read_revision(worktree_dir: Path) -> str | None:
    """Read a worktree's HEAD (impure seam for tests)."""
    completed = subprocess.run(
        build_revision_argv(worktree_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        return None
    revision = completed.stdout.strip()
    return revision or None


def remove_stale_output(worktree_dir: Path, output_name: str) -> None:
    """Delete a previous capture so a stale file can never be read as fresh."""
    path = worktree_dir / ".tmp" / output_name
    if path.exists():
        path.unlink()


def aggregate(
    results: Sequence[ShardResult],
    *,
    parallel_wall: float,
    baseline_wall: float | None,
    baseline_label: str,
    baseline_summary: str | None,
    baseline_returncode: int | None = None,
    baseline_revision: str | None = None,
) -> BenchSummary:
    """Combine measured walls into the reported figures.

    >>> shard = Shard(0, "w", ("t",))
    >>> summary = aggregate(
    ...     [ShardResult(shard, 100.0, 0, "1 passed in 90.0s")],
    ...     parallel_wall=110.0, baseline_wall=220.0,
    ...     baseline_label="remote-sequential", baseline_summary=None)
    >>> summary.slowest_shard, summary.launch_overhead, summary.speedup
    (100.0, 10.0, 2.0)
    """
    if not results:
        raise ValueError("no shard results to aggregate")
    slowest = max(result.seconds for result in results)
    speedup = None
    if baseline_wall is not None and parallel_wall > 0:
        speedup = baseline_wall / parallel_wall
    return BenchSummary(
        results=tuple(results),
        parallel_wall=parallel_wall,
        slowest_shard=slowest,
        launch_overhead=parallel_wall - slowest,
        baseline_wall=baseline_wall,
        baseline_label=baseline_label,
        baseline_summary=baseline_summary,
        speedup=speedup,
        baseline_returncode=baseline_returncode,
        baseline_revision=baseline_revision,
    )


def render_table(summary: BenchSummary) -> str:
    """Render the measured results as minimal-separator markdown tables."""
    lines = [
        "|shard|worktree|revision|tests|wall s|exit|pytest summary|",
        "|-|-|-|-|-|-|-|",
    ]
    for result in summary.results:
        lines.append(
            "|{index}|{worktree}|{revision}|{count}|{seconds:.1f}|{code}|{summary}|".format(
                index=result.shard.index,
                worktree=result.shard.worktree,
                revision=(result.revision or "unknown")[:12],
                count=len(result.shard.test_ids),
                seconds=result.seconds,
                code=result.returncode,
                summary=result.summary or "MISSING",
            )
        )
    lines.append("")
    lines.append("|metric|value|")
    lines.append("|-|-|")
    lines.append(f"|shards|{len(summary.results)}|")
    lines.append(f"|parallel wall (s)|{summary.parallel_wall:.1f}|")
    lines.append(f"|slowest shard (s)|{summary.slowest_shard:.1f}|")
    lines.append(f"|launch overhead (s)|{summary.launch_overhead:.1f}|")
    if summary.baseline_wall is None:
        lines.append(f"|baseline ({summary.baseline_label})|not measured|")
    else:
        lines.append(
            f"|baseline {summary.baseline_label} wall (s)|{summary.baseline_wall:.1f}|"
        )
        lines.append(f"|baseline summary|{summary.baseline_summary or 'MISSING'}|")
        lines.append(f"|baseline exit|{summary.baseline_returncode}|")
        lines.append(f"|baseline revision|{(summary.baseline_revision or 'unknown')[:12]}|")
    if summary.speedup is None:
        lines.append("|speedup (baseline / parallel)|not measured|")
    else:
        lines.append(f"|speedup (baseline / parallel)|{summary.speedup:.2f}x|")
    return "\n".join(lines)


def read_output(worktree_dir: Path, output_name: str) -> str:
    path = worktree_dir / ".tmp" / output_name
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def run_commands_concurrently(
    commands: Sequence[Sequence[str]],
    *,
    cwd: Path,
    env: dict[str, str],
) -> tuple[list[tuple[float, int]], float]:
    """Launch every command at once; return per-command (wall, rc) and total wall."""
    started: list[tuple[subprocess.Popen[bytes], float]] = []
    overall_start = time.monotonic()
    for command in commands:
        process = subprocess.Popen(
            list(command),
            cwd=str(cwd),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        started.append((process, time.monotonic()))
    measurements: list[tuple[float, int]] = []
    for process, launch_time in started:
        returncode = process.wait()
        measurements.append((time.monotonic() - launch_time, returncode))
    return measurements, time.monotonic() - overall_start


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--remote", required=True, help="remote Docker engine host")
    parser.add_argument(
        "--shard",
        action="append",
        default=[],
        metavar="WORKTREE=TEST_ID[,TEST_ID...]",
        help="one worktree and its test ids; repeat for more shards",
    )
    parser.add_argument(
        "--baseline",
        choices=("local", "remote-sequential", "none"),
        default=DEFAULT_BASELINE,
        help="how to measure the unsharded arm (default: remote-sequential)",
    )
    parser.add_argument("--repo-root", default=None, help="repo root that owns .worktrees (default: this checkout)")
    parser.add_argument(
        "--runner",
        default=None,
        help=(
            "runner script to invoke (default: the copy next to this script). "
            "-w mounts the worktree's sources but always executes THIS runner, so the "
            "default deliberately does not follow --repo-root."
        ),
    )
    parser.add_argument("--worktree-root", default=".worktrees", help="D810_WORKTREE_ROOT")
    parser.add_argument(
        "--allow-mixed-revisions",
        action="store_true",
        help="do not fail when the sharded worktrees are on different revisions",
    )
    parser.add_argument("--dry-run", action="store_true", help="print the planned commands only")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    repo_root = Path(arguments.repo_root or Path(__file__).resolve().parents[2]).resolve()
    runner = str(
        Path(arguments.runner).resolve()
        if arguments.runner
        else default_runner()
    )
    try:
        shards = build_shards(arguments.shard)
    except ValueError as error:
        print(f"ERROR: {error}")
        return 2

    commands = [
        build_shard_command(
            runner,
            remote=arguments.remote,
            worktree=shard.worktree,
            output_name=shard.output_name,
            test_ids=shard.test_ids,
        )
        for shard in shards
    ]
    all_ids = tuple(test_id for shard in shards for test_id in shard.test_ids)
    baseline_command = None
    if arguments.baseline != "none":
        baseline_command = build_shard_command(
            runner,
            remote=arguments.remote if arguments.baseline == "remote-sequential" else None,
            worktree=shards[0].worktree,
            output_name="shard-baseline.txt",
            test_ids=all_ids,
        )

    if arguments.dry_run:
        for command in commands:
            print(" ".join(command))
        if baseline_command is not None:
            print(" ".join(baseline_command))
        return 0

    env = dict(os.environ)
    env["D810_REPO_ROOT"] = str(repo_root)
    env["D810_WORKTREE_ROOT"] = arguments.worktree_root

    # A previous run's capture would otherwise be read as this run's evidence.
    baseline_worktree_dir = repo_root / arguments.worktree_root / shards[0].worktree
    for shard in shards:
        remove_stale_output(
            repo_root / arguments.worktree_root / shard.worktree, shard.output_name
        )
    if baseline_command is not None:
        remove_stale_output(baseline_worktree_dir, "shard-baseline.txt")

    print(f"[bench] launching {len(commands)} shard container(s) on {arguments.remote}")
    measurements, parallel_wall = run_commands_concurrently(commands, cwd=repo_root, env=env)

    results: list[ShardResult] = []
    for shard, (seconds, returncode) in zip(shards, measurements):
        worktree_dir = repo_root / arguments.worktree_root / shard.worktree
        summary = extract_pytest_summary(read_output(worktree_dir, shard.output_name))
        results.append(
            ShardResult(
                shard=shard,
                seconds=seconds,
                returncode=returncode,
                summary=summary,
                revision=read_revision(worktree_dir),
            )
        )

    baseline_wall: float | None = None
    baseline_summary: str | None = None
    baseline_returncode: int | None = None
    baseline_revision: str | None = None
    if baseline_command is not None:
        print(f"[bench] measuring the {arguments.baseline} baseline")
        baseline_start = time.monotonic()
        completed = subprocess.run(
            baseline_command,
            cwd=str(repo_root),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        baseline_wall = time.monotonic() - baseline_start
        baseline_returncode = completed.returncode
        baseline_summary = extract_pytest_summary(
            read_output(baseline_worktree_dir, "shard-baseline.txt")
        )
        baseline_revision = read_revision(baseline_worktree_dir)

    summary = aggregate(
        results,
        parallel_wall=parallel_wall,
        baseline_wall=baseline_wall,
        baseline_label=arguments.baseline,
        baseline_summary=baseline_summary,
        baseline_returncode=baseline_returncode,
        baseline_revision=baseline_revision,
    )
    print(render_table(summary))

    problems: list[str] = []
    for result in results:
        label = f"shard {result.shard.index} ({result.shard.worktree})"
        if result.returncode != 0:
            problems.append(f"{label} runner exited {result.returncode}")
        if not summary_is_green(result.summary):
            problems.append(
                f"{label} produced no passing summary (got {result.summary or 'no summary'})"
            )
    if baseline_command is not None:
        if baseline_returncode != 0:
            problems.append(f"baseline runner exited {baseline_returncode}")
        if not summary_is_green(baseline_summary):
            problems.append(
                f"baseline produced no passing summary (got {baseline_summary or 'no summary'})"
            )
    revisions = [result.revision for result in results]
    if baseline_command is not None:
        revisions.append(baseline_revision)
    conflict = revision_conflict(revisions, arguments.allow_mixed_revisions)
    if conflict is not None:
        problems.append(f"{conflict}; pass --allow-mixed-revisions to accept it")
    if problems:
        for problem in problems:
            print(f"ERROR: {problem}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
