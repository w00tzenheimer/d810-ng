#!/usr/bin/env python3
"""Run IDA system tests in fresh, bounded interpreter batches.

IDA and Hex-Rays retain native allocations after database teardown. A single
pytest process for the complete system suite eventually reaches the container
memory limit, while ``pytest-forked`` is unsafe after the IDA runtime has been
initialized. This driver collects node IDs once, then starts a clean Python
process for each bounded batch and propagates the first failing status.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
import subprocess
import sys


Run = Callable[..., subprocess.CompletedProcess]


def parse_collected_nodeids(output: str) -> tuple[str, ...]:
    return tuple(
        line.strip()
        for line in output.splitlines()
        if line.startswith("tests/") and "::" in line
    )


def _batches(values: Sequence[str], size: int) -> tuple[tuple[str, ...], ...]:
    if size < 1:
        raise ValueError("batch size must be positive")
    return tuple(tuple(values[index : index + size]) for index in range(0, len(values), size))


def run_batches(
    *,
    python: str,
    root: str,
    pytest_args: Sequence[str],
    batch_size: int,
    start_batch: int = 1,
    run: Run = subprocess.run,
) -> int:
    collect_command = [
        python,
        "-m",
        "pytest",
        "--collect-only",
        "-q",
        root,
        *pytest_args,
    ]
    collected = run(collect_command, check=False, capture_output=True, text=True)
    if collected.returncode != 0:
        sys.stdout.write(collected.stdout or "")
        sys.stderr.write(collected.stderr or "")
        return int(collected.returncode)

    nodeids = parse_collected_nodeids(collected.stdout)
    if not nodeids:
        sys.stderr.write("[system-batch] collection selected no tests\n")
        return 5

    batches = _batches(nodeids, batch_size)
    if start_batch < 1 or start_batch > len(batches):
        sys.stderr.write(
            f"[system-batch] start_batch={start_batch} outside "
            f"1..{len(batches)}\n"
        )
        return 5
    print(
        f"[system-batch] collected={len(nodeids)} "
        f"batch_size={batch_size} batches={len(batches)} "
        f"start_batch={start_batch}",
        flush=True,
    )
    for index, batch in enumerate(batches[start_batch - 1 :], start=start_batch):
        print(
            f"[system-batch {index}/{len(batches)}] "
            f"tests={len(batch)} first={batch[0]}",
            flush=True,
        )
        command = [python, "-m", "pytest", "-v", *batch, *pytest_args]
        completed = run(command, check=False)
        if completed.returncode != 0:
            print(
                f"[system-batch {index}/{len(batches)}] "
                f"failed exit={completed.returncode}",
                file=sys.stderr,
                flush=True,
            )
            return int(completed.returncode)

    print(f"[system-batch] completed={len(nodeids)} exit=0", flush=True)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--batch-size", type=int, default=20)
    parser.add_argument("--start-batch", type=int, default=1)
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    pytest_args = tuple(args.pytest_args)
    if pytest_args[:1] == ("--",):
        pytest_args = pytest_args[1:]
    return run_batches(
        python=args.python,
        root=args.root,
        pytest_args=pytest_args,
        batch_size=args.batch_size,
        start_batch=args.start_batch,
    )


if __name__ == "__main__":
    raise SystemExit(main())
