"""Shared benchmark utilities for d810 performance tests.

Extracted from test_cython_benchmark.py to avoid duplication across
multiple benchmark modules.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from d810.core.typing import Callable


@dataclass
class BenchResult:
    """Result of a single benchmark run."""
    name: str
    cython_time: float
    python_time: float
    iterations: int

    @property
    def speedup(self) -> float:
        if self.cython_time == 0:
            return float('inf')
        return self.python_time / self.cython_time

    def report(self) -> str:
        return (
            f"\n{self.name}:\n"
            f"  Cython:      {self.cython_time * 1000:.2f} ms ({self.iterations} iterations)\n"
            f"  Pure Python: {self.python_time * 1000:.2f} ms ({self.iterations} iterations)\n"
            f"  Speedup:     {self.speedup:.2f}x"
        )


def timed_run(func: Callable[[], None], iterations: int, warmup: int = 3) -> float:
    """Run function multiple times and return total elapsed time.

    Args:
        func: Function to benchmark (takes no arguments)
        iterations: Number of iterations to run
        warmup: Number of warmup iterations (default: 3)

    Returns:
        Total elapsed time in seconds for all iterations
    """
    # Warmup
    for _ in range(warmup):
        func()

    start = time.perf_counter()
    for _ in range(iterations):
        func()
    return time.perf_counter() - start


def save_baseline(results: dict, path: Path, label: str) -> None:
    """Save baseline benchmark results as JSON and markdown.

    Args:
        results: Dict mapping benchmark_name -> metric_dict
        path: Path to JSON file (e.g., baseline_pattern_engine.json)
        label: Human-readable label for the markdown summary
    """
    # Ensure parent directory exists
    path.parent.mkdir(parents=True, exist_ok=True)

    # Write JSON
    with open(path, 'w') as f:
        json.dump(results, f, indent=2, sort_keys=True)

    # Write markdown summary
    md_path = path.with_suffix('.md')
    with open(md_path, 'w') as f:
        f.write(f"# {label}\n\n")
        f.write(f"**Generated**: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("## Summary\n\n")
        f.write("| Benchmark | Metric | Value |\n")
        f.write("|-----------|--------|-------|\n")
        for name, metrics in sorted(results.items()):
            for metric, value in sorted(metrics.items()):
                if isinstance(value, float):
                    f.write(f"| {name} | {metric} | {value:.4f} |\n")
                else:
                    f.write(f"| {name} | {metric} | {value} |\n")
        f.write("\n---\n\n")
        f.write(f"Full JSON: `{path.name}`\n")
