"""Test-only aggregation for live Egglog execution metadata."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
import json
import os
from pathlib import Path
from statistics import quantiles

from d810.core.typing import TypeVar
from d810.manager.profiling import CProfileWrapper


T = TypeVar("T")


def profile_native_egglog_cprofile(corpus: str, run: Callable[[], T]) -> T:
    """Run a real-IDB callback under D810's opt-in cProfile hook.

    The artifact directory is deliberately test-only. Without it, this helper
    returns directly without constructing a profiler or changing execution.
    ``D810_CYTHON_PROFILE=1`` requests a trace-enabled Cython build from the
    Docker runner; its debug timings are for attribution, never comparison.
    """

    artifact_dir = os.environ.get("D810_EGGLOG_CPROFILE_DIR")
    if not artifact_dir:
        return run()
    if Path(corpus).name != corpus:
        raise ValueError("Egglog cProfile corpus must be a basename")

    destination = Path(artifact_dir)
    destination.mkdir(parents=True, exist_ok=True)
    profile_path = destination / f"{corpus}.prof"
    temporary_path = destination / f".{corpus}.prof.tmp"
    profiler = CProfileWrapper()
    profiler.enable()
    try:
        return run()
    finally:
        profiler.disable()
        profiler.profiler.dump_stats(str(temporary_path))
        temporary_path.replace(profile_path)
        print(
            "\nEGGLOG_MBA_CPROFILE_ARTIFACT="
            + json.dumps(
                {
                    "corpus": corpus,
                    "path": profile_path.name,
                    "cython_trace_requested": os.environ.get("D810_CYTHON_PROFILE")
                    == "1",
                },
                sort_keys=True,
            )
        )


def _percentile(samples: tuple[float, ...], percentile: int) -> float:
    if len(samples) == 1:
        return samples[0]
    return quantiles(samples, n=100, method="inclusive")[percentile - 1]


def build_native_egglog_profile(stats, *, corpus: str) -> dict[str, object]:
    """Summarize actual native Egglog firings without treating refusal as success."""

    executions = tuple(
        execution
        for execution in stats.rule_execution_log
        if execution.rule_name == "EgglogOptimizer"
    )
    outcomes = Counter()
    source_names: list[list[str]] = []
    stage_sample_counts = Counter()
    stage_samples: dict[str, list[float]] = {}
    for execution in executions:
        metadata = execution.metadata
        skip_reason = metadata.get("skip_reason")
        outcomes["accepted" if skip_reason is None else str(skip_reason)] += 1
        names = metadata.get("source_names")
        if isinstance(names, tuple):
            source_names.append(list(names))
        stage_timings = metadata.get("stage_timings_ms")
        if isinstance(stage_timings, dict):
            for stage, elapsed_ms in stage_timings.items():
                if type(stage) is str and type(elapsed_ms) is float and elapsed_ms >= 0:
                    stage_sample_counts[stage] += 1
                    stage_samples.setdefault(stage, []).append(elapsed_ms)
    stage_timing_ms = {
        stage: {
            "p50_ms": _percentile(tuple(samples), 50),
            "p95_ms": _percentile(tuple(samples), 95),
            "max_ms": max(samples),
        }
        for stage, samples in sorted(stage_samples.items())
    }
    return {
        "corpus": corpus,
        "execution_count": len(executions),
        "outcomes": dict(sorted(outcomes.items())),
        "source_names": source_names,
        "stage_sample_counts": dict(sorted(stage_sample_counts.items())),
        "stage_timing_ms": stage_timing_ms,
    }


__all__ = ["build_native_egglog_profile", "profile_native_egglog_cprofile"]
