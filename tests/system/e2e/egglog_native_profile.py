"""Test-only aggregation for live Egglog execution metadata."""

from __future__ import annotations

from collections import Counter
from statistics import quantiles


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


__all__ = ["build_native_egglog_profile"]
