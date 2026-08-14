"""Test-only aggregation for live Egglog execution metadata."""

from __future__ import annotations

from collections import Counter


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
    for execution in executions:
        metadata = execution.metadata
        skip_reason = metadata.get("skip_reason")
        outcomes["accepted" if skip_reason is None else str(skip_reason)] += 1
        names = metadata.get("source_names")
        if isinstance(names, tuple):
            source_names.append(list(names))
        stage_timings = metadata.get("stage_timings_ms")
        if isinstance(stage_timings, dict):
            stage_sample_counts.update(stage_timings.keys())
    return {
        "corpus": corpus,
        "execution_count": len(executions),
        "outcomes": dict(sorted(outcomes.items())),
        "source_names": source_names,
        "stage_sample_counts": dict(sorted(stage_sample_counts.items())),
    }


__all__ = ["build_native_egglog_profile"]
