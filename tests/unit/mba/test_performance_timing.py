"""Portable timing records for MBA provider stage telemetry."""

from __future__ import annotations

import pytest

from d810.mba.performance_timing import MbaStageTimer


def test_stage_timer_records_ordered_elapsed_durations() -> None:
    ticks = iter((1.0, 1.002, 1.005, 1.009))
    timer = MbaStageTimer(enabled=True, clock=lambda: next(ticks))

    timer.begin("native_preflight")
    timer.finish("native_preflight")
    timer.begin("egglog_extraction")
    timer.finish("egglog_extraction")

    timings = timer.freeze()

    assert tuple(name for name, _elapsed in timings.stages) == (
        "native_preflight",
        "egglog_extraction",
    )
    assert tuple(elapsed for _name, elapsed in timings.stages) == pytest.approx(
        (2.0, 4.0)
    )
    assert timings.as_dict() == pytest.approx(
        {"native_preflight": 2.0, "egglog_extraction": 4.0}
    )


def test_disabled_stage_timer_never_reads_clock() -> None:
    def forbidden_clock() -> float:
        raise AssertionError("disabled timing must not read the clock")

    timer = MbaStageTimer(enabled=False, clock=forbidden_clock)

    timer.begin("native_preflight")
    timer.finish("native_preflight")

    assert timer.freeze().stages == ()


def test_stage_timer_rejects_invalid_transitions() -> None:
    timer = MbaStageTimer(enabled=True, clock=lambda: 1.0)

    with pytest.raises(ValueError, match="not started"):
        timer.finish("native_preflight")

    timer.begin("native_preflight")
    with pytest.raises(ValueError, match="already started"):
        timer.begin("native_preflight")
    timer.finish("native_preflight")
    with pytest.raises(ValueError, match="already completed"):
        timer.begin("native_preflight")
