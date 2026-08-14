"""Portable, opt-in timing records for serial MBA provider attempts."""

from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter

from d810.core.typing import Callable


@dataclass(frozen=True)
class MbaStageTimings:
    """Immutable ordered stage durations in milliseconds."""

    stages: tuple[tuple[str, float], ...] = ()

    def __post_init__(self) -> None:
        names: set[str] = set()
        normalized: list[tuple[str, float]] = []
        for name, elapsed_ms in self.stages:
            if type(name) is not str or not name:
                raise ValueError("stage name must be a non-empty string")
            if name in names:
                raise ValueError(f"duplicate stage name: {name}")
            if type(elapsed_ms) is not float or elapsed_ms < 0:
                raise ValueError("stage elapsed time must be a non-negative float")
            names.add(name)
            normalized.append((name, elapsed_ms))
        object.__setattr__(self, "stages", tuple(normalized))

    def as_dict(self) -> dict[str, float]:
        """Return JSON-ready stage durations without changing their order."""

        return dict(self.stages)


EMPTY_MBA_STAGE_TIMINGS = MbaStageTimings()


class MbaStageTimer:
    """Collect named serial stages without reading the clock when disabled."""

    def __init__(
        self,
        *,
        enabled: bool,
        clock: Callable[[], float] = perf_counter,
    ) -> None:
        self._enabled = bool(enabled)
        self._clock = clock
        self._started: dict[str, float] = {}
        self._completed: list[tuple[str, float]] = []
        self._completed_names: set[str] = set()

    def begin(self, name: str) -> None:
        """Start one unique stage."""

        if not self._enabled:
            return
        self._validate_name(name)
        if name in self._started:
            raise ValueError(f"stage already started: {name}")
        if name in self._completed_names:
            raise ValueError(f"stage already completed: {name}")
        self._started[name] = self._clock()

    def finish(self, name: str) -> None:
        """Finish a started stage and append its elapsed duration."""

        if not self._enabled:
            return
        self._validate_name(name)
        started = self._started.pop(name, None)
        if started is None:
            raise ValueError(f"stage not started: {name}")
        elapsed_ms = max(0.0, (self._clock() - started) * 1000.0)
        self._completed.append((name, elapsed_ms))
        self._completed_names.add(name)

    def freeze(self) -> MbaStageTimings:
        """Freeze all completed timings; active stages are a caller error."""

        if not self._enabled:
            return EMPTY_MBA_STAGE_TIMINGS
        if self._started:
            names = ", ".join(sorted(self._started))
            raise ValueError(f"unfinished stages: {names}")
        return MbaStageTimings(tuple(self._completed))

    @staticmethod
    def _validate_name(name: object) -> None:
        if type(name) is not str or not name:
            raise ValueError("stage name must be a non-empty string")


__all__ = ["EMPTY_MBA_STAGE_TIMINGS", "MbaStageTimer", "MbaStageTimings"]
