"""Profiling and timing runtime support for the D810 driver."""

from __future__ import annotations

import dataclasses
import pathlib
import pstats
import time

from d810.core.logging import getLogger
from d810.core.typing import Any

try:
    import cProfile
except ImportError:
    cProfile = None  # type: ignore[assignment]

try:
    import pyinstrument  # type: ignore
except ImportError:
    pyinstrument = None


logger = getLogger("D810")


class CProfileWrapper:
    """Small cProfile wrapper that tracks whether profiling is running."""

    def __init__(self) -> None:
        self._profiler = cProfile.Profile()
        self._is_running = False

    @property
    def is_running(self) -> bool:
        return self._is_running

    def enable(self, *args: Any, **kwargs: Any) -> None:
        self._profiler.enable(*args, **kwargs)
        self._is_running = True

    def disable(self) -> None:
        self._profiler.disable()
        self._is_running = False

    @property
    def profiler(self) -> Any:
        return self._profiler

    def snapshot(self, output_path: str) -> None:
        """Dump current stats to file and start a fresh profiler for the next segment."""
        if self._is_running:
            self._profiler.disable()
        self._profiler.dump_stats(output_path)
        self._profiler = cProfile.Profile()
        if self._is_running:
            self._profiler.enable()


def _new_cprofile_wrapper() -> CProfileWrapper | None:
    if cProfile is None:
        return None
    return CProfileWrapper()


def _new_pyinstrument_profiler() -> Any | None:
    if pyinstrument is None:
        return None
    return pyinstrument.Profiler()


@dataclasses.dataclass
class ProfilingController:
    """Own profiler state, profile outputs, and decompilation timing."""

    log_dir: pathlib.Path
    profiler: Any | None = dataclasses.field(default_factory=_new_pyinstrument_profiler)
    cprofiler: CProfileWrapper | None = dataclasses.field(
        default_factory=_new_cprofile_wrapper
    )
    enabled: bool = False
    _start_ts: float = 0.0

    def __post_init__(self) -> None:
        self.log_dir = pathlib.Path(self.log_dir)

    @property
    def is_running(self) -> bool:
        """Return True if either profiler is currently running."""
        if self.cprofiler and self.cprofiler.is_running:
            return True
        if self.profiler and getattr(self.profiler, "is_running", False):
            return True
        return False

    def enable(self) -> None:
        self.enabled = True
        self.start()

    def disable(self) -> pathlib.Path | None:
        self.enabled = False
        return self.stop()

    def start(self) -> None:
        if not self.enabled:
            return
        if self.cprofiler and not self.cprofiler.is_running:
            self.cprofiler.enable()
        if self.profiler and not getattr(self.profiler, "is_running", False):
            self.profiler.start()

    def stop(self) -> pathlib.Path | None:
        if self.cprofiler and self.cprofiler.is_running:
            self.cprofiler.disable()
            output_path = self.log_dir / "d810_cprofile.prof"
            self.cprofiler.profiler.dump_stats(str(output_path))
            pstats.Stats(str(output_path)).strip_dirs().sort_stats("time").print_stats()
            return output_path
        if self.profiler and getattr(self.profiler, "is_running", False):
            self.profiler.stop()
            self.profiler.print()
            output_path = self.log_dir / "d810_profile.html"
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(self.profiler.output_html())
            return output_path
        return None

    def dump_segment(self, maturity_name: str) -> pathlib.Path | None:
        """Dump a cProfile snapshot when maturity changes."""
        if not self.enabled:
            return None
        if not self.cprofiler or not self.cprofiler.is_running:
            return None
        output_path = self.log_dir / f"d810_cprofile_{maturity_name}.prof"
        self.cprofiler.snapshot(str(output_path))
        logger.info("Profiling segment dumped for %s: %s", maturity_name, output_path)
        return output_path

    def start_timer(self) -> None:
        self._start_ts = time.perf_counter()

    def stop_timer(self, report: bool = True) -> None:
        if report:
            m, s = divmod(time.perf_counter() - self._start_ts, 60)
            logger.info(
                "Decompilation finished in %dm %ds",
                int(m),
                int(s),
            )
        self._start_ts = 0.0
