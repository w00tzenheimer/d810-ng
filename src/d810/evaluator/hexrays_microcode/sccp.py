"""Public SCCP facade over the immutable model and pure Python solver.

Live MBA traversal belongs to :mod:`sccp_snapshot`.  Keeping this module
detached from SWIG objects makes the per-session memo safe and gives legacy
constant-overlay callers a fail-closed compatibility surface.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import time

from d810.core.logging import getLogger
from d810.evaluator.hexrays_microcode import p_sccp
from d810.evaluator.hexrays_microcode.sccp_model import (
    SccpProgram,
    SccpResult,
    SccpStatus,
)
from d810.evaluator.hexrays_microcode.sccp_snapshot import (
    SccpSnapshotError,
    snapshot_from_mba,
)


logger = getLogger(__name__)
DEFAULT_SOLVER = p_sccp.solve

SnapshotFn = Callable[[object], SccpProgram]
SolveFn = Callable[[SccpProgram], SccpResult]
ClockFn = Callable[[], float]


@dataclass(slots=True)
class SccpSessionStats:
    """Mutable counters for one decompilation/session."""

    requests: int = 0
    executions: int = 0
    reuses: int = 0
    fallbacks: int = 0
    converged: int = 0
    work_limit: int = 0
    block_limit: int = 0
    errors: int = 0
    python_runs: int = 0
    cython_runs: int = 0
    cfg_events: int = 0
    value_events: int = 0
    adapter_seconds: float = 0.0
    solver_seconds: float = 0.0
    constants_exposed: int = 0
    edges_exposed: int = 0

    def reset(self) -> None:
        """Clear all counters without replacing the stats object."""

        self.requests = 0
        self.executions = 0
        self.reuses = 0
        self.fallbacks = 0
        self.converged = 0
        self.work_limit = 0
        self.block_limit = 0
        self.errors = 0
        self.python_runs = 0
        self.cython_runs = 0
        self.cfg_events = 0
        self.value_events = 0
        self.adapter_seconds = 0.0
        self.solver_seconds = 0.0
        self.constants_exposed = 0
        self.edges_exposed = 0

    def as_dict(self) -> dict[str, int | float]:
        return {
            "requests": self.requests,
            "executions": self.executions,
            "reuses": self.reuses,
            "fallbacks": self.fallbacks,
            "converged": self.converged,
            "work_limit": self.work_limit,
            "block_limit": self.block_limit,
            "errors": self.errors,
            "python_runs": self.python_runs,
            "cython_runs": self.cython_runs,
            "cfg_events": self.cfg_events,
            "value_events": self.value_events,
            "adapter_seconds": self.adapter_seconds,
            "solver_seconds": self.solver_seconds,
            "constants_exposed": self.constants_exposed,
            "edges_exposed": self.edges_exposed,
        }


class SccpFacade:
    """Snapshot, memoize, and solve SCCP programs within one session."""

    def __init__(
        self,
        snapshot_fn: SnapshotFn = snapshot_from_mba,
        solve_fn: SolveFn = DEFAULT_SOLVER,
        clock: ClockFn = time.perf_counter,
    ) -> None:
        self._snapshot_fn = snapshot_fn
        self._solve_fn = solve_fn
        self._clock = clock
        self._memo: dict[str, SccpResult] = {}
        self._stats = SccpSessionStats()

    def start_session(self) -> None:
        """Discard memoized results and reset counters for a new session."""

        self._memo.clear()
        self._stats.reset()

    def stats(self) -> SccpSessionStats:
        return self._stats

    @staticmethod
    def _project_constants(result: SccpResult) -> dict[object, int | None]:
        if result.status is not SccpStatus.CONVERGED:
            return {}
        return dict(result.constants)

    def _record_execution(self, result: SccpResult) -> None:
        status = result.status
        if status is SccpStatus.CONVERGED:
            self._stats.converged += 1
            self._stats.constants_exposed += len(result.constants)
            self._stats.edges_exposed += len(result.executable_edges)
        elif status is SccpStatus.WORK_LIMIT:
            self._stats.work_limit += 1
            logger.warning(
                "sccp: non-converged result status=%s fingerprint=%s",
                status.value,
                result.program_fingerprint,
            )
        elif status is SccpStatus.BLOCK_LIMIT:
            self._stats.block_limit += 1
            logger.warning(
                "sccp: non-converged result status=%s fingerprint=%s",
                status.value,
                result.program_fingerprint,
            )
        elif status is SccpStatus.ERROR:
            self._stats.errors += 1
            logger.warning(
                "sccp: non-converged result status=%s fingerprint=%s reason=%s",
                status.value,
                result.program_fingerprint,
                result.fallback_reason,
            )

        backend = result.backend.lower()
        if backend.startswith("python"):
            self._stats.python_runs += 1
        if backend.startswith("cython"):
            self._stats.cython_runs += 1
        if "fallback" in backend or result.fallback_reason:
            self._stats.fallbacks += 1
        self._stats.cfg_events += result.cfg_events
        self._stats.value_events += result.value_events
        self._stats.solver_seconds += result.solver_seconds

    def run(self, mba: object) -> SccpResult:
        """Run SCCP for *mba*, returning a proof-aware immutable result."""

        self._stats.requests += 1
        adapter_started = self._clock()
        try:
            program = self._snapshot_fn(mba)
        except SccpSnapshotError as exc:
            self._stats.errors += 1
            logger.warning("sccp: snapshot failure: %s", exc)
            return SccpResult.empty(
                status=SccpStatus.ERROR,
                backend="python",
                fallback_reason=f"snapshot: {exc}",
            )
        finally:
            elapsed = self._clock() - adapter_started
            if elapsed >= 0.0:
                self._stats.adapter_seconds += elapsed

        if not isinstance(program, SccpProgram):
            raise TypeError("snapshot_fn must return SccpProgram")
        cached = self._memo.get(program.fingerprint)
        if cached is not None:
            self._stats.reuses += 1
            return cached

        self._stats.executions += 1
        result = self._solve_fn(program)
        if not isinstance(result, SccpResult):
            raise TypeError("solve_fn must return SccpResult")
        if not isinstance(result.status, SccpStatus):
            raise TypeError("solve_fn must return SccpResult with a valid SccpStatus")
        self._memo[program.fingerprint] = result
        self._record_execution(result)
        return result


_SCCP_FACADE = SccpFacade()


def get_sccp_facade() -> SccpFacade:
    return _SCCP_FACADE


def reset_sccp_session() -> None:
    _SCCP_FACADE.start_session()


def sccp_session_stats() -> SccpSessionStats:
    return _SCCP_FACADE.stats()


def _ida_unavailable(exc: ImportError) -> bool:
    supported_roots = {
        "ida_auto",
        "ida_bytes",
        "ida_dbg",
        "ida_diskio",
        "ida_fpro",
        "ida_funcs",
        "ida_graph",
        "ida_hexrays",
        "ida_idaapi",
        "ida_kernwin",
        "ida_lines",
        "ida_loader",
        "ida_name",
        "ida_nalt",
        "ida_pro",
        "ida_search",
        "ida_segment",
        "ida_struct",
        "ida_typeinf",
        "ida_ua",
        "ida_xref",
        "idaapi",
        "idautils",
        "idc",
        "idapro",
    }
    name = getattr(exc, "name", None)
    if not isinstance(name, str):
        return False
    root = name.split(".", 1)[0]
    return root in supported_roots


def run_sccp_ex(mba: object) -> SccpResult | None:
    """Run the session facade, preserving ``None`` only without IDA."""

    try:
        return get_sccp_facade().run(mba)
    except ImportError as exc:
        if _ida_unavailable(exc):
            return None
        raise


def run_sccp(mba: object) -> dict[tuple, int | None]:
    """Return a copied constant overlay only for converged SCCP proof."""

    result = run_sccp_ex(mba)
    if result is None or result.status is not SccpStatus.CONVERGED:
        return {}
    return dict(result.constants)


__all__ = [
    "DEFAULT_SOLVER",
    "SccpFacade",
    "SccpResult",
    "SccpSessionStats",
    "SccpSnapshotError",
    "SccpStatus",
    "get_sccp_facade",
    "reset_sccp_session",
    "run_sccp",
    "run_sccp_ex",
    "sccp_session_stats",
]
