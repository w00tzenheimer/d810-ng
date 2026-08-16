"""Runtime dispatcher for the optional Cython SCCP solver.

The dispatcher is deliberately small and owns the policy boundary between
the immutable Python model, the optional extension, and the fail-closed
Python fallback.  The extension itself never sees live IDA objects: the
snapshot adapter has already detached those before this module is called.
"""

from __future__ import annotations

from dataclasses import replace
import importlib
import os
from types import ModuleType

from d810.core import CythonMode
from d810.evaluator.hexrays_microcode import p_sccp
from d810.evaluator.hexrays_microcode.sccp_model import SccpProgram, SccpResult


def _load_cython_solver() -> ModuleType | object | None:
    """Load the optional solver module when Cython mode is enabled."""

    if not CythonMode().is_enabled():
        return None
    return importlib.import_module("d810.speedups.evaluator.c_sccp")


def _python_fallback(
    program: SccpProgram,
    work_budget: int | None,
    reason: str,
) -> SccpResult:
    """Run the reference solver and annotate why the fast path was skipped."""

    result = p_sccp.solve(program, work_budget=work_budget)
    return replace(
        result,
        backend="python-fallback",
        fallback_reason=reason or "Cython SCCP solver unavailable",
    )


def solve(program: SccpProgram, *, work_budget: int | None = None) -> SccpResult:
    """Solve *program* with the selected backend.

    Disabled mode is intentionally direct Python.  Any Cython import,
    execution, result-shape, or optional parity-check failure runs the same
    immutable input through :mod:`p_sccp` and returns a proof-equivalent
    ``python-fallback`` result with a non-empty diagnostic reason.
    """

    if not CythonMode().is_enabled():
        return p_sccp.solve(program, work_budget=work_budget)

    try:
        solver = _load_cython_solver()
        if solver is None:
            return _python_fallback(
                program,
                work_budget,
                "Cython SCCP extension is unavailable",
            )

        cython_solve = getattr(solver, "solve")
        result = cython_solve(program, work_budget=work_budget)
        if not isinstance(result, SccpResult):
            raise TypeError("Cython SCCP solver returned a non-SccpResult")

        if os.environ.get("D810_SCCP_PARITY_CHECK", "") == "1":
            reference = p_sccp.solve(program, work_budget=work_budget)
            if result.parity_key() != reference.parity_key():
                raise RuntimeError("SCCP parity mismatch between Cython and Python")

        # The compiled solver owns its result counters/timing.  Only normalize
        # the backend label here; all proof fields stay frozen and untouched.
        if result.backend != "cython":
            result = replace(result, backend="cython")
        return result
    except Exception as exc:
        return _python_fallback(
            program,
            work_budget,
            f"Cython SCCP failure: {exc}",
        )


__all__ = ["solve"]
