"""Exceptions raised by the data-flow fixpoint machinery."""
from __future__ import annotations


class FixpointDidNotConverge(Exception):
    """Raised by ``run_forward_fixpoint`` / ``run_valrange_fixpoint`` when
    ``raise_on_nonconvergence=True`` is set and the worklist does not drain
    before ``max_iterations`` is exhausted.

    Soundness-critical callers (return-carrier resolution, DSVE, dead-branch
    elimination, etc.) should pass ``raise_on_nonconvergence=True`` and let
    this exception propagate; consuming ``in_states`` / ``out_states`` from a
    partial fixpoint can corrupt the analysis.  Best-effort / diagnostic
    callers may omit the kwarg and inspect ``FixpointResult.converged``
    instead.
    """

    def __init__(self, iterations: int, max_iterations: int, message: str | None = None) -> None:
        self.iterations = iterations
        self.max_iterations = max_iterations
        super().__init__(
            message
            or (
                f"forward fixpoint did not converge in {iterations} iterations "
                f"(max_iterations={max_iterations})"
            )
        )
