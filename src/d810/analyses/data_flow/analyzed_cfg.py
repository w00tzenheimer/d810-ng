"""Fixpoint result and analyzed-CFG container."""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Any, Generic

from d810.analyses.data_flow.domain import StateT


@dataclass(frozen=True)
class FixpointResult(Generic[StateT]):
    """Result of a forward fixpoint computation.

    ``converged`` is ``True`` iff the worklist drained before
    ``max_iterations`` was reached.  Callers that use ``out_states`` /
    ``in_states`` to drive soundness-critical decisions MUST either:

    1. pass ``raise_on_nonconvergence=True`` to the fixpoint call (preferred,
       enforced by the ``fixpoint-result-without-convergence-check`` ast-grep
       rule), OR
    2. check ``result.converged`` and fail closed before reading state.

    The ``converged`` field has a default of ``True`` for back-compat: when
    no explicit value is passed (legacy construction sites that build a
    ``FixpointResult`` outside the engine), the field assumes the caller's
    own loop converged.  Engine-managed constructions always pass an explicit
    value.
    """

    in_states: dict[int, StateT]
    out_states: dict[int, StateT]
    iterations: int
    converged: bool = True


@dataclass(frozen=True)
class AnalyzedCFG(Generic[StateT]):
    """A graph paired with the fixpoint result computed over it.

    ``graph`` is intentionally typed ``Any`` for now.  The portable graph
    type (``d810.cfg.FlowGraph`` today, a future ``d810.ir`` graph handle
    later) is not yet pinned at this layer -- mirroring the Slice 9
    narrowing decision recorded in
    ``docs/plans/recon-and-cfg-restructuring.md``.  Pinning it would force
    ``d810.analyses`` to take an upward import on ``d810.cfg`` before the
    graph type is relocated.
    """

    graph: Any
    result: FixpointResult[StateT]
