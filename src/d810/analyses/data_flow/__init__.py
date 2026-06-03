"""Generic data-flow analysis vocabulary (LiSA-style, intraprocedural).

This package defines the *abstractions* a forward/backward fixpoint
analysis is written against:

- :class:`~d810.analyses.data_flow.domain.FlowDomain` -- the abstract
  domain Protocol (bottom / meet / transfer / equals / widen).
- :class:`~d810.analyses.data_flow.configuration.FixpointConfiguration`
  + :class:`~d810.analyses.data_flow.configuration.Direction` -- solver
  knobs.
- :class:`~d810.analyses.data_flow.analyzed_cfg.FixpointResult` -- the
  per-node in/out states produced by a run.
- :class:`~d810.analyses.data_flow.analyzed_cfg.AnalyzedCFG` -- a graph
  paired with its fixpoint result.
- :class:`~d810.analyses.data_flow.working_set.WorkingSet` -- the
  worklist data structure.
- :class:`~d810.analyses.data_flow.exceptions.FixpointDidNotConverge` --
  raised by soundness-critical callers on non-convergence.

The concrete worklist solver and concrete domains still live in
``d810.evaluator.hexrays_microcode.forward_dataflow`` for now; they are
migrated onto ``FlowDomain`` in a later slice (Landing Sequence step 5).
``FixpointResult`` and ``FixpointDidNotConverge`` are re-exported from
that module for back-compat.
"""
from __future__ import annotations

from d810.analyses.data_flow.abstract_value import (
    AbstractValue,
    Block,
    Const,
    EntersDispatcher,
    Guarded,
    OneOf,
    RouteOneOf,
    RouteResult,
    TOP,
    Top,
    Unknown,
)
from d810.analyses.data_flow.analyzed_cfg import AnalyzedCFG, FixpointResult
from d810.analyses.data_flow.configuration import Direction, FixpointConfiguration
from d810.analyses.data_flow.domain import FlowDomain, NodeId, StateT
from d810.analyses.data_flow.exceptions import FixpointDidNotConverge
from d810.analyses.data_flow.working_set import WorkingSet
from d810.analyses.data_flow.worklist import run_fixpoint

__all__ = [
    "AbstractValue",
    "AnalyzedCFG",
    "Block",
    "Const",
    "Direction",
    "EntersDispatcher",
    "FixpointConfiguration",
    "FixpointDidNotConverge",
    "FixpointResult",
    "FlowDomain",
    "Guarded",
    "NodeId",
    "OneOf",
    "RouteOneOf",
    "RouteResult",
    "StateT",
    "TOP",
    "Top",
    "Unknown",
    "WorkingSet",
    "run_fixpoint",
]
