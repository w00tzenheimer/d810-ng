"""Trace-partitioned reduced-product concolic domain (portable; no IDA, no z3).

The fusion of abstract interpretation + (later) symbolic + concrete execution as a
**reduced-product** value domain over the already-built portable fixpoint engine:

* :class:`~d810.analyses.data_flow.concolic.abstract_evidence.AbstractEvidence`
  -- the abstract floor (``KnownBits x WrappedInterval`` reduced product).
* :class:`~d810.analyses.data_flow.concolic.values.ConcolicValue`
  -- ``(concrete, symbolic, abstract)`` evidence + :func:`reduce`.
* :class:`~d810.analyses.data_flow.concolic.refs.LocationRef` / ``ValueRef``
  -- portable storage references (the mop <-> value seam).
* :class:`~d810.analyses.data_flow.concolic.store.ConcolicStore`
  -- ``LocationRef -> ConcolicValue`` (value precision; partitioning is separate).

S1 (ticket llr-xvkt) is the concrete+abstract floor with ``symbolic`` always
``None`` and nothing wired into the live path -- pure unit-tested types.  Symbolic
(S5) + the ``RecoverStateTransitions`` wiring (S4) land in later slices.  Epic
llr-7ouc; see plan ``2026-06-07-concolic-state-transition-fusion-plan.md``.
"""
from __future__ import annotations

from d810.analyses.data_flow.concolic.abstract_evidence import AbstractEvidence
from d810.analyses.data_flow.concolic.refs import (
    LocationKind,
    LocationRef,
    ValueRef,
)
from d810.analyses.data_flow.concolic.store import ConcolicStore
from d810.analyses.data_flow.concolic.values import (
    ConcolicValue,
    PrecisionStatus,
    reduce,
)

__all__ = [
    "AbstractEvidence",
    "LocationKind",
    "LocationRef",
    "ValueRef",
    "ConcolicStore",
    "ConcolicValue",
    "PrecisionStatus",
    "reduce",
]
