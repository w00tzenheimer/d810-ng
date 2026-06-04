"""Abstract numeric/bitwise domains for machine-word analysis (LiSA-shaped).

Sound, word-correct lattice elements behind a common :class:`AbstractDomain`
protocol, for the state-value resolver and the guard / opaque-predicate oracle:

* :class:`KnownBits`        — per-bit 3-valued domain; the MBA / bitwise workhorse.
* :class:`WrappedInterval`  — modular (wrapping) interval; word-correct ranges.
* :class:`IntervalBox`      — non-relational per-variable interval product.
* :class:`RelationalDomain` — Octagon/Polyhedra seam (deferred; :class:`NullRelational`
  is the sound no-op default), with :class:`Satisfiability` guard verdicts.

All portable (no IDA). Reference: LiSA ``it.unive.lisa.analysis.Lattice``.
"""
from __future__ import annotations

from d810.analyses.abstract_domains.protocol import AbstractDomain
from d810.analyses.abstract_domains.known_bits import KnownBits
from d810.analyses.abstract_domains.wrapped_interval import WrappedInterval
from d810.analyses.abstract_domains.interval_box import IntervalBox
from d810.analyses.abstract_domains.interval_set import Interval, IntervalSet
from d810.analyses.abstract_domains.relational import (
    LinearConstraint,
    NullRelational,
    RelationalDomain,
    Satisfiability,
)
from d810.analyses.abstract_domains.operations import (
    BinaryOp,
    CompareOp,
    UnaryOp,
    eval_const_binary,
    eval_const_compare,
    eval_const_unary,
)
from d810.analyses.abstract_domains.value_domain import (
    KnownBitsValueDomain,
    ValueDomain,
    WrappedIntervalValueDomain,
)

__all__ = [
    "AbstractDomain",
    "KnownBits",
    "WrappedInterval",
    "IntervalBox",
    "Interval",
    "IntervalSet",
    "RelationalDomain",
    "NullRelational",
    "LinearConstraint",
    "Satisfiability",
    # operations
    "BinaryOp",
    "UnaryOp",
    "CompareOp",
    "eval_const_binary",
    "eval_const_unary",
    "eval_const_compare",
    # value-domain semantic layer
    "ValueDomain",
    "KnownBitsValueDomain",
    "WrappedIntervalValueDomain",
]
