"""Portable bit-vector expression algebra + constraint DSL.

Relocated from ``d810.mba`` to live BELOW the analyses layer so both the MBA rule
engine (``d810.mba``) and the concolic / abstract-interpretation analyses
(``d810.analyses``) can import one expression language without an upward dependency
on ``d810.mba``. IDA-free: the only backend reach (live-mop structural comparisons,
used at rule-matching time) is injected via :mod:`d810.ir.expr.mop_ops`, never a
static or ``importlib`` import of Hex-Rays. See ticket llr-n2so / concolic epic
llr-7ouc.
"""
from __future__ import annotations

from .constraints import (
    AndConstraint,
    AndConstraintProtocol,
    ComparisonConstraint,
    ComparisonConstraintProtocol,
    ConstraintExpr,
    ConstraintExprProtocol,
    EqualityConstraint,
    EqualityConstraintProtocol,
    NotConstraint,
    NotConstraintProtocol,
    OrConstraint,
    OrConstraintProtocol,
    is_constraint_expr,
)
from .dsl import (
    NEGATIVE_ONE,
    NEGATIVE_TWO,
    ONE,
    TWO,
    ZERO,
    Const,
    ConstraintPredicate,
    DynamicConst,
    High,
    Low,
    Sdiv,
    Smod,
    SymbolicExpression,
    SymbolicExpressionProtocol,
    Udiv,
    Umod,
    Var,
    Zext,
    when,
)
from .mop_ops import MopOpsProvider, get_mop_ops, register_mop_ops

__all__ = [
    # DSL
    "SymbolicExpression",
    "SymbolicExpressionProtocol",
    "Var",
    "Const",
    "Zext",
    "Udiv",
    "Sdiv",
    "Umod",
    "Smod",
    "High",
    "Low",
    "DynamicConst",
    "ConstraintPredicate",
    "when",
    "ZERO",
    "ONE",
    "TWO",
    "NEGATIVE_ONE",
    "NEGATIVE_TWO",
    # Constraints
    "ConstraintExpr",
    "ConstraintExprProtocol",
    "EqualityConstraint",
    "EqualityConstraintProtocol",
    "ComparisonConstraint",
    "ComparisonConstraintProtocol",
    "AndConstraint",
    "AndConstraintProtocol",
    "OrConstraint",
    "OrConstraintProtocol",
    "NotConstraint",
    "NotConstraintProtocol",
    "is_constraint_expr",
    # Injected backend oracle
    "MopOpsProvider",
    "register_mop_ops",
    "get_mop_ops",
]
