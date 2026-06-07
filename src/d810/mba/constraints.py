"""Back-compat re-export shim -> :mod:`d810.ir.expr.constraints`.

Relocated below the ``analyses`` layer alongside the expression DSL (see
``d810.mba.dsl`` / ticket llr-n2so). The 1 ``importlib -> hexrays_helpers`` leak in
``EqualityConstraint`` was sealed during the move via the injected
``d810.ir.expr.mop_ops`` provider.
"""
from d810.ir.expr.constraints import (  # noqa: F401  (re-export)
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
from d810.ir.expr.dsl import (  # noqa: F401  (re-export for back-compat)
    SymbolicExpression,
    SymbolicExpressionProtocol,
)

__all__ = [
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
]
