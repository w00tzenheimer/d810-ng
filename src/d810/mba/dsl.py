"""Back-compat re-export shim -> :mod:`d810.ir.expr.dsl`.

The portable expression DSL was relocated to ``d810.ir.expr.dsl`` (below the
``analyses`` layer) so ``d810.analyses`` can import one expression language without
an upward dependency on ``d810.mba``. This shim preserves the
``from d810.mba.dsl import ...`` surface used by the 30+ rule modules. The 3
``importlib -> hexrays_helpers`` leaks that used to live here were sealed during the
move via the injected ``d810.ir.expr.mop_ops`` provider. See ticket llr-n2so.
"""
from d810.ir.expr.dsl import (  # noqa: F401  (re-export)
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

__all__ = [
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
]
