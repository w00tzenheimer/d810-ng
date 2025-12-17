"""d810.mba - Mixed Boolean Arithmetic verification and simplification.

This package provides IDA-independent tools for:
- Symbolic expression DSL
- Constraint system
- Z3-based theorem proving
- MBA simplification algorithms

The package is designed to be reusable outside of d810/IDA Pro.
"""

__version__ = "0.1.0"

# Phase 2 & 3 complete: Pure Python components and verifier available
from d810.core.bits import AND_TABLE, SUB_TABLE

from .constraints import (
    AndConstraint,
    ComparisonConstraint,
    ConstraintExpr,
    EqualityConstraint,
    NotConstraint,
    OrConstraint,
)
from .dsl import Const, SymbolicExpression, Var, Zext
from .rules import SymbolicRule, VerifiableRule
from .verifier import (
    DEFAULT_OPTIONS,
    ConstrainedMBARule,
    MBARule,
    VerificationEngine,
    VerificationOptions,
    get_default_engine,
    verify_transformation,
)

# Public API
__all__ = [
    # Constants
    "SUB_TABLE",
    "AND_TABLE",
    # DSL
    "Var",
    "Const",
    "Zext",
    "SymbolicExpression",
    # Constraints
    "ConstraintExpr",
    "EqualityConstraint",
    "ComparisonConstraint",
    "AndConstraint",
    "OrConstraint",
    "NotConstraint",
    # Verification engine protocol and implementations
    "VerificationOptions",
    "DEFAULT_OPTIONS",
    "VerificationEngine",
    "get_default_engine",
    # Rule base classes
    "MBARule",
    "ConstrainedMBARule",
    "verify_transformation",
    # Rules
    "SymbolicRule",
    "VerifiableRule",
]
