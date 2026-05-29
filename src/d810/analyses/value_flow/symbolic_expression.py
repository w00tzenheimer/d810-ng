"""Symbolic-expression fact.

A symbolic/SSA expression value. Maps to angr Claripy ASTs and LLVM SSA
values; previously ``ExpressionCarrierFact``.

This is the canonical serialized ``FactObservation.kind`` value. The
diagnostic alias registry maps the historical ``ExpressionCarrierFact``
string to this family.
"""
from __future__ import annotations

SYMBOLIC_EXPRESSION_FACT_TYPE = "SymbolicExpressionFact"

__all__ = ["SYMBOLIC_EXPRESSION_FACT_TYPE"]
