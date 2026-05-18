"""Symbolic-expression fact.

A symbolic/SSA expression value. Maps to angr Claripy ASTs and LLVM SSA
values; previously ``ExpressionCarrierFact``.

The string value mirrors the legacy serialized ``FactObservation.kind``
during Phase 1 of the value-flow terminology rename; Phase 4 may
introduce a new canonical value behind the diagnostic alias registry.
"""
from __future__ import annotations

from d810.recon.facts.carrier import EXPRESSION_CARRIER_FACT_KIND as SYMBOLIC_EXPRESSION_FACT_TYPE

__all__ = ["SYMBOLIC_EXPRESSION_FACT_TYPE"]
