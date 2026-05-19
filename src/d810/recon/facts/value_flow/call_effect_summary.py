"""Call effect-summary fact.

Summarizes which memory locations a call may modify or reference. Maps
to LLVM ModRef / effect-system terminology; previously
``CallSideEffectAnchorFact``.

This is the canonical serialized ``FactObservation.kind`` value. The
diagnostic alias registry maps the historical ``CallSideEffectAnchorFact``
string to this family.
"""
from __future__ import annotations

CALL_EFFECT_SUMMARY_FACT_TYPE = "CallEffectSummaryFact"

__all__ = ["CALL_EFFECT_SUMMARY_FACT_TYPE"]
