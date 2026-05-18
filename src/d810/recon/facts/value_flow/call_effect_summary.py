"""Call effect-summary fact.

Summarizes which memory locations a call may modify or reference. Maps
to LLVM ModRef / effect-system terminology; previously
``CallSideEffectAnchorFact``.

The string value mirrors the legacy serialized ``FactObservation.kind``
during Phase 1 of the value-flow terminology rename; Phase 4 may
introduce a new canonical value behind the diagnostic alias registry.
"""
from __future__ import annotations

from d810.recon.facts.carrier import CALL_SIDE_EFFECT_ANCHOR_FACT_KIND as CALL_EFFECT_SUMMARY_FACT_TYPE

__all__ = ["CALL_EFFECT_SUMMARY_FACT_TYPE"]
