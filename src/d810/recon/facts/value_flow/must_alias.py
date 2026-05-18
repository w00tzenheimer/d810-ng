"""Must-alias fact.

Proves two abstract locations refer to the exact same storage. Standard
alias-analysis terminology; previously ``SameCarrierAliasFact``.

The string value mirrors the legacy serialized ``FactObservation.kind``
during Phase 1 of the value-flow terminology rename; Phase 4 may
introduce a new canonical value behind the diagnostic alias registry.
"""
from __future__ import annotations

from d810.recon.facts.carrier import SAME_CARRIER_ALIAS_FACT_KIND as MUST_ALIAS_FACT_TYPE

__all__ = ["MUST_ALIAS_FACT_TYPE"]
