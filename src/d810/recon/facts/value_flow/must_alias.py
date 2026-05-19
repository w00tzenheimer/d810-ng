"""Must-alias fact.

Proves two abstract locations refer to the exact same storage. Standard
alias-analysis terminology; previously ``SameCarrierAliasFact``.

This is the canonical serialized ``FactObservation.kind`` value. The
diagnostic alias registry maps the historical ``SameCarrierAliasFact``
string to this family.
"""
from __future__ import annotations

MUST_ALIAS_FACT_TYPE = "MustAliasFact"

__all__ = ["MUST_ALIAS_FACT_TYPE"]
