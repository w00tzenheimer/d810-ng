"""May-alias fact.

Records that two abstract locations may refer to overlapping storage, without
claiming exact identity. Standard alias-analysis terminology; this is weaker
than :mod:`must_alias` and should not authorize rewrites that require location
equivalence.

This is the canonical serialized ``FactObservation.kind`` value.
"""
from __future__ import annotations

MAY_ALIAS_FACT_TYPE = "MayAliasFact"

__all__ = ["MAY_ALIAS_FACT_TYPE"]
