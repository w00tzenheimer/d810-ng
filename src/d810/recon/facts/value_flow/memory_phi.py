"""Memory-phi fact.

A merge of memory-backed value versions at a control-flow frontier. This is
the MemorySSA analogue for facts such as Hodur return frontiers where several
writer/carrier observations converge before terminal materialization.
"""
from __future__ import annotations

MEMORY_PHI_FACT_TYPE = "MemoryPhiFact"

__all__ = ["MEMORY_PHI_FACT_TYPE"]
