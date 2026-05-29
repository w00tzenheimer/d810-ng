"""Memory-use fact.

A read/use of a memory location or memory-backed value version. In LLVM
MemorySSA terms this is the read side of a def-use relation; in D-810 it is
used when existing producer evidence already identifies a memory-backed
semantic use such as a Hodur return-slot use.
"""
from __future__ import annotations

MEMORY_USE_FACT_TYPE = "MemoryUseFact"

__all__ = ["MEMORY_USE_FACT_TYPE"]
