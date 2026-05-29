"""Portable def-use chains (LLVM / LiSA-style).

Backend-neutral def-use facts over the IR value substrate: for each defined
value, which value-refs use it.  Net-new and unwired (Landing Sequence LS8); a
future capability populates it from a backend's reaching-definitions pass.

Minimum viable scope: a forward (def -> uses) mapping with a lookup helper.
Reverse (use -> reaching def) and richer chain queries are added on demand.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.core.typing import Mapping
from d810.ir.value_refs import ValueRef

__all__ = ["DefUseFacts"]


@dataclass(frozen=True)
class DefUseFacts:
    """Def-use chains: the value-refs reached by each definition."""

    uses_by_def: Mapping[ValueRef, tuple[ValueRef, ...]] = field(default_factory=dict)

    def uses_of(self, definition: ValueRef) -> tuple[ValueRef, ...]:
        """Return the value-refs that use ``definition`` (empty if none)."""
        return tuple(self.uses_by_def.get(definition, ()))

    def has_uses(self, definition: ValueRef) -> bool:
        """True iff ``definition`` reaches at least one use."""
        return bool(self.uses_by_def.get(definition))
