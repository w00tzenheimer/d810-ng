"""Portable loop-semantics classification (unwired).

Backend-neutral high-level classification of a loop's intent (counted,
reduction, memory copy/fill, or unknown), combining the lower-level induction /
memory-access / recurrence facts.  Net-new and fully unwired (Landing Sequence
LS8 S7): the classifier takes pre-computed evidence flags so it stays decoupled
from the sibling fact modules and from any backend.

Minimum viable scope: a small evidence-flag heuristic.  Replace the flags with
the concrete sibling fact types once a backend wires per-loop fact collection.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

from d810.ir.confidence import FactConfidence

__all__ = [
    "LoopSemanticsClassification",
    "LoopSemanticsClassifier",
    "LoopSemanticsKind",
]


class LoopSemanticsKind(Enum):
    """High-level intent of a loop."""

    UNKNOWN = auto()
    COUNTED = auto()
    REDUCTION = auto()
    MEMORY_COPY = auto()
    MEMORY_FILL = auto()


@dataclass(frozen=True)
class LoopSemanticsClassification:
    """The classified kind of a loop, with confidence and human-readable evidence."""

    kind: LoopSemanticsKind
    confidence: FactConfidence = FactConfidence(1.0)
    evidence: tuple[str, ...] = ()


class LoopSemanticsClassifier:
    """Combines per-loop evidence flags into a :class:`LoopSemanticsClassification`.

    Unwired: callers pass booleans derived from the induction / memory-access /
    recurrence analyses.  Defaults to ``UNKNOWN`` when no evidence is present.
    """

    def classify(
        self,
        *,
        has_induction: bool = False,
        has_strided_access: bool = False,
        has_store: bool = False,
        has_constant_store: bool = False,
        has_reduction: bool = False,
    ) -> LoopSemanticsClassification:
        if has_reduction:
            return LoopSemanticsClassification(
                LoopSemanticsKind.REDUCTION, evidence=("reduction",)
            )
        # A memory-shaping classification requires an actual STORE, not just a
        # strided access stream (which may be a read/load). MEMORY_FILL further
        # requires the stored value be invariant (constant_store); a strided
        # store of a varying/loaded value is a MEMORY_COPY. Strided access with
        # no store is intentionally NOT a fill -- it stays COUNTED / UNKNOWN.
        if has_strided_access and has_constant_store:
            return LoopSemanticsClassification(
                LoopSemanticsKind.MEMORY_FILL,
                evidence=("strided_access", "constant_store"),
            )
        if has_strided_access and has_store:
            return LoopSemanticsClassification(
                LoopSemanticsKind.MEMORY_COPY,
                evidence=("strided_access", "store"),
            )
        if has_induction:
            return LoopSemanticsClassification(
                LoopSemanticsKind.COUNTED, evidence=("induction",)
            )
        return LoopSemanticsClassification(LoopSemanticsKind.UNKNOWN)
