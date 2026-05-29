"""Portable fact-confidence scalar.

A normalized confidence score for a derived fact, factored out of the recon
fact model (which used a plain ``float``) so portable ``analyses`` /
``capabilities`` code can annotate confidence distinctly from an arbitrary
float (Landing Sequence LS8 substrate gap fix).

Minimum viable scope: a ``NewType`` over ``float`` (zero runtime overhead).
The 0.0..1.0 convention is enforced at construction sites, not by the type;
add a validating constructor here only when a consumer needs it.
"""
from __future__ import annotations

from d810.core.typing import NewType

__all__ = ["FactConfidence"]


FactConfidence = NewType("FactConfidence", float)
"""A normalized confidence in ``[0.0, 1.0]`` for a derived fact.

Wrapped via ``NewType`` so ``FactConfidence(0.9)`` is distinct from ``float``
at type-check time but is a plain ``float`` at runtime.
"""
