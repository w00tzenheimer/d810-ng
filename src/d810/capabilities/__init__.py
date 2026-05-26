"""Backend-neutral capability protocols.

This package hosts ``Protocol`` types that describe optional backend
capabilities (value ranges, def-use queries, constant fixpoints,
recurrence analysis, alias queries, etc.).  Portable analysis code
depends on capability Protocols defined here; concrete backend
implementations live under ``d810.backends/<vendor>/`` and inject
instances via the composition root.

Per the llvm-lisa-restructure plan: capability names and return types
are SEMANTIC, not vendor-named.  ``ValRangeCapability`` not
``IdaValRangeCapability``.  Capability return types are intended to be
abstract, portable dataclasses (e.g. ``ValRange``); a Protocol return
annotation may be widened to ``Any`` only while the result type has
no stable portable home, and tightens once that home exists.
"""
from __future__ import annotations

from .constant_fixpoint import ConstantFixpointBackend, ConstantFixpointCapability
from .use_def_safety import SeveranceViolation, UseDefSafetyCapability

__all__ = [
    "ConstantFixpointBackend",  # back-compat alias of ConstantFixpointCapability
    "ConstantFixpointCapability",
    "SeveranceViolation",
    "UseDefSafetyCapability",
]
