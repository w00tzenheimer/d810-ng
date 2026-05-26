"""Portable IR layer for d810.

Per the LLVM/LiSA-style taxonomy in
``docs/plans/recon-and-cfg-restructuring.md``, this package hosts the
backend-neutral IR vocabulary: opaque handles for references that
flow across capability boundaries (``BlockHandle``, ``OperandHandle``,
``FlowGraphHandle``) and portable analysis-result dataclasses
(``ConstantFixpointResult``).

It sits **below** ``d810.capabilities`` in the layer stack so
capability Protocols can reference IR result/handle types without
circularity, and **above** ``d810.core`` / ``d810.errors`` only.
This package must remain IDA-free at import time -- enforced by
``rules/no-live-ida-in-portable-core.yml`` and by import-linter's
``portable-core-no-ida`` contract.

Scope discipline (slice 9):

* Only types that have a known consumer in this slice are landed here.
  ``ConstantFixpointResult`` is lifted from the existing
  ``SnapshotConstantFixpointResult`` shape because
  ``ConstantFixpointCapability.compute()`` needs to tighten its return
  annotation off ``Any``.
* Handles are landed as opaque identity types (no methods) so future
  capability moves have a portable counterpart without forcing a
  premature graph/value/SSA representation.
* ``RedirectIntent`` and ``UseDefSafetyCapability`` redirect-arg
  tightening are intentionally **deferred to slice 10** -- that work
  touches multiple Hodur strategy call sites and the Hex-Rays
  adjacency builder, so it does not belong in foundation scaffolding.
"""

from __future__ import annotations

from .handles import BlockHandle, FlowGraphHandle, OperandHandle
from .results import ConstantFixpointResult

__all__ = [
    "BlockHandle",
    "ConstantFixpointResult",
    "FlowGraphHandle",
    "OperandHandle",
]
