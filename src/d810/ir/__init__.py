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

Scope discipline:

* Slice 9: ``BlockHandle``, ``OperandHandle``, ``FlowGraphHandle``,
  ``ConstantFixpointResult``.  Handles are opaque identity types (no
  methods) so future capability moves have a portable counterpart
  without forcing a premature graph/value/SSA representation.
  ``ConstantFixpointResult`` is lifted from the existing
  ``SnapshotConstantFixpointResult`` shape because
  ``ConstantFixpointCapability.compute()`` needs to tighten its
  return annotation off ``Any``.
* Slice 10: ``RedirectGotoIntent``, ``RedirectBranchIntent``,
  ``RedirectIntent`` union for tightening
  ``UseDefSafetyCapability.redirect_use_def_violations`` off ``Any``.
  The CFG-layer ``RedirectGoto`` / ``RedirectBranch`` types stay
  where they are (they own construction-time diagnostics that don't
  belong in IR); call sites convert via the
  ``d810.cfg.graph_modification.to_redirect_intent`` helper at the
  capability boundary.
"""

from __future__ import annotations

from .handles import BlockHandle, FlowGraphHandle, OperandHandle
from .redirect import RedirectBranchIntent, RedirectGotoIntent, RedirectIntent
from .results import ConstantFixpointResult

__all__ = [
    "BlockHandle",
    "ConstantFixpointResult",
    "FlowGraphHandle",
    "OperandHandle",
    "RedirectBranchIntent",
    "RedirectGotoIntent",
    "RedirectIntent",
]
