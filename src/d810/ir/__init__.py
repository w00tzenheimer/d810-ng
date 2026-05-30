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
  ``d810.transforms.graph_modification.to_redirect_intent`` helper at the
  capability boundary.
* Axis-C B2 prep: ``PredicateKind`` + ``ControlTransferKind`` -- the
  first slice of the backend-neutral semantic-operation vocabulary.
  Recon-side files normalize their ``ida_hexrays.m_jbe`` / ``m_jtbl``
  / ``m_goto`` etc. comparisons through the adapter functions in
  ``d810.hexrays.mutation.ir_translator`` (``classify_branch_predicate``,
  ``classify_control_transfer``) so they only see portable enum values.
  Other semantic families (``ValueOpKind``, ``MemoryOpKind``,
  ``FlagComputationKind``, ``ConversionKind``, ``CallKind``, etc.) are
  named in the ``d810.ir.semantics`` docstring but NOT implemented yet
  -- add them incrementally when consumers need them.
"""

from __future__ import annotations

from .confidence import FactConfidence
from .expressions import Add, Const, ExprRef, Load, Move, Store, Sub, ValueOpKind
from .handles import BlockHandle, FlowGraphHandle, InsnHandle, OperandHandle
from .locations import (
    AggregateLocation,
    MemoryCell,
    RegisterLocation,
    StackSlot,
    StorageLocation,
)
from .redirect import RedirectBranchIntent, RedirectGotoIntent, RedirectIntent
from .results import ConstantFixpointResult
from .semantics import ControlTransferKind, PredicateKind
from .value_refs import (
    DefinitionRef,
    InstructionResultRef,
    SSAValueRef,
    TemporaryRef,
    ValueRef,
)

__all__ = [
    "Add",
    "AggregateLocation",
    "BlockHandle",
    "Const",
    "ConstantFixpointResult",
    "ControlTransferKind",
    "DefinitionRef",
    "ExprRef",
    "FactConfidence",
    "FlowGraphHandle",
    "InsnHandle",
    "InstructionResultRef",
    "Load",
    "MemoryCell",
    "Move",
    "OperandHandle",
    "PredicateKind",
    "RedirectBranchIntent",
    "RedirectGotoIntent",
    "RedirectIntent",
    "RegisterLocation",
    "SSAValueRef",
    "StackSlot",
    "Store",
    "StorageLocation",
    "Sub",
    "TemporaryRef",
    "ValueOpKind",
    "ValueRef",
]
