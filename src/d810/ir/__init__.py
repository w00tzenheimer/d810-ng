"Portable IR layer for d810.\n\nPer the LLVM/LiSA-style taxonomy in\n``docs/plans/preanalysis-and-cfg-restructuring.md``, this package hosts the\nbackend-neutral IR vocabulary: opaque handles for references that\nflow across capability boundaries (``BlockHandle``, ``OperandHandle``,\n``FlowGraphHandle``) and portable analysis-result dataclasses\n(``ConstantFixpointResult``).\n\nIt sits **below** ``d810.capabilities`` in the layer stack so\ncapability Protocols can reference IR result/handle types without\ncircularity, and **above** ``d810.core`` / ``d810.errors`` only.\nThis package must remain IDA-free at import time -- enforced by\n``rules/no-live-ida-in-portable-core.yml`` and by import-linter's\n``portable-core-no-ida`` contract.\n\nScope discipline:\n\n* Slice 9: ``BlockHandle``, ``OperandHandle``, ``FlowGraphHandle``,\n  ``ConstantFixpointResult``.  Handles are opaque identity types (no\n  methods) so future capability moves have a portable counterpart\n  without forcing a premature graph/value/SSA representation.\n  ``ConstantFixpointResult`` is lifted from the existing\n  ``SnapshotConstantFixpointResult`` shape because\n  ``ConstantFixpointCapability.compute()`` needs to tighten its\n  return annotation off ``Any``.\n* Slice 10: ``RedirectGotoIntent``, ``RedirectBranchIntent``,\n  ``RedirectIntent`` union for tightening\n  ``UseDefSafetyCapability.redirect_use_def_violations`` off ``Any``.\n  The CFG-layer ``RedirectGoto`` / ``RedirectBranch`` types stay\n  where they are (they own construction-time diagnostics that don't\n  belong in IR); call sites convert via the\n  ``d810.transforms.graph_modification.to_redirect_intent`` helper at the\n  capability boundary.\n* Axis-C operation vocabulary: ``ValueOpKind`` + ``PredicateKind`` +\n  ``ControlTransferKind`` + ``CallKind``. Backend adapters normalize raw\n  opcodes into these families and keep raw opcode integers/names in\n  diagnostic attrs only.\n* llr-epu0: ``Instruction`` is the canonical portable instruction record. Its\n  ``operation`` field uses the operation vocabulary above, operands/results are\n  ``Varnode``s, and legacy statement projections remain views over the\n  canonical instruction source.\n"

from __future__ import annotations

from .confidence import FactConfidence
from .expressions import Add, Const, ExprRef, Load, Move, Store, Sub, ValueOpKind
from .handles import BlockHandle, FlowGraphHandle, InsnHandle, OperandHandle
from .instructions import (
    Instruction,
    InstructionControl,
    InstructionEffect,
    InstructionEffectKind,
    InstructionMemoryAccess,
    InstructionMemoryAccessKind,
    InstructionSwitchCase,
)
from .locations import (
    AggregateLocation,
    MemoryCell,
    RegisterLocation,
    StackSlot,
    StorageLocation,
)
from .redirect import RedirectBranchIntent, RedirectGotoIntent, RedirectIntent
from .results import ConstantFixpointResult
from .semantics import (
    CallKind,
    ControlTransferKind,
    LiftedOpcode,
    OperationKind,
    PredicateKind,
)
from .storage_identity import (
    StorageIdentity,
    StorageIdentityKind,
    storage_identity_from_mop_snapshot,
    storage_identity_from_varnode,
    storage_identity_key,
    storage_identity_offset,
)
from .value_refs import (
    DefinitionRef,
    InstructionResultRef,
    SSAValueRef,
    TemporaryRef,
    ValueRef,
)
from .varnode import Space, Varnode, varnode_key, varnode_offset

__all__ = [
    "Add",
    "AggregateLocation",
    "BlockHandle",
    "CallKind",
    "Const",
    "ConstantFixpointResult",
    "ControlTransferKind",
    "DefinitionRef",
    "ExprRef",
    "FactConfidence",
    "FlowGraphHandle",
    "InsnHandle",
    "Instruction",
    "InstructionControl",
    "InstructionEffect",
    "InstructionEffectKind",
    "InstructionMemoryAccess",
    "InstructionMemoryAccessKind",
    "InstructionSwitchCase",
    "InstructionResultRef",
    "LiftedOpcode",
    "Load",
    "MemoryCell",
    "Move",
    "OperandHandle",
    "OperationKind",
    "PredicateKind",
    "RedirectBranchIntent",
    "RedirectGotoIntent",
    "RedirectIntent",
    "RegisterLocation",
    "SSAValueRef",
    "Space",
    "StackSlot",
    "Store",
    "StorageIdentity",
    "StorageIdentityKind",
    "StorageLocation",
    "Sub",
    "TemporaryRef",
    "ValueOpKind",
    "ValueRef",
    "Varnode",
    "storage_identity_from_mop_snapshot",
    "storage_identity_from_varnode",
    "storage_identity_key",
    "storage_identity_offset",
    "varnode_key",
    "varnode_offset",
]
