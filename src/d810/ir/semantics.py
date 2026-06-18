"""Portable semantic IR — operation families for microcode-style ops.

This module hosts the **backend-neutral** semantic vocabulary for
microcode-style operations.  Files that consume these enums never
need to know about Hex-Rays ``mcode_t`` / IDA opcode integers /
vendor identifier names; they consume ``ValueOpKind``, ``PredicateKind``,
``ControlTransferKind``, ``CallKind`` and let the backend
lifter -- ``d810.hexrays.mutation.ir_translator`` for the Hex-Rays
side, or equivalent adapters for future angr / Ghidra backends --
resolve raw vendor opcodes into these families at the seam.

Design principles
-----------------

* **Not a flat opcode enum.**  IDA's ``mcode_t`` flattens value
  operations, flag computations, conditional jumps, calls, and stack
  effects into one integer space; the portable model SPLITS those
  into separate family enums because they have distinct downstream
  consumers and concerns.
* **Minimum viable scope.**  Only the enum members that current
  axis-C consumers actually need are listed here.  Extend (or add
  new family enums) when a consumer requires more -- do NOT preload
  the universe of operations up front.
* **Backend mapping lives in adapters.**  This file never imports
  ``ida_hexrays`` (or any other vendor SDK).  The Hex-Rays adapter
  at ``d810.hexrays.mutation.ir_translator`` is the only thing that
  knows how to turn a ``mcode_t`` int into one of these kinds.

The remaining planned families are narrower effect domains (for example stack
effects or floating-point operations) and should be added only when a consumer
needs that distinction.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType

from d810.core.typing import TypeAlias
from d810.ir.expressions import ValueOpKind

__all__ = [
    "CallKind",
    "ControlTransferKind",
    "LiftedOpcode",
    "OperationKind",
    "PredicateKind",
]


class PredicateKind(str, Enum):
    """Comparison / truthiness predicates used in conditional branches
    and ``m_set*`` materializations.

    Naming follows LLVM ICMP conventions.  This is the single portable
    predicate vocabulary: it absorbed and retired the older
    ``BranchPredicate`` (formerly in ``d810.ir.flowgraph``) -- the string
    values below are exactly BranchPredicate's, so any code that
    reconstructs a predicate from its serialized value
    (``PredicateKind(str(raw))``) keeps working.  Conditional branches and
    ``set*`` byte materializations both consume this -- they share the
    predicate semantic; the call site separately determines whether the
    result is "branch taken" or "byte materialized".
    """

    EQ = "eq"
    NE = "ne"
    UGE = "uge"
    UGT = "ugt"
    ULE = "ule"
    ULT = "ult"
    SGE = "sge"
    SGT = "sgt"
    SLE = "sle"
    SLT = "slt"
    TRUTHY = "truthy"


class ControlTransferKind(str, Enum):
    """Coarse categorization of an instruction's control-flow effect.

    Use this when a consumer needs "is this a goto vs a table branch
    vs a return vs a conditional branch"; pair with ``PredicateKind``
    when the branch additionally carries a comparison.  Direct /
    indirect / intrinsic calls are out of scope for this enum -- they
    get their own ``CallKind`` family.
    """

    GOTO = "goto"
    CONDITIONAL_BRANCH = "conditional_branch"
    TABLE_BRANCH = "table_branch"
    INDIRECT_BRANCH = "indirect_branch"
    RETURN = "return"


class CallKind(str, Enum):
    """Call operation family.

    Directness belongs here rather than in ``ControlTransferKind`` because calls
    produce call effects and often values; dispatcher recovery treats direct /
    indirect jumps as transfers, but call modeling consumes a sibling family.
    """

    DIRECT = "direct"
    INDIRECT = "indirect"
    INTRINSIC = "intrinsic"


OperationKind: TypeAlias = ValueOpKind | PredicateKind | ControlTransferKind | CallKind


@dataclass(frozen=True)
class LiftedOpcode:
    """Backend opcode lifted into the canonical semantic vocabulary.

    ``attrs`` is provenance only. Portable algorithms switch on ``kind`` and may
    record the raw backend fields for diagnostics without treating them as
    behavior-authorizing semantics.
    """

    kind: OperationKind
    attrs: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "attrs", MappingProxyType(dict(self.attrs)))
