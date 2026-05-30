"""Portable semantic IR — operation families for microcode-style ops.

This module hosts the **backend-neutral** semantic vocabulary for
microcode-style operations.  Files that consume these enums never
need to know about Hex-Rays ``mcode_t`` / IDA opcode integers /
vendor identifier names; they consume ``PredicateKind``,
``ControlTransferKind`` (and future siblings) and let the backend
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

Planned (NOT yet implemented) family enums
------------------------------------------

* ``ValueOpKind``        -- pure arithmetic / bitwise / partition
  operations (COPY, NEG, ADD/SUB/MUL, OR/AND/XOR, SHL/LSHR/ASHR,
  LOW_PART/HIGH_PART, etc.)
* ``MemoryOpKind``       -- LOAD / STORE
* ``FlagComputationKind`` -- explicit OVERFLOW_FLAG / UADD_CARRY /
  SHL_CARRY / SIGN_BIT / PARITY materializations (note: ``m_seto``
  is "overflow flag materialized", NOT necessarily subtraction
  overflow -- model it as ``OVERFLOW_FLAG`` until a consumer needs
  to distinguish the source)
* ``ConversionKind``     -- SIGN_EXTEND / ZERO_EXTEND / INT_TO_FLOAT
  / FLOAT_TO_INT / FLOAT_RESIZE / FLOAT_NEG
* ``FloatOpKind``        -- ADD / SUB / MUL / DIV
* ``CallKind``           -- DIRECT / INDIRECT / INTRINSIC
* ``StackEffectKind``    -- PUSH / POP

Add these on demand as new axis-C slices need them.
"""

from __future__ import annotations

from enum import Enum, auto

__all__ = [
    "ControlTransferKind",
    "PredicateKind",
]


class PredicateKind(Enum):
    """Comparison / truthiness predicates used in conditional branches
    and ``m_set*`` materializations.

    Naming follows LLVM ICMP conventions (shorter than
    ``BranchPredicate`` in ``d810.ir.flowgraph``, which is the older
    equivalent kept in place for back-compat with the slice-9 / slice-10
    ``RedirectIntent`` work).  Conditional branches and ``set*`` byte
    materializations both consume this -- they share the predicate
    semantic; the call site separately determines whether the result
    is "branch taken" or "byte materialized".
    """

    EQ = auto()
    NE = auto()
    UGE = auto()
    UGT = auto()
    ULE = auto()
    ULT = auto()
    SGE = auto()
    SGT = auto()
    SLE = auto()
    SLT = auto()
    TRUTHY = auto()


class ControlTransferKind(Enum):
    """Coarse categorization of an instruction's control-flow effect.

    Use this when a consumer needs "is this a goto vs a table branch
    vs a return vs a conditional branch"; pair with ``PredicateKind``
    when the branch additionally carries a comparison.  Direct /
    indirect / intrinsic calls are out of scope for this enum -- they
    get their own ``CallKind`` family once a consumer needs them.
    """

    GOTO = auto()
    CONDITIONAL_BRANCH = auto()
    TABLE_BRANCH = auto()
    INDIRECT_BRANCH = auto()
    RETURN = auto()
