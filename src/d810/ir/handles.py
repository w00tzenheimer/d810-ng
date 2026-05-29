"""Opaque IR handles for capability-boundary references.

These handles carry **identity, not structure**.  A capability that
takes a ``BlockHandle`` does not get to peek at block contents through
the handle -- it must use a separate capability call to ask the
backend to resolve the block.  This keeps the portable layer free of
vendor object shapes (no ``ida_hexrays.mblock_t``, no ``angr.Block``,
no ``ghidra.Block``).

Slice 9 scope: handles are landed as opaque identity types only.  No
methods, no resolution helpers, no graph-walking surface.  When a
future capability slice needs richer access (e.g. iterating
predecessors), the handle stays opaque and the capability gains a
``successors_of(handle: BlockHandle) -> Iterable[BlockHandle]``
method.  Do NOT add navigation surface here.

Runtime representation:

* ``BlockHandle`` -- an opaque integer (block serial in Hex-Rays;
  basic-block id in angr/Ghidra).  Wrapped via ``typing.NewType``
  so ``BlockHandle(42)`` is distinct from ``int`` at type-check time
  but is a plain ``int`` at runtime (zero overhead, no boxing).
* ``OperandHandle`` -- an opaque integer identity for an operand.
  The interpretation (mop_t address, SSA value-id, etc.) is the
  backend's concern.
* ``FlowGraphHandle`` -- an opaque object reference for a flow
  graph.  Wider than ``BlockHandle``/``OperandHandle`` because
  graph identity in practice carries arbitrary backend state
  (``ida_hexrays.mba_t`` / ``angr.Function`` / ``ghidra.Function``).
  Wrapped via ``NewType[object]`` so capabilities can type-check the
  parameter while the concrete object is opaque.

These choices intentionally mirror LLVM's ``llvm::BasicBlock *`` /
``llvm::Value *`` discipline: identity over structure, with all
queries routed through APIs the analysis layer owns.
"""

from __future__ import annotations

from d810.core.typing import NewType

__all__ = ["BlockHandle", "FlowGraphHandle", "InsnHandle", "OperandHandle"]


BlockHandle = NewType("BlockHandle", int)
"""Opaque identity for a single basic block.

Concrete backends interpret the wrapped ``int`` (``mblock_t.serial``
in Hex-Rays; a basic-block id in angr/Ghidra).  Portable code does not
inspect the underlying value -- it passes the handle through capability
calls.
"""


OperandHandle = NewType("OperandHandle", int)
"""Opaque identity for a single operand / value.

Concrete backends interpret the wrapped ``int`` (an ``id(mop_t)``
or operand-table index in Hex-Rays; an SSA value-id in angr/Ghidra).
Portable code does not inspect the underlying value.
"""


InsnHandle = NewType("InsnHandle", int)
"""Opaque identity for a single instruction.

Concrete backends interpret the wrapped ``int`` (an instruction address or
``minsn_t`` index in Hex-Rays; a statement id in angr/Ghidra).  Portable code
does not inspect the underlying value.
"""


FlowGraphHandle = NewType("FlowGraphHandle", object)
"""Opaque identity for a flow graph.

Wider than block/operand handles because graph identity carries
arbitrary backend state in practice.  Concrete callers pass their
native graph object; portable consumers must not introspect it
(no ``getattr``, no ``isinstance`` checks against vendor types).
"""
