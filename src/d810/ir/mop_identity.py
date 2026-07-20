"Compatibility helpers for ``MopSnapshot`` identity.\n\nThe named portable identity boundary is\n``d810.ir.storage_identity.StorageIdentity``.  This module keeps the older\n``mop_snapshot_key`` / ``mop_snapshot_offset`` API byte-compatible for existing\ndiagnostics and transitional callers.\n\nThis is the *Identifier* layer (LiSA-style abstract location id / LLVM\nValue-identity / VEX guest-offset): a size-AGNOSTIC, kind-prefixed key over\nregister / stack / global / lvar operands.  It is deliberately distinct from\nthe syntactic operand-expression layer (``d810.ir.statements`` /\n``d810.ir.expressions``): an audit (llr-lxas) confirmed that re-keying off a\nsize-aware ``DefinitionRef(StackSlot(off, size))`` would split one state\nvariable accessed at multiple widths and would drop lvar / nested operands.\nKeep identity and expression separate; both are already portable.\n\nE2a slice of ``docs/plans/preanalysis-portability-end-state.md``: snapshot\ngap closure for the dispatcher state-variable port.  E3-rewire\nlanded the pure ``analyze_dispatcher(flow_graph)`` consumer; these\nhelpers are part of its identity surface.\n\nKey schema:\n\n* ``mop_snapshot_key`` returns ``\"r{reg}\" | \"S{stkoff}\" |\n  \"v{gaddr}\" | \"l{lvar_off}\" | None`` -- the prefix encodes the\n  operand kind so distinct kinds with the same numeric value\n  (e.g. ``r3`` vs ``S3``) cannot collide.\n* ``mop_snapshot_offset`` returns the per-kind numeric identifier\n  with a ``0`` fallback for unsupported kinds.\n\nAcceptance rule for the E3 dispatcher port (pinned here because this\nmodule is what portable consumers will import):\n\n* Consumers MUST read operands via ``InsnSnapshot.l`` / ``.r`` / ``.d``\n  (typed as the portable ``d810.ir.flowgraph.MopSnapshot``) or via\n  ``cfg_operand_slots(insn)`` below.\n* Consumers MUST NOT read ``InsnSnapshot.operand_slots`` or\n  ``InsnSnapshot.operands``.  Those fields are typed ``object`` and\n  today carry the *rich* ``d810.hexrays.ir.mop_snapshot.MopSnapshot``\n  (which holds an IDA ``mop_t`` clone) -- reaching into them\n  re-introduces vendor coupling.\n* Any missing data discovered while porting (nested ``mop_d``\n  expression structure, etc.) gets added to ``InsnSnapshot.l/r/d`` or\n  ``MopSnapshot`` as new portable fields -- it does NOT get borrowed\n  from ``operand_slots``.\n"

from __future__ import annotations

from d810.ir.flowgraph import InsnSnapshot, MopSnapshot
from d810.ir.storage_identity import (
    StorageIdentity,
    operand_storage_identities,
    storage_identity_from_mop_snapshot,
    storage_identity_key,
    storage_identity_offset,
)

__all__ = [
    "cfg_operand_slots",
    "mop_snapshot_key",
    "mop_snapshot_offset",
    "mop_storage_identity",
    "operand_storage_identities",
]


def cfg_operand_slots(
    insn: InsnSnapshot,
) -> tuple[tuple[str, MopSnapshot], ...]:
    """Return ``(slot_name, operand)`` pairs from the portable
    ``InsnSnapshot.l/r/d`` fields, skipping ``None``.

    Use this in portable analyses instead of ``insn.operand_slots``.
    ``operand_slots`` is typed ``tuple[tuple[str, object], ...]`` and
    today carries the rich ``d810.hexrays.ir.mop_snapshot.MopSnapshot``
    variant which holds a live IDA ``mop_t`` clone -- reading from it
    silently re-couples portable code to the Hex-Rays backend.

    The return type pins the operand as the portable
    ``d810.ir.flowgraph.MopSnapshot``; callers can pass each operand
    directly to ``mop_snapshot_key`` / ``mop_snapshot_offset`` without
    a vendor adapter.
    """
    return tuple(
        (slot, operand)
        for slot, operand in (("l", insn.l), ("r", insn.r), ("d", insn.d))
        if operand is not None
    )


def mop_snapshot_key(mop: MopSnapshot | None) -> str | None:
    """Return a stable per-operand key string, or ``None`` for kinds
    that don't carry a portable identity (numbers, blocks, helpers,
    etc.).  The four keyed kinds (``REGISTER`` / ``STACK`` /
    ``GLOBAL`` / ``LVAR``) match the operand identities that
    dispatcher state-variable comparisons can take.

    Returns ``None`` if the operand is ``None``, has unknown kind, or
    is a kind that has no stable identity (number, block ref, etc.).
    """
    return storage_identity_key(mop_storage_identity(mop))


def mop_snapshot_offset(mop: MopSnapshot | None) -> int:
    """Return the per-kind numeric identifier (register number, stack
    offset, global address, lvar offset) with a ``0`` fallback for
    kinds that don't carry a portable identifier.
    """
    return storage_identity_offset(mop_storage_identity(mop))


def mop_storage_identity(mop: MopSnapshot | None) -> StorageIdentity | None:
    """Compatibility adapter from ``MopSnapshot`` to ``StorageIdentity``."""
    return storage_identity_from_mop_snapshot(mop)
