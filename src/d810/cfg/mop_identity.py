"""Portable identity helpers for ``MopSnapshot``.

These helpers are the canonical operand-identity functions for
dispatcher-state analyses -- they replaced the live-IDA operand-keying
methods from the retired dispatcher-analysis owner. Portable analyses no
longer need a live ``ida_hexrays.mop_t`` to key operands.

E2a slice of ``docs/plans/recon-portability-end-state.md``: snapshot
gap closure for the dispatcher state-variable port.  E3-rewire
landed the pure ``analyze_dispatcher(flow_graph)`` consumer; these
helpers are part of its identity surface.

Key schema:

* ``mop_snapshot_key`` returns ``"r{reg}" | "S{stkoff}" |
  "v{gaddr}" | "l{lvar_off}" | None`` -- the prefix encodes the
  operand kind so distinct kinds with the same numeric value
  (e.g. ``r3`` vs ``S3``) cannot collide.
* ``mop_snapshot_offset`` returns the per-kind numeric identifier
  with a ``0`` fallback for unsupported kinds.

Acceptance rule for the E3 dispatcher port (pinned here because this
module is what portable consumers will import):

* Consumers MUST read operands via ``InsnSnapshot.l`` / ``.r`` / ``.d``
  (typed as the portable ``d810.cfg.flowgraph.MopSnapshot``) or via
  ``cfg_operand_slots(insn)`` below.
* Consumers MUST NOT read ``InsnSnapshot.operand_slots`` or
  ``InsnSnapshot.operands``.  Those fields are typed ``object`` and
  today carry the *rich* ``d810.hexrays.ir.mop_snapshot.MopSnapshot``
  (which holds an IDA ``mop_t`` clone) -- reaching into them
  re-introduces vendor coupling.
* Any missing data discovered while porting (nested ``mop_d``
  expression structure, etc.) gets added to ``InsnSnapshot.l/r/d`` or
  ``MopSnapshot`` as new portable fields -- it does NOT get borrowed
  from ``operand_slots``.
"""

from __future__ import annotations

from d810.cfg.flowgraph import InsnSnapshot, MopSnapshot, OperandKind

__all__ = ["cfg_operand_slots", "mop_snapshot_key", "mop_snapshot_offset"]


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
    ``d810.cfg.flowgraph.MopSnapshot``; callers can pass each operand
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
    if mop is None:
        return None
    kind = mop.kind
    if kind is OperandKind.REGISTER and mop.reg is not None:
        return f"r{mop.reg}"
    if kind is OperandKind.STACK and mop.stkoff is not None:
        return f"S{mop.stkoff}"
    if kind is OperandKind.GLOBAL and mop.gaddr is not None:
        return f"v{mop.gaddr}"
    if kind is OperandKind.LVAR and mop.lvar_off is not None:
        return f"l{mop.lvar_off}"
    return None


def mop_snapshot_offset(mop: MopSnapshot | None) -> int:
    """Return the per-kind numeric identifier (register number, stack
    offset, global address, lvar offset) with a ``0`` fallback for
    kinds that don't carry a portable identifier.
    """
    if mop is None:
        return 0
    kind = mop.kind
    if kind is OperandKind.REGISTER and mop.reg is not None:
        return int(mop.reg)
    if kind is OperandKind.STACK and mop.stkoff is not None:
        return int(mop.stkoff)
    if kind is OperandKind.GLOBAL and mop.gaddr is not None:
        return int(mop.gaddr)
    if kind is OperandKind.LVAR and mop.lvar_off is not None:
        return int(mop.lvar_off)
    return 0
