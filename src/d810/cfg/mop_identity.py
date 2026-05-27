"""Portable identity helpers for ``MopSnapshot``.

These helpers replace the live-IDA ``_get_mop_key`` / ``_get_mop_offset``
methods on ``d810.recon.flow.dispatcher_detection.DispatcherCache`` with
pure-snapshot equivalents so that dispatcher-state analyses no longer
need a live ``ida_hexrays.mop_t`` to key operands.

E2a slice of ``docs/plans/recon-portability-end-state.md``: snapshot
gap closure for the dispatcher state-variable port.  Does NOT rewire
any recon consumer; pure additive layer that future slices can adopt
incrementally.

Semantics parity with the live-IDA originals (in
``dispatcher_detection.py:609,867``):

* ``mop_snapshot_key`` returns ``"r{reg}" | "S{stkoff}" |
  "v{gaddr}" | "l{lvar_off}" | None`` -- the prefix encodes the
  operand kind so distinct kinds with the same numeric value
  (e.g. ``r3`` vs ``S3``) cannot collide.
* ``mop_snapshot_offset`` returns the per-kind numeric identifier with
  a ``0`` fallback (matches the legacy ``return 0`` arm in
  ``_get_mop_offset``).
"""

from __future__ import annotations

from d810.cfg.flowgraph import MopSnapshot, OperandKind

__all__ = ["mop_snapshot_key", "mop_snapshot_offset"]


def mop_snapshot_key(mop: MopSnapshot | None) -> str | None:
    """Return a stable per-operand key string, or ``None`` for kinds
    that don't carry a portable identity (numbers, blocks, helpers,
    etc.).  Parity with the live-IDA ``_get_mop_key`` in
    ``dispatcher_detection.py``.

    Returns ``None`` if the operand is ``None``, has unknown kind, or
    is a kind that the legacy helper also didn't key (number, block
    ref, etc.).
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
    kinds that don't carry a portable identifier.  Parity with the
    live-IDA ``_get_mop_offset`` in ``dispatcher_detection.py``.
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
