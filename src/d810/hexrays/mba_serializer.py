"""Serialize live IDA MBA to BlockSnapshot dataclasses.

This module contains IDA-dependent helpers that convert a live ``mba_t``
into a list of :class:`BlockSnapshot` dataclasses suitable for
``d810.core.diag.snapshot.snapshot_mba``.  It is importable from any
hexrays-aware module (hexrays hooks, executor, unflattener, etc.).

Lives under ``d810.hexrays`` so the live Hex-Rays adaptation stays
inside the Hex-Rays domain; ``d810.core.diag`` keeps the neutral
dataclasses (``BlockSnapshot``, ``InstructionSnapshot``) and the
SQLite sink that consumes them. Runtime callers should normally reach
this module through ``d810.hexrays.observability.mba_to_block_snapshots``.

IDA imports are guarded so the rest of ``d810.core.diag`` stays
unit-testable without IDA.
"""
from __future__ import annotations

try:
    import ida_hexrays as _ihr
except ImportError:
    _ihr = None

from d810.core.diag.snapshot import BlockSnapshot, InstructionSnapshot

# ---------- opcode / mop helpers ----------

_OPCODE_NAME_CACHE: dict[int, str] = {}


def _opcode_name(opcode: int) -> str:
    """Return human-readable opcode name, with a cache to avoid repeated lookups."""
    if opcode in _OPCODE_NAME_CACHE:
        return _OPCODE_NAME_CACHE[opcode]
    try:
        name = _ihr.get_mreg_name(opcode, 0)  # type: ignore[union-attr]
        if not name:
            name = f"op_{opcode}"
    except Exception:
        name = f"op_{opcode}"
    _OPCODE_NAME_CACHE[opcode] = name
    return name


def _mop_type_name(mop: "ida_hexrays.mop_t") -> str | None:
    """Return the mop type as a human-readable string, or None if zero/empty."""
    _MOP_NAMES = {
        _ihr.mop_z: None,
        _ihr.mop_r: "mop_r",
        _ihr.mop_n: "mop_n",
        _ihr.mop_d: "mop_d",
        _ihr.mop_S: "mop_S",
        _ihr.mop_v: "mop_v",
        _ihr.mop_b: "mop_b",
        _ihr.mop_f: "mop_f",
        _ihr.mop_l: "mop_l",
        _ihr.mop_a: "mop_a",
        _ihr.mop_h: "mop_h",
        _ihr.mop_str: "mop_str",
        _ihr.mop_c: "mop_c",
        _ihr.mop_fn: "mop_fn",
        _ihr.mop_p: "mop_p",
        _ihr.mop_sc: "mop_sc",
    }
    return _MOP_NAMES.get(mop.t)


# ---------- main serializer ----------


def mba_to_block_snapshots(
    mba: "ida_hexrays.mba_t",
) -> list[BlockSnapshot]:
    """Convert live MBA to a list of BlockSnapshot dataclasses for diagnostic snapshot.

    Requires IDA to be available at runtime (``ida_hexrays`` must be importable).
    Uses lazy import of snapshot types to avoid import cycle when diag is disabled.

    Args:
        mba: Live ``mba_t`` object from IDA Hex-Rays.

    Returns:
        List of :class:`BlockSnapshot` dataclasses, one per MBA block.

    Raises:
        RuntimeError: If ``ida_hexrays`` is not available.
    """
    if _ihr is None:
        raise RuntimeError("mba_to_block_snapshots requires ida_hexrays")

    blocks: list[BlockSnapshot] = []
    for idx in range(mba.qty):
        blk = mba.get_mblock(idx)
        if blk is None:
            continue

        succs = [blk.succ(i) for i in range(blk.nsucc())]
        preds = [blk.pred(i) for i in range(blk.npred())]

        insns: list[InstructionSnapshot] = []
        insn = blk.head
        insn_idx = 0
        while insn is not None:
            dest_type = _mop_type_name(insn.d) if insn.d.t != _ihr.mop_z else None
            dest_stkoff = insn.d.s.off if insn.d.t == _ihr.mop_S else None
            dest_size = insn.d.size if dest_type is not None else None

            src_l_type = _mop_type_name(insn.l)
            src_l_stkoff = insn.l.s.off if insn.l.t == _ihr.mop_S else None
            src_l_value = insn.l.nnn.value if insn.l.t == _ihr.mop_n else None

            src_r_type = _mop_type_name(insn.r)
            src_r_stkoff = insn.r.s.off if insn.r.t == _ihr.mop_S else None
            src_r_value = insn.r.nnn.value if insn.r.t == _ihr.mop_n else None

            try:
                dstr = insn.dstr()
            except Exception:
                dstr = ""

            insns.append(InstructionSnapshot(
                index=insn_idx,
                ea=insn.ea,
                opcode=insn.opcode,
                opcode_name=_opcode_name(insn.opcode),
                dest_type=dest_type,
                dest_stkoff=dest_stkoff,
                dest_size=dest_size,
                src_l_type=src_l_type,
                src_l_stkoff=src_l_stkoff,
                src_l_value=src_l_value,
                src_r_type=src_r_type,
                src_r_stkoff=src_r_stkoff,
                src_r_value=src_r_value,
                dstr=dstr,
            ))
            insn = insn.next
            insn_idx += 1

        # Block type name
        _BLT_NAMES = {
            _ihr.BLT_NONE: "BLT_NONE",
            _ihr.BLT_STOP: "BLT_STOP",
            _ihr.BLT_1WAY: "BLT_1WAY",
            _ihr.BLT_2WAY: "BLT_2WAY",
            _ihr.BLT_NWAY: "BLT_NWAY",
            _ihr.BLT_XTRN: "BLT_XTRN",
        }
        type_name = _BLT_NAMES.get(blk.type, f"BLT_{blk.type}")

        blocks.append(BlockSnapshot(
            serial=idx,
            block_type=blk.type,
            type_name=type_name,
            start_ea=blk.start,
            end_ea=blk.end,
            nsucc=blk.nsucc(),
            npred=blk.npred(),
            succs=succs,
            preds=preds,
            instructions=insns,
        ))

    return blocks
