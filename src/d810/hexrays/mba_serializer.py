"""Serialize live IDA MBA to BlockSnapshot dataclasses.

This module contains IDA-dependent helpers that convert a live ``mba_t``
into a list of :class:`BlockSnapshot` dataclasses suitable for
``d810.core.diag.snapshot.snapshot_mba``.  It is importable from any
hexrays-aware module (hexrays hooks, executor, unflattener, etc.).

Lives under ``d810.hexrays`` so the live Hex-Rays adaptation stays
inside the Hex-Rays domain. The neutral data containers
(:class:`BlockSnapshot`, :class:`InstructionSnapshot`) live in
:mod:`d810.core.observability_models`; the SQLite sink in
``d810.core.diag.snapshot`` consumes them. Runtime callers should
normally reach this module through
``d810.hexrays.observability.mba_to_block_snapshots``.

IDA imports are guarded so the rest of ``d810.core.diag`` stays
unit-testable without IDA.
"""
from __future__ import annotations

import json

try:
    import ida_hexrays as _ihr
except ImportError:
    _ihr = None

from d810.core.observability_models import BlockSnapshot, InstructionSnapshot

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


def _safe_dstr(obj: object) -> str:
    dstr = getattr(obj, "dstr", None)
    if callable(dstr):
        try:
            return str(dstr())
        except Exception:
            return ""
    if dstr is not None:
        return str(dstr)
    return ""


def _register_name(register: int | None, size: int | None = None) -> str | None:
    if register is None or _ihr is None:
        return None
    try:
        return str(_ihr.get_mreg_name(int(register), int(size or 0)) or "")
    except Exception:
        return None


def _mop_to_meta(
    mop: "ida_hexrays.mop_t | None",
    *,
    depth: int = 0,
    max_depth: int = 8,
) -> dict[str, object] | None:
    if mop is None or _ihr is None or depth > max_depth:
        return None
    mop_type = getattr(mop, "t", None)
    if mop_type is None or mop_type == _ihr.mop_z:
        return None

    result: dict[str, object] = {
        "type": _mop_type_name(mop) or f"mop_{mop_type}",
        "type_num": int(mop_type),
        "size": int(getattr(mop, "size", 0) or 0),
        "dstr": _safe_dstr(mop),
    }
    if mop_type == _ihr.mop_n:
        nnn = getattr(mop, "nnn", None)
        if nnn is not None:
            value = getattr(nnn, "value", None)
            if value is not None:
                result["value"] = int(value)
    elif mop_type == _ihr.mop_r:
        register = getattr(mop, "r", None)
        if register is not None:
            result["register"] = int(register)
            name = _register_name(int(register), int(getattr(mop, "size", 0) or 0))
            if name:
                result["register_name"] = name
    elif mop_type == _ihr.mop_v:
        global_ea = getattr(mop, "g", None)
        if global_ea is not None:
            result["global_ea"] = f"0x{int(global_ea):x}"
    elif mop_type == _ihr.mop_b:
        block_num = getattr(mop, "b", None)
        if block_num is not None:
            result["block_num"] = int(block_num)
    elif mop_type == _ihr.mop_S:
        stack = getattr(mop, "s", None)
        if stack is not None and getattr(stack, "off", None) is not None:
            result["stkoff"] = int(stack.off)
    elif mop_type == _ihr.mop_l:
        local = getattr(mop, "l", None)
        if local is not None and getattr(local, "idx", None) is not None:
            result["lvar_idx"] = int(local.idx)
    elif mop_type == _ihr.mop_a:
        inner = getattr(mop, "a", None)
        inner_meta = _mop_to_meta(inner, depth=depth + 1, max_depth=max_depth)
        if inner_meta is not None:
            result["sub_operand"] = inner_meta
    elif mop_type == _ihr.mop_d:
        sub_insn = getattr(mop, "d", None)
        sub_meta = _instruction_operands_meta(
            sub_insn,
            depth=depth + 1,
            max_depth=max_depth,
        )
        if sub_meta is not None:
            result["sub_instruction"] = sub_meta
    elif mop_type == _ihr.mop_f:
        func = getattr(mop, "f", None)
        args = getattr(func, "args", ()) if func is not None else ()
        result["args"] = [
            arg_meta
            for arg in args
            if (arg_meta := _mop_to_meta(arg, depth=depth + 1, max_depth=max_depth))
            is not None
        ]
    return result


def _instruction_operands_meta(
    insn: "ida_hexrays.minsn_t | None",
    *,
    depth: int = 0,
    max_depth: int = 8,
) -> dict[str, object] | None:
    if insn is None or _ihr is None or depth > max_depth:
        return None
    result: dict[str, object] = {
        "opcode": int(getattr(insn, "opcode", -1)),
        "opcode_name": _opcode_name(int(getattr(insn, "opcode", -1))),
        "ea": f"0x{int(getattr(insn, 'ea', 0) or 0):x}",
        "dstr": _safe_dstr(insn),
    }
    for slot_name, attr_name in (("l", "l"), ("r", "r"), ("d", "d")):
        mop_meta = _mop_to_meta(
            getattr(insn, attr_name, None),
            depth=depth + 1,
            max_depth=max_depth,
        )
        if mop_meta is not None:
            result[slot_name] = mop_meta
    return result


def _instruction_snapshot_meta(
    insn: "ida_hexrays.minsn_t",
    *,
    insn_index: int,
    block_register_defs: dict[int, dict[str, object]],
) -> str | None:
    meta = _instruction_operands_meta(insn)
    if meta is None:
        return None

    if _ihr is not None and getattr(insn, "opcode", None) in {
        getattr(_ihr, "m_call", object()),
        getattr(_ihr, "m_icall", object()),
    }:
        meta["call_setup_registers"] = [
            dict(record)
            for _, record in sorted(block_register_defs.items(), key=lambda item: item[0])
        ]

    try:
        return json.dumps(meta, sort_keys=True, separators=(",", ":"))
    except TypeError:
        return None


def _record_register_definition(
    block_register_defs: dict[int, dict[str, object]],
    *,
    insn_index: int,
    insn: "ida_hexrays.minsn_t",
) -> None:
    if _ihr is None:
        return
    dest = getattr(insn, "d", None)
    if dest is None or getattr(dest, "t", None) != _ihr.mop_r:
        return
    register = getattr(dest, "r", None)
    if register is None:
        return
    source = _mop_to_meta(getattr(insn, "l", None))
    block_register_defs[int(register)] = {
        "writer_index": int(insn_index),
        "writer_ea": f"0x{int(getattr(insn, 'ea', 0) or 0):x}",
        "opcode": int(getattr(insn, "opcode", -1)),
        "opcode_name": _opcode_name(int(getattr(insn, "opcode", -1))),
        "register": int(register),
        "register_name": _register_name(
            int(register),
            int(getattr(dest, "size", 0) or 0),
        ),
        "source": source,
    }


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
        block_register_defs: dict[int, dict[str, object]] = {}
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

            meta = _instruction_snapshot_meta(
                insn,
                insn_index=insn_idx,
                block_register_defs=block_register_defs,
            )
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
                meta=meta,
            ))
            _record_register_definition(
                block_register_defs,
                insn_index=insn_idx,
                insn=insn,
            )
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
