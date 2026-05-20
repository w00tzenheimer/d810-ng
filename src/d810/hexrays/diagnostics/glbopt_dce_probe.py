"""Probe IDA's dataflow classification of byte-emit ``m_stx`` writes.

At MMAT_GLBOPT1 post_d810 (snap17), bytes 2-6 of the sub_7FFD3338C040
byte-emit corridor disappear after IDA runs ``mba_t::optimize_global()``
between snap17 and snap18.  This module gives us non-destructive insight
into *why* by inspecting IDA's own def/use classification just before
the kill step runs.

For each byte-emit EA the caller passes in, we locate the parent
``mblock_t``, force its def/use lists ready via ``make_lists_ready()``
(non-destructive: passes ``kill_deads=False``), and report whether the
write is already classified dead (in ``dnu``), whether the
destination address sits in ``mba.aliased_memory`` or
``mba.restricted_memory``, and whether ``mba.nodel_memory`` already
keeps it alive.

Pure observation; nothing in this module mutates the mba.
"""
from __future__ import annotations

import ida_hexrays

from d810.core.logging import getLogger
from d810.core.typing import Iterable, List, Optional, Tuple

logger = getLogger(__name__)


def _opcode_name(opcode: int) -> str:
    """Reverse-lookup an ``ida_hexrays.m_*`` constant to its mnemonic name."""
    for name in dir(ida_hexrays):
        if not name.startswith("m_"):
            continue
        try:
            if getattr(ida_hexrays, name) == opcode:
                return name
        except Exception:
            continue
    return f"<unknown:{opcode}>"


def _find_insn_at_ea(
    mba,
    target_ea: int,
) -> Tuple[Optional[object], Optional[object]]:
    """Locate the ``(mblock, minsn)`` whose ``ea`` matches ``target_ea``.

    Walks every block in serial order; for each block walks the
    instruction chain via ``head.next``.  Returns ``(None, None)`` if
    the EA is no longer present (block may have been DCE'd before us).
    """
    qty = int(getattr(mba, "qty", 0) or 0)
    for serial in range(qty):
        blk = mba.get_mblock(serial)
        if blk is None:
            continue
        insn = blk.head
        while insn is not None:
            try:
                if int(insn.ea) == int(target_ea):
                    return blk, insn
            except Exception:
                pass
            insn = insn.next
    return None, None


def _ivlset_contains(ivlset, ea: int) -> Optional[bool]:
    """Best-effort check whether an ``ivlset_t`` contains the byte at ``ea``.

    Returns ``None`` when the ivlset cannot be inspected from Python
    (some IDA versions expose only opaque getters).
    """
    if ivlset is None:
        return None
    try:
        return bool(ivlset.contains(ea))
    except (AttributeError, TypeError):
        pass
    try:
        for ivl in ivlset:
            start = int(getattr(ivl, "off", getattr(ivl, "start", 0)))
            size = int(getattr(ivl, "size", 0))
            if size:
                end = start + size
            else:
                end = int(getattr(ivl, "end", start))
            if start <= ea < end:
                return True
        return False
    except Exception:
        return None


def _mlist_summary(lst) -> str:
    """Render a one-line summary of a ``mlist_t``."""
    if lst is None:
        return "<missing>"
    try:
        has_mem = bool(lst.has_memory())
    except Exception:
        has_mem = False
    try:
        has_reg = not lst.reg.empty()
    except Exception:
        has_reg = False
    return f"mem={'Y' if has_mem else '-'} reg={'Y' if has_reg else '-'}"


def _scan_caller_memory_stx(
    mba,
    caller_offset_range: Tuple[int, int] = (0x50, 0x90),
) -> List[Tuple[object, object, Optional[int]]]:
    """Walk every block and collect ``m_stx`` whose destination looks like
    ``add(arg_or_reg, k)`` for ``k`` in ``[caller_offset_range)``.

    The byte-emit corridor writes to ``*(a5 + 0x50 + 8*idx)`` for
    ``idx in 0..7``, giving offsets ``0x50, 0x58, ..., 0x88``.  HCC's
    composition rewrites instruction EAs to the function entry, so
    matching by EA fails post-D810; pattern matching survives.

    Returns a list of ``(mblock, minsn, detected_offset_or_None)``.
    """
    hits: List[Tuple[object, object, Optional[int]]] = []
    qty = int(getattr(mba, "qty", 0) or 0)
    m_stx = getattr(ida_hexrays, "m_stx", -1)
    m_add = getattr(ida_hexrays, "m_add", -1)
    mop_n = getattr(ida_hexrays, "mop_n", -1)
    mop_d = getattr(ida_hexrays, "mop_d", -1)
    low, high = caller_offset_range

    def _extract_const_addend(addr_mop) -> Optional[int]:
        """If ``addr_mop`` is a ``mop_d`` of ``add(_, mop_n)``, return the constant."""
        if addr_mop is None:
            return None
        try:
            if int(addr_mop.t) != mop_d:
                return None
            d_insn = addr_mop.d
            if d_insn is None or int(d_insn.opcode) != m_add:
                return None
            for sub in (d_insn.l, d_insn.r):
                if sub is None:
                    continue
                if int(sub.t) == mop_n:
                    return int(sub.nnn.value)
        except Exception:
            pass
        return None

    for serial in range(qty):
        blk = mba.get_mblock(serial)
        if blk is None:
            continue
        insn = blk.head
        while insn is not None:
            try:
                if int(insn.opcode) == m_stx:
                    offset = _extract_const_addend(insn.d)
                    if offset is not None and low <= offset < high:
                        hits.append((blk, insn, offset))
            except Exception:
                pass
            insn = insn.next
    return hits


def probe_byte_emit_dce(
    mba,
    byte_emit_eas: Iterable[int],
) -> List[str]:
    """Probe IDA's classification of each byte-emit instruction.

    For every EA in ``byte_emit_eas``:

    * locate the parent ``mblock_t`` and the ``minsn_t`` at that EA
    * non-destructively populate def/use lists via ``make_lists_ready()``
    * report per-block ``maybuse`` / ``mustbuse`` / ``maybdef`` /
      ``mustbdef`` / ``dnu`` summaries
    * record whether the instruction itself reports
      ``may_use_aliased_memory()`` -- if False, IDA already believes
      the write does not escape and is a strong DCE candidate

    Returns a list of text lines suitable for printing or persisting.
    """
    out: List[str] = []
    qty = int(getattr(mba, "qty", 0) or 0)
    maturity = int(getattr(mba, "maturity", 0) or 0)
    out.append(
        f"=== GLBOPT_DCE_PROBE maturity={maturity} blocks={qty} ==="
    )

    aliased = getattr(mba, "aliased_memory", None)
    restricted = getattr(mba, "restricted_memory", None)
    nodel = getattr(mba, "nodel_memory", None)
    nodel_has_mem = "N/A"
    if nodel is not None:
        try:
            nodel_has_mem = "Y" if nodel.has_memory() else "-"
        except Exception:
            nodel_has_mem = "?"
    out.append(
        f"  mba.aliased_memory={'present' if aliased is not None else 'missing'}"
        f"  mba.restricted_memory={'present' if restricted is not None else 'missing'}"
        f"  mba.nodel_memory.has_memory={nodel_has_mem}"
    )

    pattern_hits = _scan_caller_memory_stx(mba)
    out.append(
        f"  pattern-scan: m_stx with destination=add(_, k) "
        f"where k in [0x50, 0x90): {len(pattern_hits)} hits"
    )
    for hit_blk, hit_insn, hit_offset in pattern_hits:
        try:
            ea = int(hit_insn.ea)
            opc = int(hit_insn.opcode)
        except Exception:
            ea, opc = 0, -1
        out.append(
            f"    blk[{hit_blk.serial}] insn ea=0x{ea:x} offset=0x{hit_offset:x} "
            f"may_use_aliased_memory={getattr(hit_insn, 'may_use_aliased_memory', lambda: '?')()}"
        )

    candidate_pairs: List[Tuple[Optional[int], object, object]] = [
        (int(ea), *_find_insn_at_ea(mba, int(ea))) for ea in byte_emit_eas
    ]
    pattern_pairs: List[Tuple[Optional[int], object, object]] = [
        (None, b, i) for (b, i, _) in pattern_hits
    ]
    for source_label, (target_ea, blk, insn) in (
        [("ea", row) for row in candidate_pairs]
        + [("pattern", row) for row in pattern_pairs]
    ):
        out.append("")
        if source_label == "ea":
            out.append(f"--- byte_emit ea=0x{target_ea:x} ---")
        else:
            out.append(
                f"--- byte_emit pattern blk[{blk.serial}]"
                f" insn ea=0x{int(insn.ea):x} ---"
            )
        if blk is None or insn is None:
            out.append("  NOT FOUND in current mba (possibly already removed)")
            continue
        try:
            opcode = int(insn.opcode)
        except Exception:
            opcode = -1
        out.append(
            f"  blk[{blk.serial}] type={int(blk.type)}"
            f" npred={blk.npred()} nsucc={blk.nsucc()}"
        )
        out.append(f"  insn opcode={opcode} ({_opcode_name(opcode)})")

        try:
            may_alias = bool(insn.may_use_aliased_memory())
        except Exception:
            may_alias = None
        out.append(f"  insn.may_use_aliased_memory={may_alias}")

        try:
            blk.make_lists_ready()
        except Exception as exc:
            out.append(f"  make_lists_ready FAILED: {exc!r}")
            continue
        try:
            ready = bool(blk.lists_ready())
        except Exception:
            ready = None
        out.append(f"  lists_ready={ready}")

        out.append(f"  block.maybuse:       {_mlist_summary(blk.maybuse)}")
        out.append(f"  block.mustbuse:      {_mlist_summary(blk.mustbuse)}")
        out.append(f"  block.maybdef:       {_mlist_summary(blk.maybdef)}")
        out.append(f"  block.mustbdef:      {_mlist_summary(blk.mustbdef)}")
        out.append(f"  block.dnu:           {_mlist_summary(blk.dnu)}")
        out.append(f"  block.dead_at_start: {_mlist_summary(blk.dead_at_start)}")

        downstream_uses: List[int] = []
        for s_idx in range(blk.nsucc()):
            succ_ser = blk.succ(s_idx)
            succ_blk = mba.get_mblock(succ_ser)
            if succ_blk is None:
                continue
            try:
                succ_blk.make_lists_ready()
            except Exception:
                continue
            try:
                if blk.mustbdef.has_common(succ_blk.maybuse):
                    downstream_uses.append(int(succ_ser))
            except Exception:
                continue
        out.append(
            f"  successors_consuming_mustbdef={len(downstream_uses)}"
            f"/{blk.nsucc()} -> {downstream_uses}"
        )

    return out
