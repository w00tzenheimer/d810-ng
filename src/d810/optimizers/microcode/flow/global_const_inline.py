"""Global constant inlining for microcode flow optimization.

Replaces loads from known-constant global addresses with their immediate values.
When a microcode instruction loads a value from a read-only global address
(``mop_v`` operand referencing ``.rodata``, ``.rdata``, ``__const``, etc.),
this rule replaces the load with the constant value directly.

This is a *flow-level* rule (operates per-block) complementing the
instruction-level ``FoldReadonlyDataRule`` peephole.  While the peephole handles
``ldx`` displacement patterns via ``mop_S``/``mop_b``, this rule targets
``mop_v`` (global variable) operands in ``mov`` and ``ldx`` instructions.

Algorithm (ported from copycat ``global_const_handler_t``):

1. **Detect** -- find ``m_mov`` / ``m_ldx`` instructions with ``mop_v``
   operands referencing global addresses.
2. **Validate** -- check the segment is read-only (``.rodata``, ``.rdata``,
   ``__const``, or segment lacking ``SEGPERM_WRITE``).  For writable
   segments (``.data``), verify via cross-references that no write xrefs
   exist.
3. **Read** -- fetch the constant value from the IDB.
4. **Filter** -- skip values that look like pointers (fall inside a known
   segment or match common ASLR ranges).
5. **Replace** -- rewrite the instruction as ``m_mov dst, #imm`` (erasing
   the segment operand for ``ldx``).
"""

from __future__ import annotations

from d810.core.typing import Optional

import ida_bytes
import ida_hexrays
import ida_segment
import ida_xref
import idaapi

from d810.core import getLogger
from d810.optimizers.microcode.flow.handler import FlowOptimizationRule

logger = getLogger(__name__)

# Common read-only section names across platforms.
_CONST_SECTION_NAMES: frozenset[str] = frozenset({
    "__const",
    ".rodata",
    ".rdata",
    "__DATA_CONST",
    "__cstring",
    "__cfstring",
})

# Writable sections where we still allow inlining if no write xrefs exist.
_DATA_SECTION_NAMES: frozenset[str] = frozenset({
    "__data",
    ".data",
})

# Maximum operand size (in bytes) that we are willing to inline.
_MAX_INLINE_SIZE: int = 8


class GlobalConstantInliner(FlowOptimizationRule):
    """Inlines known constant values from read-only global addresses.

    Scans each basic block for ``m_mov`` / ``m_ldx`` instructions whose
    source operand is a global variable (``mop_v``) residing in a read-only
    segment.  When the referenced value is a small numeric constant (not a
    pointer), the load is replaced with an immediate operand.
    """

    CATEGORY = "Constant Folding"
    DESCRIPTION = "Inlines known constant values from read-only global addresses"

    # This rule does *not* modify the CFG; it only rewrites operands.
    USES_DEFERRED_CFG = True
    SAFE_MATURITIES = None  # safe at any maturity

    def __init__(self) -> None:
        super().__init__()
        # Best results when addresses are resolved but before aggressive opts.
        self.maturities = [
            ida_hexrays.MMAT_PREOPTIMIZED,
            ida_hexrays.MMAT_LOCOPT,
        ]

    # ------------------------------------------------------------------ #
    # FlowOptimizationRule interface                                      #
    # ------------------------------------------------------------------ #

    def optimize(self, blk: ida_hexrays.mblock_t) -> int:
        """Scan *blk* for global loads and inline constant values."""
        count: int = 0
        insn: Optional[ida_hexrays.minsn_t] = blk.head
        while insn is not None:
            n = self._try_inline_globals(blk, insn)
            count += n
            insn = insn.next
        if count > 0:
            blk.mark_lists_dirty()
        return count

    # ------------------------------------------------------------------ #
    # Core logic                                                          #
    # ------------------------------------------------------------------ #

    def _try_inline_globals(
        self, blk: ida_hexrays.mblock_t, insn: ida_hexrays.minsn_t
    ) -> int:
        """Check all operands of *insn* for inlinable global references.

        Returns the number of replacements performed (0 or 1).
        """
        if insn.opcode not in (ida_hexrays.m_mov, ida_hexrays.m_ldx):
            return 0

        ea: int = idaapi.BADADDR
        size: int = 0
        target_mop: Optional[ida_hexrays.mop_t] = None

        # -- Pattern 1: mov dst, gv  (left operand is mop_v) ----------- #
        if insn.opcode == ida_hexrays.m_mov and insn.l.t == ida_hexrays.mop_v:
            ea = insn.l.g
            size = insn.l.size
            target_mop = insn.l

        # -- Pattern 2: ldx dst, seg, gv  (right operand is mop_v) ----- #
        elif insn.opcode == ida_hexrays.m_ldx:
            if insn.r.t == ida_hexrays.mop_v:
                ea = insn.r.g
                size = insn.d.size
                target_mop = insn.r

        if ea == idaapi.BADADDR or size <= 0 or size > _MAX_INLINE_SIZE:
            return 0

        # Must reference data, not code.
        flags = ida_bytes.get_flags(ea)
        if ida_bytes.is_code(flags):
            return 0

        if not _is_constant_global(ea):
            return 0

        value: int = _read_constant_value(ea, size)

        # Skip pointer-like values -- we do not want to inline addresses.
        if _looks_like_pointer(value, size):
            return 0

        # Perform the replacement.
        _replace_with_immediate(insn, value, size)
        logger.info(
            "Inlined global constant at 0x%X -> 0x%X (size=%d)",
            ea,
            value,
            size,
        )
        return 1


# ====================================================================== #
# Module-level helpers (also usable independently in tests)               #
# ====================================================================== #


def _is_constant_global(ea: int) -> bool:
    """Return ``True`` if *ea* resides in a read-only data section.

    For writable data sections (``.data``, ``__data``) we additionally
    verify that no write cross-references target the address.
    """
    seg = ida_segment.getseg(ea)
    if seg is None:
        return False

    seg_name: str = ida_segment.get_segm_name(seg)

    # Unconditionally constant sections.
    if seg_name in _CONST_SECTION_NAMES:
        return True

    # Writable data sections -- conservative check via xrefs.
    if seg_name in _DATA_SECTION_NAMES:
        xb = ida_xref.xrefblk_t()
        ok = xb.first_to(ea, ida_xref.XREF_ALL)
        while ok:
            if xb.type == ida_xref.dr_W:
                return False
            ok = xb.next_to()
        return True

    # Fallback: check segment permissions.
    if (seg.perm & idaapi.SEGPERM_WRITE) == 0:
        return True

    return False


def _read_constant_value(ea: int, size: int) -> int:
    """Read *size* bytes from the IDB at *ea* and return as an integer."""
    if size == 1:
        return idaapi.get_byte(ea)
    if size == 2:
        return idaapi.get_word(ea)
    if size == 4:
        return idaapi.get_dword(ea)
    if size == 8:
        return idaapi.get_qword(ea)
    # Fallback for unusual sizes -- read raw bytes, little-endian.
    raw = ida_bytes.get_bytes(ea, size)
    if raw is None:
        return 0
    return int.from_bytes(raw, byteorder="little")


def _looks_like_pointer(value: int, size: int) -> bool:
    """Heuristic: return ``True`` if *value* resembles a pointer.

    * Values smaller than 4 bytes cannot be pointers.
    * Zero is ambiguous (NULL) but also a common constant -- keep it.
    * If the value falls inside any known segment, treat it as a pointer.
    * If ``imagebase + value`` falls inside any known segment, treat it as a
      rebased RVA-style pointer (common in PE binaries).
    * Common 64-bit ASLR ranges are also flagged.
    """
    if size < 4:
        return False
    if value == 0:
        return False

    # IDA's ida_segment.getseg() expects an ea_t-sized integer. Some rebased
    # values can overflow ea_t (or be non-int-like from SWIG wrappers), which
    # raises TypeError in callbacks. Coerce defensively and treat invalid EAs
    # as "not a pointer-like segment hit".
    try:
        ea_mask = int(idaapi.BADADDR)
    except Exception:
        ea_mask = 0xFFFFFFFFFFFFFFFF

    def _safe_getseg(addr: int):
        try:
            ea = int(addr)
        except Exception:
            return None
        if ea < 0:
            return None
        if ea_mask > 0:
            ea &= ea_mask
        try:
            return ida_segment.getseg(ea)
        except (TypeError, OverflowError, ValueError):
            return None

    # Falls inside a known segment?
    if _safe_getseg(value) is not None:
        return True

    # PE binaries often store RVAs (imagebase-relative offsets) instead of
    # absolute addresses.  If rebasing the value lands in a loaded segment, it
    # is very likely address-like and should not be folded into an integer.
    try:
        imagebase = idaapi.get_imagebase()
    except Exception:
        imagebase = idaapi.BADADDR
    if imagebase not in (0, idaapi.BADADDR):
        rebased = imagebase + value
        if _safe_getseg(rebased) is not None:
            return True

    # 64-bit heuristics for common user-space ranges.
    if size == 8:
        # macOS/iOS ASLR range (0x1XX_XXXX_XXXX)
        if (value >> 40) == 0x1:
            return True
        # Linux typical user-space (0x5X_XXXX_XXXX, 0x7X_XXXX_XXXX)
        top_nibble = value >> 44
        if top_nibble in (0x5, 0x7):
            return True

    return False


def _replace_with_immediate(
    insn: ida_hexrays.minsn_t, value: int, size: int
) -> None:
    """Rewrite *insn* as ``m_mov dst, #value``.

    For ``m_ldx`` instructions the segment (``l``) and address (``r``)
    operands are collapsed: the instruction becomes a plain ``m_mov``
    with an immediate source.
    """
    insn.opcode = ida_hexrays.m_mov
    insn.l.make_number(value, size)
    insn.r.erase()
