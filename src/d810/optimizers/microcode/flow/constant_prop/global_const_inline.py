"""Global constant inlining for microcode flow optimization.

Replaces loads from known-constant global addresses with their immediate values.
When a microcode instruction loads a value from a read-only global address
(``mop_v`` operand referencing ``.rodata``, ``.rdata``, ``__const``, etc.),
this rule replaces the load with the constant value directly.

This is a *flow-level* rule (operates per-block) complementing the
instruction-level ``FoldReadonlyDataRule`` peephole.  While the peephole handles
``ldx`` displacement patterns via ``mop_S``/``mop_b``, this rule targets
``mop_v`` (global variable) operands in ``mov`` and ``ldx`` instructions.

Algorithm (ported from the copycat project ``global_const_handler_t``):

1. **Detect** -- find ``m_mov`` / ``m_ldx`` instructions with ``mop_v``
   operands referencing global addresses.
2. **Validate** -- ask the shared, architecture-neutral global-constness
   oracle to classify the concrete data item and all known write evidence.
3. **Read** -- fetch the constant value from the IDB.
4. **Filter** -- skip values that look like pointers (fall inside a known
   segment or match common ASLR ranges).
5. **Replace** -- rewrite the instruction as ``m_mov dst, #imm`` (erasing
   the segment operand for ``ldx``).
"""

from __future__ import annotations

from d810.core.typing import Callable, Optional

import ida_bytes
import ida_hexrays
import ida_segment
import idaapi

from d810.analyses.value_flow.global_constness import GlobalConstPolicy
from d810.backends.hexrays.evidence.global_constness import (
    decide_hexrays_global_read,
)
from d810.core import getLogger
from d810.optimizers.microcode.constant_materialization import (
    replace_operand_with_immediate,
    rewrite_load_as_immediate_move,
)
from d810.optimizers.microcode.flow.handler import FlowOptimizationRule
from d810.optimizers.microcode.handler import ConfigParam

logger = getLogger(__name__)

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
    CONFIG_SCHEMA = FlowOptimizationRule.CONFIG_SCHEMA + (
        ConfigParam(
            "fold_writable_constants",
            bool,
            False,
            "Fold data items with no direct write evidence",
        ),
        ConfigParam(
            "allow_executable_readonly",
            bool,
            False,
            "VERY DANGEROUS: treat executable read-only memory as constant data",
        ),
    )

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
        self._fold_writable_constants = False
        self._allow_executable = False

    def configure(self, kwargs: dict) -> None:
        """Configure compatibility options that feed the shared oracle."""
        super().configure(kwargs)
        self._fold_writable_constants = kwargs.get("fold_writable_constants", False)
        self._allow_executable = kwargs.get("allow_executable_readonly", False)
        if self._allow_executable:
            logger.warning(
                "VERY DANGEROUS constant-folding override enabled: "
                "executable read-only memory may be treated as data"
            )

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

    def _get_global_constant(self, ea: int, size: int) -> Optional[int]:
        """Return the constant value at *ea* if it is a safe, non-pointer global.

        Returns ``None`` if the address is not a safe constant to inline.
        """
        if ea == idaapi.BADADDR or size <= 0 or size > _MAX_INLINE_SIZE:
            return None
        policy = (
            GlobalConstPolicy.AGGRESSIVE_NO_DIRECT_WRITES
            if self._fold_writable_constants
            else GlobalConstPolicy.STRICT
        )
        decision = decide_hexrays_global_read(
            ea,
            size,
            policy=policy,
            allow_executable_readonly=self._allow_executable,
        )
        if not decision.can_inline_read or decision.value is None:
            return None
        if _looks_like_pointer(decision.value, size):
            return None
        return decision.value

    def _replace_nested_globals(self, mop: ida_hexrays.mop_t) -> int:
        """Recursively replace mop_v globals in operand tree. Returns count of replacements."""
        count = 0
        if mop is None or mop.t == ida_hexrays.mop_z:
            return 0

        if mop.t == ida_hexrays.mop_v:
            val = self._get_global_constant(mop.g, mop.size)
            if val is not None:
                replace_operand_with_immediate(mop, val, mop.size)
                logger.info(
                    "Inlined nested global at 0x%X -> 0x%X (size=%d)",
                    mop.g,
                    val,
                    mop.size,
                )
                return 1

        # Recurse into sub-operands for mop_d (inline instruction)
        if mop.t == ida_hexrays.mop_d:
            sub = mop.d  # the sub-instruction
            if sub is not None:
                if sub.l.t != ida_hexrays.mop_z:
                    count += self._replace_nested_globals(sub.l)
                if sub.r.t != ida_hexrays.mop_z:
                    count += self._replace_nested_globals(sub.r)

        return count

    def _try_inline_globals(
        self, blk: ida_hexrays.mblock_t, insn: ida_hexrays.minsn_t
    ) -> int:
        """Check all operands of *insn* for inlinable global references.

        Returns the number of replacements performed (0 or more).
        """
        count: int = 0

        if insn.opcode in (ida_hexrays.m_mov, ida_hexrays.m_ldx):
            ea: int = idaapi.BADADDR
            size: int = 0

            # -- Pattern 1: mov dst, gv  (left operand is mop_v) ----------- #
            if insn.opcode == ida_hexrays.m_mov and insn.l.t == ida_hexrays.mop_v:
                ea = insn.l.g
                size = insn.l.size

            # -- Pattern 2: ldx dst, seg, gv  (right operand is mop_v) ----- #
            elif insn.opcode == ida_hexrays.m_ldx:
                if insn.r.t == ida_hexrays.mop_v:
                    ea = insn.r.g
                    size = insn.d.size

            if ea != idaapi.BADADDR and size > 0:
                value = self._get_global_constant(ea, size)
                if value is not None:
                    rewrite_load_as_immediate_move(insn, value, size)
                    logger.info(
                        "Inlined global constant at 0x%X -> 0x%X (size=%d)",
                        ea,
                        value,
                        size,
                    )
                    count += 1

        # Recursively search for nested globals in all operands
        if insn.l.t != ida_hexrays.mop_z:
            count += self._replace_nested_globals(insn.l)
        if insn.r.t != ida_hexrays.mop_z:
            count += self._replace_nested_globals(insn.r)
        if insn.d.t != ida_hexrays.mop_z:
            count += self._replace_nested_globals(insn.d)

        return count


# ====================================================================== #
# Module-level helpers (also usable independently in tests)               #
# ====================================================================== #


def _is_constant_global(ea: int) -> bool:
    """Compatibility predicate backed by the shared constness oracle."""
    return decide_hexrays_global_read(
        ea,
        1,
        policy=GlobalConstPolicy.AGGRESSIVE_NO_DIRECT_WRITES,
    ).can_inline_read


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


class _PointerHeuristicContext:
    """Input shared by pointer-likeness heuristic handlers."""

    def __init__(
        self,
        value: int,
        size: int,
        badaddr: int,
        imagebase: int,
        safe_getseg: Callable[[int], Optional[object]],
    ) -> None:
        self.value = value
        self.size = size
        self.badaddr = badaddr
        self.imagebase = imagebase
        self.safe_getseg = safe_getseg


class _PointerHeuristicHandler:
    """Chain-of-responsibility handler for pointer heuristics.

    Each handler returns:
    - ``True``: value is pointer-like (stop chain)
    - ``False``: value is definitely not pointer-like (stop chain)
    - ``None``: no decision, continue with next handler
    """

    def __init__(
        self, next_handler: Optional["_PointerHeuristicHandler"] = None
    ) -> None:
        self._next = next_handler

    def handle(self, ctx: _PointerHeuristicContext) -> bool:
        decision = self._check(ctx)
        if decision is not None:
            return decision
        if self._next is None:
            return False
        return self._next.handle(ctx)

    def _check(self, ctx: _PointerHeuristicContext) -> Optional[bool]:
        raise NotImplementedError


class _MinimumPointerSizeHandler(_PointerHeuristicHandler):
    def _check(self, ctx: _PointerHeuristicContext) -> Optional[bool]:
        return False if ctx.size < 4 else None


class _ZeroValueHandler(_PointerHeuristicHandler):
    def _check(self, ctx: _PointerHeuristicContext) -> Optional[bool]:
        return False if ctx.value == 0 else None


class _BadaddrSentinelHandler(_PointerHeuristicHandler):
    def _check(self, ctx: _PointerHeuristicContext) -> Optional[bool]:
        width_mask = (1 << (ctx.size * 8)) - 1
        if (ctx.value & width_mask) == (ctx.badaddr & width_mask):
            return True
        return None


class _SegmentHitHandler(_PointerHeuristicHandler):
    def _check(self, ctx: _PointerHeuristicContext) -> Optional[bool]:
        if ctx.safe_getseg(ctx.value) is not None:
            return True
        return None


class _RebasedSegmentHitHandler(_PointerHeuristicHandler):
    # Only treat values below this threshold as potential RVAs/pointers.
    # Large values like 0x76DFE728 are obfuscation constants, not pointers.
    _MAX_RVA_VALUE: int = 0x10000000  # 256 MB

    def _check(self, ctx: _PointerHeuristicContext) -> Optional[bool]:
        if ctx.imagebase in (0, ctx.badaddr):
            return None
        # Only treat as RVA/pointer if value is below the threshold
        if ctx.value >= self._MAX_RVA_VALUE:
            return None
        rebased = ctx.imagebase + ctx.value
        if ctx.safe_getseg(rebased) is not None:
            return True
        return None


class _AslrRangeHandler(_PointerHeuristicHandler):
    def _check(self, ctx: _PointerHeuristicContext) -> Optional[bool]:
        if ctx.size != 8:
            return None
        # macOS/iOS ASLR range (0x1XX_XXXX_XXXX)
        if (ctx.value >> 40) == 0x1:
            return True
        # Linux typical user-space (0x5X_XXXX_XXXX, 0x7X_XXXX_XXXX)
        top_nibble = ctx.value >> 44
        if top_nibble in (0x5, 0x7):
            return True
        return None


def _get_badaddr_value() -> int:
    try:
        return int(idaapi.BADADDR)
    except Exception:
        return 0xFFFFFFFFFFFFFFFF


def _get_imagebase_value(badaddr: int) -> int:
    try:
        return int(idaapi.get_imagebase())
    except Exception:
        return badaddr


def _build_safe_getseg(ea_mask: int) -> Callable[[int], Optional[object]]:
    def _safe_getseg(addr: int) -> Optional[object]:
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

    return _safe_getseg


def _build_pointer_heuristic_chain() -> _PointerHeuristicHandler:
    return _MinimumPointerSizeHandler(
        _ZeroValueHandler(
            _BadaddrSentinelHandler(
                _SegmentHitHandler(
                    _RebasedSegmentHitHandler(
                        _AslrRangeHandler(),
                    )
                )
            )
        )
    )


_POINTER_HEURISTIC_CHAIN = _build_pointer_heuristic_chain()


def _looks_like_pointer(value: int, size: int) -> bool:
    """Heuristic: return ``True`` if *value* resembles a pointer.

    * Values smaller than 4 bytes cannot be pointers.
    * Zero is ambiguous (NULL) but also a common constant -- keep it.
    * If the value falls inside any known segment, treat it as a pointer.
    * If ``imagebase + value`` falls inside any known segment, treat it as a
      rebased RVA-style pointer (common in PE binaries).
    * Common 64-bit ASLR ranges are also flagged.
    * ``BADADDR``-like all-ones sentinels are treated as pointer-like to avoid
      folding unresolved/invalid addresses into bogus call targets.
    """
    badaddr = _get_badaddr_value()
    ctx = _PointerHeuristicContext(
        value=value,
        size=size,
        badaddr=badaddr,
        imagebase=_get_imagebase_value(badaddr),
        safe_getseg=_build_safe_getseg(badaddr),
    )
    return _POINTER_HEURISTIC_CHAIN.handle(ctx)


def _replace_with_immediate(insn: ida_hexrays.minsn_t, value: int, size: int) -> None:
    """Compatibility wrapper around the canonical materializer."""
    rewrite_load_as_immediate_move(insn, value, size)
