"""Indirect Call Resolution -- the copycat project Phase 6.

Resolves obfuscated indirect calls (``m_icall``, ``m_call`` with computed
targets) by analysing encoded call tables, decoding entries, and replacing
with direct calls.

The algorithm is ported from the copycat project's ``indirect_call.cpp`` handler and
adapted to the d810-ng FlowOptimizationRule framework.

Detection flow
--------------
1. Scan **all** instructions in the block for ``m_icall`` or ``m_call``
   with computed targets (``mop_r`` or ``mop_d``).
2. Trace ``m_ldx`` instructions to locate the global call table.  Fall
   back to the Hikari ``m_sub`` pattern: a large constant subtracted
   from a table load, preceded by ``m_mov`` with ``mop_a`` pointing to
   a global table.
3. Multi-strategy target resolution: track register values via ``m_mov``
   of immediates, track stack variable values, extract LDX index from
   stack variables / registers / immediates, detect ``add(base, mul(index,
   8))`` patterns, and use ``find_xor_with_globals()`` for encrypted
   index/offset.
4. Compute target: ``target = table[index * entry_size] - offset``,
   validated against code flags.
5. Replace indirect call: update ``mcallinfo_t`` or create a new one,
   convert ``m_icall`` to ``m_call`` with ``mop_v`` target.  Fall back
   to annotation if target validation fails.

Key differences from Phase 5 (indirect branches)
-------------------------------------------------
- Phase 5 only checks ``blk.tail`` for ``m_ijmp``.  Phase 6 iterates
  **all** instructions for ``m_icall`` / ``m_call``.
- Phase 6 manipulates ``mcallinfo_t`` and requires ``MMAT_CALLS``
  maturity or later.
- Phase 6 has a ``m_sub`` large-constant pattern specific to Hikari
  call obfuscation.
- No CFG edge modification is needed -- calls do not change control
  flow structure.
"""
from __future__ import annotations

from d810.core.typing import TYPE_CHECKING, Dict, List, Optional, Tuple

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_name
import ida_typeinf
import idaapi
from idaapi import BADADDR

if TYPE_CHECKING:
    from ida_hexrays import mblock_t, minsn_t

from d810.core import getLogger
from d810.hexrays.table_utils import (
    find_table_reference,
    find_xor_with_globals,
    get_func_safe,
    is_valid_database_ea,
    read_global_value,
    validate_code_target,
)

from d810.optimizers.microcode.handler import ConfigParam
from d810.optimizers.microcode.flow.handler import FlowOptimizationRule

logger = getLogger("D810.optimizer")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_TABLE_ENTRIES: int = 512
"""Maximum number of table entries to consider."""

DEFAULT_ENTRY_SIZE: int = 8
"""Default size (bytes) of each call table entry."""

MIN_SUB_OFFSET: int = 0x10000
"""Minimum value for the Hikari sub-offset pattern."""

MAX_SUB_OFFSET: int = 0x1000000
"""Maximum value for the Hikari sub-offset pattern."""


# ---------------------------------------------------------------------------
# IndirectCallResolver
# ---------------------------------------------------------------------------
class IndirectCallResolver(FlowOptimizationRule):
    """Resolve obfuscated indirect calls by analysing encoded call tables.

    This rule detects ``m_icall`` and ``m_call`` instructions with
    computed targets, locates the backing call table, computes the
    resolved target address, and converts the instruction to a direct
    ``m_call`` with ``mop_v`` target.

    Configuration keys
    ------------------
    table_entry_size : int
        Size of each table entry in bytes (default ``8``).
    """

    NAME = "IndirectCallResolver"
    DESCRIPTION = "Resolves obfuscated indirect calls by analysing encoded call tables"
    CATEGORY = "Indirect Calls"
    # IndirectCallResolver only modifies instruction content (opcodes and
    # operands) -- it never adds/removes CFG edges or blocks.  Therefore it
    # is safe at any maturity and does not need DeferredGraphModifier.
    USES_DEFERRED_CFG = True
    SAFE_MATURITIES: list[int] = []  # Populated after class definition when IDA is available

    # Config
    MAX_TABLE_ENTRIES = MAX_TABLE_ENTRIES
    DEFAULT_ENTRY_SIZE = DEFAULT_ENTRY_SIZE
    MIN_SUB_OFFSET = MIN_SUB_OFFSET
    MAX_SUB_OFFSET = MAX_SUB_OFFSET

    def __init__(self) -> None:
        super().__init__()
        self.table_entry_size: int = DEFAULT_ENTRY_SIZE
        if True:
            self.maturities = [
                ida_hexrays.MMAT_LOCOPT,
                ida_hexrays.MMAT_CALLS,
                ida_hexrays.MMAT_GLBOPT1,
            ]

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------
    def configure(self, kwargs: dict) -> None:  # type: ignore[override]
        super().configure(kwargs)
        if "table_entry_size" in self.config:
            self.table_entry_size = int(self.config["table_entry_size"])

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------
    def optimize(self, blk: "mblock_t") -> int:
        """Scan all instructions in *blk* for indirect calls and resolve them.

        Returns the number of resolved calls.
        """
        count = 0
        insn = blk.head
        while insn is not None:
            if insn.opcode in (ida_hexrays.m_icall, ida_hexrays.m_call):
                logger.info(
                    "IndirectCallResolver: inspect call ea=%#x op=%d l.t=%d r.t=%d d.t=%d",
                    insn.ea,
                    insn.opcode,
                    insn.l.t,
                    insn.r.t,
                    insn.d.t,
                )
            if self._is_indirect_call(insn):
                if self._resolve_indirect_call(blk, insn):
                    count += 1
            insn = insn.next
        return count

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------
    @staticmethod
    def _is_indirect_call(insn: "minsn_t") -> bool:
        """Return True if *insn* is an indirect call with a computed target.

        Detects:
        - ``m_icall`` instructions (always indirect)
        - ``m_call`` with ``mop_r`` target (register)
        - ``m_call`` with ``mop_d`` target (result of computation)

        Direct calls (``m_call`` with ``mop_v`` target) are skipped.
        """
        if insn.opcode == ida_hexrays.m_icall:
            return True

        if insn.opcode == ida_hexrays.m_call:
            if insn.l.t in (ida_hexrays.mop_r, ida_hexrays.mop_d):
                return True

        return False

    # ------------------------------------------------------------------
    # Orchestrator
    # ------------------------------------------------------------------
    def _resolve_indirect_call(
        self, blk: "mblock_t", insn: "minsn_t"
    ) -> bool:
        """Orchestrate table finding, target computation, and replacement.

        Returns True if the call was successfully resolved and replaced.
        """
        logger.debug(
            "IndirectCallResolver: analysing indirect call at %#x in block %d",
            insn.ea, blk.serial,
        )

        # Fast path: many optimized samples fold table lookup/sub-offset into a
        # single callee expression (e.g., table_const[1] - 0x200000). Resolve
        # that expression directly before table/index tracing.
        direct_target = self._resolve_folded_callee_target(blk, insn)
        if direct_target is not None:
            logger.debug(
                "IndirectCallResolver: folded callee resolved %#x at %#x",
                direct_target, insn.ea,
            )
            if not is_valid_database_ea(direct_target):
                return False
            func = ida_funcs.get_func(direct_target)
            if func is None or func.start_ea != direct_target:
                flags = ida_bytes.get_flags(direct_target)
                if ida_bytes.is_code(flags):
                    try:
                        ida_funcs.add_func(direct_target)
                        func = ida_funcs.get_func(direct_target)
                    except Exception:
                        func = None
            if func is None or func.start_ea != direct_target:
                self._annotate_call(insn, direct_target)
                return False
            return self._replace_call(insn, direct_target, blk)

        # Step 1: Find the call table
        table_ea = self._find_call_table(blk, insn)
        if table_ea is None:
            logger.debug(
                "IndirectCallResolver: no call table found for insn at %#x",
                insn.ea,
            )
            return False

        logger.debug(
            "IndirectCallResolver: table at %#x for insn at %#x",
            table_ea, insn.ea,
        )

        # Step 2: Trace call target (index + offset)
        result = self._trace_call_target(blk, insn, table_ea)
        if result is None:
            logger.debug(
                "IndirectCallResolver: could not trace target for insn at %#x",
                insn.ea,
            )
            return False

        index, offset = result
        logger.debug(
            "IndirectCallResolver: index=%d, offset=%d for insn at %#x",
            index, offset, insn.ea,
        )

        # Step 3: Compute the resolved target
        target_ea = self._compute_target(
            table_ea, index, offset, self.table_entry_size,
        )
        if target_ea is None:
            logger.debug(
                "IndirectCallResolver: target computation failed for insn at %#x",
                insn.ea,
            )
            return False

        logger.debug(
            "IndirectCallResolver: computed target %#x for insn at %#x",
            target_ea, insn.ea,
        )

        # Step 4: Validate EA is in database range and is a function start
        if not is_valid_database_ea(target_ea):
            logger.info("target %#x outside database EA range, skipping", target_ea)
            return False

        func = ida_funcs.get_func(target_ea)
        is_func_start = func is not None and func.start_ea == target_ea

        if not is_func_start:
            # Try to create a function at the target if it points to code
            flags = ida_bytes.get_flags(target_ea)
            if ida_bytes.is_code(flags):
                try:
                    ida_funcs.add_func(target_ea)
                    func = ida_funcs.get_func(target_ea)
                    is_func_start = (
                        func is not None and func.start_ea == target_ea
                    )
                except Exception:
                    pass

            if not is_func_start:
                logger.info(
                    "IndirectCallResolver: target %#x is not a function start, "
                    "annotating instead",
                    target_ea,
                )
                self._annotate_call(insn, target_ea)
                return False

        # Step 5: Replace the indirect call with a direct call
        return self._replace_call(insn, target_ea, blk)

    # ------------------------------------------------------------------
    # Folded-callee fast path
    # ------------------------------------------------------------------
    def _resolve_folded_callee_target(
        self,
        blk: "mblock_t",
        insn: "minsn_t",
    ) -> Optional[int]:
        """Resolve folded call-target expressions to a concrete EA.

        This handles callee forms where Hex-Rays already folded table/index
        logic into expressions rooted at globals and constants, while still
        leaving an indirect call in microcode.
        """
        reg_values: Dict[int, int] = {}
        scan = blk.head
        while scan is not None and scan is not insn:
            self._update_reg_value_map(scan, reg_values)
            scan = scan.next

        # In m_icall, the computed target is commonly carried in r; in m_call
        # variants it is usually in l. Try both and keep the first valid EA.
        candidates = [insn.r, insn.l] if insn.opcode == ida_hexrays.m_icall else [insn.l, insn.r]
        for mop in candidates:
            target = self._eval_operand_to_ea(mop, reg_values)
            if target is not None and is_valid_database_ea(target):
                return target
        return None

    @staticmethod
    def _update_reg_value_map(insn: "minsn_t", reg_values: Dict[int, int]) -> None:
        """Track simple register definitions with evaluable constant values."""
        if insn.d.t != ida_hexrays.mop_r:
            return
        value = IndirectCallResolver._eval_insn_to_ea(insn, reg_values)

        if value is not None:
            reg_values[insn.d.r] = value
        else:
            reg_values.pop(insn.d.r, None)

    @staticmethod
    def _eval_operand_to_ea(
        mop,
        reg_values: Dict[int, int],
    ) -> Optional[int]:
        """Best-effort evaluator for microcode operands into 64-bit constants."""
        if mop is None:
            return None

        t = mop.t
        if t == ida_hexrays.mop_n:
            return int(mop.nnn.value) & 0xFFFFFFFFFFFFFFFF
        if t == ida_hexrays.mop_r:
            return reg_values.get(mop.r)
        if t == ida_hexrays.mop_v:
            return read_global_value(mop.g, 8)
        if t == ida_hexrays.mop_a and mop.a is not None:
            if mop.a.t == ida_hexrays.mop_v:
                return read_global_value(mop.a.g, 8)
            return IndirectCallResolver._eval_operand_to_ea(mop.a, reg_values)
        if t == ida_hexrays.mop_d and mop.d is not None:
            return IndirectCallResolver._eval_insn_to_ea(mop.d, reg_values)
        return None

    @staticmethod
    def _eval_insn_to_ea(
        insn: "minsn_t",
        reg_values: Dict[int, int],
    ) -> Optional[int]:
        """Evaluate a tiny arithmetic subset used by folded call targets."""
        if insn is None:
            return None

        op = insn.opcode
        if op == ida_hexrays.m_mov:
            return IndirectCallResolver._eval_operand_to_ea(insn.l, reg_values)
        if op in (ida_hexrays.m_add, ida_hexrays.m_sub, ida_hexrays.m_xor):
            left = IndirectCallResolver._eval_operand_to_ea(insn.l, reg_values)
            right = IndirectCallResolver._eval_operand_to_ea(insn.r, reg_values)
            if left is None or right is None:
                return None
            if op == ida_hexrays.m_add:
                return (left + right) & 0xFFFFFFFFFFFFFFFF
            if op == ida_hexrays.m_sub:
                return (left - right) & 0xFFFFFFFFFFFFFFFF
            return (left ^ right) & 0xFFFFFFFFFFFFFFFF
        if op == ida_hexrays.m_ldx:
            base = IndirectCallResolver._eval_operand_to_ea(insn.l, reg_values)
            offs = IndirectCallResolver._eval_operand_to_ea(insn.r, reg_values)
            if base is None or offs is None:
                return None
            entry_addr = (base + offs) & 0xFFFFFFFFFFFFFFFF
            return read_global_value(entry_addr, 8)
        return None

    # ------------------------------------------------------------------
    # Table discovery
    # ------------------------------------------------------------------
    def _find_call_table(
        self, blk: "mblock_t", insn: "minsn_t"
    ) -> Optional[int]:
        """Locate the call table EA via ``m_ldx`` or Hikari sub pattern.

        Strategy 1: Reuse the shared ``find_table_reference`` which scans
        for ``m_ldx`` with global operands.

        Strategy 2 (Hikari): Walk backwards from *insn* looking for
        ``m_sub`` with a large constant (MIN_SUB_OFFSET < c < MAX_SUB_OFFSET),
        preceded by ``m_mov`` with ``mop_a`` to a global table.
        """
        # Strategy 1: m_ldx-based table reference
        table_ea = find_table_reference(blk)
        if table_ea is not None:
            return table_ea

        # Strategy 2: Hikari sub pattern -- scan backwards from insn
        prev = blk.head
        while prev is not None and prev is not insn:
            if (
                prev.opcode == ida_hexrays.m_mov
                and prev.l.t == ida_hexrays.mop_a
                and prev.l.a is not None
                and prev.l.a.t == ida_hexrays.mop_v
            ):
                global_ea = prev.l.a.g
                # Validate that the first entry of this table looks like code
                first_entry = read_global_value(global_ea, 8)
                if first_entry is not None and first_entry != 0:
                    if validate_code_target(first_entry):
                        return global_ea

            prev = prev.next

        return None

    # ------------------------------------------------------------------
    # Target tracing
    # ------------------------------------------------------------------
    def _trace_call_target(
        self,
        blk: "mblock_t",
        insn: "minsn_t",
        table_ea: int,
    ) -> Optional[Tuple[int, int]]:
        """Multi-strategy target resolution.

        Returns ``(index, offset)`` or ``None`` if resolution fails.

        Strategies:
        - Track register values via ``m_mov`` of immediates.
        - Track stack variable values.
        - Extract LDX index from stack variables, registers, or immediates.
        - Extract SUB offset (large constants in ``m_sub``).
        - Detect ``add(base, mul(index, 8))`` pattern for index.
        - Use ``find_xor_with_globals()`` for encrypted index/offset.
        """
        reg_values: Dict[int, int] = {}
        stkvar_values: Dict[int, int] = {}
        resolved_index: int = -1
        resolved_offset: int = 0

        # Single-pass scan of all instructions in the block
        scan = blk.head
        while scan is not None:
            opcode = scan.opcode

            # -- Track mov of immediate to register -------------------------
            if opcode == ida_hexrays.m_mov and scan.d.t == ida_hexrays.mop_r:
                if scan.l.t == ida_hexrays.mop_n:
                    reg_values[scan.d.r] = scan.l.nnn.value

            # -- Track mov of immediate to stack variable -------------------
            if (
                opcode == ida_hexrays.m_mov
                and scan.d.t == ida_hexrays.mop_S
                and scan.l.t == ida_hexrays.mop_n
            ):
                stkvar_values[scan.d.s.off] = scan.l.nnn.value

            # -- Track mov of register to stack variable --------------------
            if (
                opcode == ida_hexrays.m_mov
                and scan.d.t == ida_hexrays.mop_S
                and scan.l.t == ida_hexrays.mop_r
            ):
                if scan.l.r in reg_values:
                    stkvar_values[scan.d.s.off] = reg_values[scan.l.r]

            # -- Extract index from m_ldx -----------------------------------
            if opcode == ida_hexrays.m_ldx:
                idx_val = self._extract_ldx_index(scan, reg_values, stkvar_values)
                if idx_val is not None and idx_val >= 0:
                    resolved_index = idx_val

            # -- Extract offset from m_sub ----------------------------------
            sub_offset = self._extract_sub_offset_from_insn(scan)
            if sub_offset > resolved_offset:
                resolved_offset = sub_offset

            # -- Detect add(base, mul(index, 8)) pattern --------------------
            if opcode == ida_hexrays.m_add:
                mul_idx = self._extract_mul8_index(scan, reg_values)
                if mul_idx is not None and mul_idx >= 0:
                    resolved_index = mul_idx

            scan = scan.next

        # Fallback: XOR-with-globals analysis
        if resolved_index < 0:
            xor_results = find_xor_with_globals(blk)
            for xr in xor_results:
                if xr.is_negated and resolved_offset == 0:
                    resolved_offset = xr.xor_key
                elif xr.xor_key >= 0 and xr.xor_key < 10000 and resolved_index < 0:
                    resolved_index = xr.xor_key

        # TODO(phase6): pre-computed XOR index brute force

        if resolved_index >= 0:
            return (resolved_index, resolved_offset)
        return None

    # ------------------------------------------------------------------
    # Sub-offset extraction
    # ------------------------------------------------------------------
    def _extract_sub_offset(
        self, blk: "mblock_t", insn: "minsn_t"
    ) -> int:
        """Find the largest large constant in ``m_sub`` instructions in the block.

        Returns the offset value or 0 if none found.  A "large constant"
        is defined as ``MIN_SUB_OFFSET < value < MAX_SUB_OFFSET``.
        """
        result = 0
        scan = blk.head
        while scan is not None:
            val = self._extract_sub_offset_from_insn(scan)
            if val > result:
                result = val
            scan = scan.next
        return result

    @staticmethod
    def _extract_sub_offset_from_insn(insn: "minsn_t") -> int:
        """Extract a large constant from a single ``m_sub`` instruction.

        Returns the constant value if it matches the Hikari pattern
        (MIN_SUB_OFFSET < value < MAX_SUB_OFFSET), otherwise 0.
        """
        if insn.opcode != ida_hexrays.m_sub:
            return 0

        if insn.r.t != ida_hexrays.mop_n:
            return 0

        val = insn.r.nnn.value
        if MIN_SUB_OFFSET < val < MAX_SUB_OFFSET:
            return val
        return 0

    # ------------------------------------------------------------------
    # LDX index extraction
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_ldx_index(
        insn: "minsn_t",
        reg_values: Dict[int, int],
        stkvar_values: Dict[int, int],
    ) -> Optional[int]:
        """Extract the table index from an ``m_ldx`` instruction.

        Checks the offset/index operand for:
        - Stack variable with tracked value (divided by 8)
        - Register with tracked value (divided by 8)
        - Immediate constant (divided by 8)

        Returns the index or ``None``.
        """
        if insn.opcode != ida_hexrays.m_ldx:
            return None

        # Check stack variable operand
        if insn.r.t == ida_hexrays.mop_S:
            stk_off = insn.r.s.off
            if stk_off in stkvar_values:
                idx_val = stkvar_values[stk_off]
                if idx_val % 8 == 0 and 0 < idx_val < 100000:
                    return idx_val // 8

        # Check register operand
        if insn.r.t == ida_hexrays.mop_r:
            if insn.r.r in reg_values:
                idx_val = reg_values[insn.r.r]
                if idx_val % 8 == 0 and 0 < idx_val < 100000:
                    return idx_val // 8

        # Check immediate operand
        if insn.r.t == ida_hexrays.mop_n:
            idx_val = insn.r.nnn.value
            if idx_val % 8 == 0 and idx_val >= 0:
                return idx_val // 8

        return None

    # ------------------------------------------------------------------
    # mul(index, 8) pattern detection
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_mul8_index(
        insn: "minsn_t",
        reg_values: Dict[int, int],
    ) -> Optional[int]:
        """Detect ``add(base, mul(index, 8))`` pattern and extract index.

        Returns the index value or ``None``.
        """
        def _check_mul8(op) -> Optional[int]:
            if (
                op.t == ida_hexrays.mop_d
                and op.d is not None
                and op.d.opcode == ida_hexrays.m_mul
            ):
                mul_insn = op.d
                # Check mul(X, 8) -- X on left, 8 on right
                if (
                    mul_insn.r.t == ida_hexrays.mop_n
                    and mul_insn.r.nnn.value == 8
                ):
                    if mul_insn.l.t == ida_hexrays.mop_n:
                        return mul_insn.l.nnn.value
                    if (
                        mul_insn.l.t == ida_hexrays.mop_r
                        and mul_insn.l.r in reg_values
                    ):
                        return reg_values[mul_insn.l.r]
                # Check mul(8, X) -- 8 on left, X on right
                if (
                    mul_insn.l.t == ida_hexrays.mop_n
                    and mul_insn.l.nnn.value == 8
                ):
                    if mul_insn.r.t == ida_hexrays.mop_n:
                        return mul_insn.r.nnn.value
                    if (
                        mul_insn.r.t == ida_hexrays.mop_r
                        and mul_insn.r.r in reg_values
                    ):
                        return reg_values[mul_insn.r.r]
            return None

        idx = _check_mul8(insn.l)
        if idx is None:
            idx = _check_mul8(insn.r)

        if idx is not None and 0 <= idx < 10000:
            return idx
        return None

    # ------------------------------------------------------------------
    # Target computation
    # ------------------------------------------------------------------
    @staticmethod
    def _compute_target(
        table_ea: int,
        index: int,
        offset: int,
        entry_size: int = DEFAULT_ENTRY_SIZE,
    ) -> Optional[int]:
        """Read ``table[index]`` and subtract *offset*.

        Returns the computed target EA, or ``None`` if the read fails or
        the result does not point to valid code.
        """
        if table_ea == BADADDR or index < 0:
            return None

        entry_addr = table_ea + index * entry_size
        entry_val = read_global_value(entry_addr, entry_size)
        if entry_val is None:
            logger.debug(
                "IndirectCallResolver: failed to read table entry at %#x",
                entry_addr,
            )
            return None

        target = entry_val - offset
        # Mask to 64-bit unsigned
        target = target & 0xFFFFFFFFFFFFFFFF

        logger.debug(
            "IndirectCallResolver: table[%d] = %#x, - %#x = %#x",
            index, entry_val, offset, target,
        )

        # Validate target
        if validate_code_target(target):
            return target

        # Also accept if it is within a known function
        if True:
            func = get_func_safe(target)
            if func is not None:
                return target

        logger.debug(
            "IndirectCallResolver: target %#x is not valid code", target,
        )
        return None

    # ------------------------------------------------------------------
    # Call replacement
    # ------------------------------------------------------------------
    def _replace_call(
        self,
        insn: "minsn_t",
        target_ea: int,
        blk: "mblock_t",
    ) -> bool:
        """Replace an indirect call with a direct call to *target_ea*.

        Handles two cases:
        - **Has mcallinfo** (``d.t == mop_f``): Update ``mcallinfo_t.callee``,
          set function type, convert ``m_icall`` to ``m_call`` with ``mop_v``
          target.
        - **Unknown call** (``d.empty()``): Create ``mcallinfo_t``, set
          calling convention and type info, convert to ``m_call``.

        Returns True on success.
        """
        logger.info(
            "IndirectCallResolver: replacing indirect call at %#x -> %#x",
            insn.ea, target_ea,
        )

        if insn.opcode == ida_hexrays.m_icall:
            has_mcallinfo = (
                insn.d.t == ida_hexrays.mop_f and insn.d.f is not None
            )

            if has_mcallinfo:
                # Update existing mcallinfo
                mci = insn.d.f
                mci.callee = target_ea

                # Try to get function type for better decompilation
                func_type = ida_typeinf.tinfo_t()
                get_tinfo = getattr(ida_typeinf, "get_tinfo", None)
                if callable(get_tinfo) and get_tinfo(func_type, target_ea):
                    mci.set_type(func_type)

                # Set l operand to direct target
                insn.l.erase()
                insn.l.t = ida_hexrays.mop_v
                insn.l.g = target_ea
                insn.l.size = ida_hexrays.NOSIZE  # NOSIZE

                # m_call requires r to be empty
                insn.r.erase()

                # Convert opcode
                insn.opcode = ida_hexrays.m_call

                logger.debug(
                    "IndirectCallResolver: converted m_icall -> m_call "
                    "(preserved mcallinfo)",
                )
            else:
                # Unknown call -- create mcallinfo and convert
                # TODO(phase6): frameless continuation fallback
                mci = ida_hexrays.mcallinfo_t()
                mci.callee = target_ea
                mci.cc = ida_typeinf.CM_CC_FASTCALL

                func_type = ida_typeinf.tinfo_t()
                get_tinfo = getattr(ida_typeinf, "get_tinfo", None)
                if callable(get_tinfo) and get_tinfo(func_type, target_ea):
                    mci.set_type(func_type)
                else:
                    mci.return_type.create_simple_type(ida_typeinf.BT_VOID)

                insn.d.erase()
                insn.d.t = ida_hexrays.mop_f
                insn.d.f = mci
                insn.d.size = 0

                insn.l.erase()
                insn.l.t = ida_hexrays.mop_v
                insn.l.g = target_ea
                insn.l.size = ida_hexrays.NOSIZE

                insn.r.erase()

                insn.opcode = ida_hexrays.m_call

                logger.debug(
                    "IndirectCallResolver: converted unknown m_icall -> m_call",
                )

        elif insn.opcode == ida_hexrays.m_call:
            # Already m_call, just update target
            if insn.d.t == ida_hexrays.mop_f and insn.d.f is not None:
                insn.d.f.callee = target_ea
            insn.l.erase()
            insn.l.t = ida_hexrays.mop_v
            insn.l.g = target_ea
            insn.l.size = ida_hexrays.NOSIZE

            logger.debug(
                "IndirectCallResolver: updated m_call target to %#x",
                target_ea,
            )
        else:
            return False

        # Mark the block as modified
        blk.mark_lists_dirty()
        blk.mba.mark_chains_dirty()

        # Add annotation comment
        name = ida_name.get_name(target_ea)
        comment = "D810: Resolved indirect call -> {} ({:#x})".format(
            name if name else "?", target_ea,
        )
        idaapi.set_cmt(insn.ea, comment, False)

        return True

    # ------------------------------------------------------------------
    # Annotation fallback
    # ------------------------------------------------------------------
    @staticmethod
    def _annotate_call(insn: "minsn_t", target_ea: int) -> None:
        """Add an IDB comment noting the resolved target without modifying the call."""
        name = ida_name.get_name(target_ea)
        comment = "D810: Indirect call resolved -> {} ({:#x}) [not replaced: not a function start]".format(
            name if name else "?", target_ea,
        )
        idaapi.set_cmt(insn.ea, comment, False)
        logger.info(
            "IndirectCallResolver: annotated indirect call at %#x -> %#x",
            insn.ea, target_ea,
        )

    # TODO(phase6): frameless continuation fallback
    # TODO(phase6): x86-64 binary pattern scanner (scan_binary_for_pattern)
    # TODO(phase6): pre-computed XOR index brute force


# Populate SAFE_MATURITIES and CONFIG_SCHEMA now that the class is defined.
if True:
    IndirectCallResolver.SAFE_MATURITIES = [
        ida_hexrays.MMAT_LOCOPT,
        ida_hexrays.MMAT_CALLS,
        ida_hexrays.MMAT_GLBOPT1,
    ]
    IndirectCallResolver.CONFIG_SCHEMA = FlowOptimizationRule.CONFIG_SCHEMA + (
        ConfigParam("table_entry_size", int, 8, "Call table entry size in bytes"),
    )
