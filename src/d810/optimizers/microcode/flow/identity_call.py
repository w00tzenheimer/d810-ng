"""Identity Call Resolution (the copycat project port).

This module resolves obfuscated identity call patterns used by obfuscators like
Hikari. The pattern uses:
  1. An identity function: __int64 identity(__int64 a1) { return a1; }
  2. Global pointers to code locations: off_XXX = &loc_YYY
  3. Indirect calls/jumps: identity(off_XXX)() or jmp identity(off_XXX)

Pattern A (indirect call):
  v4 = identity_func(off_1008B8B80);  // Returns the pointer value
  return v4();                         // Calls the target

Pattern B (indirect jump - Hikari style):
  mov rdi, cs:off_10095FB68           // Load pointer into arg1
  call sub_1007260C0                  // Call identity function
  jmp rax                             // Jump to returned address

The targets themselves may follow the same pattern, creating chains.

Ported from the copycat project's identity_call.h/.cpp.
"""
from __future__ import annotations

import dataclasses
from d810.core.typing import TYPE_CHECKING

import ida_funcs
import ida_hexrays
import ida_name

if TYPE_CHECKING:
    from ida_hexrays import mblock_t, minsn_t

from d810.core import getLogger
from d810.hexrays import arch_utils
from d810.hexrays.table_utils import is_valid_database_ea, read_global_value
from d810.optimizers.microcode.handler import ConfigParam
from d810.optimizers.microcode.flow.handler import FlowOptimizationRule, FlowRulePriority
from d810.optimizers.microcode.flow.jumps.indirect_call import IndirectCallResolver

logger = getLogger(__name__)


# ---------------------------------------------------------------------------
# Deferred Analysis Storage
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class DeferredIdentityCall:
    """Record of identity call pattern detected in analysis."""

    call_ea: int  # Address of identity function call instruction
    ijmp_ea: int  # Address of paired indirect transfer (icall/ijmp)
    identity_func_ea: int  # Address of identity function
    global_ptr_ea: int  # Global pointer EA if known, else BADADDR
    final_target_ea: int  # Resolved final target
    target_name: str  # Name of target function (for annotation)
    is_ijmp_pattern: bool  # True if paired transfer is m_ijmp


# Module-level deferred analysis storage: func_ea -> list[DeferredIdentityCall]
_deferred_analysis: dict[int, list[DeferredIdentityCall]] = {}


# ---------------------------------------------------------------------------
# Pure Logic Functions (no IDA dependencies)
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class TableResolution:
    """Result of table entry classification."""

    table_base: int
    entry0_target: int
    entry1_target: int | None
    both_same: bool
    is_cff_dispatcher: bool


def classify_table_entries(
    final0: int,
    final1: int | None,
    func_ea: int,
    func_start: int,
    func_end: int,
) -> TableResolution:
    """Classify table entries to determine pattern type.

    Args:
        final0: Final resolved target for table[0]
        final1: Final resolved target for table[1] (may be None)
        func_ea: Current function entry address
        func_start: Current function start address
        func_end: Current function end address

    Returns:
        TableResolution with classification results
    """
    # Check if targets are self-references
    t0_is_self = (final0 == func_ea) or (func_start <= final0 < func_end)
    t1_is_self = (
        (final1 == func_ea or (func_start <= final1 < func_end))
        if final1 is not None
        else False
    )

    # Both same target or entry1 missing
    both_same = (final0 == final1) or (final1 is None)

    # Both self-reference = CFF dispatcher
    is_cff = t0_is_self and t1_is_self

    # Determine which entry to use
    if both_same:
        entry0_target = final0
        entry1_target = None
    elif not t0_is_self and t1_is_self:
        # Entry 0 valid, entry 1 self-ref
        entry0_target = final0
        entry1_target = None
    elif t0_is_self and not t1_is_self:
        # Entry 1 valid, entry 0 self-ref
        entry0_target = final1
        entry1_target = None
    elif not t0_is_self and not t1_is_self:
        # Both valid, different targets (conditional)
        entry0_target = final0
        entry1_target = final1
    else:
        # Both self-reference
        entry0_target = final0
        entry1_target = final1

    return TableResolution(
        table_base=0,  # Filled by caller
        entry0_target=entry0_target,
        entry1_target=entry1_target,
        both_same=both_same,
        is_cff_dispatcher=is_cff,
    )


def store_deferred_analysis(
    func_ea: int, deferred_call: DeferredIdentityCall
) -> None:
    """Store deferred analysis for later application.

    Args:
        func_ea: Function address
        deferred_call: DeferredIdentityCall record
    """
    if func_ea not in _deferred_analysis:
        _deferred_analysis[func_ea] = []
    _deferred_analysis[func_ea].append(deferred_call)


def retrieve_deferred_analysis(func_ea: int) -> list[DeferredIdentityCall]:
    """Retrieve deferred analysis for a function.

    Args:
        func_ea: Function address

    Returns:
        List of DeferredIdentityCall records (may be empty)
    """
    return _deferred_analysis.get(func_ea, [])


def clear_deferred_analysis(func_ea: int | None = None) -> None:
    """Clear deferred analysis.

    Args:
        func_ea: Function address (if None, clear all)
    """
    if func_ea is None:
        _deferred_analysis.clear()
    else:
        _deferred_analysis.pop(func_ea, None)


# ---------------------------------------------------------------------------
# IdentityCallResolver Rule
# ---------------------------------------------------------------------------
class IdentityCallResolver(FlowOptimizationRule):
    """Identity call pattern resolver.

    Detects identity-wrapper call patterns and rewrites paired indirect calls
    to direct calls when a stable target is derivable from local state updates.

    Status:
      This remains experimental and is disabled by default
      (``enable_experimental=false``).
    """

    NAME = "IdentityCallResolver"
    DESCRIPTION = "Resolve identity function call patterns (Hikari-style)"
    CATEGORY = "Indirect Calls"
    USES_DEFERRED_CFG = True

    if True:
        SAFE_MATURITIES = [
            ida_hexrays.MMAT_PREOPTIMIZED,
            ida_hexrays.MMAT_LOCOPT,
            ida_hexrays.MMAT_CALLS,
            ida_hexrays.MMAT_GLBOPT1,
        ]
        priority = FlowRulePriority.DEFAULT
        CONFIG_SCHEMA = FlowOptimizationRule.CONFIG_SCHEMA + (
            ConfigParam(
                "enable_experimental",
                bool,
                False,
                "Enable experimental identity-call resolver scaffold",
            ),
            ConfigParam(
                "max_trampoline_depth",
                int,
                32,
                "Maximum depth when following trampoline chains",
            ),
            ConfigParam(
                "max_search_instructions",
                int,
                30,
                "Maximum instructions to scan when pairing call/icall",
            ),
        )
    else:
        priority = 100
        CONFIG_SCHEMA = ()

    def __init__(self):
        super().__init__()
        self.enable_experimental = False
        self._stub_warning_emitted = False
        self.max_trampoline_depth = 32
        self.max_search_instructions = 30
        self.maturities = []
        self._call_rewriter = None
        self._processed_mba_keys: set[tuple[int, int]] = set()

        if True:
            self._call_rewriter = IndirectCallResolver()

    def configure(self, kwargs):
        """Configure from kwargs dict."""
        super().configure(kwargs)
        self.enable_experimental = bool(self.config.get("enable_experimental", False))

        if not self.enable_experimental:
            self.maturities = []
        elif "maturities" not in self.config:
            # Identity wrapper + paired icall is visible at LOCOPT in our harness.
            self.maturities = [
                ida_hexrays.MMAT_PREOPTIMIZED,
                ida_hexrays.MMAT_LOCOPT,
                ida_hexrays.MMAT_CALLS,
            ]

        if "max_trampoline_depth" in self.config:
            self.max_trampoline_depth = int(self.config["max_trampoline_depth"])
        if "max_search_instructions" in self.config:
            self.max_search_instructions = int(self.config["max_search_instructions"])

    def optimize(self, blk) -> int:
        """Optimize a microcode block.

        Returns:
            Number of modifications made.
        """

        if not self.enable_experimental:
            return 0

        if not self._stub_warning_emitted:
            logger.warning(
                "IdentityCallResolver is experimental; running LOCOPT identity-wrapper matching."
            )
            self._stub_warning_emitted = True

        maturity = blk.mba.maturity
        if maturity in (ida_hexrays.MMAT_PREOPTIMIZED, ida_hexrays.MMAT_LOCOPT):
            return self._analyze_and_apply_locopt(blk)

        # Keep cleanup safety in later maturities; nothing to apply currently.
        if maturity == ida_hexrays.MMAT_CALLS:
            return self._phase2_cleanup(blk)

        return 0

    def _analyze_and_apply_locopt(self, blk) -> int:
        """Analyze the whole function and apply rewrites at LOCOPT."""
        mba = blk.mba
        func_ea = mba.entry_ea

        # Process once per (mba object, maturity), regardless of first block
        # callback ordering. Hex-Rays does not guarantee blk 0 is visited first.
        process_key = (id(mba), int(mba.maturity))
        if process_key in self._processed_mba_keys:
            return 0
        self._processed_mba_keys.add(process_key)
        if len(self._processed_mba_keys) > 512:
            self._processed_mba_keys.clear()

        clear_deferred_analysis(func_ea)
        global_writes = self._collect_global_constant_writes(mba)

        detected = self._detect_identity_patterns(mba, global_writes)
        for rec in detected:
            store_deferred_analysis(func_ea, rec)

        if not detected:
            return 0

        changed = self._apply_deferred_for_function(mba, func_ea)
        clear_deferred_analysis(func_ea)
        return changed

    def _phase2_cleanup(self, blk) -> int:
        """Drop stale deferred state if still present."""
        if blk.serial != 0:
            return 0
        clear_deferred_analysis(blk.mba.entry_ea)
        return 0

    def _detect_identity_patterns(
        self,
        mba,
        global_writes: dict[int, set[int]],
    ) -> list[DeferredIdentityCall]:
        """Detect identity call + indirect transfer pairs in *mba*."""
        records: list[DeferredIdentityCall] = []
        seen_icall_ea: set[int] = set()

        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            reg_values: dict[int, int] = {}
            stk_values: dict[int, int] = {}

            ins = blk.head
            while ins is not None:
                self._track_values(ins, reg_values, stk_values, global_writes)

                if not self._is_identity_call_insn(ins):
                    ins = ins.next
                    continue

                identity_func_ea = self._extract_direct_call_target(ins)
                if identity_func_ea is None:
                    ins = ins.next
                    continue

                arg_val, global_ptr_ea = self._resolve_identity_arg_value(
                    ins,
                    reg_values,
                    stk_values,
                    global_writes,
                )
                if arg_val is None:
                    ins = ins.next
                    continue

                final_target = self._resolve_final_target(arg_val, global_writes)
                if final_target is None:
                    ins = ins.next
                    continue

                paired = self._find_paired_indirect_transfer(blk, ins, mba)
                if paired is None:
                    ins = ins.next
                    continue

                paired_blk, paired_ins = paired
                if paired_ins.ea in seen_icall_ea:
                    ins = ins.next
                    continue

                # Skip CFF-like self recursion targets.
                if self._is_self_target(mba.entry_ea, final_target):
                    logger.debug(
                        "IdentityCallResolver: skip self-target %#x in %#x",
                        final_target,
                        mba.entry_ea,
                    )
                    ins = ins.next
                    continue

                target_name = ida_name.get_name(final_target) or ""
                record = DeferredIdentityCall(
                    call_ea=ins.ea,
                    ijmp_ea=paired_ins.ea,
                    identity_func_ea=identity_func_ea,
                    global_ptr_ea=global_ptr_ea,
                    final_target_ea=final_target,
                    target_name=target_name,
                    is_ijmp_pattern=paired_ins.opcode == ida_hexrays.m_ijmp,
                )
                records.append(record)
                seen_icall_ea.add(paired_ins.ea)

                logger.info(
                    "IdentityCallResolver: detected call pair in %#x: call %#x, transfer %#x -> %#x",
                    mba.entry_ea,
                    record.call_ea,
                    record.ijmp_ea,
                    record.final_target_ea,
                )

                ins = ins.next

        return records

    def _apply_deferred_for_function(self, mba, func_ea: int) -> int:
        """Apply deferred rewrites collected for *func_ea*."""
        records = retrieve_deferred_analysis(func_ea)
        if not records:
            return 0

        by_ea: dict[int, tuple[mblock_t, minsn_t]] = {}
        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            ins = blk.head
            while ins is not None:
                by_ea[ins.ea] = (blk, ins)
                ins = ins.next

        changed = 0
        nopped_calls: set[int] = set()

        for rec in records:
            loc = by_ea.get(rec.ijmp_ea)
            if loc is None:
                continue
            transfer_blk, transfer_ins = loc

            if rec.is_ijmp_pattern:
                # Keep ijmp path as analysis-only for now.
                continue

            if transfer_ins.opcode not in (ida_hexrays.m_icall, ida_hexrays.m_call):
                continue

            if self._call_rewriter is None:
                continue

            if not self._call_rewriter._replace_call(transfer_ins, rec.final_target_ea, transfer_blk):
                continue

            changed += 1

            call_loc = by_ea.get(rec.call_ea)
            if call_loc is not None and rec.call_ea not in nopped_calls:
                call_blk, call_ins = call_loc
                self._nop_instruction(call_blk, call_ins)
                nopped_calls.add(rec.call_ea)

        if changed:
            mba.mark_chains_dirty()

        return changed

    @staticmethod
    def _nop_instruction(blk, ins) -> None:
        """Replace *ins* with m_nop in-place."""
        ins.opcode = ida_hexrays.m_nop
        ins.l.erase()
        ins.r.erase()
        ins.d.erase()
        blk.mark_lists_dirty()

    @staticmethod
    def _is_self_target(func_ea: int, target_ea: int) -> bool:
        """Return True if *target_ea* is the containing function itself."""
        func = ida_funcs.get_func(func_ea)
        if func is None:
            return target_ea == func_ea
        return target_ea == func_ea or (func.start_ea <= target_ea < func.end_ea)

    def _track_values(
        self,
        ins,
        reg_values: dict[int, int],
        stk_values: dict[int, int],
        global_writes: dict[int, set[int]],
    ) -> None:
        """Track simple register/stack values used for call-arg recovery."""
        if ins.opcode == ida_hexrays.m_mov:
            value = self._eval_operand_to_ea(ins.l, reg_values, stk_values, global_writes)
            if ins.d.t == ida_hexrays.mop_r:
                if value is None:
                    reg_values.pop(ins.d.r, None)
                else:
                    reg_values[ins.d.r] = value
            elif ins.d.t == ida_hexrays.mop_S:
                if value is None:
                    stk_values.pop(ins.d.s.off, None)
                else:
                    stk_values[ins.d.s.off] = value
            return

        if ins.opcode == ida_hexrays.m_ldx and ins.d.t == ida_hexrays.mop_r:
            value = self._eval_ldx_to_ea(ins, reg_values, stk_values, global_writes)
            if value is None:
                reg_values.pop(ins.d.r, None)
            else:
                reg_values[ins.d.r] = value

    def _collect_global_constant_writes(self, mba) -> dict[int, set[int]]:
        """Collect in-function writes of constants to global pointers."""
        writes: dict[int, set[int]] = {}
        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            reg_values: dict[int, int] = {}
            stk_values: dict[int, int] = {}
            ins = blk.head
            while ins is not None:
                self._track_values(ins, reg_values, stk_values, writes)
                if ins.opcode == ida_hexrays.m_mov and ins.d.t == ida_hexrays.mop_v:
                    value = self._eval_operand_to_ea(
                        ins.l, reg_values, stk_values, writes
                    )
                    if value is not None and is_valid_database_ea(value):
                        writes.setdefault(ins.d.g, set()).add(value)
                ins = ins.next
        return writes

    def _resolve_identity_arg_value(
        self,
        call_ins,
        reg_values: dict[int, int],
        stk_values: dict[int, int],
        global_writes: dict[int, set[int]],
    ) -> tuple[int | None, int]:
        """Resolve identity call arg value using call-arg semantics first."""
        # Preferred path: decode mcallinfo arg mops if available.
        if call_ins.d.t == ida_hexrays.mop_f and call_ins.d.f is not None:
            try:
                args = call_ins.d.f.args
            except Exception:
                args = []
            if len(args) >= 1 and args[0] is not None:
                ptr_ea = self._extract_global_ptr_ea(args[0])
                val = self._eval_operand_to_ea(args[0], reg_values, stk_values, global_writes)
                return (val, ptr_ea)

        # ABI register fallback.
        arg_reg = arch_utils.get_first_arg_reg()
        if arg_reg >= 0:
            arg_val = reg_values.get(arg_reg)
            if arg_val is not None:
                return (arg_val, arch_utils.BADADDR)

        # Heuristic fallback for microcode register-ID mismatches:
        # pick the latest pointer-like register value.
        candidate = self._select_arg_from_reg_values(reg_values)
        if candidate is not None:
            return (candidate, arch_utils.BADADDR)

        return (None, arch_utils.BADADDR)

    @staticmethod
    def _is_pointer_like_target(value: int) -> bool:
        """Return True if *value* looks like a code/trampoline pointer."""
        if not is_valid_database_ea(value):
            return False
        if ida_funcs.get_func(value) is not None:
            return True
        is_tramp, _ = arch_utils.is_trampoline_code(value)
        return is_tramp

    def _select_arg_from_reg_values(self, reg_values: dict[int, int]) -> int | None:
        """Best-effort pick for call arg value when ABI reg IDs don't match."""
        candidates: list[int] = []
        for _, value in reversed(list(reg_values.items())):
            if self._is_pointer_like_target(value):
                candidates.append(value)
        if len(candidates) == 1:
            return candidates[0]
        if len(candidates) > 1:
            # Keep deterministic behavior: prefer most recently observed.
            return candidates[0]

        # Last fallback: if exactly one concrete EA was tracked, use it.
        concrete = [
            value for _, value in reversed(list(reg_values.items()))
            if is_valid_database_ea(value)
        ]
        if len(concrete) == 1:
            return concrete[0]
        return None

    @staticmethod
    def _extract_global_ptr_ea(mop) -> int:
        """Extract global pointer EA from an arg mop if present."""
        if mop is None:
            return arch_utils.BADADDR
        if mop.t == ida_hexrays.mop_v:
            return mop.g
        if mop.t == ida_hexrays.mop_a and mop.a is not None and mop.a.t == ida_hexrays.mop_v:
            return mop.a.g
        return arch_utils.BADADDR

    def _resolve_final_target(self, target_ea: int, global_writes: dict[int, set[int]]) -> int | None:
        """Resolve trampoline chain with local write-map fallback."""
        if not is_valid_database_ea(target_ea):
            return None

        current = target_ea

        # If the argument is a global/table slot address, resolve through
        # in-function writes before trampoline chasing.
        slot_values = global_writes.get(current)
        if slot_values and len(slot_values) == 1:
            current = next(iter(slot_values))

        visited: set[int] = set()
        depth = self.max_trampoline_depth

        while depth > 0 and current not in visited:
            visited.add(current)
            is_tramp, global_ptr = arch_utils.is_trampoline_code(current)
            if not is_tramp or global_ptr is None:
                break

            next_target = arch_utils.resolve_global_pointer(global_ptr)
            if next_target is None:
                values = global_writes.get(global_ptr)
                if values and len(values) == 1:
                    next_target = next(iter(values))

            if next_target is None:
                break

            current = next_target
            depth -= 1

        if ida_funcs.get_func(current) is not None:
            return current
        is_tramp, _ = arch_utils.is_trampoline_code(current)
        if is_tramp:
            return current
        return None

    def _find_paired_indirect_transfer(self, blk, call_ins, mba):
        """Find paired icall/ijmp that consumes return register after *call_ins*."""
        ret_reg = arch_utils.get_return_reg()

        # First search in the same block after call.
        ins = call_ins.next
        scanned = 0
        while ins is not None:
            if self._is_paired_transfer_candidate(ins, ret_reg):
                return (blk, ins)
            ins = ins.next
            scanned += 1
            if scanned >= self.max_search_instructions:
                break

        # Then search successor block head (common split block shape).
        if blk.nsucc() == 1:
            succ = mba.get_mblock(blk.succ(0))
            if succ is not None:
                ins = succ.head
                scanned = 0
                while ins is not None and scanned < self.max_search_instructions:
                    if self._is_paired_transfer_candidate(ins, ret_reg):
                        return (succ, ins)
                    ins = ins.next
                    scanned += 1

        # Some maturities split call/icall into disconnected 0-way blocks.
        # Fallback: choose the nearest later indirect transfer in EA order.
        best = None
        best_delta = None
        for i in range(mba.qty):
            cand_blk = mba.get_mblock(i)
            cand_ins = cand_blk.head
            while cand_ins is not None:
                if (
                    cand_ins.ea > call_ins.ea
                    and self._is_paired_transfer_candidate(cand_ins, ret_reg)
                ):
                    delta = cand_ins.ea - call_ins.ea
                    if best_delta is None or delta < best_delta:
                        best = (cand_blk, cand_ins)
                        best_delta = delta
                cand_ins = cand_ins.next

        if best is not None and best_delta is not None and best_delta <= 0x200:
            return best

        return None

    @staticmethod
    def _is_indirect_transfer(ins) -> bool:
        """Return True for indirect transfer instructions (reg-based call/jump)."""
        if ins.opcode in (ida_hexrays.m_icall, ida_hexrays.m_ijmp):
            return True
        if ins.opcode == ida_hexrays.m_call and ins.l.t == ida_hexrays.mop_r:
            return True
        return False

    def _is_paired_transfer_candidate(self, ins, ret_reg: int) -> bool:
        """Return True if instruction can be paired with preceding identity call."""
        if ret_reg >= 0 and self._is_indirect_transfer_using_reg(ins, ret_reg):
            return True
        # Fallback for register-ID mismatches between assembly and microcode.
        return self._is_indirect_transfer(ins)

    @staticmethod
    def _is_indirect_transfer_using_reg(ins, reg: int) -> bool:
        """Return True when *ins* is indirect transfer using register *reg*."""
        if ins.opcode in (ida_hexrays.m_icall, ida_hexrays.m_ijmp):
            if ins.r.t == ida_hexrays.mop_r and ins.r.r == reg:
                return True
            if ins.l.t == ida_hexrays.mop_r and ins.l.r == reg:
                return True
        if ins.opcode == ida_hexrays.m_call and ins.l.t == ida_hexrays.mop_r:
            return ins.l.r == reg
        return False

    def _is_identity_call_insn(self, ins) -> bool:
        """Return True if *ins* is direct call to an identity function."""
        if ins.opcode != ida_hexrays.m_call:
            return False

        target = self._extract_direct_call_target(ins)
        if target is None:
            return False

        if arch_utils.is_identity_function(target):
            return True

        # Fallback for test builds where identity wrappers compile as
        # stack-spill shuffles that the strict detector may miss.
        name = (ida_name.get_name(target) or "").lower()
        return "identity" in name

    @staticmethod
    def _extract_direct_call_target(ins) -> int | None:
        """Extract direct call target EA for m_call instructions."""
        if ins.opcode != ida_hexrays.m_call:
            return None

        # LOCOPT uses helper call operands (`$name`) with l.t==mop_h and `g` set.
        if hasattr(ins.l, "g"):
            target = ins.l.g
            if isinstance(target, int) and target != 0:
                return target

        if ins.l.t == ida_hexrays.mop_v:
            return ins.l.g

        if ins.l.t == ida_hexrays.mop_a and ins.l.a is not None:
            if ins.l.a.t == ida_hexrays.mop_v:
                return ins.l.a.g

        return None

    def _eval_ldx_to_ea(
        self,
        ins,
        reg_values: dict[int, int],
        stk_values: dict[int, int],
        global_writes: dict[int, set[int]],
    ) -> int | None:
        """Evaluate m_ldx to EA with fallback for unknown dynamic indices."""
        base = self._eval_operand_to_ea(ins.l, reg_values, stk_values, global_writes)
        offs = self._eval_operand_to_ea(ins.r, reg_values, stk_values, global_writes)

        if base is None:
            return None

        if offs is not None:
            addr = (base + offs) & 0xFFFFFFFFFFFFFFFF
            val = read_global_value(addr, 8)
            if val is not None and val != 0:
                return val
            values = global_writes.get(addr)
            if values and len(values) == 1:
                return next(iter(values))

        # Unknown offset: if all known writes in this table region agree, use that.
        candidate_values: set[int] = set()
        for addr, values in global_writes.items():
            if addr < base:
                continue
            delta = addr - base
            if delta % 8 != 0 or delta > 0x100:
                continue
            candidate_values.update(values)

        if len(candidate_values) == 1:
            return next(iter(candidate_values))

        return None

    def _eval_operand_to_ea(
        self,
        mop,
        reg_values: dict[int, int],
        stk_values: dict[int, int],
        global_writes: dict[int, set[int]],
    ) -> int | None:
        """Best-effort evaluator for mops into concrete addresses."""
        if mop is None:
            return None

        t = mop.t
        if t == ida_hexrays.mop_n:
            return int(mop.nnn.value) & 0xFFFFFFFFFFFFFFFF

        if t == ida_hexrays.mop_r:
            return reg_values.get(mop.r)

        if t == ida_hexrays.mop_S:
            return stk_values.get(mop.s.off)

        if t == ida_hexrays.mop_v:
            val = read_global_value(mop.g, 8)
            if val not in (None, 0, arch_utils.BADADDR):
                return val
            values = global_writes.get(mop.g)
            if values and len(values) == 1:
                return next(iter(values))
            return None

        if t == ida_hexrays.mop_a and mop.a is not None:
            if mop.a.t == ida_hexrays.mop_v:
                # Address-of global/code symbol (`&symbol`) carries the EA
                # directly; do not dereference bytes at that address.
                return mop.a.g
            return self._eval_operand_to_ea(mop.a, reg_values, stk_values, global_writes)

        if t == ida_hexrays.mop_d and mop.d is not None:
            op = mop.d.opcode
            if op == ida_hexrays.m_mov:
                return self._eval_operand_to_ea(mop.d.l, reg_values, stk_values, global_writes)
            if op == ida_hexrays.m_ldx:
                return self._eval_ldx_to_ea(mop.d, reg_values, stk_values, global_writes)
            if op in (ida_hexrays.m_add, ida_hexrays.m_sub, ida_hexrays.m_xor):
                left = self._eval_operand_to_ea(mop.d.l, reg_values, stk_values, global_writes)
                right = self._eval_operand_to_ea(mop.d.r, reg_values, stk_values, global_writes)
                if left is None or right is None:
                    return None
                if op == ida_hexrays.m_add:
                    return (left + right) & 0xFFFFFFFFFFFFFFFF
                if op == ida_hexrays.m_sub:
                    return (left - right) & 0xFFFFFFFFFFFFFFFF
                return (left ^ right) & 0xFFFFFFFFFFFFFFFF

        return None


if True:
    IdentityCallResolver.SAFE_MATURITIES = [
        ida_hexrays.MMAT_PREOPTIMIZED,
        ida_hexrays.MMAT_LOCOPT,
        ida_hexrays.MMAT_CALLS,
        ida_hexrays.MMAT_GLBOPT1,
    ]
