"""Indirect Branch Resolution -- the copycat project Phase 5.

Resolves obfuscated indirect jumps (``m_ijmp``) by analysing encoded jump
tables, decoding entries, and converting them to direct jumps (``m_goto``).

The algorithm is ported from the copycat project's ``indirect_branch.cpp`` handler and
adapted to the d810-ng FlowOptimizationRule framework.

Detection flow
--------------
1. Block ends in ``m_ijmp`` (indirect jump).
2. Trace ``m_ldx`` instructions to locate the global array.  Fall back to
   ``ida_nalt.get_switch_info()`` and named-global lookup for known Hikari
   table names.
3. Analyse encoding (XOR / ADD patterns) to classify as DIRECT, OFFSET,
   XOR, or OFFSET_XOR.
4. Walk backwards from ``m_ijmp`` for ``m_and`` / ``m_low`` to determine
   the maximum table index.
5. Read and decode table entries; stop after 512 entries or 5 consecutive
   invalid targets.
6. Convert to ``m_goto`` when all entries resolve to a single block; annotate
   otherwise.
"""
from __future__ import annotations

from d810.core.typing import TYPE_CHECKING, List, Optional

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_nalt
import ida_name
import idaapi
from idaapi import BADADDR

if TYPE_CHECKING:
    from ida_hexrays import mblock_t

from d810.core import getLogger
from d810.hexrays.table_utils import (
    TableEncoding,
    analyze_table_encoding,
    decode_table_entry,
    find_table_reference,
    read_global_value,
    validate_code_target,
)

from d810.optimizers.microcode.handler import ConfigParam
from d810.hexrays.cfg_utils import (
    change_0way_block_successor,
    change_1way_block_successor,
    safe_verify,
)
from d810.optimizers.microcode.flow.handler import FlowOptimizationRule

logger = getLogger("D810.optimizer")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_TABLE_ENTRIES: int = 512
"""Maximum number of table entries to read before giving up."""

MAX_CONSECUTIVE_INVALID: int = 5
"""Stop scanning after this many consecutive invalid targets."""

DEFAULT_TABLE_ENTRY_SIZE: int = 8
"""Default size (bytes) of each jump table entry."""

# Known Hikari global table names (searched as a fallback).
_HIKARI_TABLE_NAMES: list[str] = [
    "IndirectBranchingGlobalTable",
    "HikariConditionalLocalIndirectBranchingTable",
    "IndirectBranchTable",
]


# ---------------------------------------------------------------------------
# IndirectBranchResolver
# ---------------------------------------------------------------------------
class IndirectBranchResolver(FlowOptimizationRule):
    """Resolve obfuscated indirect jumps by analysing encoded jump tables.

    This rule detects ``m_ijmp`` instructions, locates the backing jump
    table, decodes its entries according to the detected encoding scheme,
    and -- when all entries resolve to a single block -- converts the
    indirect jump to a direct ``m_goto``.

    Configuration keys
    ------------------
    table_entry_size : int
        Size of each table entry in bytes (default ``8``).
    candidate_max_depth : int
        Maximum predecessor-walk depth for collecting candidate blocks
        (default ``8``).
    """

    NAME = "IndirectBranchResolver"
    DESCRIPTION = "Resolves obfuscated indirect jumps by analysing encoded jump tables"
    CATEGORY = "Indirect Jumps"
    USES_DEFERRED_CFG = True  # Uses DeferredGraphModifier for CFG changes
    SAFE_MATURITIES: list[int] = []  # Populated after class definition when IDA is available

    def __init__(self) -> None:
        super().__init__()
        self.table_entry_size: int = DEFAULT_TABLE_ENTRY_SIZE
        self.candidate_max_depth: int = 8
        if True:
            self.maturities = [ida_hexrays.MMAT_LOCOPT]

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------
    def configure(self, kwargs: dict) -> None:  # type: ignore[override]
        super().configure(kwargs)
        if "table_entry_size" in self.config:
            self.table_entry_size = int(self.config["table_entry_size"])
        if "candidate_max_depth" in self.config:
            configured_depth = int(self.config["candidate_max_depth"])
            self.candidate_max_depth = max(1, configured_depth)

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------
    def optimize(self, blk: "mblock_t") -> int:
        """Attempt to resolve an indirect jump in *blk*.

        Returns the number of changes (0 or 1).
        """

        # 1. Check if block ends in m_ijmp
        if blk.tail is None or blk.tail.opcode != ida_hexrays.m_ijmp:
            return 0

        logger.debug(
            "IndirectBranchResolver: analysing block %d (m_ijmp at %#x)",
            blk.serial, blk.tail.ea,
        )
        logger.info(
            "IndirectBranchResolver: inspect ijmp blk=%d ea=%#x l.t=%d r.t=%d d.t=%d",
            blk.serial,
            blk.tail.ea,
            blk.tail.l.t,
            blk.tail.r.t,
            blk.tail.d.t,
        )
        candidate_blocks = self._collect_candidate_blocks(
            blk, max_depth=self.candidate_max_depth
        )
        runtime_globals = self._collect_runtime_global_writes(candidate_blocks)

        # Fast path for folded/simplified ijmp targets where table analysis is
        # no longer obvious but the jump destination is still evaluable.
        direct_target = self._resolve_folded_ijmp_target(blk)
        if direct_target is not None:
            logger.info(
                "IndirectBranchResolver: folded ijmp target %#x for blk %d",
                direct_target,
                blk.serial,
            )
            target_blocks = self._resolve_target_blocks(blk.mba, [direct_target])
            if target_blocks and target_blocks[0] is not None:
                logger.info(
                    "IndirectBranchResolver: folded target maps to blk %d",
                    target_blocks[0],
                )
                return self._convert_to_goto(blk, target_blocks[0])
            logger.info(
                "IndirectBranchResolver: folded target %#x did not map to block",
                direct_target,
            )

        # 2. Find the jump table reference
        table_ea = self._find_table_reference_in_blocks(candidate_blocks)
        if table_ea is None:
            table_ea = self._find_table_by_switch_info_blocks(candidate_blocks)
        if table_ea is None:
            table_ea = self._find_table_by_known_names()
        if table_ea is None:
            logger.debug(
                "IndirectBranchResolver: no jump table found for block %d",
                blk.serial,
            )
            return 0

        logger.debug(
            "IndirectBranchResolver: table at %#x for block %d",
            table_ea, blk.serial,
        )

        # 3. Analyse table encoding
        encoding, xor_key, base_offset = self._analyze_table_encoding_in_blocks(
            candidate_blocks
        )
        logger.debug(
            "IndirectBranchResolver: encoding=%s key=%#x base=%#x",
            encoding.name, xor_key, base_offset,
        )
        base_offset = self._resolve_base_offset_value(base_offset, runtime_globals)

        # 4. Determine table size (trace index bounds)
        max_entries = self._trace_index_bounds_in_blocks(candidate_blocks)

        # 5. Read and decode table entries
        func_start, func_end = self._get_function_bounds(blk)
        raw_entries = self._read_table_entries_with_overrides(
            table_ea,
            max_entries,
            entry_size=self.table_entry_size,
            global_overrides=runtime_globals,
        )

        targets = self._decode_valid_targets(
            raw_entries, encoding, xor_key, base_offset, func_start, func_end
        )
        if not targets and encoding != TableEncoding.DIRECT:
            fallback_encodings = (
                TableEncoding.DIRECT,
                TableEncoding.OFFSET,
                TableEncoding.XOR,
                TableEncoding.OFFSET_XOR,
            )
            for fallback in fallback_encodings:
                if fallback == encoding:
                    continue
                fb_key = xor_key if fallback in (TableEncoding.XOR, TableEncoding.OFFSET_XOR) else 0
                fb_base = base_offset if fallback in (TableEncoding.OFFSET, TableEncoding.OFFSET_XOR) else 0
                alt_targets = self._decode_valid_targets(
                    raw_entries, fallback, fb_key, fb_base, func_start, func_end
                )
                if alt_targets:
                    logger.info(
                        "IndirectBranchResolver: fallback encoding %s -> %s for block %d (%d targets)",
                        encoding.name,
                        fallback.name,
                        blk.serial,
                        len(alt_targets),
                    )
                    encoding = fallback
                    targets = alt_targets
                    break

        if not targets:
            logger.info(
                "IndirectBranchResolver: no valid targets for block %d (table=%#x, entries=%d, encoding=%s, key=%#x, base=%#x, runtime_globals=%d)",
                blk.serial,
                table_ea,
                len(raw_entries),
                encoding.name,
                xor_key,
                base_offset,
                len(runtime_globals),
            )
            return 0

        logger.info(
            "IndirectBranchResolver: resolved %d targets for block %d",
            len(targets), blk.serial,
        )

        # 6. Convert to direct jump
        unique_targets = list(dict.fromkeys(targets))  # preserve order, deduplicate

        # Check if all targets resolve to a single *block*
        target_block_indices = self._resolve_target_blocks(blk.mba, unique_targets)
        unique_block_indices = list(dict.fromkeys(target_block_indices))

        if len(unique_block_indices) == 1 and unique_block_indices[0] is not None:
            return self._convert_to_goto(blk, unique_block_indices[0])
        elif len(unique_block_indices) > 1:
            self._annotate_targets(blk, unique_targets)
            return 0
        else:
            logger.debug(
                "IndirectBranchResolver: could not map targets to blocks for blk %d",
                blk.serial,
            )
            return 0

    # ------------------------------------------------------------------
    # Folded-target fast path
    # ------------------------------------------------------------------
    def _resolve_folded_ijmp_target(self, blk: "mblock_t") -> Optional[int]:
        """Resolve simplified ijmp targets to a single concrete EA."""
        reg_values: dict[int, int] = {}
        ins = blk.head
        while ins is not None and ins is not blk.tail:
            self._update_reg_value_map(ins, reg_values)
            ins = ins.next
        if blk.tail is None:
            return None

        # If the jump register is not defined in the current block, try to
        # recover it from predecessor blocks.
        if blk.tail.r.t == ida_hexrays.mop_r and blk.tail.r.r not in reg_values:
            pred_val = self._resolve_reg_from_predecessors(
                blk, blk.tail.r.r, max_depth=2
            )
            if pred_val is not None:
                reg_values[blk.tail.r.r] = pred_val

        logger.info(
            "IndirectBranchResolver: folded eval reg map size=%d for blk %d",
            len(reg_values),
            blk.serial,
        )
        func_start, func_end = self._get_function_bounds(blk)
        # m_ijmp target is frequently in r (and not l). Try r first.
        for mop in (blk.tail.r, blk.tail.l):
            target = self._eval_operand_to_ea(mop, reg_values)
            if target is not None and validate_code_target(target, func_start, func_end):
                return target
        return None

    def _resolve_reg_from_predecessors(
        self,
        blk: "mblock_t",
        reg: int,
        *,
        max_depth: int = 2,
    ) -> Optional[int]:
        """Best-effort predecessor walk to recover a register constant."""
        mba = blk.mba
        if mba is None:
            return None

        queue: list[tuple[int, int]] = [(int(pred), 1) for pred in blk.predset]
        seen: set[int] = set()
        values: list[int] = []

        while queue:
            serial, depth = queue.pop(0)
            if serial in seen:
                continue
            seen.add(serial)
            if serial < 0 or serial >= mba.qty:
                continue
            pred_blk = mba.get_mblock(serial)
            val = self._resolve_reg_value_in_block(pred_blk, reg)
            if val is not None:
                values.append(val)
                continue
            if depth < max_depth:
                for p in pred_blk.predset:
                    queue.append((int(p), depth + 1))

        if not values:
            return None
        first = values[0]
        if all(v == first for v in values):
            return first
        return None

    @staticmethod
    def _resolve_reg_value_in_block(blk: "mblock_t", reg: int) -> Optional[int]:
        """Evaluate the latest value assigned to *reg* in a block."""
        reg_values: dict[int, int] = {}
        ins = blk.head
        value: Optional[int] = None
        while ins is not None:
            IndirectBranchResolver._update_reg_value_map(ins, reg_values)
            if ins.d.t == ida_hexrays.mop_r and ins.d.r == reg:
                value = reg_values.get(reg)
            ins = ins.next
        return value

    @staticmethod
    def _update_reg_value_map(insn, reg_values: dict[int, int]) -> None:
        """Track evaluable register values in a single block."""
        if insn.d.t != ida_hexrays.mop_r:
            return
        value = IndirectBranchResolver._eval_insn_to_ea(insn, reg_values)
        if value is not None:
            reg_values[insn.d.r] = value
        else:
            reg_values.pop(insn.d.r, None)

    @staticmethod
    def _eval_operand_to_ea(mop, reg_values: dict[int, int]) -> Optional[int]:
        """Best-effort evaluator for jump-target operands."""
        if mop is None:
            return None
        t = mop.t
        if t == ida_hexrays.mop_n:
            return int(mop.nnn.value) & 0xFFFFFFFFFFFFFFFF
        if t == ida_hexrays.mop_r:
            return reg_values.get(mop.r)
        if t == ida_hexrays.mop_v:
            value = read_global_value(mop.g, 8)
            if value is not None:
                return value
            return int(mop.g) & 0xFFFFFFFFFFFFFFFF
        if t == ida_hexrays.mop_a and mop.a is not None:
            if mop.a.t == ida_hexrays.mop_v:
                return read_global_value(mop.a.g, 8)
            return IndirectBranchResolver._eval_operand_to_ea(mop.a, reg_values)
        if t == ida_hexrays.mop_d and mop.d is not None:
            return IndirectBranchResolver._eval_insn_to_ea(mop.d, reg_values)
        return None

    @staticmethod
    def _eval_insn_to_ea(insn, reg_values: dict[int, int]) -> Optional[int]:
        """Evaluate a minimal arithmetic subset used by folded ijmp targets."""
        if insn is None:
            return None
        op = insn.opcode
        if op == ida_hexrays.m_mov:
            return IndirectBranchResolver._eval_operand_to_ea(insn.l, reg_values)
        if op in (ida_hexrays.m_add, ida_hexrays.m_sub, ida_hexrays.m_xor):
            left = IndirectBranchResolver._eval_operand_to_ea(insn.l, reg_values)
            right = IndirectBranchResolver._eval_operand_to_ea(insn.r, reg_values)
            if left is None or right is None:
                return None
            if op == ida_hexrays.m_add:
                return (left + right) & 0xFFFFFFFFFFFFFFFF
            if op == ida_hexrays.m_sub:
                return (left - right) & 0xFFFFFFFFFFFFFFFF
            return (left ^ right) & 0xFFFFFFFFFFFFFFFF
        if op == ida_hexrays.m_ldx:
            base = IndirectBranchResolver._eval_address_operand(insn.l, reg_values)
            offs = IndirectBranchResolver._eval_operand_to_ea(insn.r, reg_values)
            if base is None or offs is None:
                return None
            return read_global_value((base + offs) & 0xFFFFFFFFFFFFFFFF, 8)
        return None

    @staticmethod
    def _eval_address_operand(mop, reg_values: dict[int, int]) -> Optional[int]:
        """Evaluate an operand as an address (not as a dereferenced value)."""
        if mop is None:
            return None
        t = mop.t
        if t == ida_hexrays.mop_v:
            return int(mop.g) & 0xFFFFFFFFFFFFFFFF
        if t == ida_hexrays.mop_n:
            return int(mop.nnn.value) & 0xFFFFFFFFFFFFFFFF
        if t == ida_hexrays.mop_r:
            return reg_values.get(mop.r)
        if t == ida_hexrays.mop_a and mop.a is not None:
            if mop.a.t == ida_hexrays.mop_v:
                return int(mop.a.g) & 0xFFFFFFFFFFFFFFFF
            return IndirectBranchResolver._eval_address_operand(mop.a, reg_values)
        if t == ida_hexrays.mop_d and mop.d is not None:
            return IndirectBranchResolver._eval_insn_to_ea(mop.d, reg_values)
        return None

    @staticmethod
    def _collect_runtime_global_writes(blocks: list["mblock_t"]) -> dict[int, int]:
        """Collect constant global writes visible in candidate predecessor blocks."""
        global_values: dict[int, int] = {}
        for candidate in reversed(blocks):
            ins = candidate.head
            while ins is not None:
                if (
                    ins.d.t == ida_hexrays.mop_v
                    and ins.opcode in (
                        ida_hexrays.m_mov,
                        ida_hexrays.m_add,
                        ida_hexrays.m_sub,
                        ida_hexrays.m_xor,
                        ida_hexrays.m_or,
                        ida_hexrays.m_and,
                    )
                ):
                    value = IndirectBranchResolver._eval_insn_constant(
                        ins, global_values
                    )
                    if value is not None:
                        global_values[int(ins.d.g)] = value & 0xFFFFFFFFFFFFFFFF
                ins = ins.next
        return global_values

    @staticmethod
    def _eval_insn_constant(insn, global_values: dict[int, int]) -> Optional[int]:
        """Evaluate arithmetic writes used by local-static init blocks."""
        if insn is None:
            return None
        op = insn.opcode
        if op == ida_hexrays.m_mov:
            return IndirectBranchResolver._eval_mop_constant(insn.l, global_values)
        if op in (
            ida_hexrays.m_add,
            ida_hexrays.m_sub,
            ida_hexrays.m_xor,
            ida_hexrays.m_or,
            ida_hexrays.m_and,
        ):
            left = IndirectBranchResolver._eval_mop_constant(insn.l, global_values)
            right = IndirectBranchResolver._eval_mop_constant(insn.r, global_values)
            if left is None or right is None:
                return None
            if op == ida_hexrays.m_add:
                return (left + right) & 0xFFFFFFFFFFFFFFFF
            if op == ida_hexrays.m_sub:
                return (left - right) & 0xFFFFFFFFFFFFFFFF
            if op == ida_hexrays.m_xor:
                return (left ^ right) & 0xFFFFFFFFFFFFFFFF
            if op == ida_hexrays.m_or:
                return (left | right) & 0xFFFFFFFFFFFFFFFF
            return (left & right) & 0xFFFFFFFFFFFFFFFF
        return None

    @staticmethod
    def _eval_mop_constant(mop, global_values: dict[int, int]) -> Optional[int]:
        """Evaluate a microcode operand to a concrete 64-bit value."""
        if mop is None:
            return None
        t = mop.t
        if t == ida_hexrays.mop_n:
            return int(mop.nnn.value) & 0xFFFFFFFFFFFFFFFF
        if t == ida_hexrays.mop_v:
            g = int(mop.g) & 0xFFFFFFFFFFFFFFFF
            if g in global_values:
                return global_values[g]
            return read_global_value(g, 8)
        if t == ida_hexrays.mop_a and mop.a is not None:
            if mop.a.t == ida_hexrays.mop_v:
                return int(mop.a.g) & 0xFFFFFFFFFFFFFFFF
            return IndirectBranchResolver._eval_mop_constant(mop.a, global_values)
        if t == ida_hexrays.mop_d and mop.d is not None:
            return IndirectBranchResolver._eval_insn_constant(mop.d, global_values)
        return None

    @staticmethod
    def _read_table_entries_with_overrides(
        table_ea: int,
        count: int,
        *,
        entry_size: int,
        global_overrides: dict[int, int],
    ) -> List[int]:
        """Read table entries with runtime global-write overrides."""
        entries: List[int] = []
        if entry_size <= 0:
            return entries
        if entry_size >= 8:
            mask = 0xFFFFFFFFFFFFFFFF
        else:
            mask = (1 << (entry_size * 8)) - 1

        for i in range(count):
            entry_ea = (table_ea + i * entry_size) & 0xFFFFFFFFFFFFFFFF
            if entry_ea in global_overrides:
                entries.append(global_overrides[entry_ea] & mask)
                continue
            value = read_global_value(entry_ea, entry_size)
            if value is None:
                break
            entries.append(int(value) & mask)

        return entries

    @staticmethod
    def _decode_valid_targets(
        raw_entries: List[int],
        encoding: TableEncoding,
        xor_key: int,
        base_offset: int,
        func_start: int,
        func_end: int,
    ) -> List[int]:
        """Decode raw table entries and keep targets that validate as code."""
        targets: List[int] = []
        consecutive_invalid = 0
        for raw in raw_entries:
            if raw == 0:
                consecutive_invalid += 1
                if consecutive_invalid >= MAX_CONSECUTIVE_INVALID:
                    break
                continue

            target = decode_table_entry(raw, encoding, xor_key, base_offset)
            if validate_code_target(target, func_start, func_end):
                targets.append(target)
                consecutive_invalid = 0
            else:
                consecutive_invalid += 1
                if consecutive_invalid >= MAX_CONSECUTIVE_INVALID:
                    break
        return targets

    @staticmethod
    def _resolve_base_offset_value(
        base_offset: int, global_overrides: dict[int, int]
    ) -> int:
        """Resolve OFFSET base from runtime writes or the IDB when possible."""
        if base_offset == 0:
            return 0
        base_ea = int(base_offset) & 0xFFFFFFFFFFFFFFFF
        if base_ea in global_overrides:
            return global_overrides[base_ea] & 0xFFFFFFFFFFFFFFFF
        db_value = read_global_value(base_ea, 8)
        if db_value not in (None, 0):
            return int(db_value) & 0xFFFFFFFFFFFFFFFF
        return base_ea

    # ------------------------------------------------------------------
    # Table discovery helpers
    # ------------------------------------------------------------------
    def _find_table_by_switch_info(self, blk: "mblock_t") -> Optional[int]:
        """Use IDA's ``get_switch_info`` to locate the jump table."""
        si = ida_nalt.switch_info_t()
        # Try block start and the ijmp EA
        for ea in (blk.start, blk.tail.ea if blk.tail else 0):
            if not ea:
                continue
            got_info = ida_nalt.get_switch_info(si, ea)
            if got_info:
                logger.debug(
                    "IndirectBranchResolver: switch_info found table at %#x",
                    si.jumps,
                )
                return si.jumps
        return None

    def _find_table_by_switch_info_blocks(
        self, blocks: list["mblock_t"]
    ) -> Optional[int]:
        """Try switch_info discovery over the ijmp block and its predecessors."""
        for candidate in blocks:
            table = self._find_table_by_switch_info(candidate)
            if table is not None:
                return table
        return None

    @staticmethod
    def _find_table_reference_in_blocks(
        blocks: list["mblock_t"],
    ) -> Optional[int]:
        """Find the first table reference across candidate predecessor blocks."""
        for candidate in blocks:
            table_ea = find_table_reference(candidate)
            if table_ea is not None:
                return table_ea
            ins = candidate.head
            while ins is not None:
                if ins.opcode == ida_hexrays.m_ldx:
                    table_ea = IndirectBranchResolver._extract_table_base_from_mop(
                        ins.r
                    )
                    if table_ea is None:
                        table_ea = IndirectBranchResolver._extract_table_base_from_mop(
                            ins.l
                        )
                    if table_ea is not None:
                        return table_ea
                ins = ins.next
        return None

    @staticmethod
    def _extract_table_base_from_mop(mop) -> Optional[int]:
        """Extract base global EA from m_ldx address expressions."""
        if mop is None:
            return None
        if mop.t == ida_hexrays.mop_v:
            return int(mop.g)
        if mop.t == ida_hexrays.mop_a and mop.a is not None:
            if mop.a.t == ida_hexrays.mop_v:
                return int(mop.a.g)
            return IndirectBranchResolver._extract_table_base_from_mop(mop.a)
        if mop.t == ida_hexrays.mop_d and mop.d is not None:
            ins = mop.d
            if ins.opcode in (ida_hexrays.m_add, ida_hexrays.m_sub):
                left = IndirectBranchResolver._extract_table_base_from_mop(ins.l)
                if left is not None:
                    return left
                return IndirectBranchResolver._extract_table_base_from_mop(ins.r)
        return None

    @staticmethod
    def _analyze_table_encoding_in_blocks(
        blocks: list["mblock_t"],
    ) -> tuple[TableEncoding, int, int]:
        """Merge encoding hints across ijmp block and predecessors."""
        has_xor = False
        has_add = False
        xor_key = 0
        base_addr = 0
        for candidate in blocks:
            encoding, key, base = analyze_table_encoding(candidate)
            if encoding == TableEncoding.OFFSET_XOR:
                return encoding, key, base
            if encoding == TableEncoding.XOR:
                has_xor = True
                if key:
                    xor_key = key
            elif encoding == TableEncoding.OFFSET:
                has_add = True
                if base:
                    base_addr = base
        if has_xor and has_add:
            return (TableEncoding.OFFSET_XOR, xor_key, base_addr)
        if has_xor:
            return (TableEncoding.XOR, xor_key, 0)
        if has_add:
            return (TableEncoding.OFFSET, 0, base_addr)
        return (TableEncoding.DIRECT, 0, 0)

    @staticmethod
    def _find_table_by_known_names() -> Optional[int]:
        """Search for Hikari-style named global tables."""
        for name in _HIKARI_TABLE_NAMES:
            ea = ida_name.get_name_ea(BADADDR, name)
            if ea != BADADDR:
                logger.debug(
                    "IndirectBranchResolver: found named table '%s' at %#x",
                    name, ea,
                )
                return ea
        return None

    # ------------------------------------------------------------------
    # Index bounds tracing
    # ------------------------------------------------------------------
    def _trace_index_bounds(self, blk: "mblock_t") -> int:
        """Walk backwards from ``m_ijmp`` looking for index-bounding ops.

        Recognised patterns:
        * ``m_and`` with a constant mask -- max index = mask + 1
        * ``m_low`` byte extraction   -- max index = 256
        * Nested ``m_sub`` + ``m_and`` -- same as ``m_and``

        Returns the maximum number of table entries to read.
        """
        ins = blk.tail
        while ins is not None:
            if ins.opcode == ida_hexrays.m_and:
                # AND with immediate mask
                if ins.r.t == ida_hexrays.mop_n:
                    mask = ins.r.nnn.value
                    max_index = int(mask) + 1
                    logger.debug(
                        "IndirectBranchResolver: index bound via AND mask %#x -> %d entries",
                        mask, max_index,
                    )
                    return min(max_index, MAX_TABLE_ENTRIES)
                if ins.l.t == ida_hexrays.mop_n:
                    mask = ins.l.nnn.value
                    max_index = int(mask) + 1
                    return min(max_index, MAX_TABLE_ENTRIES)

                # Check for nested m_sub inside m_and
                for operand in (ins.l, ins.r):
                    if (
                        operand.t == ida_hexrays.mop_d
                        and operand.d is not None
                        and operand.d.opcode == ida_hexrays.m_sub
                    ):
                        sub_ins = operand.d
                        # The mask is on the other operand of the AND
                        other = ins.r if operand is ins.l else ins.l
                        if other.t == ida_hexrays.mop_n:
                            mask = other.nnn.value
                            return min(int(mask) + 1, MAX_TABLE_ENTRIES)

            if ins.opcode == ida_hexrays.m_low:
                logger.debug(
                    "IndirectBranchResolver: index bound via LOW -> 256 entries",
                )
                return min(256, MAX_TABLE_ENTRIES)

            ins = ins.prev

        # Default: scan up to MAX_TABLE_ENTRIES
        return MAX_TABLE_ENTRIES

    def _trace_index_bounds_in_blocks(self, blocks: list["mblock_t"]) -> int:
        """Use the tightest mask/LOW bound discovered across candidate blocks."""
        bounds: list[int] = []
        for candidate in blocks:
            bound = self._trace_index_bounds(candidate)
            if bound != MAX_TABLE_ENTRIES:
                bounds.append(bound)
        if bounds:
            return min(bounds)
        return MAX_TABLE_ENTRIES

    @staticmethod
    def _collect_candidate_blocks(
        blk: "mblock_t", *, max_depth: int = 3
    ) -> list["mblock_t"]:
        """Collect ijmp block plus predecessor blocks up to max_depth."""
        mba = blk.mba
        queue: list[tuple[int, int]] = [(blk.serial, 0)]
        seen: set[int] = set()
        ordered: list["mblock_t"] = []
        while queue:
            serial, depth = queue.pop(0)
            if serial in seen:
                continue
            seen.add(serial)
            if serial < 0 or serial >= mba.qty:
                continue
            cur = mba.get_mblock(serial)
            ordered.append(cur)
            if depth >= max_depth:
                continue
            for pred in cur.predset:
                queue.append((int(pred), depth + 1))
        return ordered

    # ------------------------------------------------------------------
    # Target block resolution
    # ------------------------------------------------------------------
    @staticmethod
    def _resolve_target_blocks(
        mba: "ida_hexrays.mba_t", targets: List[int],
    ) -> List[Optional[int]]:
        """Map target EAs to block serial numbers."""
        result: List[Optional[int]] = []
        for target_ea in targets:
            found = None
            for i in range(mba.qty):
                mb = mba.get_mblock(i)
                if mb.start <= target_ea < mb.end:
                    found = i
                    break
            result.append(found)
        return result

    @staticmethod
    def _get_function_bounds(blk: "mblock_t") -> tuple[int, int]:
        """Return (func_start, func_end) for the function containing *blk*."""
        func = ida_funcs.get_func(blk.mba.entry_ea)
        if func is not None:
            return func.start_ea, func.end_ea
        return 0, 0

    # ------------------------------------------------------------------
    # CFG conversion
    # ------------------------------------------------------------------
    def _convert_to_goto(self, blk: "mblock_t", target_blk_idx: int) -> int:
        """Convert ``m_ijmp`` to ``m_goto`` targeting *target_blk_idx*.

        Uses a deferred pattern: captures only the block serial and target
        serial during analysis, then re-fetches fresh block pointers before
        applying the CFG modification.  The underlying ``cfg_utils`` helpers
        (``change_0way_block_successor`` / ``change_1way_block_successor``)
        handle all ``m_ijmp`` -> ``m_goto`` conversion, succset/predset
        bookkeeping, and ``mark_lists_dirty()`` calls.

        Returns 1 on success, 0 on failure.
        """
        # --- Analysis phase: capture only serials, not live pointers ---
        block_serial = blk.serial
        mba = blk.mba

        logger.info(
            "IndirectBranchResolver: converting block %d m_ijmp -> m_goto(blk %d)",
            block_serial, target_blk_idx,
        )

        # --- Apply phase: re-fetch fresh pointer and modify ---
        try:
            fresh_blk = mba.get_mblock(block_serial)
            if fresh_blk is None:
                logger.warning(
                    "IndirectBranchResolver: block %d no longer exists",
                    block_serial,
                )
                return 0

            if fresh_blk.nsucc() == 0:
                ok = change_0way_block_successor(
                    fresh_blk, target_blk_idx, verify=False,
                )
            else:
                ok = change_1way_block_successor(
                    fresh_blk, target_blk_idx, verify=False,
                )

            if ok:
                safe_verify(
                    mba,
                    f"after IndirectBranchResolver block {block_serial} -> {target_blk_idx}",
                    logger_func=logger.error,
                )
        except RuntimeError:
            logger.error(
                "IndirectBranchResolver: CFG modification failed for block %d",
                block_serial,
                exc_info=True,
            )
            return 0

        if ok:
            logger.info(
                "IndirectBranchResolver: block %d successfully converted to goto blk %d",
                block_serial, target_blk_idx,
            )
            return 1

        logger.warning(
            "IndirectBranchResolver: change_block_successor returned False for block %d",
            block_serial,
        )
        return 0

    # ------------------------------------------------------------------
    # Annotation
    # ------------------------------------------------------------------
    @staticmethod
    def _annotate_targets(blk: "mblock_t", targets: List[int]) -> None:
        """Add an IDB comment listing the resolved targets."""
        lines = [f"D810: Indirect jump resolved to {len(targets)} targets:"]
        for idx, target_ea in enumerate(targets):
            if idx >= 20:
                lines.append(f"  ... and {len(targets) - 20} more")
                break
            name = ida_name.get_name(target_ea)
            if name:
                lines.append(f"  [{idx}] {target_ea:#x} ({name})")
            else:
                lines.append(f"  [{idx}] {target_ea:#x}")

        comment = "\n".join(lines)
        idaapi.set_cmt(blk.start, comment, False)
        logger.info(
            "IndirectBranchResolver: annotated block %d with %d targets",
            blk.serial, len(targets),
        )

    # TODO(phase5): Add frameless continuation fallback (see stack_tracker.cpp)


# Populate SAFE_MATURITIES and CONFIG_SCHEMA now that the class is defined.
if True:
    IndirectBranchResolver.SAFE_MATURITIES = [ida_hexrays.MMAT_LOCOPT]
    IndirectBranchResolver.CONFIG_SCHEMA = FlowOptimizationRule.CONFIG_SCHEMA + (
        ConfigParam("table_entry_size", int, 8, "Jump table entry size in bytes"),
        ConfigParam(
            "candidate_max_depth",
            int,
            8,
            "Max predecessor traversal depth when collecting ijmp candidate blocks",
        ),
    )
