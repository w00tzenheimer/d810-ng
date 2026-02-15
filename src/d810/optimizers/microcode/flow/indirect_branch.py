"""Indirect Branch Resolution -- copycat Phase 5.

Resolves obfuscated indirect jumps (``m_ijmp``) by analysing encoded jump
tables, decoding entries, and converting them to direct jumps (``m_goto``).

The algorithm is ported from copycat's ``indirect_branch.cpp`` handler and
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

# ---------------------------------------------------------------------------
# IDA-dependent imports -- guarded so unit tests can run without IDA.
# ---------------------------------------------------------------------------
try:
    import ida_bytes
    import ida_funcs
    import ida_hexrays
    import ida_nalt
    import ida_name
    import idaapi

    _IDA_AVAILABLE = True
except ImportError:
    ida_bytes = None  # type: ignore[assignment]
    ida_funcs = None  # type: ignore[assignment]
    ida_hexrays = None  # type: ignore[assignment]
    ida_nalt = None  # type: ignore[assignment]
    ida_name = None  # type: ignore[assignment]
    idaapi = None  # type: ignore[assignment]
    _IDA_AVAILABLE = False

if TYPE_CHECKING:
    from ida_hexrays import mblock_t

from d810.core import getLogger
from d810.hexrays.table_utils import (
    TableEncoding,
    analyze_table_encoding,
    decode_table_entry,
    find_table_reference,
    read_table_entries,
    validate_code_target,
)

from d810.optimizers.microcode.handler import ConfigParam

if _IDA_AVAILABLE:
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

BADADDR: int = 0xFFFFFFFFFFFFFFFF

# Known Hikari global table names (searched as a fallback).
_HIKARI_TABLE_NAMES: list[str] = [
    "IndirectBranchingGlobalTable",
    "HikariConditionalLocalIndirectBranchingTable",
    "IndirectBranchTable",
]


# ---------------------------------------------------------------------------
# IndirectBranchResolver
# ---------------------------------------------------------------------------
if _IDA_AVAILABLE:
    _BASE_CLASS = FlowOptimizationRule
else:
    # Provide a dummy base so the module can be imported in tests without IDA.
    import abc

    class _DummyBase(abc.ABC):  # type: ignore[no-redef]
        USES_DEFERRED_CFG = True
        SAFE_MATURITIES: list[int] = []

        def __init__(self) -> None:
            self.maturities: list[int] = []
            self.config: dict = {}

        def configure(self, kwargs: dict) -> None:  # type: ignore[override]
            self.config = kwargs or {}

        @abc.abstractmethod
        def optimize(self, blk: object) -> int:
            raise NotImplementedError

    _BASE_CLASS = _DummyBase  # type: ignore[assignment,misc]


class IndirectBranchResolver(_BASE_CLASS):
    """Resolve obfuscated indirect jumps by analysing encoded jump tables.

    This rule detects ``m_ijmp`` instructions, locates the backing jump
    table, decodes its entries according to the detected encoding scheme,
    and -- when all entries resolve to a single block -- converts the
    indirect jump to a direct ``m_goto``.

    Configuration keys
    ------------------
    table_entry_size : int
        Size of each table entry in bytes (default ``8``).
    """

    NAME = "IndirectBranchResolver"
    DESCRIPTION = "Resolves obfuscated indirect jumps by analysing encoded jump tables"
    CATEGORY = "Indirect Jumps"
    USES_DEFERRED_CFG = True  # Uses DeferredGraphModifier for CFG changes
    SAFE_MATURITIES: list[int] = []  # Populated after class definition when IDA is available

    def __init__(self) -> None:
        super().__init__()
        self.table_entry_size: int = DEFAULT_TABLE_ENTRY_SIZE
        if _IDA_AVAILABLE:
            self.maturities = [ida_hexrays.MMAT_LOCOPT]

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
        """Attempt to resolve an indirect jump in *blk*.

        Returns the number of changes (0 or 1).
        """
        if not _IDA_AVAILABLE:
            return 0

        # 1. Check if block ends in m_ijmp
        if blk.tail is None or blk.tail.opcode != ida_hexrays.m_ijmp:
            return 0

        logger.debug(
            "IndirectBranchResolver: analysing block %d (m_ijmp at %#x)",
            blk.serial, blk.tail.ea,
        )

        # 2. Find the jump table reference
        table_ea = find_table_reference(blk)
        if table_ea is None:
            table_ea = self._find_table_by_switch_info(blk)
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
        encoding, xor_key, base_offset = analyze_table_encoding(blk)
        logger.debug(
            "IndirectBranchResolver: encoding=%s key=%#x base=%#x",
            encoding.name, xor_key, base_offset,
        )

        # 4. Determine table size (trace index bounds)
        max_entries = self._trace_index_bounds(blk)

        # 5. Read and decode table entries
        func_start, func_end = self._get_function_bounds(blk)
        raw_entries = read_table_entries(
            table_ea, max_entries, entry_size=self.table_entry_size,
        )

        targets: List[int] = []
        consecutive_invalid = 0
        for raw in raw_entries:
            if raw == 0:
                # Zero entry typically marks end of table
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

        if not targets:
            logger.debug(
                "IndirectBranchResolver: no valid targets for block %d",
                blk.serial,
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
    # Table discovery helpers
    # ------------------------------------------------------------------
    def _find_table_by_switch_info(self, blk: "mblock_t") -> Optional[int]:
        """Use IDA's ``get_switch_info`` to locate the jump table."""
        si = ida_nalt.switch_info_t()
        # Try block start and the ijmp EA
        for ea in (blk.start, blk.tail.ea if blk.tail else 0):
            if ea and ida_nalt.get_switch_info(si, ea) > 0:
                logger.debug(
                    "IndirectBranchResolver: switch_info found table at %#x",
                    si.jumps,
                )
                return si.jumps
        return None

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
if _IDA_AVAILABLE:
    IndirectBranchResolver.SAFE_MATURITIES = [ida_hexrays.MMAT_LOCOPT]
    IndirectBranchResolver.CONFIG_SCHEMA = FlowOptimizationRule.CONFIG_SCHEMA + (
        ConfigParam("table_entry_size", int, 8, "Jump table entry size in bytes"),
    )
