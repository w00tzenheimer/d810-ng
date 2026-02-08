"""Shared table-reading utilities for indirect branch and call resolution.

This module provides infrastructure shared by Phases 5 (Indirect Branch
Resolution) and 6 (Indirect Call Resolution).  Both phases need to read
jump/call tables from the IDB, decode encoded entries, and find
XOR-with-globals patterns.

The algorithms are ported from the Chernobog C++ plugin's
``indirect_branch.cpp`` and ``indirect_call.cpp`` handlers.
"""
from __future__ import annotations

import dataclasses
import enum
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# IDA-dependent imports -- guarded so unit tests can run without IDA.
# ---------------------------------------------------------------------------
try:
    import ida_bytes
    import ida_hexrays

    _IDA_AVAILABLE = True
except ImportError:
    ida_bytes = None  # type: ignore[assignment]
    ida_hexrays = None  # type: ignore[assignment]
    _IDA_AVAILABLE = False

if TYPE_CHECKING:
    from ida_hexrays import mblock_t

from d810.core import getLogger

logger = getLogger(__name__)


# ---------------------------------------------------------------------------
# 1. Table Encoding Enum
# ---------------------------------------------------------------------------
class TableEncoding(enum.IntEnum):
    """How entries in a jump/call table are encoded.

    Mirrors the ``table_encoding_t`` enum from Chernobog's deobf_types.h.
    """

    DIRECT = 0       # raw addresses
    OFFSET = 1       # table[i] + base
    XOR = 2          # table[i] ^ key
    OFFSET_XOR = 3   # (table[i] ^ key) + base


# ---------------------------------------------------------------------------
# 2. XorKeyInfo dataclass
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class XorKeyInfo:
    """Result of XOR-with-globals analysis.

    Produced by :func:`find_xor_with_globals` when a ``m_xor`` instruction
    combining an immediate value with a global variable is detected.
    """

    xor_key: int           # The XOR key value (immediate ^ global_value)
    is_negated: bool       # True if offset is negated (m_neg applied)
    source_ea: int         # EA of the global containing the key
    reg: int               # Register involved in the XOR


# ---------------------------------------------------------------------------
# 3. read_global_value
# ---------------------------------------------------------------------------
def read_global_value(ea: int, size: int) -> Optional[int]:
    """Read a scalar integer from the IDB at *ea* with the given *size*.

    Parameters
    ----------
    ea : int
        Effective address to read from.
    size : int
        Number of bytes to read (1, 2, 4, or 8).

    Returns
    -------
    int or None
        The integer value at *ea*, or ``None`` if the read failed.
    """
    if not _IDA_AVAILABLE:
        logger.warning("read_global_value called without IDA -- returning None")
        return None

    if ea == 0xFFFFFFFFFFFFFFFF:  # BADADDR
        return None

    raw = ida_bytes.get_bytes(ea, size)
    if raw is None or len(raw) != size:
        return None

    return int.from_bytes(raw, byteorder="little", signed=False)


# ---------------------------------------------------------------------------
# 4. read_table_entries
# ---------------------------------------------------------------------------
def read_table_entries(
    base_ea: int, count: int, entry_size: int = 8
) -> List[int]:
    """Read *count* table entries starting at *base_ea*.

    Parameters
    ----------
    base_ea : int
        Start address of the table.
    count : int
        Maximum number of entries to read.
    entry_size : int
        Size of each entry in bytes (default 8).

    Returns
    -------
    list[int]
        Raw integer values read from the table.  Stops early if a read
        fails.
    """
    entries: List[int] = []
    for i in range(count):
        val = read_global_value(base_ea + i * entry_size, entry_size)
        if val is None:
            break
        entries.append(val)
    return entries


# ---------------------------------------------------------------------------
# 5. decode_table_entry
# ---------------------------------------------------------------------------
def decode_table_entry(
    raw_value: int,
    encoding: TableEncoding,
    key: int = 0,
    base: int = 0,
) -> int:
    """Decode a single table entry according to *encoding*.

    Parameters
    ----------
    raw_value : int
        Raw integer read from the table.
    encoding : TableEncoding
        Encoding scheme.
    key : int
        XOR key (used by ``XOR`` and ``OFFSET_XOR``).
    base : int
        Base offset (used by ``OFFSET`` and ``OFFSET_XOR``).

    Returns
    -------
    int
        Decoded address.
    """
    if encoding == TableEncoding.DIRECT:
        return raw_value
    if encoding == TableEncoding.OFFSET:
        return base + raw_value
    if encoding == TableEncoding.XOR:
        return raw_value ^ key
    if encoding == TableEncoding.OFFSET_XOR:
        return base + (raw_value ^ key)
    # Unknown encoding -- treat as direct
    return raw_value


# ---------------------------------------------------------------------------
# 6. validate_code_target
# ---------------------------------------------------------------------------
def validate_code_target(
    ea: int,
    func_start: int = 0,
    func_end: int = 0,
) -> bool:
    """Check whether *ea* points to code.

    Parameters
    ----------
    ea : int
        Address to validate.
    func_start, func_end : int
        Optional function bounds.  When both are non-zero the target is also
        accepted if it falls within ``[func_start, func_end)``.

    Returns
    -------
    bool
    """
    if not _IDA_AVAILABLE:
        return False

    flags = ida_bytes.get_flags(ea)
    if ida_bytes.is_code(flags):
        return True

    if func_start and func_end and func_start <= ea < func_end:
        return True

    return False


# ---------------------------------------------------------------------------
# 7. find_xor_with_globals
# ---------------------------------------------------------------------------
def find_xor_with_globals(blk: "mblock_t") -> List[XorKeyInfo]:
    """Scan a microcode block for XOR patterns involving global values.

    Walks instructions from head to tail (matching Chernobog's forward
    iteration) and tracks:

    * ``m_mov`` of immediates and global loads to registers
    * ``m_ldx`` loading from globals
    * ``m_xor`` patterns between registers holding immediates and globals
    * ``m_neg`` to mark negated offsets

    Parameters
    ----------
    blk : mblock_t
        The microcode block to analyse.

    Returns
    -------
    list[XorKeyInfo]
        Discovered XOR key information.
    """
    if not _IDA_AVAILABLE:
        logger.warning("find_xor_with_globals called without IDA")
        return []

    if blk is None:
        return []

    results: List[XorKeyInfo] = []

    # Data-flow tracking maps: register -> value
    reg_immediates: Dict[int, int] = {}   # reg -> immediate value
    reg_globals: Dict[int, int] = {}      # reg -> global EA

    ins = blk.head
    while ins is not None:
        opcode = ins.opcode

        # -- Track m_mov: immediate or global to register ---------------
        if opcode == ida_hexrays.m_mov and ins.d.t == ida_hexrays.mop_r:
            if ins.l.t == ida_hexrays.mop_n:
                reg_immediates[ins.d.r] = ins.l.nnn.value
            elif ins.l.t == ida_hexrays.mop_v:
                reg_globals[ins.d.r] = ins.l.g

        # -- Track m_ldx: load from global to register ------------------
        if opcode == ida_hexrays.m_ldx and ins.d.t == ida_hexrays.mop_r:
            if ins.r.t == ida_hexrays.mop_v:
                reg_globals[ins.d.r] = ins.r.g
            elif (
                ins.r.t == ida_hexrays.mop_a
                and ins.r.a is not None
                and ins.r.a.t == ida_hexrays.mop_v
            ):
                reg_globals[ins.d.r] = ins.r.a.g

        # -- Look for m_xor patterns -----------------------------------
        if opcode == ida_hexrays.m_xor and ins.d.t == ida_hexrays.mop_r:
            dest_reg = ins.d.r
            immediate: Optional[int] = None
            global_addr: Optional[int] = None

            lt = ins.l.t
            rt = ins.r.t

            # Pattern: xor #imm, global
            if lt == ida_hexrays.mop_n and rt == ida_hexrays.mop_v:
                immediate = ins.l.nnn.value
                global_addr = ins.r.g
            # Pattern: xor global, #imm
            elif rt == ida_hexrays.mop_n and lt == ida_hexrays.mop_v:
                immediate = ins.r.nnn.value
                global_addr = ins.l.g
            # Pattern: xor reg, global (reg holds immediate)
            elif lt == ida_hexrays.mop_r and rt == ida_hexrays.mop_v:
                if ins.l.r in reg_immediates:
                    immediate = reg_immediates[ins.l.r]
                    global_addr = ins.r.g
            # Pattern: xor global, reg (reg holds immediate)
            elif rt == ida_hexrays.mop_r and lt == ida_hexrays.mop_v:
                if ins.r.r in reg_immediates:
                    immediate = reg_immediates[ins.r.r]
                    global_addr = ins.l.g
            # Pattern: xor reg1, reg2 (one imm, one global)
            elif lt == ida_hexrays.mop_r and rt == ida_hexrays.mop_r:
                if ins.l.r in reg_immediates and ins.r.r in reg_globals:
                    immediate = reg_immediates[ins.l.r]
                    global_addr = reg_globals[ins.r.r]
                elif ins.r.r in reg_immediates and ins.l.r in reg_globals:
                    immediate = reg_immediates[ins.r.r]
                    global_addr = reg_globals[ins.l.r]

            # If we matched, read the global and record the result
            if immediate is not None and global_addr is not None:
                gval = read_global_value(global_addr, 4)
                if gval is not None:
                    xor_key = immediate ^ gval
                    results.append(
                        XorKeyInfo(
                            xor_key=xor_key,
                            is_negated=False,
                            source_ea=global_addr,
                            reg=dest_reg,
                        )
                    )
                    logger.debug(
                        "XOR: 0x%x ^ [0x%x]=0x%x -> 0x%x",
                        immediate, global_addr, gval, xor_key,
                    )

            # Invalidate the destination register tracking
            reg_immediates.pop(dest_reg, None)
            reg_globals.pop(dest_reg, None)

        # -- Track m_neg: mark associated XOR result as negated ----------
        if opcode == ida_hexrays.m_neg and ins.d.t == ida_hexrays.mop_r:
            for info in results:
                if info.reg == ins.l.r or info.reg == ins.d.r:
                    info.is_negated = True
                    # Negate the key: -(signed)
                    info.xor_key = (-info.xor_key) & 0xFFFFFFFFFFFFFFFF
                    info.reg = ins.d.r
                    logger.debug(
                        "  -> Negated to 0x%x", info.xor_key,
                    )

        # -- Invalidate register tracking on other writes ---------------
        if (
            ins.d.t == ida_hexrays.mop_r
            and opcode != ida_hexrays.m_xor
            and opcode != ida_hexrays.m_neg
        ):
            if opcode != ida_hexrays.m_mov or (
                ins.l.t != ida_hexrays.mop_n and ins.l.t != ida_hexrays.mop_v
            ):
                reg_immediates.pop(ins.d.r, None)
                reg_globals.pop(ins.d.r, None)

        ins = ins.next

    return results


# ---------------------------------------------------------------------------
# 8. analyze_table_encoding
# ---------------------------------------------------------------------------
def analyze_table_encoding(
    blk: "mblock_t",
) -> Tuple[TableEncoding, int, int]:
    """Determine the table encoding used in *blk*.

    Traces instructions in the block looking for ``m_xor`` (with constant or
    global operand) and ``m_add`` (with global operand) patterns.

    Parameters
    ----------
    blk : mblock_t
        The microcode block to analyse.

    Returns
    -------
    tuple[TableEncoding, int, int]
        ``(encoding, xor_key, base_offset)``
    """
    if not _IDA_AVAILABLE or blk is None:
        return (TableEncoding.DIRECT, 0, 0)

    has_xor = False
    has_add = False
    xor_key = 0
    base_addr = 0

    ins = blk.head
    while ins is not None:
        # Look for XOR with constant
        if ins.opcode == ida_hexrays.m_xor:
            if ins.l.t == ida_hexrays.mop_n:
                has_xor = True
                xor_key = ins.l.nnn.value
            elif ins.r.t == ida_hexrays.mop_n:
                has_xor = True
                xor_key = ins.r.nnn.value
            elif ins.l.t == ida_hexrays.mop_v or ins.r.t == ida_hexrays.mop_v:
                # XOR with global -- try to read the value
                gaddr = (
                    ins.l.g if ins.l.t == ida_hexrays.mop_v else ins.r.g
                )
                gval = read_global_value(gaddr, 4)
                if gval is not None:
                    has_xor = True
                    # The key is derived from the global; simplified heuristic
                    xor_key = gval

        # Look for ADD with global address (base offset)
        if ins.opcode == ida_hexrays.m_add:
            if ins.l.t == ida_hexrays.mop_v:
                has_add = True
                base_addr = ins.l.g
            elif ins.r.t == ida_hexrays.mop_v:
                has_add = True
                base_addr = ins.r.g

        ins = ins.next

    if has_xor and has_add:
        return (TableEncoding.OFFSET_XOR, xor_key, base_addr)
    if has_xor:
        return (TableEncoding.XOR, xor_key, 0)
    if has_add:
        return (TableEncoding.OFFSET, 0, base_addr)
    return (TableEncoding.DIRECT, 0, 0)


# ---------------------------------------------------------------------------
# 9. find_table_reference
# ---------------------------------------------------------------------------
def find_table_reference(blk: "mblock_t") -> Optional[int]:
    """Find a global table address referenced in *blk*.

    Scans for ``m_ldx`` instructions whose operands reference a global
    address.  Returns the EA of the table, or ``None`` if none is found.

    Parameters
    ----------
    blk : mblock_t
        The microcode block to scan.

    Returns
    -------
    int or None
        The effective address of the referenced table, or ``None``.
    """
    if not _IDA_AVAILABLE or blk is None:
        return None

    ins = blk.head
    while ins is not None:
        if ins.opcode == ida_hexrays.m_ldx:
            # Check left operand for global reference
            if ins.l.t == ida_hexrays.mop_v:
                return ins.l.g
            # Check for nested add with global operand
            if (
                ins.l.t == ida_hexrays.mop_d
                and ins.l.d is not None
                and ins.l.d.opcode == ida_hexrays.m_add
            ):
                sub_ins = ins.l.d
                if sub_ins.l.t == ida_hexrays.mop_v:
                    return sub_ins.l.g
                if sub_ins.r.t == ida_hexrays.mop_v:
                    return sub_ins.r.g
            # Check right operand
            if ins.r.t == ida_hexrays.mop_v:
                return ins.r.g

        ins = ins.next

    return None
