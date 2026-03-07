"""Microcode dump tool for debugging and LLM analysis.

This module provides functionality to dump Hex-Rays microcode into
JSON format for debugging, visualization, and LLM-based analysis.

Usage (from IDA Python or via headless script):
    from d810.recon.microcode_dump import dump_microcode_json, dump_function_microcode

    # Dump to dict
    result = dump_function_microcode(func_ea)

    # Dump to JSON string
    json_str = dump_microcode_json(func_ea)

    # Dump to file
    dump_microcode_json(func_ea, output_path="/tmp/func.json")
"""

from __future__ import annotations

import json
import re
from d810.core.logging import getLogger
from dataclasses import dataclass, field, asdict
from enum import IntEnum

from d810.core.typing import List, Optional, Dict, Any, Union, Tuple, TYPE_CHECKING
from d810.recon.flow.bst_analysis import (
    analyze_bst_dispatcher,
    BSTAnalysisResult,
    _get_mop_const_value,
    _dump_dispatcher_node,
    _find_pre_header,
    _mop_matches_stkoff,
    _resolve_mop_value_in_block,
    _extract_state_from_block,
    _find_pre_header_state,
    _detect_state_var_stkoff,
)
from d810.recon.flow.transition_report import (
    build_dispatcher_transition_report,
)

# Defer IDA imports until needed - allows module to be imported for CLI --help
idaapi = None


def _ensure_ida_imports():
    """Lazy import IDA modules when actually needed."""
    global idaapi
    if idaapi is not None:
        return

    import idaapi as _idaapi

    idaapi = _idaapi

    # Ensure Hex-Rays definitions are available
    if not hasattr(idaapi, "MMAT_GENERATED"):
        try:
            import ida_hexrays

            for k, v in ida_hexrays.__dict__.items():
                if not k.startswith("_"):
                    setattr(idaapi, k, v)
        except ImportError:
            logging.warning(
                "Could not import ida_hexrays. Hex-Rays functionality may fail."
            )

# -----------------------------------------------------------------------------
# Configuration & Logging
# -----------------------------------------------------------------------------
logger = getLogger(__name__)

# -----------------------------------------------------------------------------
# Constants & Enums (lazily initialized)
# -----------------------------------------------------------------------------

# These will be populated when IDA is available
MATURITY_NAMES: Dict[int, str] = {}
OPCODE_MAP: Dict[int, str] = {}
MOP_TYPE_MAP: Dict[int, str] = {}
_maps_initialized = False


def _init_constants():
    """Initialize constant maps that require IDA imports."""
    global MATURITY_NAMES, OPCODE_MAP, MOP_TYPE_MAP, _maps_initialized
    if _maps_initialized:
        return

    _ensure_ida_imports()

    MATURITY_NAMES.update(
        {
            idaapi.MMAT_GENERATED: "MMAT_GENERATED",
            idaapi.MMAT_PREOPTIMIZED: "MMAT_PREOPTIMIZED",
            idaapi.MMAT_LOCOPT: "MMAT_LOCOPT",
            idaapi.MMAT_CALLS: "MMAT_CALLS",
            idaapi.MMAT_GLBOPT1: "MMAT_GLBOPT1",
            idaapi.MMAT_GLBOPT2: "MMAT_GLBOPT2",
            idaapi.MMAT_GLBOPT3: "MMAT_GLBOPT3",
            idaapi.MMAT_LVARS: "MMAT_LVARS",
        }
    )

    # Build opcode map
    for name in dir(idaapi):
        if name.startswith("m_"):
            try:
                val = getattr(idaapi, name)
                if isinstance(val, int):
                    OPCODE_MAP[val] = name
            except Exception:
                pass

    # Build mop type map
    for name in dir(idaapi):
        if name.startswith("mop_"):
            try:
                val = getattr(idaapi, name)
                if isinstance(val, int):
                    MOP_TYPE_MAP[val] = name
            except Exception:
                pass

    _maps_initialized = True

# -----------------------------------------------------------------------------
# Data Classes for JSON Serialization
# -----------------------------------------------------------------------------


@dataclass
class MopInfo:
    """Serializable representation of a microcode operand (mop_t)."""

    type: str
    type_num: int
    size: int
    dstr: str
    # Optional fields based on mop type
    value: Optional[int] = None  # For mop_n
    register: Optional[int] = None  # For mop_r
    global_ea: Optional[str] = None  # For mop_v (hex string)
    block_num: Optional[int] = None  # For mop_b
    string_value: Optional[str] = None  # For mop_str
    helper_name: Optional[str] = None  # For mop_h
    # Sub-operands for compound types
    sub_instruction: Optional["InstructionInfo"] = None  # For mop_d
    sub_operand: Optional["MopInfo"] = None  # For mop_a
    args: Optional[List["MopInfo"]] = None  # For mop_f (function call args)


@dataclass
class InstructionInfo:
    """Serializable representation of a microcode instruction (minsn_t)."""

    opcode: str
    opcode_num: int
    ea: str  # Hex string
    dstr: str  # Human-readable representation
    l: Optional[MopInfo] = None  # Left operand
    r: Optional[MopInfo] = None  # Right operand
    d: Optional[MopInfo] = None  # Destination operand


@dataclass
class BlockInfo:
    """Serializable representation of a microcode basic block (mblock_t)."""

    serial: int
    start_ea: str  # Hex string
    end_ea: str  # Hex string
    type: int
    type_name: str
    flags: int
    instructions: List[InstructionInfo] = field(default_factory=list)
    # CFG edges
    predecessors: List[int] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)


@dataclass
class FunctionMicrocode:
    """Complete microcode dump for a function."""

    function_name: str
    function_ea: str  # Hex string
    maturity: str
    maturity_num: int
    num_blocks: int
    blocks: List[BlockInfo] = field(default_factory=list)
    # CFG summary
    cfg_edges: List[Dict[str, int]] = field(default_factory=list)


# -----------------------------------------------------------------------------
# Conversion Functions
# -----------------------------------------------------------------------------


def mop_to_dict(mop: "idaapi.mop_t", depth: int = 0, max_depth: int = 10) -> Optional[Dict[str, Any]]:
    """Convert a mop_t to a dictionary for JSON serialization."""
    _init_constants()

    if mop is None or depth > max_depth:
        return None

    mop_type = getattr(mop, "t", None)
    if mop_type is None:
        return None

    type_name = MOP_TYPE_MAP.get(mop_type, f"unknown_{mop_type}")
    size = getattr(mop, "size", 0)

    # Get dstr representation
    try:
        dstr = str(mop.dstr()) if hasattr(mop, "dstr") else str(mop)
    except Exception:
        dstr = "<error>"

    result: Dict[str, Any] = {
        "type": type_name,
        "type_num": mop_type,
        "size": size,
        "dstr": dstr,
    }

    # Add type-specific fields
    if mop_type == idaapi.mop_n:  # Number
        nnn = getattr(mop, "nnn", None)
        if nnn is not None:
            result["value"] = getattr(nnn, "value", None)

    elif mop_type == idaapi.mop_r:  # Register
        result["register"] = getattr(mop, "r", None)

    elif mop_type == idaapi.mop_v:  # Global variable
        g = getattr(mop, "g", None)
        if g is not None:
            result["global_ea"] = f"0x{g:x}"

    elif mop_type == idaapi.mop_b:  # Block reference
        result["block_num"] = getattr(mop, "b", None)

    elif mop_type == idaapi.mop_str:  # String
        result["string_value"] = getattr(mop, "cstr", None)

    elif mop_type == idaapi.mop_h:  # Helper function
        result["helper_name"] = getattr(mop, "helper", None)

    elif mop_type == idaapi.mop_d:  # Sub-instruction
        sub_ins = getattr(mop, "d", None)
        if sub_ins is not None:
            result["sub_instruction"] = instruction_to_dict(sub_ins, depth + 1, max_depth)

    elif mop_type == idaapi.mop_a:  # Address (mop_addr_t)
        inner = getattr(mop, "a", None)
        if inner is not None:
            result["sub_operand"] = mop_to_dict(inner, depth + 1, max_depth)

    elif mop_type == idaapi.mop_f:  # Function call args
        f = getattr(mop, "f", None)
        if f is not None:
            args = getattr(f, "args", [])
            result["args"] = [mop_to_dict(arg, depth + 1, max_depth) for arg in args if arg is not None]

    elif mop_type == idaapi.mop_l:  # Local variable
        l = getattr(mop, "l", None)
        if l is not None:
            result["lvar_idx"] = getattr(l, "idx", None)

    elif mop_type == idaapi.mop_S:  # Stack variable
        s = getattr(mop, "s", None)
        if s is not None:
            result["stkoff"] = getattr(s, "off", None)

    elif mop_type == idaapi.mop_p:  # Pair
        pair = getattr(mop, "pair", None)
        if pair is not None:
            result["pair_low"] = mop_to_dict(getattr(pair, "lop", None), depth + 1, max_depth)
            result["pair_high"] = mop_to_dict(getattr(pair, "hop", None), depth + 1, max_depth)

    return result


def instruction_to_dict(
    ins: "idaapi.minsn_t", depth: int = 0, max_depth: int = 10
) -> Optional[Dict[str, Any]]:
    """Convert a minsn_t to a dictionary for JSON serialization."""
    if ins is None or depth > max_depth:
        return None

    opcode = getattr(ins, "opcode", None)
    if opcode is None:
        return None

    opcode_name = OPCODE_MAP.get(opcode, f"unknown_{opcode}")
    ea = getattr(ins, "ea", 0)

    # Get dstr representation
    try:
        dstr = str(ins._print()) if hasattr(ins, "_print") else str(ins)
        # Clean non-printable characters
        dstr = "".join(c if 0x20 <= ord(c) <= 0x7E else " " for c in dstr)
    except Exception:
        dstr = "<error>"

    result: Dict[str, Any] = {
        "opcode": opcode_name,
        "opcode_num": opcode,
        "ea": f"0x{ea:x}",
        "dstr": dstr,
    }

    # Add operands
    l_mop = getattr(ins, "l", None)
    r_mop = getattr(ins, "r", None)
    d_mop = getattr(ins, "d", None)

    if l_mop is not None:
        l_dict = mop_to_dict(l_mop, depth + 1, max_depth)
        if l_dict:
            result["l"] = l_dict

    if r_mop is not None:
        r_dict = mop_to_dict(r_mop, depth + 1, max_depth)
        if r_dict:
            result["r"] = r_dict

    if d_mop is not None:
        d_dict = mop_to_dict(d_mop, depth + 1, max_depth)
        if d_dict:
            result["d"] = d_dict

    return result


def block_to_dict(blk: "idaapi.mblock_t") -> Dict[str, Any]:
    """Convert a mblock_t to a dictionary for JSON serialization."""
    serial = blk.serial
    start_ea = getattr(blk, "start", 0)
    end_ea = getattr(blk, "end", 0)
    block_type = getattr(blk, "type", 0)
    flags = getattr(blk, "flags", 0)

    # Get block type name
    type_names = {
        0: "BLT_NONE",
        1: "BLT_STOP",
        2: "BLT_0WAY",
        3: "BLT_1WAY",
        4: "BLT_2WAY",
        5: "BLT_NWAY",
        6: "BLT_XTRN",
    }
    type_name = type_names.get(block_type, f"BLT_UNKNOWN_{block_type}")

    # Collect instructions
    instructions = []
    ins = blk.head
    while ins is not None:
        ins_dict = instruction_to_dict(ins)
        if ins_dict:
            instructions.append(ins_dict)
        ins = ins.next

    # Collect predecessors and successors
    predecessors = []
    successors = []

    # Get predecessors - use list() to convert intvec_t to Python list
    try:
        predecessors = list(blk.predset)
    except Exception:
        # Fallback: iterate manually
        for i in range(blk.predset.size()):
            predecessors.append(blk.predset[i])

    # Get successors - use list() to convert intvec_t to Python list
    try:
        successors = list(blk.succset)
    except Exception:
        # Fallback: iterate manually
        for i in range(blk.succset.size()):
            successors.append(blk.succset[i])

    return {
        "serial": serial,
        "start_ea": f"0x{start_ea:x}",
        "end_ea": f"0x{end_ea:x}",
        "type": block_type,
        "type_name": type_name,
        "flags": flags,
        "instructions": instructions,
        "predecessors": predecessors,
        "successors": successors,
    }


def mba_to_dict(mba: "idaapi.mbl_array_t", func_name: str = "") -> Dict[str, Any]:
    """Convert a mbl_array_t (microcode block array) to a dictionary."""
    _init_constants()

    entry_ea = getattr(mba, "entry_ea", 0)
    maturity = getattr(mba, "maturity", 0)
    maturity_name = MATURITY_NAMES.get(maturity, f"MMAT_UNKNOWN_{maturity}")
    num_blocks = mba.qty

    # Collect all blocks
    blocks = []
    cfg_edges = []

    for i in range(num_blocks):
        blk = mba.get_mblock(i)
        if blk is None:
            continue

        block_dict = block_to_dict(blk)
        blocks.append(block_dict)

        # Add CFG edges
        for succ in block_dict["successors"]:
            cfg_edges.append({"from": i, "to": succ})

    return {
        "function_name": func_name,
        "function_ea": f"0x{entry_ea:x}",
        "maturity": maturity_name,
        "maturity_num": maturity,
        "num_blocks": num_blocks,
        "blocks": blocks,
        "cfg_edges": cfg_edges,
    }


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------


def dump_function_microcode(
    func_ea: int,
    maturity: Optional[int] = None,
    max_depth: int = 10,
) -> Dict[str, Any]:
    """Dump microcode for a function at the given EA.

    Args:
        func_ea: Function entry address
        maturity: Optional maturity level (default: final maturity MMAT_LVARS)
        max_depth: Maximum recursion depth for nested operands

    Returns:
        Dictionary with complete microcode information
    """
    _ensure_ida_imports()
    import ida_funcs
    import ida_name

    # Get function
    func = ida_funcs.get_func(func_ea)
    if func is None:
        raise ValueError(f"No function found at 0x{func_ea:x}")

    func_name = ida_name.get_name(func_ea) or f"sub_{func_ea:x}"

    # Decompile to get microcode
    if maturity is None:
        maturity = idaapi.MMAT_LVARS

    try:
        # Use gen_microcode for specific maturity levels
        mbr = idaapi.mba_ranges_t()
        mbr.ranges.push_back(idaapi.range_t(func.start_ea, func.end_ea))

        hf = idaapi.hexrays_failure_t()
        mba = idaapi.gen_microcode(mbr, hf, None, idaapi.DECOMP_NO_WAIT, maturity)

        if mba is None:
            # Fall back to decompile
            cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            if cfunc is None:
                raise ValueError(f"Failed to decompile function at 0x{func_ea:x}")
            mba = cfunc.mba

    except Exception as e:
        # Fall back to decompile
        cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
        if cfunc is None:
            raise ValueError(f"Failed to decompile function at 0x{func_ea:x}: {e}")
        mba = cfunc.mba

    return mba_to_dict(mba, func_name)


def dump_microcode_json(
    func_ea: int,
    output_path: Optional[str] = None,
    maturity: Optional[int] = None,
    indent: int = 2,
) -> str:
    """Dump microcode for a function as JSON.

    Args:
        func_ea: Function entry address
        output_path: Optional path to write JSON file
        maturity: Optional maturity level
        indent: JSON indentation (default: 2)

    Returns:
        JSON string
    """
    data = dump_function_microcode(func_ea, maturity)
    json_str = json.dumps(data, indent=indent, ensure_ascii=False)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_str)
        logger.info(f"Microcode dumped to {output_path}")

    return json_str


def _fix_block_refs(s: str) -> str:
    """Fix _print() block references to IDA native format.

    ``_print()`` renders block targets as ``@ ) (ADDR16serial )`` where
    ``ADDR16`` is a 16-hex-char block address and ``serial`` is the decimal
    block number appended directly after it.  Replace every such pattern with
    ``@serial``, then collapse the spurious ``@ @`` artifact left in goto
    lines.

    Examples::

        '@ ) (00000000000000102 )' -> '@2'
        '0 =>  ) (00000000000000183 )' -> '0 => @3'
    """
    # Pattern: ') (' + exactly 16 hex chars + decimal digits + ' )'
    # Capture group 1: the trailing decimal serial
    s = re.sub(r'\) \([0-9A-Fa-f]{16}(\d+) \)', r'@\1', s)
    # goto lines end up with '@ @N' after the above substitution
    s = s.replace('@ @', '@')
    return s


def _fix_var_names(s: str, frsize: int) -> str:
    """Replace ``%var_XX.N`` placeholders with ``sp+0xOFF.N`` notation.

    IDA's ``minsn_t._print()`` emits stack variables as ``%var_HEX.size``
    where *HEX* is the frame-relative offset in hex.  IDA's native C++ dump
    shows them as ``sp+0xOFF.size`` where ``OFF = frsize - frame_hex``.

    Only converts names matching the ``%var_[0-9A-Fa-f]+`` pattern; register
    variables and other ``%``-prefixed names are left untouched.
    """
    if not frsize:
        return s

    def _repl(m: re.Match) -> str:
        frame_off = int(m.group(1), 16)
        size = m.group(2)
        sp_off = frsize - frame_off
        return f"sp+0x{sp_off:X}.{size}"

    return re.sub(r'%var_([0-9A-Fa-f]+)\.(\d+)', _repl, s)


def print_mba_human_readable(
    mba: "idaapi.mbl_array_t",
    func_name: str = "",
) -> None:
    """Print an mbl_array_t in IDA's native human-readable microcode format.

    Produces output similar to IDA's own microcode listing, including:
    - Block headers with type, predecessor/successor sets, EA range
    - USE/DEF/DNU liveness sets per block
    - VALRANGES per block (via :func:`d810.recon.flow.valranges.collect_block_valranges`)
    - Instructions via ``minsn_t._print()`` with per-instruction u=/d= annotations

    Args:
        mba: The microcode block array to print.
        func_name: Optional function name shown in the header.
    """
    from d810.recon.flow.valranges import collect_block_valranges

    _init_constants()

    entry_ea = getattr(mba, "entry_ea", 0)
    maturity = getattr(mba, "maturity", 0)

    # frsize is needed to convert %var_XX.N -> sp+0xOFF.N
    _frsize: int = (
        getattr(mba, "stacksize", 0)
        or getattr(mba, "frsize", 0)
        or 0
    )
    maturity_name = MATURITY_NAMES.get(maturity, f"MMAT_UNKNOWN_{maturity}")
    num_blocks = mba.qty

    # Block type enum: try runtime constants first, fall back to hard-coded
    try:
        import ida_hexrays as _ihr
        _BLT_NAMES = {
            _ihr.BLT_NONE: "BLT_NONE",
            _ihr.BLT_STOP: "BLT_STOP",
            _ihr.BLT_1WAY: "BLT_1WAY",
            _ihr.BLT_2WAY: "BLT_2WAY",
            _ihr.BLT_NWAY: "BLT_NWAY",
            _ihr.BLT_XTRN: "BLT_XTRN",
        }
    except Exception:
        _BLT_NAMES = {
            0: "BLT_NONE",
            1: "BLT_STOP",
            2: "BLT_1WAY",
            3: "BLT_2WAY",
            4: "BLT_NWAY",
            5: "BLT_XTRN",
        }

    # Flag constants
    try:
        import ida_hexrays as _ihr2
        MBL_FAKE = getattr(_ihr2, "MBL_FAKE", 0x200)
        MBL_INBOUNDS = getattr(_ihr2, "MBL_INBOUNDS", 0x0040)
        SHINS_NUMADDR = getattr(_ihr2, "SHINS_NUMADDR", 0x01)
        SHINS_VALNUM = getattr(_ihr2, "SHINS_VALNUM", 0x02)
        SHINS_SHORT = getattr(_ihr2, "SHINS_SHORT", 0x04)
    except Exception:
        MBL_FAKE = 0x200
        MBL_INBOUNDS = 0x0040
        SHINS_NUMADDR = 0x01
        SHINS_VALNUM = 0x02
        SHINS_SHORT = 0x04

    _PRINT_FLAGS = SHINS_SHORT | SHINS_VALNUM | SHINS_NUMADDR

    def _mlist_dstr(ml) -> str:
        if ml is None:
            return ""
        try:
            s = ml.dstr()
            return s if s else ""
        except Exception:
            return ""

    def _collect_bitset(bs) -> list:
        try:
            return list(bs)
        except Exception:
            try:
                return [bs[j] for j in range(bs.size())]
            except Exception:
                return []

    def _clean_insn_str(raw) -> str:
        if raw is None:
            return "<none>"
        return "".join(
            c if c == "\t" or 0x20 <= ord(c) <= 0x7E else " "
            for c in str(raw)
        ).rstrip()

    header = func_name or f"sub_{entry_ea:x}"
    print(f"; ===== Microcode: {header} @ 0x{entry_ea:x}  maturity={maturity_name}  blocks={num_blocks} =====")

    for i in range(num_blocks):
        blk = mba.get_mblock(i)
        if blk is None:
            continue

        serial = blk.serial
        start_ea = getattr(blk, "start", 0)
        end_ea = getattr(blk, "end", 0)
        block_type = getattr(blk, "type", 0)
        type_name = _BLT_NAMES.get(block_type, f"BLT_UNKNOWN_{block_type}")

        preds = _collect_bitset(blk.predset)
        succs = _collect_bitset(blk.succset)

        preds_str = ", ".join(str(p) for p in sorted(preds)) if preds else ""
        succs_str = ", ".join(str(s) for s in sorted(succs)) if succs else ""

        flags = getattr(blk, "flags", 0)
        is_inbounds = bool(flags & MBL_INBOUNDS)

        # Block header line
        inbounds_tag = " (INBOUNDS)" if is_inbounds else ""
        print(f"\nblock {serial}{inbounds_tag}: ; preds: {preds_str}; succs: {succs_str}")

        # Stack frame info on block 0
        if serial == 0:
            _stkd_parts = []
            for _attr in ("stacksize", "frsize", "argsize", "tmpstk_size"):
                _val = getattr(mba, _attr, None)
                if _val is not None:
                    _stkd_parts.append(f"{_attr}={_val}")
            _minargref = getattr(mba, "minargref", None)
            _minstkref = getattr(mba, "minstkref", None)
            _shadow_args = getattr(mba, "shadow_args", None)
            _pfn_flags = getattr(mba, "pfn_flags", None)
            _stkd_extra = []
            if _minargref is not None:
                _stkd_extra.append(f"MINARGREF={_minargref:#x}")
            if _minstkref is not None:
                _stkd_extra.append(f"MINSTKREF={_minstkref:#x}")
            if _shadow_args is not None:
                _stkd_extra.append(f"SHADOW={_shadow_args:#x}")
            if _pfn_flags is not None:
                _stkd_extra.append(f"FLAGS={_pfn_flags:#x}")
            _stkd_str = " ".join(_stkd_parts + _stkd_extra)
            if _stkd_str:
                print(f"; STKD: {_stkd_str}")

        # MAXBSP
        try:
            maxbsp = blk.maxbsp
            print(f"; MAXBSP: 0x{maxbsp:X}")
        except AttributeError:
            pass

        # USE / DEF / DNU liveness sets
        def_must = _mlist_dstr(getattr(blk, "mustbdef", None))
        dnu = _mlist_dstr(getattr(blk, "dnu", None))
        use_must = _mlist_dstr(getattr(blk, "mustbuse", None))
        use_may = _mlist_dstr(getattr(blk, "maybuse", None))
        def_may = _mlist_dstr(getattr(blk, "maybdef", None))

        def _paren_if_multi(s: str) -> str:
            return f"({s})" if "," in s else s

        use_parts = []
        if use_must:
            use_parts.append(use_must)
        if use_may and use_may != use_must:
            use_parts.append(f"(may:{use_may})")
        use_str = ", ".join(use_parts)

        def_parts = [def_must] if def_must else []
        if def_may and def_may != def_must:
            def_parts.append(f"(may:{def_may})")
        def_str = ", ".join(def_parts)

        print(f"; USE: {_paren_if_multi(use_str)} ; DEF: {_paren_if_multi(def_str)} ; DNU: {_paren_if_multi(dnu)}")

        # VALRANGES
        try:
            vr_parts = collect_block_valranges(blk)
            if vr_parts:
                print(f"; VALRANGES: {', '.join(vr_parts)}")
        except Exception:
            pass

        # Collect instructions
        insns = []
        ins = blk.head
        while ins is not None:
            insns.append(ins)
            ins = ins.next

        # Per-instruction use/def lists
        try:
            import ida_hexrays as _ihr_ins
            _mlist_t = _ihr_ins.mlist_t
            _MUST_ACCESS = _ihr_ins.MUST_ACCESS
            _MAY_ACCESS = _ihr_ins.MAY_ACCESS
            _has_mlist = True
        except Exception:
            _has_mlist = False

        for insn_idx, ins in enumerate(insns, start=1):
            ea = getattr(ins, "ea", 0)
            try:
                insn_str = _clean_insn_str(ins._print(_PRINT_FLAGS))
            except Exception:
                try:
                    insn_str = _clean_insn_str(ins._print())
                except Exception as exc:
                    insn_str = f"<error: {exc}>"

            insn_str = _fix_block_refs(insn_str)
            insn_str = _fix_var_names(insn_str, _frsize)

            ins_use = ""
            ins_def = ""
            if _has_mlist:
                try:
                    must_use_ml = _mlist_t()
                    blk.build_use_list(must_use_ml, ins, _MUST_ACCESS)
                    ins_use = must_use_ml.dstr() if not must_use_ml.empty() else ""
                except Exception:
                    try:
                        ul = ins.build_use_list(0)
                        ins_use = ul.dstr() if ul is not None else ""
                    except Exception:
                        pass
                try:
                    must_def_ml = _mlist_t()
                    blk.build_def_list(must_def_ml, ins, _MUST_ACCESS)
                    ins_def = must_def_ml.dstr() if not must_def_ml.empty() else ""
                except Exception:
                    try:
                        dl = ins.build_def_list(0)
                        ins_def = dl.dstr() if dl is not None else ""
                    except Exception:
                        try:
                            ins_def = ins.d.dstr()
                        except Exception:
                            pass
            else:
                try:
                    ul = ins.build_use_list(0)
                    ins_use = ul.dstr() if ul is not None else ""
                except Exception:
                    pass
                try:
                    dl = ins.build_def_list(0)
                    ins_def = dl.dstr() if dl is not None else ""
                except Exception:
                    try:
                        ins_def = ins.d.dstr()
                    except Exception:
                        pass

            ins_use = _fix_var_names(ins_use, _frsize)
            ins_def = _fix_var_names(ins_def, _frsize)

            ea_str = f"{ea:016X}"
            suffix = f" ; {ea_str} u={ins_use} d={ins_def}"

            print(f"  {serial}.{insn_idx - 1:<4} {insn_str:<50}{suffix}")

    print(f"\n; ===== End microcode: {header} =====")


def dump_mba_json(
    mba: "idaapi.mbl_array_t",
    func_name: str = "",
    output_path: Optional[str] = None,
    indent: int = 2,
) -> str:
    """Dump an existing mbl_array_t as JSON.

    Useful when you already have an mba from a callback/hook.

    Args:
        mba: The microcode block array
        func_name: Optional function name
        output_path: Optional path to write JSON file
        indent: JSON indentation

    Returns:
        JSON string
    """
    data = mba_to_dict(mba, func_name)
    json_str = json.dumps(data, indent=indent, ensure_ascii=False)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_str)
        logger.info(f"Microcode dumped to {output_path}")

    return json_str


# -----------------------------------------------------------------------------
# Dispatcher Tree Visualization
# (BST analysis helpers imported from d810.recon.flow.bst_analysis)
# -----------------------------------------------------------------------------


def dump_dispatcher_tree(
    mba: "idaapi.mbl_array_t",
    dispatcher_entry_serial: int,
    state_var_stkoff: int = None,
    state_constants: set = None,
    transitions: dict = None,
    max_depth: int = 20,
) -> str:
    """Walk the BST dispatcher and return a full state machine visualization.

    Outputs three sections:
    1. Pre-header: the block that initializes the state variable.
    2. BST tree: the binary search tree of comparison blocks.
    3. Handler transitions: for each handler, the next-state written and
       whether it loops back to the dispatcher or exits.

    Args:
        mba: The microcode block array.
        dispatcher_entry_serial: Block serial number of the BST root.
        state_var_stkoff: Optional stack offset of the state variable. Used to
            extract state writes in handler chains and pre-header.
        state_constants: Optional set of known state constant values (from Hodur
            detector). Used for annotation only.
        transitions: Optional dict mapping handler info from Hodur detector.
            If provided, used to annotate handler transition entries.
        max_depth: Maximum recursion depth to guard against malformed CFGs.

    Returns:
        Multi-section string (not printed — caller decides what to do with it).
    """
    _init_constants()
    sections: List[str] = []

    # Diagnostics collected during pre-header search and first-3-handler walks
    diag_section: List[str] = []

    # Auto-detect state_var_stkoff (and lvar_idx for mop_l) from the BST root
    state_var_lvar_idx: Optional[int] = None
    if state_var_stkoff is None:
        (detected, detected_lvar_idx), detect_diag = _detect_state_var_stkoff(
            mba, dispatcher_entry_serial, diag=True
        )
        if detect_diag:
            diag_section.extend(detect_diag)
        if detected is not None:
            state_var_stkoff = detected
            state_var_lvar_idx = detected_lvar_idx
            lvar_note = (
                f" lvar_idx={detected_lvar_idx}" if detected_lvar_idx is not None else ""
            )
            diag_section.append(
                f"Auto-detected state_var_stkoff=0x{detected:x}{lvar_note}"
                f" from blk[{dispatcher_entry_serial}]"
            )

    # --- Section 1: Pre-header ---
    sections.append("=== STATE MACHINE ===")
    pre_header_serial, initial_state = _find_pre_header_state(
        mba, dispatcher_entry_serial, state_var_stkoff, diag_lines=diag_section,
        state_var_lvar_idx=state_var_lvar_idx,
    )
    if pre_header_serial is not None:
        state_str = f"0x{initial_state:08x}" if initial_state is not None else "<unknown>"
        sections.append(
            f"Pre-header: blk[{pre_header_serial}] -> state = {state_str}"
            f" -> dispatcher blk[{dispatcher_entry_serial}]"
        )
    else:
        sections.append(
            f"Pre-header: <not found> -> dispatcher blk[{dispatcher_entry_serial}]"
        )
    sections.append("")

    # --- Section 2: BST tree ---
    sections.append("=== DISPATCHER BST ===")
    bst_lines: List[str] = []
    bst_visited: set = set()
    handler_state_map: Dict[int, int] = {}   # handler_serial -> state_constant (from BST leaf)
    handler_serials: set = set()
    handler_range_map: Dict[int, Tuple[Optional[int], Optional[int]]] = {}  # handler_serial -> (lo, hi)

    _dump_dispatcher_node(
        mba,
        dispatcher_entry_serial,
        indent=0,
        visited=bst_visited,
        lines=bst_lines,
        depth=0,
        max_depth=max_depth,
        value_lo=0,
        value_hi=0xFFFFFFFF,
        handler_state_map=handler_state_map,
        handler_serials=handler_serials,
        handler_range_map=handler_range_map,
    )
    sections.extend(bst_lines)
    sections.append("")

    # --- Section 3: Handler transitions ---
    sections.append("=== HANDLER TRANSITIONS ===")

    if not handler_serials:
        sections.append("<no handlers found in BST>")
    else:
        report = build_dispatcher_transition_report(
            mba=mba,
            dispatcher_entry_serial=dispatcher_entry_serial,
            state_var_stkoff=state_var_stkoff,
            transitions_hint_by_handler=transitions,
            state_var_lvar_idx=state_var_lvar_idx,
            capture_diagnostics=True,
            max_diag_handlers=3,
        )
        if report.diagnostics:
            diag_section.extend(list(report.diagnostics))

        for row in report.rows:
            chain_str = f"chain={list(row.chain_preview)}" if row.chain_preview else ""
            sections.append(
                f"{row.state_label} -> blk[{row.handler_serial}]:  "
                f"{row.transition_label}  {chain_str}"
            )

        sections.append("")
        sections.append(
            f"Summary: {report.summary.handlers_total} handlers, "
            f"{report.summary.known_count} with known transitions, "
            f"{report.summary.conditional_count} conditional, "
            f"{report.summary.exit_count} exits, "
            f"{report.summary.unknown_count} unknown"
        )

    # --- Section 4: Diagnostics ---
    if diag_section:
        sections.append("")
        sections.append("=== DIAGNOSTICS (pre-header + first 3 handlers) ===")
        sections.extend(diag_section)

    return "\n".join(sections)


# -----------------------------------------------------------------------------
# CLI / IDA Script Entry Point
# -----------------------------------------------------------------------------


def main_cli():
    """Command-line interface for microcode dump tool."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Dump Hex-Rays microcode to JSON for debugging and analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dump function at address 0x650 from a binary
  python -m d810.recon.microcode_dump binary.dylib 0x650

  # Dump at specific maturity level
  python -m d810.recon.microcode_dump binary.dylib 0x650 --maturity PREOPTIMIZED

  # Save output to file
  python -m d810.recon.microcode_dump binary.dylib 0x650 -o output.json
        """,
    )
    parser.add_argument("binary", help="Path to the binary file to analyze")
    parser.add_argument(
        "address",
        help="Function address (hex or decimal, e.g., 0x650 or 1616)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output file path (default: stdout)",
    )
    parser.add_argument(
        "-m",
        "--maturity",
        choices=["GENERATED", "PREOPTIMIZED", "LOCOPT", "CALLS", "GLBOPT1", "GLBOPT2", "GLBOPT3", "LVARS"],
        default="LVARS",
        help="Microcode maturity level (default: LVARS)",
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=2,
        help="JSON indentation (default: 2)",
    )

    args = parser.parse_args()

    # Parse address
    try:
        if args.address.startswith("0x") or args.address.startswith("0X"):
            func_ea = int(args.address, 16)
        else:
            func_ea = int(args.address)
    except ValueError:
        print(f"Error: Invalid address '{args.address}'", file=sys.stderr)
        sys.exit(1)

    # Open database first (this makes idaapi available)
    try:
        import idapro

        idapro.open_database(args.binary, run_auto_analysis=True)
    except Exception as e:
        print(f"Error opening database: {e}", file=sys.stderr)
        sys.exit(1)

    # Now import and map maturity constants (after IDA is loaded)
    _ensure_ida_imports()

    maturity_map = {
        "GENERATED": idaapi.MMAT_GENERATED,
        "PREOPTIMIZED": idaapi.MMAT_PREOPTIMIZED,
        "LOCOPT": idaapi.MMAT_LOCOPT,
        "CALLS": idaapi.MMAT_CALLS,
        "GLBOPT1": idaapi.MMAT_GLBOPT1,
        "GLBOPT2": idaapi.MMAT_GLBOPT2,
        "GLBOPT3": idaapi.MMAT_GLBOPT3,
        "LVARS": idaapi.MMAT_LVARS,
    }
    maturity = maturity_map[args.maturity]

    # Dump microcode
    try:
        json_output = dump_microcode_json(
            func_ea,
            output_path=args.output,
            maturity=maturity,
            indent=args.indent,
        )
        if not args.output:
            print(json_output)
    except Exception as e:
        print(f"Error dumping microcode: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    import sys

    # Check if running inside IDA (idc module available)
    try:
        import idc

        # Running inside IDA - dump current function
        _ensure_ida_imports()
        ea = idc.here()
        func = idaapi.get_func(ea)
        if func:
            json_output = dump_microcode_json(func.start_ea)
            print(json_output)
        else:
            print(f"No function at current address 0x{ea:x}")
    except ImportError:
        # Running from command line
        main_cli()
