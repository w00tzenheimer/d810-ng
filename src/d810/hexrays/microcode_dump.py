"""Microcode dump tool for debugging and LLM analysis.

This module provides functionality to dump Hex-Rays microcode into
JSON format for debugging, visualization, and LLM-based analysis.

Usage (from IDA Python or via headless script):
    from d810.hexrays.microcode_dump import dump_microcode_json, dump_function_microcode

    # Dump to dict
    result = dump_function_microcode(func_ea)

    # Dump to JSON string
    json_str = dump_microcode_json(func_ea)

    # Dump to file
    dump_microcode_json(func_ea, output_path="/tmp/func.json")
"""

from __future__ import annotations

import json
from d810.core.logging import getLogger
from dataclasses import dataclass, field, asdict
from enum import IntEnum

from d810.core.typing import List, Optional, Dict, Any, Union, Tuple, TYPE_CHECKING

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
# -----------------------------------------------------------------------------


def _get_mop_const_value(mop: "idaapi.mop_t") -> Optional[int]:
    """Extract a constant integer value from a mop_t if it is a number operand."""
    _init_constants()
    if mop is None:
        return None
    mop_type = getattr(mop, "t", None)
    if mop_type == idaapi.mop_n:
        nnn = getattr(mop, "nnn", None)
        if nnn is not None:
            return getattr(nnn, "value", None)
    return None


def _dump_dispatcher_node(
    mba: "idaapi.mbl_array_t",
    serial: int,
    indent: int,
    visited: set,
    lines: List[str],
    depth: int,
    max_depth: int,
    value_lo: Optional[int] = None,
    value_hi: Optional[int] = None,
    handler_state_map: Optional[Dict[int, int]] = None,
    handler_serials: Optional[set] = None,
    handler_range_map: Optional[Dict[int, Tuple[Optional[int], Optional[int]]]] = None,
    chain_depth: int = 0,
) -> None:
    """Recursive helper for dump_dispatcher_tree.

    Args:
        value_lo: Inclusive lower bound of state values that can reach this node.
        value_hi: Inclusive upper bound of state values that can reach this node.
        handler_state_map: If provided, maps handler_serial -> state_constant extracted
            from the leaf comparison node (jnz/jz).
        handler_serials: If provided, collects all handler block serials seen at leaves.
        handler_range_map: If provided, maps handler_serial -> (value_lo, value_hi) from
            the BST path leading to that handler leaf.
        chain_depth: Current depth of m_jnz chain recursion (max 10).
    """
    _init_constants()

    if depth > max_depth:
        lines.append("  " * indent + f"blk[{serial}] <max depth reached>")
        return

    if serial in visited:
        lines.append("  " * indent + f"blk[{serial}] <already visited>")
        return
    visited.add(serial)

    blk = mba.get_mblock(serial)
    if blk is None:
        lines.append("  " * indent + f"blk[{serial}] <null block>")
        return

    insn = blk.tail
    if insn is None:
        lines.append("  " * indent + f"blk[{serial}] <no tail instruction>")
        return

    opcode = getattr(insn, "opcode", None)
    opcode_name = OPCODE_MAP.get(opcode, f"opcode_{opcode}") if opcode is not None else "unknown"

    succs = [blk.succ(i) for i in range(blk.nsucc())]

    # Determine comparison constant from l or r operand
    l_val = _get_mop_const_value(getattr(insn, "l", None))
    r_val = _get_mop_const_value(getattr(insn, "r", None))
    cmp_val = l_val if l_val is not None else r_val

    prefix = "  " * indent

    is_jbe = opcode is not None and hasattr(idaapi, "m_jbe") and opcode == idaapi.m_jbe
    is_ja = opcode is not None and hasattr(idaapi, "m_ja") and opcode == idaapi.m_ja
    is_jnz = opcode is not None and hasattr(idaapi, "m_jnz") and opcode == idaapi.m_jnz
    is_jz = opcode is not None and hasattr(idaapi, "m_jz") and opcode == idaapi.m_jz

    if is_jbe or is_ja:
        cmp_str = f"<= 0x{cmp_val:x}" if cmp_val is not None else "<= ?"
        lines.append(f"{prefix}blk[{serial}] {opcode_name} {cmp_str} (succs: {succs})")

        # Propagate narrowed ranges to successors.
        # succs[0] = fall-through branch, succs[1] = jump/taken branch.
        # m_jbe: if state_var <= X → jump (succs[1]); else fall-through (succs[0])
        #   fall-through range: [X+1, hi]  (state > X)
        #   taken      range:   [lo,  X]   (state <= X)
        # m_ja: if state_var > X → jump (succs[1]); else fall-through (succs[0])
        #   fall-through range: [lo,  X]   (state <= X)
        #   taken      range:   [X+1, hi]  (state > X)
        X = cmp_val
        MASK = 0xFFFFFFFF
        if is_jbe:
            fall_lo = (X + 1) & MASK if X is not None else None
            fall_hi = value_hi
            taken_lo = value_lo
            taken_hi = X
        else:  # m_ja
            fall_lo = value_lo
            fall_hi = X
            taken_lo = (X + 1) & MASK if X is not None else None
            taken_hi = value_hi

        child_ranges = [(fall_lo, fall_hi), (taken_lo, taken_hi)]
        for idx, s in enumerate(succs):
            c_lo, c_hi = child_ranges[idx] if idx < len(child_ranges) else (None, None)
            _dump_dispatcher_node(
                mba, s, indent + 1, visited, lines, depth + 1, max_depth,
                value_lo=c_lo,
                value_hi=c_hi,
                handler_state_map=handler_state_map,
                handler_serials=handler_serials,
                handler_range_map=handler_range_map,
                chain_depth=chain_depth,
            )

    elif is_jnz or is_jz:
        op_sym = "==" if is_jz else "!="
        cmp_str = f"0x{cmp_val:x}" if cmp_val is not None else "?"
        # succs[0] = fall-through, succs[1] = jump target
        fall_blk = succs[0] if succs else "?"
        jump_blk = succs[1] if len(succs) > 1 else "?"

        # Derive states from the BST range rather than V-1/V+1 heuristic.
        # For m_jnz != V:
        #   fall-through (succs[0]) = state == V  → fall_state = V
        #   jump target  (succs[1]) = state != V  → jump_state = the other value in [lo..hi]
        # For m_jz == V:
        #   fall-through (succs[0]) = state != V  → fall_state = the other value in [lo..hi]
        #   jump target  (succs[1]) = state == V  → jump_state = V
        range_known = value_lo is not None and value_hi is not None
        range_is_pair = range_known and (value_hi - value_lo == 1)

        if is_jnz:
            fall_state = cmp_val
            if range_is_pair and cmp_val is not None:
                jump_state = value_lo if cmp_val == value_hi else value_hi
            else:
                jump_state = None
        else:  # m_jz
            jump_state = cmp_val
            if range_is_pair and cmp_val is not None:
                fall_state = value_lo if cmp_val == value_hi else value_hi
            else:
                fall_state = None

        # Build display strings for range and derived states.
        range_str = ""
        if range_known:
            range_str = f" [range: 0x{value_lo:x}..0x{value_hi:x}]"
        jump_state_str = f"state=0x{jump_state:x}" if jump_state is not None else "state=?"
        fall_state_str = f"state=0x{fall_state:x}" if fall_state is not None else "state=?"

        lines.append(
            f"{prefix}blk[{serial}] {opcode_name} {op_sym} {cmp_str}{range_str}"
            f" -> fall-through blk[{fall_blk}] ({fall_state_str})"
            f" jump blk[{jump_blk}] ({jump_state_str})"
        )

        # Helper: determine if a block serial is a BST comparison node
        # (has a conditional tail opcode and exactly 2 successors).
        _bst_opcodes = set()
        for _attr in ("m_jbe", "m_ja", "m_jnz", "m_jz"):
            _v = getattr(idaapi, _attr, None)
            if _v is not None:
                _bst_opcodes.add(_v)

        def _is_bst_node(blk_serial: int) -> bool:
            if blk_serial in visited:
                return False
            _b = mba.get_mblock(blk_serial)
            if _b is None or _b.nsucc() != 2:
                return False
            _tail = _b.tail
            if _tail is None:
                return False
            return getattr(_tail, "opcode", None) in _bst_opcodes

        # Compute narrowed range for the "not-equal" continuation path.
        # When recursing from m_jnz != V, V is excluded from the range.
        MASK = 0xFFFFFFFF

        def _narrow_range_excluding(v, lo, hi):
            """Return (new_lo, new_hi) after excluding v from [lo..hi].

            If v == lo, the new range is [lo+1, hi].
            If v == hi, the new range is [lo, hi-1].
            Otherwise (v is in the interior), the range cannot be expressed as a
            single contiguous interval, so return (lo, hi) unchanged.
            """
            if v is None or lo is None or hi is None:
                return lo, hi
            if v == lo:
                return (lo + 1) & MASK, hi
            if v == hi:
                return lo, (hi - 1) & MASK
            return lo, hi

        # Check whether cmp_val falls within the active range for this BST node.
        # If cmp_val is outside [value_lo, value_hi] the equality branch is dead
        # code planted by the obfuscator; do not register it as a handler.
        cmp_in_range = (
            value_lo is not None
            and value_hi is not None
            and cmp_val is not None
            and value_lo <= cmp_val <= value_hi
        )

        # Variant of _is_bst_node that skips the visited-set check — used for
        # chain recursion (m_jnz/m_jz continuation path) so that a node already
        # visited via interior recursion (with a wide range) can still be
        # re-entered from a chain to produce a narrower range.
        def _is_bst_node_chain(blk_serial: int) -> bool:
            _b = mba.get_mblock(blk_serial)
            if _b is None or _b.nsucc() != 2:
                return False
            _tail = _b.tail
            if _tail is None:
                return False
            return getattr(_tail, "opcode", None) in _bst_opcodes

        MAX_CHAIN_DEPTH = 10

        if is_jnz:
            # fall-through (succs[0]) is state == V → handler leaf only when V is in range
            if isinstance(fall_blk, int):
                if cmp_val is None:
                    lines.append(f"{prefix}  [unknown cmp_val: cannot classify fall-through blk[{fall_blk}]]")
                elif not cmp_in_range:
                    lines.append(
                        f"{prefix}  [dead-code: 0x{cmp_val:x} outside range"
                        f" 0x{value_lo:x}..0x{value_hi:x}]"
                    )
                else:
                    if handler_serials is not None:
                        handler_serials.add(fall_blk)
                    if handler_state_map is not None and fall_state is not None:
                        handler_state_map[fall_blk] = fall_state
                    if handler_range_map is not None:
                        handler_range_map[fall_blk] = (value_lo, value_hi)

            # jump target (succs[1]) is state != V → recurse if BST node, else handler.
            # For the chain path: bypass visited check; guard by chain_depth instead.
            if isinstance(jump_blk, int):
                already_resolved = (
                    handler_state_map is not None
                    and jump_blk in handler_state_map
                    and handler_state_map[jump_blk] is not None
                )
                if not already_resolved and _is_bst_node_chain(jump_blk) and chain_depth < MAX_CHAIN_DEPTH:
                    new_lo, new_hi = _narrow_range_excluding(cmp_val, value_lo, value_hi)
                    _dump_dispatcher_node(
                        mba, jump_blk, indent + 1, visited, lines, depth + 1, max_depth,
                        value_lo=new_lo,
                        value_hi=new_hi,
                        handler_state_map=handler_state_map,
                        handler_serials=handler_serials,
                        handler_range_map=handler_range_map,
                        chain_depth=chain_depth + 1,
                    )
                elif not already_resolved and not _is_bst_node_chain(jump_blk):
                    if cmp_val is None:
                        lines.append(f"{prefix}  [unknown cmp_val: cannot classify jump blk[{jump_blk}]]")
                    elif handler_serials is not None:
                        handler_serials.add(jump_blk)
                        if handler_state_map is not None and jump_state is not None:
                            handler_state_map[jump_blk] = jump_state
                        if handler_range_map is not None:
                            handler_range_map[jump_blk] = (value_lo, value_hi)

        else:  # m_jz
            # jump target (succs[1]) is state == V → handler leaf only when V is in range
            if isinstance(jump_blk, int):
                if cmp_val is None:
                    lines.append(f"{prefix}  [unknown cmp_val: cannot classify jump blk[{jump_blk}]]")
                elif not cmp_in_range:
                    lines.append(
                        f"{prefix}  [dead-code: 0x{cmp_val:x} outside range"
                        f" 0x{value_lo:x}..0x{value_hi:x}]"
                    )
                else:
                    if handler_serials is not None:
                        handler_serials.add(jump_blk)
                    if handler_state_map is not None and jump_state is not None:
                        handler_state_map[jump_blk] = jump_state
                    if handler_range_map is not None:
                        handler_range_map[jump_blk] = (value_lo, value_hi)

            # fall-through (succs[0]) is state != V → recurse if BST node, else handler.
            # For the chain path: bypass visited check; guard by chain_depth instead.
            if isinstance(fall_blk, int):
                already_resolved = (
                    handler_state_map is not None
                    and fall_blk in handler_state_map
                    and handler_state_map[fall_blk] is not None
                )
                if not already_resolved and _is_bst_node_chain(fall_blk) and chain_depth < MAX_CHAIN_DEPTH:
                    new_lo, new_hi = _narrow_range_excluding(cmp_val, value_lo, value_hi)
                    _dump_dispatcher_node(
                        mba, fall_blk, indent + 1, visited, lines, depth + 1, max_depth,
                        value_lo=new_lo,
                        value_hi=new_hi,
                        handler_state_map=handler_state_map,
                        handler_serials=handler_serials,
                        handler_range_map=handler_range_map,
                        chain_depth=chain_depth + 1,
                    )
                elif not already_resolved and not _is_bst_node_chain(fall_blk):
                    if cmp_val is None:
                        lines.append(f"{prefix}  [unknown cmp_val: cannot classify fall-through blk[{fall_blk}]]")
                    elif handler_serials is not None:
                        handler_serials.add(fall_blk)
                        if handler_state_map is not None and fall_state is not None:
                            handler_state_map[fall_blk] = fall_state
                        if handler_range_map is not None:
                            handler_range_map[fall_blk] = (value_lo, value_hi)

    else:
        cmp_str = f"0x{cmp_val:x}" if cmp_val is not None else "?"
        lines.append(
            f"{prefix}blk[{serial}] {opcode_name} {cmp_str} (succs: {succs})"
        )


def _find_pre_header(
    mba: "idaapi.mbl_array_t",
    dispatcher_entry_serial: int,
    diag_lines: Optional[List[str]] = None,
) -> Optional[int]:
    """Find the pre-header block that initializes the state variable.

    The pre-header is the predecessor of the dispatcher entry block that is
    NOT a handler back-edge (i.e., it has only one successor: the dispatcher).

    Args:
        mba: The microcode block array.
        dispatcher_entry_serial: Block serial of the dispatcher entry.
        diag_lines: Optional list to collect diagnostic output strings.

    Returns:
        Serial of the pre-header block, or None if not found.
    """
    blk = mba.get_mblock(dispatcher_entry_serial)
    if blk is None:
        return None

    if diag_lines is not None:
        preds = [blk.pred(i) for i in range(blk.npred())]
        diag_lines.append(
            f"_find_pre_header: dispatcher=blk[{dispatcher_entry_serial}]"
            f" npred={blk.npred()} preds={preds}"
        )

    # Collect all candidates with nsucc=1 targeting the dispatcher,
    # then prefer the one with the fewest predecessors (the real pre-header
    # comes from the function entry and has npred=0 or 1; handler back-edges
    # have more predecessors).
    best_serial: Optional[int] = None
    best_npred: int = 999999
    for i in range(blk.npred()):
        pred_serial = blk.pred(i)
        pred_blk = mba.get_mblock(pred_serial)
        if pred_blk is None:
            continue
        nsucc = pred_blk.nsucc()
        pred_npred = pred_blk.npred()
        tail = pred_blk.tail
        tail_opcode = getattr(tail, "opcode", None) if tail is not None else None
        tail_opname = OPCODE_MAP.get(tail_opcode, f"opcode_{tail_opcode}") if tail_opcode is not None else "no_tail"
        if diag_lines is not None:
            diag_lines.append(
                f"  pred blk[{pred_serial}]: nsucc={nsucc} npred={pred_npred}"
                f" tail={tail_opname}"
                + (f" succ0=blk[{pred_blk.succ(0)}]" if nsucc >= 1 else "")
            )
        # Pre-header has exactly one successor: the dispatcher entry
        if nsucc == 1 and pred_blk.succ(0) == dispatcher_entry_serial:
            # Prefer fewest predecessors; break ties by lowest serial
            if pred_npred < best_npred or (pred_npred == best_npred and pred_serial < best_serial):
                best_npred = pred_npred
                best_serial = pred_serial
    if best_serial is not None and diag_lines is not None:
        diag_lines.append(f"  -> selected pre-header: blk[{best_serial}] (npred={best_npred})")
    return best_serial


def _mop_matches_stkoff(
    mop: "idaapi.mop_t",
    state_var_stkoff: int,
    diag_lines: Optional[List[str]] = None,
    state_var_lvar_idx: Optional[int] = None,
    mba: Optional["idaapi.mbl_array_t"] = None,
) -> bool:
    """Return True if mop is a stack variable operand at the given stack offset.

    Handles mop_S (direct stack var), mop_a wrapping a mop_S (address-of
    pattern used in m_stx instructions), and mop_l (local variable promoted
    from stack var at higher maturity levels such as GLBOPT2).

    Args:
        mop: The microcode operand to test.
        state_var_stkoff: Stack offset of the state variable.
        diag_lines: Optional list to collect diagnostic strings.
        state_var_lvar_idx: If not None, match mop_l by lvar index directly.
        mba: If provided and state_var_lvar_idx is None, fall back to
            ``mba.vars[idx].location.stkoff()`` comparison for mop_l operands.
    """
    if mop is None:
        return False
    mop_type = getattr(mop, "t", None)
    mop_S_type = getattr(idaapi, "mop_S", None)
    mop_a_type = getattr(idaapi, "mop_a", None)
    mop_l_type = getattr(idaapi, "mop_l", None)

    if diag_lines is not None:
        mop_type_name = MOP_TYPE_MAP.get(mop_type, f"unknown_{mop_type}") if mop_type is not None else "None"
        diag_lines.append(
            f"    _mop_matches_stkoff: mop.t={mop_type_name}({mop_type})"
            f" target_stkoff=0x{state_var_stkoff:x}"
            f" mop_S_type={mop_S_type} mop_a_type={mop_a_type} mop_l_type={mop_l_type}"
            f" state_var_lvar_idx={state_var_lvar_idx}"
        )

    # Direct stack variable (mop_S)
    if mop_type == mop_S_type:
        s = getattr(mop, "s", None)
        if s is not None:
            off = getattr(s, "off", None)
            if diag_lines is not None:
                diag_lines.append(f"      -> mop_S: s.off=0x{off:x} match={off == state_var_stkoff}")
            return off == state_var_stkoff

    # Address-of a stack variable (mop_a containing mop_S) — used by m_stx
    if mop_type == mop_a_type:
        inner = getattr(mop, "a", None)
        if inner is not None:
            inner_type = getattr(inner, "t", None)
            if inner_type == mop_S_type:
                s = getattr(inner, "s", None)
                if s is not None:
                    off = getattr(s, "off", None)
                    if diag_lines is not None:
                        diag_lines.append(f"      -> mop_a->mop_S: s.off=0x{off:x} match={off == state_var_stkoff}")
                    return off == state_var_stkoff

    # Local variable (mop_l) — promoted stack var at GLBOPT2 maturity
    if mop_l_type is not None and mop_type == mop_l_type:
        lref = getattr(mop, "l", None)
        if lref is not None:
            idx = getattr(lref, "idx", None)
            if diag_lines is not None:
                diag_lines.append(
                    f"      -> mop_l: lvar idx={idx}"
                    f" state_var_lvar_idx={state_var_lvar_idx}"
                )
            if idx is not None:
                # Fast path: match by lvar index if we know it
                if state_var_lvar_idx is not None:
                    match = idx == state_var_lvar_idx
                    if diag_lines is not None:
                        diag_lines.append(f"      -> mop_l idx match={match}")
                    return match
                # Fallback: resolve stkoff via mba.vars when lvar_idx unknown
                if mba is not None:
                    try:
                        lvar = mba.vars[idx]
                        off = lvar.location.stkoff()
                        match = off == state_var_stkoff
                        if diag_lines is not None:
                            diag_lines.append(
                                f"      -> mop_l mba.vars[{idx}].stkoff()=0x{off:x} match={match}"
                            )
                        return match
                    except Exception as exc:
                        if diag_lines is not None:
                            diag_lines.append(f"      -> mop_l stkoff lookup failed: {exc}")

    return False


def _extract_state_from_block(
    blk: "idaapi.mblock_t",
    state_var_stkoff: int,
    diag_lines: Optional[List[str]] = None,
    state_var_lvar_idx: Optional[int] = None,
    mba: Optional["idaapi.mbl_array_t"] = None,
) -> Optional[int]:
    """Scan a block's instructions for a write to state_var_stkoff.

    Handles two patterns:
    - ``m_mov <const>, <mop_S stkoff=N>`` — simple stack-variable move
    - ``m_mov <const>, <mop_l lvar_idx=N>`` — local-var move at GLBOPT2
    - ``m_stx <const>, <addr_of_stkoff>, <size>`` — store via address, used at
      GLBOPT1/2 maturity levels

    Args:
        blk: The microcode block to scan.
        state_var_stkoff: Stack offset of the state variable.
        diag_lines: Optional list to collect diagnostic strings.
        state_var_lvar_idx: If not None, also match mop_l writes by lvar index.
        mba: Passed to ``_mop_matches_stkoff`` for mop_l fallback stkoff lookup.

    Returns the constant value written, or None if not found.
    """
    _init_constants()
    m_mov_opcode = getattr(idaapi, "m_mov", None)
    m_stx_opcode = getattr(idaapi, "m_stx", None)

    if m_mov_opcode is None:
        return None

    insn = blk.head
    insn_idx = 0
    while insn is not None:
        opcode = getattr(insn, "opcode", None)
        opcode_name = OPCODE_MAP.get(opcode, f"opcode_{opcode}") if opcode is not None else "None"

        l_mop = getattr(insn, "l", None)
        r_mop = getattr(insn, "r", None)
        d_mop = getattr(insn, "d", None)

        l_t = getattr(l_mop, "t", None) if l_mop is not None else None
        r_t = getattr(r_mop, "t", None) if r_mop is not None else None
        d_t = getattr(d_mop, "t", None) if d_mop is not None else None

        l_tname = MOP_TYPE_MAP.get(l_t, f"unknown_{l_t}") if l_t is not None else "None"
        r_tname = MOP_TYPE_MAP.get(r_t, f"unknown_{r_t}") if r_t is not None else "None"
        d_tname = MOP_TYPE_MAP.get(d_t, f"unknown_{d_t}") if d_t is not None else "None"

        if diag_lines is not None:
            diag_lines.append(
                f"  insn[{insn_idx}]: {opcode_name}"
                f"  l.t={l_tname}  r.t={r_tname}  d.t={d_tname}"
            )

        if opcode == m_mov_opcode:
            d = getattr(insn, "d", None)
            if _mop_matches_stkoff(
                d, state_var_stkoff, diag_lines=diag_lines,
                state_var_lvar_idx=state_var_lvar_idx, mba=mba,
            ):
                l = getattr(insn, "l", None)
                val = _get_mop_const_value(l)
                if val is not None:
                    if diag_lines is not None:
                        diag_lines.append(f"  -> FOUND m_mov state write: 0x{val:x}")
                    return val

        elif m_stx_opcode is not None and opcode == m_stx_opcode:
            # m_stx <value>, <addr>, <size_mop>
            # l = value being stored, r = destination address
            r = getattr(insn, "r", None)
            if _mop_matches_stkoff(
                r, state_var_stkoff, diag_lines=diag_lines,
                state_var_lvar_idx=state_var_lvar_idx, mba=mba,
            ):
                l = getattr(insn, "l", None)
                val = _get_mop_const_value(l)
                if val is not None:
                    if diag_lines is not None:
                        diag_lines.append(f"  -> FOUND m_stx state write: 0x{val:x}")
                    return val

        insn = getattr(insn, "next", None)
        insn_idx += 1
    return None


def _walk_handler_chain(
    mba: "idaapi.mbl_array_t",
    handler_start_serial: int,
    dispatcher_entry_serial: int,
    state_var_stkoff: int,
    chain_visited: Optional[set] = None,
    max_chain_depth: int = 64,
    diag_lines: Optional[List[str]] = None,
    state_var_lvar_idx: Optional[int] = None,
) -> Dict[str, Any]:
    """Walk a handler's block chain to find the next-state write and back-edge.

    Follows single-successor chains. Scans each block for an m_mov write to
    the state variable (matched by stkoff or lvar index). Stops at:
    - Blocks with multiple predecessors (potential merge/join)
    - The dispatcher entry (back-edge detected)
    - A block with no successors (function exit)
    - Max depth exceeded

    Args:
        mba: The microcode block array.
        handler_start_serial: First block of this handler.
        dispatcher_entry_serial: Serial of the dispatcher entry block.
        state_var_stkoff: Stack offset of the state variable.
        chain_visited: External visited set to avoid re-walking shared blocks.
        max_chain_depth: Maximum blocks to walk per handler.
        diag_lines: Optional list to collect diagnostic output strings.
        state_var_lvar_idx: If not None, also match mop_l writes by lvar index.

    Returns:
        Dict with keys:
            - next_state: int or None — constant written to state var
            - back_edge: bool — True if chain reaches dispatcher
            - exit: bool — True if chain reaches a no-successor block
            - chain: List[int] — block serials walked
    """
    _init_constants()
    result: Dict[str, Any] = {
        "next_state": None,
        "back_edge": False,
        "exit": False,
        "chain": [],
    }

    if chain_visited is None:
        chain_visited = set()

    if diag_lines is not None:
        diag_lines.append(
            f"  walker start: blk[{handler_start_serial}]"
            f" dispatcher=blk[{dispatcher_entry_serial}]"
            f" stkoff=0x{state_var_stkoff:x}"
        )

    current = handler_start_serial
    depth = 0

    while current is not None and depth < max_chain_depth:
        if current in chain_visited:
            if diag_lines is not None:
                diag_lines.append(f"  walker: blk[{current}] already in chain_visited -> stop")
            break
        chain_visited.add(current)
        result["chain"].append(current)

        if current == dispatcher_entry_serial:
            result["back_edge"] = True
            if diag_lines is not None:
                diag_lines.append(f"  walker: blk[{current}] == dispatcher_entry -> back_edge stop")
            break

        blk = mba.get_mblock(current)
        if blk is None:
            if diag_lines is not None:
                diag_lines.append(f"  walker: blk[{current}] is None -> stop")
            break

        num_insns = 0
        tmp = blk.head
        while tmp is not None:
            num_insns += 1
            tmp = getattr(tmp, "next", None)

        if diag_lines is not None:
            diag_lines.append(f"  walker: visiting blk[{current}] ({num_insns} insns)")

        # Scan for state variable write if not yet found
        if result["next_state"] is None and state_var_stkoff is not None:
            val = _extract_state_from_block(
                blk, state_var_stkoff, diag_lines=diag_lines,
                state_var_lvar_idx=state_var_lvar_idx, mba=mba,
            )
            if val is not None:
                result["next_state"] = val
                if diag_lines is not None:
                    diag_lines.append(f"  walker: found next_state=0x{val:x} in blk[{current}]")

        nsucc = blk.nsucc()
        if nsucc == 0:
            result["exit"] = True
            if diag_lines is not None:
                diag_lines.append(f"  walker: blk[{current}] nsucc=0 -> exit stop")
            break
        if nsucc == 1:
            next_serial = blk.succ(0)
            if diag_lines is not None:
                diag_lines.append(f"  walker: blk[{current}] nsucc=1 -> follow blk[{next_serial}]")
            # Check if next block is dispatcher entry (back-edge)
            if next_serial == dispatcher_entry_serial:
                result["back_edge"] = True
                if diag_lines is not None:
                    diag_lines.append(f"  walker: next blk[{next_serial}] == dispatcher -> back_edge stop")
                break
            # Continue walking — do NOT stop on multi-predecessor blocks.
            # Handler blocks in a flattened loop naturally have multiple
            # predecessors (multiple BST leaves route adjacent state values
            # to the same handler block). Stopping there prevents finding
            # the state variable write.
            current = next_serial
        else:
            # Multiple successors — handler branches internally.
            # Still scan this block for state write before stopping.
            # (The scan above already ran on this block, so just stop.)
            succs = [blk.succ(i) for i in range(nsucc)]
            if diag_lines is not None:
                diag_lines.append(
                    f"  walker: blk[{current}] nsucc={nsucc} succs={succs} -> multi-succ stop"
                )
            break

        depth += 1

    if diag_lines is not None:
        diag_lines.append(
            f"  walker done: next_state={result['next_state']} "
            f"back_edge={result['back_edge']} exit={result['exit']} "
            f"chain={result['chain']}"
        )

    return result


def _find_pre_header_state(
    mba: "idaapi.mbl_array_t",
    dispatcher_entry_serial: int,
    state_var_stkoff: Optional[int],
    diag_lines: Optional[List[str]] = None,
    state_var_lvar_idx: Optional[int] = None,
) -> tuple:
    """Find pre-header block and extract initial state constant.

    Args:
        mba: The microcode block array.
        dispatcher_entry_serial: Block serial of the BST root.
        state_var_stkoff: Stack offset of the state variable.
        diag_lines: Optional list to collect diagnostic strings.
        state_var_lvar_idx: If not None, also match mop_l writes by lvar index.

    Returns:
        Tuple of (pre_header_serial: Optional[int], initial_state: Optional[int])
    """
    pre_header_serial = _find_pre_header(mba, dispatcher_entry_serial, diag_lines=diag_lines)
    if pre_header_serial is None or state_var_stkoff is None:
        return pre_header_serial, None
    blk = mba.get_mblock(pre_header_serial)
    if blk is None:
        return pre_header_serial, None
    initial_state = _extract_state_from_block(
        blk, state_var_stkoff, diag_lines=diag_lines,
        state_var_lvar_idx=state_var_lvar_idx, mba=mba,
    )
    return pre_header_serial, initial_state


def _detect_state_var_stkoff(
    mba: "idaapi.mbl_array_t",
    dispatcher_entry_serial: int,
    diag: bool = False,
):
    """Auto-detect the state variable stack offset from the BST root comparison.

    The BST root block's tail instruction is a conditional jump (jbe/ja/jnz/jz)
    whose left operand is the state variable.  If that operand is a direct stack
    variable (mop_S), its ``.s.off`` is the stkoff we need.  If the operand is
    a register (mop_r), we try to find the stack variable via the register's
    definition chain.  If it is a local variable (mop_l, promoted at GLBOPT2),
    we return both the stkoff and the lvar index.

    Args:
        mba: The microcode block array.
        dispatcher_entry_serial: Block serial of the BST root.
        diag: If True, return ((stkoff, lvar_idx), diag_lines) tuple.

    Returns:
        If diag=False: Tuple of (stkoff_or_None, lvar_idx_or_None).
        If diag=True: Tuple of ((stkoff_or_None, lvar_idx_or_None), diag_lines_list).
    """
    _init_constants()
    diag_lines: List[str] = [] if diag else None

    def _return(stkoff, lvar_idx=None):
        result = (stkoff, lvar_idx)
        if diag:
            return result, diag_lines
        return result

    mop_S_type = getattr(idaapi, "mop_S", None)
    mop_r_type = getattr(idaapi, "mop_r", None)

    blk = mba.get_mblock(dispatcher_entry_serial)
    if blk is None:
        if diag_lines is not None:
            diag_lines.append(f"_detect_stkoff: blk[{dispatcher_entry_serial}] is None")
        return _return(None)

    tail = getattr(blk, "tail", None)
    if tail is None:
        if diag_lines is not None:
            diag_lines.append(f"_detect_stkoff: blk[{dispatcher_entry_serial}] has no tail")
        return _return(None)

    left = getattr(tail, "l", None)
    if left is None:
        if diag_lines is not None:
            diag_lines.append(f"_detect_stkoff: tail has no .l operand")
        return _return(None)

    mop_type = getattr(left, "t", None)
    if diag_lines is not None:
        diag_lines.append(
            f"_detect_stkoff: blk[{dispatcher_entry_serial}] tail opcode={tail.opcode}"
            f" left.t={mop_type} (mop_S={mop_S_type}, mop_r={mop_r_type})"
        )

    # Direct stack variable (mop_S)
    if mop_type == mop_S_type:
        s = getattr(left, "s", None)
        if s is not None:
            off = getattr(s, "off", None)
            if off is not None:
                if diag_lines is not None:
                    diag_lines.append(f"_detect_stkoff: mop_S hit -> stkoff=0x{off:x}")
                return _return(off, None)

    # Register (mop_r) — try to find underlying stack variable
    if mop_type == mop_r_type:
        reg = getattr(left, "r", None)
        if diag_lines is not None:
            diag_lines.append(f"_detect_stkoff: mop_r register={reg}")
        # Walk instructions in the block looking for m_mov from mop_S to this reg
        insn = blk.head
        while insn is not None:
            d = getattr(insn, "d", None)
            if d is not None and getattr(d, "t", None) == mop_r_type and getattr(d, "r", None) == reg:
                src = getattr(insn, "l", None)
                if src is not None and getattr(src, "t", None) == mop_S_type:
                    s = getattr(src, "s", None)
                    if s is not None:
                        off = getattr(s, "off", None)
                        if off is not None:
                            if diag_lines is not None:
                                diag_lines.append(f"_detect_stkoff: found m_mov mop_S(0x{off:x}) -> reg{reg}")
                            return _return(off, None)
            insn = getattr(insn, "next", None)
        if diag_lines is not None:
            diag_lines.append(f"_detect_stkoff: no mop_S source found for reg{reg} in blk[{dispatcher_entry_serial}]")

    # Local variable (mop_l) — promoted stack var at higher maturity levels
    mop_l_type = getattr(idaapi, "mop_l", None)
    if mop_type == mop_l_type:
        lref = getattr(left, "l", None)
        if lref is not None:
            idx = getattr(lref, "idx", None)
            if diag_lines is not None:
                diag_lines.append(f"_detect_stkoff: mop_l lvar idx={idx}")
            if idx is not None:
                try:
                    lvar = mba.vars[idx]
                    loc = lvar.location
                    off = loc.stkoff()
                    if diag_lines is not None:
                        diag_lines.append(
                            f"_detect_stkoff: mop_l lvar[{idx}] location.stkoff()=0x{off:x}"
                        )
                    return _return(off, idx)
                except Exception as e:
                    if diag_lines is not None:
                        diag_lines.append(f"_detect_stkoff: mop_l lvar[{idx}] stkoff failed: {e}")

    if diag_lines is not None:
        diag_lines.append(f"_detect_stkoff: FAILED - unhandled operand type {mop_type}")
    return _return(None)


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
        chain_visited: set = set()
        # Build entries: list of (state_const, handler_serial, walk_result)
        entries = []
        diag_handler_count = 0
        for h_serial in sorted(handler_serials):
            state_const = handler_state_map.get(h_serial)
            if state_var_stkoff is not None:
                # Collect diagnostics for the first 3 handlers only
                handler_diag: Optional[List[str]] = None
                if diag_handler_count < 3:
                    handler_diag = []
                    diag_section.append(f"Handler blk[{h_serial}] (state={hex(state_const) if state_const is not None else '?'}):")
                    diag_handler_count += 1

                walk = _walk_handler_chain(
                    mba,
                    h_serial,
                    dispatcher_entry_serial,
                    state_var_stkoff,
                    chain_visited=chain_visited,
                    diag_lines=handler_diag,
                    state_var_lvar_idx=state_var_lvar_idx,
                )
                if handler_diag:
                    diag_section.extend(handler_diag)
            else:
                walk = {"next_state": None, "back_edge": False, "exit": False, "chain": []}
            entries.append((state_const, h_serial, walk))

        # Sort by state constant (None sorts last)
        entries.sort(key=lambda e: (e[0] is None, e[0] if e[0] is not None else 0))

        known_count = 0
        exit_count = 0
        unknown_count = 0

        for state_const, h_serial, walk in entries:
            if state_const is not None:
                state_label = f"State 0x{state_const:08x}"
            else:
                rng = handler_range_map.get(h_serial)
                if rng is not None and rng[0] is not None and rng[1] is not None:
                    state_label = f"State range [0x{rng[0]:x}..0x{rng[1]:x}]"
                else:
                    state_label = "State <unknown>"
            next_state = walk.get("next_state")

            # If transitions dict provided, prefer its value
            if transitions is not None:
                trans_next = transitions.get(h_serial)
                if trans_next is not None and next_state is None:
                    next_state = trans_next

            # A handler that completes its chain without ever reaching the
            # dispatcher back-edge (and without a 0-successor exit block) is
            # also classified as an exit — it doesn't loop back to the state
            # machine (e.g., a `break` that falls through to a return path).
            is_exit = walk.get("exit") or (
                not walk.get("back_edge") and walk.get("chain")
            )
            if is_exit:
                label = "RETURN (exit)"
                exit_count += 1
            elif walk.get("back_edge") and next_state is not None:
                label = f"next=0x{next_state:08x} (back-edge)"
                known_count += 1
            elif walk.get("back_edge"):
                label = "back-edge (next state unknown)"
                unknown_count += 1
            elif next_state is not None:
                label = f"next=0x{next_state:08x}"
                known_count += 1
            else:
                label = "unknown"
                unknown_count += 1

            chain_str = f"chain={walk['chain'][:4]}" if walk["chain"] else ""
            sections.append(
                f"{state_label} -> blk[{h_serial}]:  {label}  {chain_str}"
            )

        sections.append("")
        sections.append(
            f"Summary: {len(handler_serials)} handlers, "
            f"{known_count} with known transitions, "
            f"{exit_count} exits, "
            f"{unknown_count} unknown"
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
  python -m d810.hexrays.microcode_dump binary.dylib 0x650

  # Dump at specific maturity level
  python -m d810.hexrays.microcode_dump binary.dylib 0x650 --maturity PREOPTIMIZED

  # Save output to file
  python -m d810.hexrays.microcode_dump binary.dylib 0x650 -o output.json
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
