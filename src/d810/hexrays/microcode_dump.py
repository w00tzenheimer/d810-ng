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
import logging
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any, Union, TYPE_CHECKING
from enum import IntEnum

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
logger = logging.getLogger(__name__)

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
