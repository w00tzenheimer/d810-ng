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
from dataclasses import dataclass, field

import idaapi

from d810.core.logging import getLogger
from d810.core.typing import Any, Dict, List, Optional, Tuple, cast
from d810.evaluator.hexrays_microcode.valrange_dataflow import (
    format_valrange_env,
    run_valrange_fixpoint,
)
from d810.evaluator.hexrays_microcode.valranges import (
    collect_instruction_valrange_records,
)
from d810.hexrays.mutation.ir_translator import IDAIRTranslator
from d810.hexrays.utils.hexrays_helpers import (
    BLT_NAMES,
    MATURITY_TO_STRING_DICT,
    MOP_INFO,
    OPCODES_INFO,
    STRING_TO_MATURITY_DICT,
    BlockType,
    MicrocodeBasicBlockFlag,
    ShowInstructionsFlags,
    UseDefFlags,
)
from d810.recon.flow.bst_analysis import (
    _detect_state_var_stkoff,
    _dump_dispatcher_node,
    _find_pre_header_state,
    analyze_bst_dispatcher,
)
from d810.recon.flow.linearized_state_dag import (
    BoundaryInlineMode,
    LabelRenderMode,
    ProgramCommentMode,
    ProgramRenderStrategy,
    RenderOrderStrategy,
    build_live_linearized_state_dag_from_graph,
    render_linearized_state_program,
    render_linearized_state_dag,
    render_linearized_state_dag_dot,
)
from d810.recon.flow.transition_builder import _convert_bst_to_result
from d810.recon.flow.transition_report import (
    TransitionKind,
    build_dispatcher_transition_report,
)
from d810.hexrays.utils.pseudocode_render import render_block

# -----------------------------------------------------------------------------
# Configuration & Logging
# -----------------------------------------------------------------------------
logger = getLogger(__name__)

# -----------------------------------------------------------------------------
# Constants & Enums (lazily initialized)
# -----------------------------------------------------------------------------

# These will be populated when IDA is available

MATURITY_NAMES: Dict[int, str] = MATURITY_TO_STRING_DICT
OPCODE_MAP: Dict[int, str] = {op: OPCODES_INFO[op]["name"] for op in OPCODES_INFO}
MOP_TYPE_MAP: Dict[int, str] = {mop: MOP_INFO[mop]["name"] for mop in MOP_INFO}

_WS_RE = re.compile(r"\s+")
_NON_PRINTABLE_CHARS_RE = re.compile(r"[^\x20-\x7E]+")
_ESC_RE = re.compile(r"[\x01\x02].", re.S)
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


def mop_to_dict(
    mop: "idaapi.mop_t", depth: int = 0, max_depth: int = 10
) -> Optional[Dict[str, Any]]:
    """Convert a mop_t to a dictionary for JSON serialization."""
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
            result["sub_instruction"] = instruction_to_dict(
                sub_ins, depth + 1, max_depth
            )

    elif mop_type == idaapi.mop_a:  # Address (mop_addr_t)
        inner = getattr(mop, "a", None)
        if inner is not None:
            result["sub_operand"] = mop_to_dict(inner, depth + 1, max_depth)

    elif mop_type == idaapi.mop_f:  # Function call args
        f = getattr(mop, "f", None)
        if f is not None:
            args = getattr(f, "args", [])
            result["args"] = [
                mop_to_dict(arg, depth + 1, max_depth)
                for arg in args
                if arg is not None
            ]

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
            result["pair_low"] = mop_to_dict(
                getattr(pair, "lop", None), depth + 1, max_depth
            )
            result["pair_high"] = mop_to_dict(
                getattr(pair, "hop", None), depth + 1, max_depth
            )

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
    # Get function
    func = idaapi.get_func(func_ea)
    if func is None:
        raise ValueError(f"No function found at 0x{func_ea:x}")

    func_name = idaapi.get_name(func_ea) or f"sub_{func_ea:x}"

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
    s = re.sub(r"@[0-9A-Fa-f]{16}(\d+)$", r"@\1", s)
    # goto lines end up with '@ @N' after the above substitution
    s = s.replace("@ @", "@")
    return s


def _replace_var_placeholders_with_sp_offset(s: str, frsize: int) -> str:
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

    return re.sub(r"%var_([0-9A-Fa-f]+)\.(\d+)", _repl, s)


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


def _split_trailing_comment(s: str) -> tuple[str, str]:
    start_marker = "\x01\x04 ;"
    idx = s.rfind(start_marker)
    if idx == -1:
        return s, ""

    head = s[:idx]
    tail = s[idx + (len(start_marker) - 1) :]  # keep "; ..."

    # Drop one trailing close-marker pair like \x02\x04, if present.
    if len(tail) >= 2 and tail[-2] == "\x02":
        tail = tail[:-2]

    return head, tail


def _clean_insn_str(raw: Optional[str]) -> str:
    if raw is None:
        return "<none>"

    s = raw
    s = _ESC_RE.sub("", s)
    s = "".join(c for c in s if 0x20 <= ord(c) <= 0x7E)
    s = _WS_RE.sub(" ", s).strip()
    return s


def _format_insn_str(insn_str: str) -> str:
    """
    Format an already-cleaned instruction string as:
      <mnemonic in 6-char field><space><rest>

    Examples:
      "mov #-1, sp+0x20.8" -> "mov    #-1, sp+0x20.8"
      "goto @87"           -> "goto   @87"
      "ret"                -> "ret   "
    """
    insn_str = _clean_insn_str(insn_str)
    if not insn_str:
        return ""

    parts = insn_str.split(None, 1)
    mnemonic = parts[0]
    operands = parts[1] if len(parts) > 1 else ""

    return f"{mnemonic.ljust(6)} {operands}" if operands else mnemonic.ljust(6)


def _print_list_pair(
    label: str, must: idaapi.mlist_t, may: Optional[idaapi.mlist_t] = None
) -> Optional[str]:
    """Mimic C++ print_list(vec, label, must, may)."""
    must_s = must.dstr()
    if not must_s:
        return None

    may_s = ""
    if may is not None and not may.empty() and may != must:
        may.sub(must)  # may -= must  (leaves the "may-only" part)
        may_s = may.dstr()

    rval = f"; {label}: {must_s}"
    if may_s:
        # must and may differ → show may in parens
        rval += f",({may_s})"

    return rval


def _print_use_def_dnu(line: List[str], blk: idaapi.mblock_t) -> None:
    """Append USE/DEF/DNU lines to *line*, matching C++ print_list calls."""
    s = _print_list_pair("USE", blk.mustbuse, blk.maybuse)
    if s:
        line.append(s)
    s = _print_list_pair("DEF", blk.mustbdef, blk.maybdef)
    if s:
        line.append(s)
    # DNU has no may variant in C++
    dnu_s = _mlist_dstr(blk.dnu)
    if dnu_s:
        line.append(f"; DNU: {dnu_s}")


def _print_stack_frame_overview(hdr: List[str], mba: idaapi.mba_t) -> None:
    """Append stack frame overview lines to *hdr*."""
    hdr.append(
        f"; STKD={mba.tmpstk_size:X}"
        f" MINREF={mba.minstkref:X}/END={mba.stacksize:X}"
        f" ARGS: OFF={mba.inargoff:X}/MINREF={mba.minargref:X}"
        f"/END={mba.fullsize:X}/SHADOW={mba.shadow_args:X}"
    )
    # SAVEDREGS (if procinf is exposed)
    procinf = getattr(mba, "procinf", None)
    if procinf is not None:
        sregs = getattr(procinf, "sregs", None)
        if sregs and len(sregs) > 0:
            parts = []
            slotsize = getattr(mba, "slotsize", None)
            for idx, sr in enumerate(sregs):
                if slotsize is not None:
                    rl = idaapi.rlist_t(sr, slotsize())
                    parts.append(rl.dstr())
                else:
                    parts.append(str(sr))
            hdr.append(f"; SAVEDREGS: {','.join(parts)}")


def _print_block_header(
    i: int, blk: idaapi.mblock_t, mba: idaapi.mba_t, valrange_env=None
) -> tuple[list[str], list[str]]:
    """Append block header lines to *line*, matching C++ print_block_header calls."""
    serial = blk.serial
    start_ea = blk.start
    end_ea = blk.end
    block_type = BlockType(blk.type)
    type_name = BLT_NAMES[block_type.value]
    flags = blk.flags

    preds = _collect_bitset(blk.predset)
    succs = _collect_bitset(blk.succset)

    preds_sorted = [str(p) for p in sorted(preds)] if preds else []
    succs_sorted = [str(s) for s in sorted(succs)] if succs else []

    # Stack frame info on block 0
    label = "Successors" if serial == 0 else "Predecessors"
    items = succs_sorted if serial == 0 else preds_sorted

    hdr = [f"{i}.{type_name:<60} ; {label}: {', '.join(items)}"]

    # Block header line
    # Stack frame info on block 0
    # ---- Block 0: STKD / frame overview ----
    if serial == 0:
        _print_stack_frame_overview(hdr, mba)

    flags_str = MicrocodeBasicBlockFlag.block_header_flags_str(flags)

    # INBOUNDS / OUTBOUNDS
    inbounds = ""
    if preds_sorted:
        inbounds = " INBOUNDS: " + " ".join(preds_sorted)
    outbounds = ""
    if succs_sorted:
        outbounds = " OUTBOUNDS: " + " ".join(succs_sorted)

    hdr.append(
        f"; {block_type.display_name}-BLOCK {serial}{flags_str}"
        f"{inbounds}{outbounds}"
        f" [START={start_ea:X} END={end_ea:X}]"
        f" MINREFS: STK={blk.minbstkref:X}/ARG={blk.minbargref:X},"
        f" MAXBSP: {blk.maxbsp:X}"
    )

    # NOTE: C++ also prints SUBFRAME info when EXTFRAME is set,
    # but mba_t.subframes is not exposed in the Python bindings

    # ---- USE / DEF / DNU liveness sets ----
    lists_ok = getattr(blk, "lists_ready", lambda: True)()
    if lists_ok:
        _print_use_def_dnu(hdr, blk)
    else:
        hdr.append("; USE-DEF LISTS ARE NOT READY")

    # ---- VALRANGES ---
    if valrange_env:
        vr_str = format_valrange_env(valrange_env)
        if vr_str != "none":
            hdr.append(f"; VALRANGES: {vr_str}")

    return hdr, succs_sorted


def _collect_block_instructions(blk: idaapi.mblock_t) -> List[idaapi.minsn_t]:
    """Collect all instructions in a block."""
    insns = []
    ins: idaapi.minsn_t = blk.head
    while ins is not None:
        insns.append(ins)
        ins = ins.next
    return insns


def _print_use_list(blk: idaapi.mblock_t, ins: idaapi.minsn_t, frsize: int) -> str:
    """Build the '; EA u=... d=...' suffix for one instruction, matching C++ print_insn_usedef."""
    # ---- USE ----
    may_use = blk.build_use_list(ins, UseDefFlags.MAY_ACCESS)
    must_use = blk.build_use_list(ins, UseDefFlags.MUST_ACCESS)

    must_use_s = (
        _replace_var_placeholders_with_sp_offset(must_use.dstr(), frsize)
        if not must_use.empty()
        else ""
    )

    if may_use == must_use:
        use_str = f"u={must_use_s:<10}"
    else:
        may_use.sub(must_use)  # may -= must  (leaves the "may-only" part)
        may_only_s = (
            _replace_var_placeholders_with_sp_offset(may_use.dstr(), frsize)
            if not may_use.empty()
            else ""
        )
        sep = "," if not must_use.empty() else ""
        use_str = f"u={must_use_s}{sep}({may_only_s})"
    return use_str


def _print_def_list(blk: idaapi.mblock_t, ins: idaapi.minsn_t, frsize: int) -> str:
    # ---- DEF ----
    may_def = blk.build_def_list(ins, UseDefFlags.MAY_ACCESS)
    if may_def.empty():
        return ""

    must_def = blk.build_def_list(ins, UseDefFlags.MUST_ACCESS)
    must_def_s = (
        _replace_var_placeholders_with_sp_offset(must_def.dstr(), frsize)
        if not must_def.empty()
        else ""
    )
    def_str = f" d={must_def_s}"
    if may_def == must_def:
        return def_str

    sep = ""
    if not must_def.empty():
        sep = ","
        may_def.sub(must_def)  # may -= must

    may_only_s = (
        _replace_var_placeholders_with_sp_offset(may_def.dstr(), frsize)
        if not may_def.empty()
        else ""
    )
    def_str += f"{sep}({may_only_s})"

    # pass regs: may_only - may_excluding_pass
    pd = may_def
    may_no_pass = blk.build_def_list(
        ins, UseDefFlags.MAY_ACCESS | UseDefFlags.EXCLUDE_PASS_REGS
    )
    pd.sub(may_no_pass)
    if not pd.empty():
        pd_s = (
            _replace_var_placeholders_with_sp_offset(pd.dstr(), frsize)
            if not pd.empty()
            else ""
        )
        def_str += f",pass={pd_s}"
    return def_str


def _print_insn_usedef(blk: idaapi.mblock_t, ins: idaapi.minsn_t, frsize: int) -> str:
    """Build the '; EA u=... d=...' suffix for one instruction, matching C++ print_insn_usedef."""

    use_str = _print_use_list(blk, ins, frsize)
    def_str = _print_def_list(blk, ins, frsize)
    return f"{use_str}{def_str}"


def mba_to_human_readable(mba: idaapi.mbl_array_t) -> List[str]:
    """Convert an mbl_array_t to a list of strings in IDA's native human-readable microcode format.

    Produces output similar to IDA's own microcode listing, including:
    - Block headers with type, predecessor/successor sets, EA range
    - USE/DEF/DNU liveness sets per block
    - VALRANGES per block (via :func:`d810.evaluator.hexrays_microcode.valrange_dataflow.run_valrange_fixpoint`)
    - Instruction-level VALRANGES via
      :func:`d810.evaluator.hexrays_microcode.valranges.collect_instruction_valrange_records`
    - Instructions via ``minsn_t._print()`` with per-instruction u=/d= annotations

    Args:
        mba: The microcode block array to print.

    Returns:
        A list of strings in IDA's native human-readable microcode format.
    """
    maturity = mba.maturity

    # frsize is needed to convert %var_XX.N -> sp+0xOFF.N
    _frsize: int = getattr(mba, "stacksize", 0) or getattr(mba, "frsize", 0) or 0
    maturity_name = MATURITY_NAMES[maturity]
    num_blocks = mba.qty

    # Block type enum: try runtime constants first, fall back to hard-coded

    # Flag constants

    _PRINT_FLAGS = (
        ShowInstructionsFlags.SHINS_VALNUM
        | ShowInstructionsFlags.SHINS_NUMADDR
        | ShowInstructionsFlags.SHINS_LDXEA
    )
    """
        
    0.BLT_1WAY                                                            ; Successors: 1
    ; STKD=0 MINREF=7F8/END=7F8 ARGS: OFF=820/MINREF=A00/END=A00/SHADOW=20
    ; 1WAY-BLOCK 0 FAKE OUTBOUNDS: 1 [START=180012B60 END=180012B60] MINREFS: STK=7F8/ARG=A00, MAXBSP: 0
    ; DEF: (rax.8,r8.8,ds.2,sp+30.8,sp+3C..A1,sp+A8.1,sp+B0.1,sp+B8.1,sp+C0.1,sp+C8.1,sp+D0.1,sp+D8.1,sp+E0.1,sp+E8..F9,sp+100.1,sp+108.1,sp+110.1,sp+118.1,sp+120.1,sp+128..139,sp+140.1,sp+148.1,sp+150.1,sp+158.1,sp+160.1,sp+168..1B9,sp+1C0.1,sp+1C8.1,sp+1D0..200,sp+208..260,sp+2D0..331,sp+338.1,sp+340.1,sp+348.1,sp+350.1,sp+358..3D8,sp+3E0.8,sp+3F0..400,sp+408.8,sp+418..481,sp+488.1,sp+490..4A9,sp+4B0..4E1,sp+4E8..4F9,sp+508..519,sp+520..534,sp+538.4,sp+540.4,sp+548.4,sp+550.4,sp+558.4,sp+560.4,sp+568.4,sp+570.4,sp+578.4,sp+580.4,sp+588.4,sp+590.4,sp+598..5B1,sp+5B8.1,sp+5C0.1,sp+5C8..5D9,sp+5E0..619,sp+620.1,sp+628.1,sp+630..67C,sp+680..690,sp+6D0..6EC,sp+6F0.4,sp+728.4,sp+730.4,sp+738.1,sp+748.4,sp+750.4,sp+758.4,sp+760.8,sp+770.4,sp+778.4,sp+780.C,sp+790.4,sp+798.4,sp+7C0.4,sp+7C8.4,sp+7E0.8,sp+7F0..,arg+0.8)

    
    32.BLT_1WAY                                                           ; Predecessors: 24, 31
    ; 1WAY-BLOCK 32 INBOUNDS: 24 31 OUTBOUNDS: 2 [START=180013274 END=18001340F] MINREFS: STK=7F8/ARG=A00, MAXBSP: 0
    ; USE: ds.2,sp+3E0.8,sp+3F0.8,sp+680.8,arg+0.8,(GLBLOW,GLBHIGH)
    ; DEF: sp+3C.4,sp+1E0..200,sp+4B0.8,sp+5D8.8,sp+668..678,(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm4.16,xmm5.16,GLBLOW,sp+0..20,GLBHIGH)
    ; DNU: sp+3C.4,sp+1E0..1F8,sp+4B0.8,sp+668..678
    ; VALRANGES: %0x3C.4:(258ED456..296F2451|==6465D165|==64AFC49D)
    32. 1 18001327C  mov    %var_408.8{37}, %var_348.8{37} ; 18001327C u=sp+3F0.8   d=sp+4B0.8
    32. 2 180013290  add    %arg_20.8{38}, #0x50@18001328C.8, %var_188.8 ; 180013290 u=arg+0.8    d=sp+670.8
    32. 3 1800132BD  call   $__ImageBase <std:"HINSTANCE hinstDLL" #0x2E@1800132B8.8,"DWORD fdwReason" %fdwReason.4,"LPVOID lpReserved" (%arg_20.8{38}+#0x50@1800132AC.8)> => BOOL .0 ; 1800132BD u=sp+3E0.4,arg+0.8,(GLBLOW,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm4.16,xmm5.16,GLBLOW,sp+0..20,GLBHIGH)
    32. 4 1800132E1  ldx    ds.2{39}, %var_178.8{40}, %var_220.8{41} ; 1800132E1 u=ds.2,sp+680.8,(GLBLOW,GLBHIGH) d=sp+5D8.8
    32. 5 18001339C  add    (#0x11@180013395.8*bnot((%var_220.8{41} | xdu.8((%var_408.1{44} & #0x78@1800132CA.1){43}){42}))), ((#7@18001337A.8*bnot(([ds.2{39}:%var_178.8{40}].8{46} | bnot(xdu.8((%var_408.1{44} & #0x78@1800132CA.1){43}){42}){47}){45}))+((((#0xC@18001331B.8*(bnot(xdu.8((%var_408.1{44} & #0x78@1800132CA.1){43}){42}){47} & %var_220.8{41}){48})+(#0x13@180013300.8*xdu.8((low.4([ds.2{39}:%var_178.8{40}].8{46}) & xdu.4((%var_408.1{44} & #0x78@1800132CA.1){43}){42}))))-(#0xB@180013339.8*([ds.2{39}:%var_178.8{40}].8{46} | bnot(xdu.8((%var_408.1{44} & #0x78@1800132CA.1){43}){42}){47}){45}))-(#6@180013358.8*bnot((%var_220.8{41} & bnot(xdu.8((%var_408.1{44} & #0x78@1800132CA.1){43}){42}){47}){48})))), %var_600.8{49} ; 18001339C u=ds.2,sp+3F0.1,sp+5D8.8,sp+680.8,(GLBLOW,GLBHIGH) d=sp+1F8.8
    32. 6 1800133B4  stx    %var_600.8{49}, ds.2{39}, %var_178.8{40} ; 1800133B4 u=ds.2,sp+1F8.8,sp+680.8 d=(GLBLOW,GLBHIGH)
    32. 7 1800133C7  add    %fdwReason.8, xdu.8((%var_408.1{44} & #0x78@1800132CA.1){43}){42}, %var_190.8 ; 1800133C7 u=sp+3E0.8,sp+3F0.1 d=sp+668.8
    32. 8 1800133D9  mov    #-0x38FBF21084F0EF3B@1800133CF.8, %var_608.8 ; 1800133D9 u=           d=sp+1F0.8
    32. 9 1800133EB  mov    #-0x768CA3E4B0983C4@1800133E1.8, %var_610.8 ; 1800133EB u=           d=sp+1E8.8
    32.10 1800133FD  mov    #-0x319327D239E76B70@1800133F3.8, %var_618.8 ; 1800133FD u=           d=sp+1E0.8
    32.11 180013405  mov    #0x432DC789@180013405.4, %var_7BC.4 ; 180013405 u=           d=sp+3C.4
    32.12 18001340D  goto   @2     ; 18001340D u=                         ; Successors: 2
    """
    # Pre-compute value ranges for all blocks via forward dataflow.
    try:
        vr_result = run_valrange_fixpoint(mba)
        vr_in_states = vr_result.in_states
    except Exception:
        logger.warning("run_valrange_fixpoint failed", exc_info=True)
        vr_in_states = {}

    as_str = [f"; Maturity: {maturity_name}"]
    for i in range(num_blocks):
        blk: idaapi.mblock_t = mba.get_mblock(i)
        if blk is None:
            continue
        serial = blk.serial
        block_type = BlockType(blk.type)
        line, succs_sorted = _print_block_header(
            i, blk, mba, valrange_env=vr_in_states.get(serial)
        )
        # Collect instructions
        insns = _collect_block_instructions(blk)

        # Per-instruction use/def lists

        for insn_idx, ins in enumerate(insns, start=1):
            ea = ins.ea
            raw = cast(str, ins._print(_PRINT_FLAGS))
            head, tail = _split_trailing_comment(raw)
            insn_str = _clean_insn_str(head)
            # line.append(raw)
            insn_str = _fix_block_refs(insn_str)
            insn_str = _format_insn_str(insn_str)
            # _print_insn_usedef(blk, ins, _frsize)

            ins_vr_records = collect_instruction_valrange_records(blk, ins)
            ins_vr = (
                f" vr={{{', '.join(str(r) for r in ins_vr_records)}}}"
                if ins_vr_records
                else ""
            )

            ea_str = f"{ea:X}"
            suffix = f"{tail}{ins_vr}"
            prefix = f"{serial}.{insn_idx:>2} {ea_str}"
            line.append(f"{prefix}  {insn_str:<12} {suffix}")

        if serial != 0 and block_type != BlockType.STOP:
            last_line = line.pop()
            last_line += f" ; Successors: {', '.join(succs_sorted)}"
            line.append(last_line)
        as_str.append("\n".join(line))

    return as_str


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
                f" lvar_idx={detected_lvar_idx}"
                if detected_lvar_idx is not None
                else ""
            )
            diag_section.append(
                f"Auto-detected state_var_stkoff=0x{detected:x}{lvar_note}"
                f" from blk[{dispatcher_entry_serial}]"
            )

    # --- Section 1: Pre-header ---
    sections.append("=== STATE MACHINE ===")
    pre_header_serial, initial_state = _find_pre_header_state(
        mba,
        dispatcher_entry_serial,
        state_var_stkoff,
        diag_lines=diag_section,
        state_var_lvar_idx=state_var_lvar_idx,
    )
    if pre_header_serial is not None:
        state_str = (
            f"0x{initial_state:08x}" if initial_state is not None else "<unknown>"
        )
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
    handler_state_map: Dict[int, int] = (
        {}
    )  # handler_serial -> state_constant (from BST leaf)
    handler_serials: set = set()
    handler_range_map: Dict[int, Tuple[Optional[int], Optional[int]]] = (
        {}
    )  # handler_serial -> (lo, hi)

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
# Linearized DAG Visualization
# -----------------------------------------------------------------------------


def _build_live_linearized_state_dag(
    mba: "idaapi.mbl_array_t",
    dispatcher_entry_serial: int,
    *,
    state_var_stkoff: Optional[int] = None,
    state_var_lvar_idx: Optional[int] = None,
    max_depth: int = 20,
):
    if state_var_stkoff is None:
        detected, detected_lvar_idx = _detect_state_var_stkoff(
            mba,
            dispatcher_entry_serial,
            diag=False,
        )
        if detected is not None:
            state_var_stkoff = detected
            if state_var_lvar_idx is None:
                state_var_lvar_idx = detected_lvar_idx

    bst_result = analyze_bst_dispatcher(
        mba,
        dispatcher_entry_serial,
        state_var_stkoff=state_var_stkoff,
        state_var_lvar_idx=state_var_lvar_idx,
        max_depth=max_depth,
    )
    transition_result = _convert_bst_to_result(bst_result)
    flow_graph = IDAIRTranslator().lift(mba)
    return build_live_linearized_state_dag_from_graph(
        flow_graph,
        transition_result,
        dispatcher_entry_serial=dispatcher_entry_serial,
        state_var_stkoff=state_var_stkoff,
        state_var_lvar_idx=state_var_lvar_idx,
        pre_header_serial=bst_result.pre_header_serial,
        initial_state=bst_result.initial_state,
        handler_range_map=bst_result.handler_range_map,
        bst_node_blocks=tuple(sorted(bst_result.bst_node_blocks)),
        dispatcher=bst_result.dispatcher,
        mba=mba,
        prefer_local_corridors=True,
    )


def dump_linearized_dag(
    mba: "idaapi.mbl_array_t",
    dispatcher_entry_serial: int,
    state_var_stkoff: Optional[int] = None,
    *,
    order_strategy: RenderOrderStrategy = RenderOrderStrategy.CATALOG,
) -> str:
    """Build and render the unified state-level DAG for a dispatcher."""
    dag = _build_live_linearized_state_dag(
        mba,
        dispatcher_entry_serial,
        state_var_stkoff=state_var_stkoff,
    )
    return render_linearized_state_dag(dag, order_strategy=order_strategy)


def dump_linearized_program(
    mba: "idaapi.mbl_array_t",
    dispatcher_entry_serial: int,
    state_var_stkoff: Optional[int] = None,
    *,
    order_strategy: RenderOrderStrategy = RenderOrderStrategy.CATALOG,
    program_strategy: ProgramRenderStrategy = ProgramRenderStrategy.LOCAL_SEGMENT_COLLAPSING,
    label_render_mode: LabelRenderMode = LabelRenderMode.STATE_FAMILY,
    boundary_inline_mode: BoundaryInlineMode = BoundaryInlineMode.LABELS_ONLY,
    comment_mode: ProgramCommentMode = ProgramCommentMode.DEBUG_METADATA,
) -> str:
    """Build and render the unified state DAG as a label-preserving program."""
    dag = _build_live_linearized_state_dag(
        mba,
        dispatcher_entry_serial,
        state_var_stkoff=state_var_stkoff,
    )
    block_payload_by_serial: Dict[int, Tuple[str, ...]] = {}
    for block_serial in range(mba.qty):
        try:
            blk = mba.get_mblock(block_serial)
        except Exception:
            continue
        if blk is None:
            continue
        try:
            block_payload_by_serial[int(blk.serial)] = tuple(render_block(blk))
        except Exception:
            continue
    return render_linearized_state_program(
        dag,
        order_strategy=order_strategy,
        program_strategy=program_strategy,
        label_render_mode=label_render_mode,
        boundary_inline_mode=boundary_inline_mode,
        comment_mode=comment_mode,
        block_payload_by_serial=block_payload_by_serial,
    )


def dump_linearized_dag_dot(
    mba: "idaapi.mbl_array_t",
    dispatcher_entry_serial: int,
    state_var_stkoff: Optional[int] = None,
    *,
    expanded: bool = False,
) -> str:
    """Build and render the unified state-level DAG as Graphviz DOT."""
    dag = _build_live_linearized_state_dag(
        mba,
        dispatcher_entry_serial,
        state_var_stkoff=state_var_stkoff,
    )
    return render_linearized_state_dag_dot(dag, expanded=expanded)


# -----------------------------------------------------------------------------
# State Machine DOT Graph
# -----------------------------------------------------------------------------


def dump_state_machine_graph(
    mba: "idaapi.mbl_array_t",
    dispatcher_entry_serial: int,
    state_var_stkoff: Optional[int] = None,
) -> Tuple[str, str]:
    """Dump the raw state machine topology as a Graphviz DOT graph.

    Extracts all handlers and transitions from the BST analysis and renders
    them as a DOT digraph.  No forward evaluation or linearization is
    performed -- this is the raw state machine as seen by the BST walker.

    Args:
        mba: The microcode block array.
        dispatcher_entry_serial: Block serial number of the BST root.
        state_var_stkoff: Optional stack offset of the state variable
            (auto-detected from the BST root when *None*).

    Returns:
        Tuple of (dot_string, summary_string) where *dot_string* is a
        complete DOT digraph and *summary_string* is a one-line summary
        like ``"N nodes, M edges, K self-loops, J conditionals, L exits"``.
    """
    report = build_dispatcher_transition_report(
        mba=mba,
        dispatcher_entry_serial=dispatcher_entry_serial,
        state_var_stkoff=state_var_stkoff,
        capture_diagnostics=False,
    )

    initial_state = report.initial_state

    def _short_hex(val: int) -> str:
        return f"0x{val:X}"

    # Collect unique nodes and edges from the report rows.
    # node_id -> (state_hex_label, handler_serial, kind)
    nodes: Dict[str, Tuple[str, int, TransitionKind]] = {}
    # (src_id, dst_id, label, style_attrs)
    edges: List[Tuple[str, str, str, str]] = []

    n_self_loops = 0
    n_conditionals = 0
    n_exits = 0

    for row in report.rows:
        if row.state_const is None:
            continue

        src_hex = _short_hex(row.state_const)
        src_id = f'"{src_hex}"'

        # Register the source node
        nodes[src_id] = (src_hex, row.handler_serial, row.kind)

        if row.kind == TransitionKind.EXIT:
            n_exits += 1
            # No outgoing edge for exits

        elif row.kind == TransitionKind.CONDITIONAL:
            n_conditionals += 1
            for branch_idx, cond_state in enumerate(row.conditional_states):
                dst_hex = _short_hex(cond_state)
                dst_id = f'"{dst_hex}"'
                label = "true" if branch_idx == 0 else "false"
                if cond_state == row.state_const:
                    n_self_loops += 1
                    edges.append(
                        (src_id, dst_id, "self-loop", "style=dashed color=red")
                    )
                else:
                    edges.append((src_id, dst_id, label, "color=blue"))

        elif row.kind == TransitionKind.TRANSITION:
            if row.next_state is not None:
                dst_hex = _short_hex(row.next_state)
                dst_id = f'"{dst_hex}"'
                if row.next_state == row.state_const:
                    n_self_loops += 1
                    edges.append(
                        (src_id, dst_id, "self-loop", "style=dashed color=red")
                    )
                else:
                    edges.append((src_id, dst_id, "", ""))

        # TransitionKind.UNKNOWN -- node exists but no edge

    # Build the DOT string
    lines: List[str] = []
    lines.append("digraph state_machine {")
    lines.append("    rankdir=LR;")
    lines.append("    node [shape=record];")
    lines.append("")

    # Initial state arrow
    if initial_state is not None:
        init_hex = _short_hex(initial_state)
        lines.append("    // Initial state")
        lines.append("    START [shape=point];")
        lines.append(f'    START -> "{init_hex}";')
        lines.append("")

    # Emit nodes
    lines.append("    // Handler nodes")
    for node_id, (state_hex, handler_serial, kind) in sorted(nodes.items()):
        if kind == TransitionKind.EXIT:
            lines.append(
                f'    {node_id} [label="{state_hex}\\nblk[{handler_serial}]'
                f'\\nEXIT" style=filled fillcolor=lightgreen];'
            )
        elif kind == TransitionKind.UNKNOWN:
            lines.append(
                f'    {node_id} [label="{state_hex}\\nblk[{handler_serial}]'
                f'\\nUNRESOLVED" style=filled fillcolor=lightyellow];'
            )
        else:
            lines.append(
                f'    {node_id} [label="{state_hex}\\nblk[{handler_serial}]"];'
            )
    lines.append("")

    # Emit edges
    lines.append("    // Transitions")
    for src_id, dst_id, label, attrs in edges:
        parts = []
        if label:
            parts.append(f'label="{label}"')
        if attrs:
            parts.append(attrs)
        attr_str = f" [{' '.join(parts)}]" if parts else ""
        lines.append(f"    {src_id} -> {dst_id}{attr_str};")

    lines.append("}")

    dot_string = "\n".join(lines)

    n_nodes = len(nodes)
    n_edges = len(edges)
    summary = (
        f"{n_nodes} nodes, {n_edges} edges, {n_self_loops} self-loops, "
        f"{n_conditionals} conditionals, {n_exits} exits"
    )

    return dot_string, summary


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
        choices=[
            "GENERATED",
            "PREOPTIMIZED",
            "LOCOPT",
            "CALLS",
            "GLBOPT1",
            "GLBOPT2",
            "GLBOPT3",
            "LVARS",
        ],
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

    maturity = STRING_TO_MATURITY_DICT[args.maturity]

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
    # Running from command line
    main_cli()
