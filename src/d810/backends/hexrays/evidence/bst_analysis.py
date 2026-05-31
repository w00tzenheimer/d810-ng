"""BST dispatcher analysis for d810 unflattening.

This module provides functions for analyzing binary search tree (BST) style
dispatchers found in control-flow-flattened code.  It extracts state machine
information — handler blocks, state constants, and handler-to-handler
transitions — from the microcode block array.

Typical usage::

    from d810.backends.hexrays.evidence.bst_analysis import analyze_bst_dispatcher

    result = analyze_bst_dispatcher(mba, dispatcher_entry_serial=5)
    # result.handler_state_map  -> {handler_serial: state_const, ...}
    # result.transitions        -> {state_const: next_state_const, ...}
    # result.exits              -> {state_const, ...}  (states that exit)
"""

from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.analyses.value_flow import state_write
from d810.backends.hexrays import bst_runtime as _hexrays_bst_runtime
from d810.capabilities.providers import BstWalkerProvider, MicrocodeEvidenceProvider
from d810.core.algorithm_metadata import algorithm_metadata
from d810.core.logging import getLogger
from d810.core.typing import (
    Any,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
)
from d810.analyses.control_flow.bst_model import BSTAnalysisResult
from d810.analyses.control_flow.bst_model import BSTNodeMap
from d810.analyses.control_flow.bst_model import resolve_target_via_bst
from d810.analyses.control_flow.interval_map import Node, NodeKind, emit_dispatch_intervals, IntervalDispatcher

logger = getLogger(__name__)


def _ensure_ida_imports() -> None:
    """Keep the legacy lazy-availability boundary for live-only callers."""

    _hexrays_bst_runtime.is_available()


# -----------------------------------------------------------------------------
# Constants (lazily initialized)
# -----------------------------------------------------------------------------

OPCODE_MAP: Dict[int, str] = {}
MOP_TYPE_MAP: Dict[int, str] = {}
_maps_initialized = False
_BST_OPCODE_NAMES = frozenset(
    {
        "m_jbe",
        "m_ja",
        "m_jb",
        "m_jae",
        "m_jnz",
        "m_jz",
    }
)
_BST_OPCODE_NAME_TO_KIND = {
    "m_jbe": NodeKind.JBE,
    "m_ja": NodeKind.JA,
    "m_jb": NodeKind.JB,
    "m_jae": NodeKind.JAE,
    "m_jnz": NodeKind.JNZ,
    "m_jz": NodeKind.JZ,
}


def _init_constants() -> None:
    """Initialize constant maps that require IDA imports."""
    global OPCODE_MAP, MOP_TYPE_MAP, _maps_initialized
    if _maps_initialized:
        return

    OPCODE_MAP = _hexrays_bst_runtime.build_opcode_map()
    MOP_TYPE_MAP = _hexrays_bst_runtime.build_mop_type_map()

    _maps_initialized = True


def _opcode_name(opcode: object) -> str | None:
    """Return the lifted backend opcode name for a live opcode value."""

    if isinstance(opcode, str):
        return opcode
    _init_constants()
    try:
        return OPCODE_MAP.get(int(opcode))
    except (TypeError, ValueError):
        return None


def _opcode_kind(opcode: object) -> NodeKind | None:
    name = _opcode_name(opcode)
    return _BST_OPCODE_NAME_TO_KIND.get(name or "")


def _is_bst_opcode(opcode: object) -> bool:
    name = _opcode_name(opcode)
    return name in _BST_OPCODE_NAMES


def _mop_type_name(mop_type: object) -> str | None:
    """Return the lifted backend operand-type name for a live mop type."""

    if isinstance(mop_type, str):
        return mop_type
    _init_constants()
    try:
        return MOP_TYPE_MAP.get(int(mop_type))
    except (TypeError, ValueError):
        return None


def _opcode_value(name: str, default: int | None = None) -> int | None:
    return _hexrays_bst_runtime.opcode_value(name, default)


def _mop_type_value(name: str, default: int | None = None) -> int | None:
    return _hexrays_bst_runtime.mop_type_value(name, default)


def find_bst_default_block(
    mba: object,
    bst_root_serial: int,
    bst_node_blocks: set,
    handler_block_serials: set,
) -> Optional[int]:
    """Find the BST's default fall-through block (reached when no comparison matches).

    Walks all BST node successors. Any successor that is neither a BST node
    nor a handler entry is the default block (contains cleanup/exit code).

    Args:
        mba: The microcode block array.
        bst_root_serial: Serial of the BST dispatcher root (included in search).
        bst_node_blocks: Set of block serials that are BST comparison nodes.
        handler_block_serials: Set of block serials that are handler entries.

    Returns:
        Serial of the default fall-through block, or None if not found.

    >>> # Doctest: pure-Python path (no IDA)
    >>> find_bst_default_block(None, 0, set(), set()) is None
    True
    """
    _ensure_ida_imports()
    if mba is None:
        return None

    all_bst_serials = bst_node_blocks | {bst_root_serial}

    for bst_serial in all_bst_serials:
        blk = mba.get_mblock(bst_serial)
        if blk is None:
            continue
        for i in range(blk.nsucc()):
            succ = blk.succ(i)
            if succ not in all_bst_serials and succ not in handler_block_serials:
                return succ

    return None


# Compat re-export.  The canonical home for the snapshot-only BST
# default-block discovery is `d810.analyses.control_flow.bst_snapshot` (axis-C
# slice 5a).  Keeping the name re-exported here so any prod consumer
# that finds it through `bst_analysis` keeps working; tests import
# from the canonical location directly.
#
# One-way dependency: bst_analysis -> bst_snapshot.  Do NOT add an
# import in the reverse direction.
from d810.analyses.control_flow.bst_snapshot import find_bst_default_block_snapshot


def resolve_via_bst_walk(
    mba: object,
    bst_root_serial: int,
    state_value: int,
    bst_node_blocks: set[int],
    max_depth: int = 30,
) -> Optional[int]:
    """Walk the BST comparison chain for a specific state value.

    Starting from *bst_root_serial*, follow the comparison at each BST node
    block for *state_value*.  Return the first block serial that is **not** in
    *bst_node_blocks* (i.e. the handler / default block this value reaches).

    Returns ``None`` if the walk exceeds *max_depth* or cannot resolve.

    >>> resolve_via_bst_walk(None, 0, 0x1234, set()) is None
    True
    """
    _ensure_ida_imports()
    _init_constants()

    if mba is None:
        return None

    current_serial = bst_root_serial

    for _ in range(max_depth):
        if current_serial not in bst_node_blocks:
            # Reached a non-BST block — this is the target.
            return current_serial

        blk = mba.get_mblock(current_serial)
        if blk is None:
            return None

        tail = blk.tail
        if tail is None:
            return None

        opcode = getattr(tail, "opcode", None)
        if opcode is None:
            return None

        # Extract comparison constant (may be in .l or .r).
        cmp_val = _get_mop_const_value(getattr(tail, "l", None))
        if cmp_val is None:
            cmp_val = _get_mop_const_value(getattr(tail, "r", None))
        if cmp_val is None:
            return None

        # Determine branch target and fall-through successor.
        # Convention: succs[0] = fall-through, succs[1] = jump/taken.
        # Branch target = tail.d.b
        branch_target: Optional[int] = None
        d_operand = getattr(tail, "d", None)
        if d_operand is not None:
            branch_target = getattr(d_operand, "b", None)

        if branch_target is None:
            return None

        # Fall-through is the other successor.
        succs = [blk.succ(i) for i in range(blk.nsucc())]
        fall_through: Optional[int] = None
        for s in succs:
            if s != branch_target:
                fall_through = s
                break
        if fall_through is None:
            return None

        # Evaluate the comparison to choose which path to follow.
        # Condition TRUE  → branch_target (taken)
        # Condition FALSE → fall_through
        take_branch: bool
        opcode_kind = _opcode_kind(opcode)
        if opcode_kind is NodeKind.JBE:
            # jump if state_var <= cmp_val
            take_branch = state_value <= cmp_val
        elif opcode_kind is NodeKind.JA:
            # jump if state_var > cmp_val
            take_branch = state_value > cmp_val
        elif opcode_kind is NodeKind.JB:
            # jump if state_var < cmp_val
            take_branch = state_value < cmp_val
        elif opcode_kind is NodeKind.JAE:
            # jump if state_var >= cmp_val
            take_branch = state_value >= cmp_val
        elif opcode_kind is NodeKind.JNZ:
            # jump if state_var != cmp_val
            take_branch = state_value != cmp_val
        elif opcode_kind is NodeKind.JZ:
            # jump if state_var == cmp_val
            take_branch = state_value == cmp_val
        else:
            # Unknown conditional opcode — cannot decide.
            return None

        current_serial = branch_target if take_branch else fall_through

    # Exhausted max_depth.
    return None


# -----------------------------------------------------------------------------
# Internal helpers
# -----------------------------------------------------------------------------


def _get_mop_const_value(mop: object) -> Optional[int]:
    """Extract a constant integer value from a microcode operand if it is a number operand.

    Thin wrapper over the portable core in
    ``d810.analyses.value_flow.state_write`` (LS6 S5); supplies the live
    operand-type name resolver.
    """
    _init_constants()
    return state_write.get_mop_const_value(mop, mop_type_name=_mop_type_name)


def _dump_dispatcher_node(
    mba: object,
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
    bst_node_blocks: Optional[BSTNodeMap] = None,
    allow_revisit: bool = False,
    parent_serial: Optional[int] = None,
    branch: str = "",
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
        bst_node_blocks: If provided, collects all BST internal/comparison block serials
            (blocks to NOP after m_jtbl conversion).
        parent_serial: Serial of the BST parent node that routes to this node.
        branch: Which branch of the parent leads here ("taken" or "fallthrough").
    """
    _init_constants()

    if depth > max_depth:
        lines.append("  " * indent + f"blk[{serial}] <max depth reached>")
        return

    if serial in visited:
        if not allow_revisit:
            lines.append("  " * indent + f"blk[{serial}] <already visited>")
            return
        # allow_revisit=True: proceed without re-adding to visited (already there)
    else:
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

    opcode_kind = _opcode_kind(opcode)
    is_jbe = opcode_kind is NodeKind.JBE
    is_ja = opcode_kind is NodeKind.JA
    is_jb = opcode_kind is NodeKind.JB
    is_jae = opcode_kind is NodeKind.JAE
    is_jnz = opcode_kind is NodeKind.JNZ
    is_jz = opcode_kind is NodeKind.JZ

    if is_jbe or is_ja or is_jb or is_jae:
        if bst_node_blocks is not None:
            bst_node_blocks.add(serial,
                value_range=(value_lo, value_hi),
                parent_serial=parent_serial,
                comparison_const=cmp_val,
                branch=branch,
                depth=depth,
                opcode=opcode,
                is_equality_branch=False,
            )
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
        # m_jb: if state_var < X → jump (succs[1]); else fall-through (succs[0])
        #   fall-through range: [X,   hi]  (state >= X)
        #   taken      range:   [lo,  X-1] (state < X)
        # m_jae: if state_var >= X → jump (succs[1]); else fall-through (succs[0])
        #   fall-through range: [lo,  X-1] (state < X)
        #   taken      range:   [X,   hi]  (state >= X)
        X = cmp_val
        MASK = 0xFFFFFFFF
        if is_jbe:
            fall_lo = (X + 1) & MASK if X is not None else None
            fall_hi = value_hi
            taken_lo = value_lo
            taken_hi = X
        elif is_ja:
            fall_lo = value_lo
            fall_hi = X
            taken_lo = (X + 1) & MASK if X is not None else None
            taken_hi = value_hi
        elif is_jb:
            fall_lo = X
            fall_hi = value_hi
            taken_lo = value_lo
            taken_hi = (X - 1) & MASK if X is not None else None
        else:  # m_jae
            fall_lo = value_lo
            fall_hi = (X - 1) & MASK if X is not None else None
            taken_lo = X
            taken_hi = value_hi

        child_ranges = [(fall_lo, fall_hi), (taken_lo, taken_hi)]
        child_branches = ["fallthrough", "taken"]
        for idx, s in enumerate(succs):
            c_lo, c_hi = child_ranges[idx] if idx < len(child_ranges) else (None, None)
            c_branch = child_branches[idx] if idx < len(child_branches) else ""
            _dump_dispatcher_node(
                mba, s, indent + 1, visited, lines, depth + 1, max_depth,
                value_lo=c_lo,
                value_hi=c_hi,
                handler_state_map=handler_state_map,
                handler_serials=handler_serials,
                handler_range_map=handler_range_map,
                chain_depth=chain_depth,
                bst_node_blocks=bst_node_blocks,
                parent_serial=serial,
                branch=c_branch,
            )

    elif is_jnz or is_jz:
        if bst_node_blocks is not None:
            bst_node_blocks.add(serial,
                value_range=(value_lo, value_hi),
                parent_serial=parent_serial,
                comparison_const=cmp_val,
                branch=branch,
                depth=depth,
                opcode=opcode,
                is_equality_branch=False,  # The leaf node itself is not an equality branch
            )
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

        # Extract the state variable size from the root BST node once so that
        # _is_bst_node / _is_bst_node_chain can reject comparisons that test a
        # differently-sized operand (e.g. an 8-byte pointer vs NULL).
        # mop_n == 2: the constant side; the other side is the state variable.
        if getattr(insn.l, "t", None) == 2:  # mop_n on left → state var on right
            _root_state_var_size = getattr(insn.r, "size", None)
        elif getattr(insn.r, "t", None) == 2:  # mop_n on right → state var on left
            _root_state_var_size = getattr(insn.l, "size", None)
        else:
            _root_state_var_size = None  # Can't determine, skip size filtering

        def _is_bst_node(blk_serial: int) -> bool:
            if blk_serial in visited:
                return False
            _b = mba.get_mblock(blk_serial)
            if _b is None or _b.nsucc() != 2:
                return False
            _tail = _b.tail
            if _tail is None:
                return False
            if not _is_bst_opcode(getattr(_tail, "opcode", None)):
                return False
            if _root_state_var_size is not None:
                _l_t = getattr(_tail.l, "t", None)
                _r_t = getattr(_tail.r, "t", None)
                if _l_t == 2:  # mop_n on left, state var on right
                    if getattr(_tail.r, "size", None) != _root_state_var_size:
                        return False
                elif _r_t == 2:  # mop_n on right, state var on left
                    if getattr(_tail.l, "size", None) != _root_state_var_size:
                        return False
                else:
                    return False  # No constant operand → not a BST comparison
            return True

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
            if not _is_bst_opcode(getattr(_tail, "opcode", None)):
                return False
            if _root_state_var_size is not None:
                _l_t = getattr(_tail.l, "t", None)
                _r_t = getattr(_tail.r, "t", None)
                if _l_t == 2:  # mop_n on left, state var on right
                    if getattr(_tail.r, "size", None) != _root_state_var_size:
                        return False
                elif _r_t == 2:  # mop_n on right, state var on left
                    if getattr(_tail.l, "size", None) != _root_state_var_size:
                        return False
                else:
                    return False  # No constant operand → not a BST comparison
            return True

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
                    if bst_node_blocks is not None:
                        bst_node_blocks.add(fall_blk,
                            value_range=(value_lo, value_hi),
                            parent_serial=serial,
                            comparison_const=cmp_val,
                            branch="fallthrough",
                            depth=depth + 1,
                            opcode=None,
                            is_equality_branch=True,
                            is_handler_entry=True,
                        )

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
                        bst_node_blocks=bst_node_blocks,
                        allow_revisit=True,
                        parent_serial=serial,
                        branch="taken",
                    )
                elif not already_resolved and not _is_bst_node_chain(jump_blk):
                    if cmp_val is None:
                        lines.append(f"{prefix}  [unknown cmp_val: cannot classify jump blk[{jump_blk}]]")
                    elif handler_serials is not None and jump_state is not None:
                        handler_serials.add(jump_blk)
                        if handler_state_map is not None:
                            handler_state_map[jump_blk] = jump_state
                        if handler_range_map is not None:
                            handler_range_map[jump_blk] = (value_lo, value_hi)
                        if bst_node_blocks is not None:
                            bst_node_blocks.add(jump_blk,
                                value_range=(value_lo, value_hi),
                                parent_serial=serial,
                                comparison_const=jump_state,
                                branch="taken",
                                depth=depth + 1,
                                opcode=None,
                                is_equality_branch=False,
                                is_handler_entry=True,
                            )
                    # When jump_state is None, the range has >2 values but the
                    # continuation is not a BST node — this is the BST default/
                    # exit block (reached when no comparison matches). Do NOT
                    # classify it as a handler.

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
                    if bst_node_blocks is not None:
                        bst_node_blocks.add(jump_blk,
                            value_range=(value_lo, value_hi),
                            parent_serial=serial,
                            comparison_const=cmp_val,
                            branch="taken",
                            depth=depth + 1,
                            opcode=None,
                            is_equality_branch=True,
                            is_handler_entry=True,
                        )

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
                        bst_node_blocks=bst_node_blocks,
                        allow_revisit=True,
                        parent_serial=serial,
                        branch="fallthrough",
                    )
                elif not already_resolved and not _is_bst_node_chain(fall_blk):
                    if cmp_val is None:
                        lines.append(f"{prefix}  [unknown cmp_val: cannot classify fall-through blk[{fall_blk}]]")
                    elif handler_serials is not None and fall_state is not None:
                        handler_serials.add(fall_blk)
                        if handler_state_map is not None:
                            handler_state_map[fall_blk] = fall_state
                        if handler_range_map is not None:
                            handler_range_map[fall_blk] = (value_lo, value_hi)
                        if bst_node_blocks is not None:
                            bst_node_blocks.add(fall_blk,
                                value_range=(value_lo, value_hi),
                                parent_serial=serial,
                                comparison_const=fall_state,
                                branch="fallthrough",
                                depth=depth + 1,
                                opcode=None,
                                is_equality_branch=False,
                                is_handler_entry=True,
                            )

    else:
        cmp_str = f"0x{cmp_val:x}" if cmp_val is not None else "?"
        lines.append(
            f"{prefix}blk[{serial}] {opcode_name} {cmp_str} (succs: {succs})"
        )


def _find_pre_header(
    mba: object,
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
        # Pre-header has exactly one successor: the dispatcher entry
        if nsucc == 1 and pred_blk.succ(0) == dispatcher_entry_serial:
            if diag_lines is not None:
                diag_lines.append(
                    f"  candidate blk[{pred_serial}]: nsucc={nsucc} npred={pred_npred}"
                    f" tail={tail_opname} succ0=blk[{pred_blk.succ(0)}]"
                )
            # Prefer fewest predecessors; break ties by lowest serial
            if pred_npred < best_npred or (pred_npred == best_npred and pred_serial < best_serial):
                best_npred = pred_npred
                best_serial = pred_serial
    if best_serial is not None and diag_lines is not None:
        diag_lines.append(f"  Selected pre-header: blk[{best_serial}] (npred={best_npred}, serial={best_serial})")
    return best_serial


def _mop_matches_stkoff(
    mop: object,
    state_var_stkoff: int,
    diag_lines: Optional[List[str]] = None,
    state_var_lvar_idx: Optional[int] = None,
    mba: Optional[object] = None,
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
    mop_S_type = _mop_type_value("mop_S", None)
    mop_a_type = _mop_type_value("mop_a", None)
    mop_l_type = _mop_type_value("mop_l", None)

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


def _resolve_mop_value_in_block(
    mop: object,
    blk: object,
    insn_before: object,
    max_depth: int = 2,
) -> Optional[int]:
    """Backward-scan *blk* for the instruction that defines *mop* and fold it.

    Only handles binary ops (m_add, m_sub, m_and, m_or, m_xor) where BOTH
    operands resolve to literal constants within the same block.  Max recursion
    depth is *max_depth* (default 2) to prevent runaway recursion.

    Args:
        mop: The source operand whose constant value we want to resolve.
        blk: The microcode block to scan backward in.
        insn_before: Scan only instructions that appear *before* this one.
        max_depth: Maximum recursive resolution depth.

    Returns:
        The folded integer value (masked to 32 bits), or None if resolution failed.
    """
    if max_depth <= 0:
        return None

    _init_constants()

    # Fast path: already a literal constant.
    val = _get_mop_const_value(mop)
    if val is not None:
        return val

    mop_type = getattr(mop, "t", None)
    # Only handle register (mop_r=1) and local-var (mop_l=9) sources.
    mop_r_type = _mop_type_value("mop_r", 1)
    mop_l_type = _mop_type_value("mop_l", 9)
    if mop_type not in (mop_r_type, mop_l_type):
        return None

    # Opcodes for binary arithmetic/logic ops.
    m_add = _opcode_value("m_add", 28)
    m_sub = _opcode_value("m_sub", 29)
    m_and = _opcode_value("m_and", 21)
    m_or = _opcode_value("m_or", 22)
    m_xor = _opcode_value("m_xor", 31)
    binary_ops = {m_add, m_sub, m_and, m_or, m_xor}

    def _mops_match(a: object, b: object) -> bool:
        """Return True when two mops refer to the same register or lvar."""
        at = getattr(a, "t", None)
        bt = getattr(b, "t", None)
        if at != bt:
            return False
        if at == mop_r_type:
            return getattr(a, "r", None) == getattr(b, "r", None)
        if at == mop_l_type:
            return getattr(a, "l", None) == getattr(b, "l", None)
        return False

    # Collect instructions before insn_before, in order.
    insns_before: List[object] = []
    cur = blk.head
    while cur is not None and cur is not insn_before:
        insns_before.append(cur)
        cur = getattr(cur, "next", None)

    # Scan backward for the instruction whose destination matches *mop*.
    for definer in reversed(insns_before):
        d = getattr(definer, "d", None)
        if d is None:
            continue
        if not _mops_match(d, mop):
            continue
        # Found the defining instruction — must be a binary op.
        op = getattr(definer, "opcode", None)
        if op not in binary_ops:
            return None
        l_op = getattr(definer, "l", None)
        r_op = getattr(definer, "r", None)
        lv = _resolve_mop_value_in_block(l_op, blk, definer, max_depth - 1)
        rv = _resolve_mop_value_in_block(r_op, blk, definer, max_depth - 1)
        if lv is None or rv is None:
            return None
        if op == m_xor:
            result = lv ^ rv
        elif op == m_sub:
            result = lv - rv
        elif op == m_add:
            result = lv + rv
        elif op == m_and:
            result = lv & rv
        else:  # m_or
            result = lv | rv
        return result & 0xFFFFFFFF

    return None


def _fetch_idb_value(address: int, size: int) -> int | None:
    """Read a scalar IDB value without depending on higher hexrays helpers."""
    return _hexrays_bst_runtime.fetch_idb_value(address, size)


def _segment_is_read_only(addr: int) -> bool:
    return _hexrays_bst_runtime.segment_is_read_only(addr)


def _is_never_written_var(address: int) -> bool:
    return _hexrays_bst_runtime.is_never_written_var(address)


def _fetch_stable_global_value(addr: int, size: int) -> int | None:
    if not addr or size not in (1, 2, 4, 8):
        return None
    if not (_segment_is_read_only(addr) or _is_never_written_var(addr)):
        return None
    value = _fetch_idb_value(addr, size)
    if value is None:
        return None
    return int(value) & ((1 << (size * 8)) - 1)


_EVAL_SEAMS = state_write.MicrocodeEvalSeams(
    mop_type_name=_mop_type_name,
    mop_type_value=_mop_type_value,
    opcode_value=_opcode_value,
    opcode_name=_opcode_name,
    fetch_stable_global_value=_fetch_stable_global_value,
    lvar_stkoff=lambda mba, idx: mba.vars[idx].location.stkoff(),
)


def _resolve_mop_from_maps(
    mop: object,
    stk_map: Dict[int, int],
    reg_map: Dict[int, int],
    mba: Optional[object] = None,
    state_var_lvar_idx: Optional[int] = None,
    diag_lines: Optional[List[str]] = None,
) -> Optional[int]:
    """Resolve a microcode operand to a concrete value using accumulated forward-eval maps.

    Thin wrapper over the portable core in
    ``d810.analyses.value_flow.state_write`` (LS6 S5).
    """
    _init_constants()
    return state_write.resolve_mop_from_maps(
        mop,
        stk_map,
        reg_map,
        seams=_EVAL_SEAMS,
        mba=mba,
        state_var_lvar_idx=state_var_lvar_idx,
        diag_lines=diag_lines,
    )


def _forward_eval_insn(
    insn: object,
    stk_map: Dict[int, int],
    reg_map: Dict[int, int],
    state_var_stkoff: int,
    mba: Optional[object] = None,
    state_var_lvar_idx: Optional[int] = None,
    diag_lines: Optional[List[str]] = None,
) -> Optional[int]:
    """Evaluate one instruction, updating stk_map/reg_map in-place.

    Thin wrapper over the portable core in
    ``d810.analyses.value_flow.state_write`` (LS6 S5).  Returns the resolved
    constant if this instruction writes the state variable; otherwise returns
    None and updates the maps.
    """
    _init_constants()
    return state_write.forward_eval_insn(
        insn,
        stk_map,
        reg_map,
        state_var_stkoff,
        seams=_EVAL_SEAMS,
        mba=mba,
        state_var_lvar_idx=state_var_lvar_idx,
        diag_lines=diag_lines,
    )


def _extract_state_from_block(
    blk: object,
    state_var_stkoff: int,
    diag_lines: Optional[List[str]] = None,
    state_var_lvar_idx: Optional[int] = None,
    mba: Optional[object] = None,
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
    m_mov_opcode = _opcode_value("m_mov", None)
    m_stx_opcode = _opcode_value("m_stx", None)

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
                # Fallback: source is non-constant — try MBA constant folding.
                folded = _resolve_mop_value_in_block(l, blk, insn)
                if folded is not None:
                    if diag_lines is not None:
                        diag_lines.append(
                            f"  -> FOUND m_mov state write (folded): 0x{folded:x}"
                        )
                    return folded

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
                # Fallback: source is non-constant — try MBA constant folding.
                folded = _resolve_mop_value_in_block(l, blk, insn)
                if folded is not None:
                    if diag_lines is not None:
                        diag_lines.append(
                            f"  -> FOUND m_stx state write (folded): 0x{folded:x}"
                        )
                    return folded

        insn = getattr(insn, "next", None)
        insn_idx += 1
    return None


def _walk_handler_chain(
    mba: object,
    handler_start_serial: int,
    dispatcher_entry_serial: int,
    state_var_stkoff: int,
    chain_visited: Optional[set] = None,
    max_chain_depth: int = 64,
    diag_lines: Optional[List[str]] = None,
    state_var_lvar_idx: Optional[int] = None,
    _branch_depth: int = 0,
) -> Dict[str, Any]:
    """Walk a handler's block chain to find the next-state write and back-edge.

    Follows single-successor chains. Scans each block for an m_mov write to
    the state variable (matched by stkoff or lvar index). Stops at:
    - Blocks with multiple predecessors (potential merge/join)
    - The dispatcher entry (back-edge detected)
    - A block with no successors (function exit)
    - Max depth exceeded

    At multi-successor blocks (nsucc <= 4), spawns recursive sub-walks for
    each successor (up to 1 level of branching). Results are merged:
    - All branches same next_state + back_edge → deterministic transition
    - All branches back_edge but different states → conditional_states set
    - Mix of exit + transition → conditional exit
    - Any branch unresolvable → unknown (conservative)

    Args:
        mba: The microcode block array.
        handler_start_serial: First block of this handler.
        dispatcher_entry_serial: Serial of the dispatcher entry block.
        state_var_stkoff: Stack offset of the state variable.
        chain_visited: External visited set to avoid re-walking shared blocks.
        max_chain_depth: Maximum blocks to walk per handler.
        diag_lines: Optional list to collect diagnostic output strings.
        state_var_lvar_idx: If not None, also match mop_l writes by lvar index.
        _branch_depth: Internal recursion depth for multi-succ branching (max 1).

    Returns:
        Dict with keys:
            - next_state: int or None — constant written to state var
            - back_edge: bool — True if chain reaches dispatcher
            - exit: bool — True if chain reaches a no-successor block
            - chain: List[int] — block serials walked
            - conditional_states: set of int (optional) — multiple next states
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

    # Forward-eval maps: accumulate variable -> value across blocks in chain.
    # Initialized once before the loop so constants from blk[N] carry into blk[N+1].
    fwd_stk_map: Dict[int, int] = {}
    fwd_reg_map: Dict[int, int] = {}

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
        if state_var_stkoff is not None:
            fast_val = _extract_state_from_block(
                blk, state_var_stkoff, diag_lines=diag_lines,
                state_var_lvar_idx=state_var_lvar_idx, mba=mba,
            ) if result["next_state"] is None else None
            if fast_val is not None:
                result["next_state"] = fast_val
                if diag_lines is not None:
                    diag_lines.append(f"  walker: found next_state=0x{fast_val:x} in blk[{current}]")
                # Fast path found it — still run forward eval to keep maps current.
                fwd_insn = blk.head
                while fwd_insn is not None:
                    _forward_eval_insn(
                        fwd_insn, fwd_stk_map, fwd_reg_map, state_var_stkoff,
                        mba=mba, state_var_lvar_idx=state_var_lvar_idx,
                    )
                    fwd_insn = getattr(fwd_insn, "next", None)
            else:
                # Fast path did not find state (or already found in prior block).
                # Run forward eval to accumulate maps and check for MBA state writes.
                fwd_insn = blk.head
                while fwd_insn is not None:
                    fwd_val = _forward_eval_insn(
                        fwd_insn, fwd_stk_map, fwd_reg_map, state_var_stkoff,
                        mba=mba, state_var_lvar_idx=state_var_lvar_idx,
                        diag_lines=diag_lines,
                    )
                    if fwd_val is not None and result["next_state"] is None:
                        result["next_state"] = fwd_val
                        if diag_lines is not None:
                            diag_lines.append(
                                f"  walker: FOUND via fwd_eval: 0x{fwd_val:x} in blk[{current}]"
                            )
                    fwd_insn = getattr(fwd_insn, "next", None)

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
            # The state-var scan above already ran on this block.
            succs = [blk.succ(i) for i in range(nsucc)]
            if diag_lines is not None:
                diag_lines.append(
                    f"  walker: blk[{current}] nsucc={nsucc} succs={succs}"
                )

            # Attempt recursive sub-walks if budget allows and not too wide.
            if nsucc <= 4 and _branch_depth < 1:
                if diag_lines is not None:
                    diag_lines.append(
                        f"  walker: blk[{current}] branching into {nsucc} successors"
                        f" (branch_depth={_branch_depth})"
                    )
                sub_results = []
                remaining_depth = max_chain_depth - depth - 1
                for succ_serial in succs:
                    sub = _walk_handler_chain(
                        mba=mba,
                        handler_start_serial=succ_serial,
                        dispatcher_entry_serial=dispatcher_entry_serial,
                        state_var_stkoff=state_var_stkoff,
                        chain_visited=set(chain_visited),
                        max_chain_depth=max(0, remaining_depth),
                        diag_lines=diag_lines,
                        state_var_lvar_idx=state_var_lvar_idx,
                        _branch_depth=_branch_depth + 1,
                    )
                    sub_results.append(sub)
                    result["chain"].extend(sub["chain"])

                # Merge sub-walk results
                all_back_edge = all(s["back_edge"] for s in sub_results)
                any_back_edge = any(s["back_edge"] for s in sub_results)
                all_exit = all(s["exit"] for s in sub_results)
                any_exit = any(s["exit"] for s in sub_results)
                sub_states = [s["next_state"] for s in sub_results if s["next_state"] is not None]
                all_resolved = all(
                    s["back_edge"] or s["exit"] for s in sub_results
                )

                if not all_resolved:
                    # At least one branch is unresolvable — conservative unknown
                    if diag_lines is not None:
                        diag_lines.append(
                            f"  walker: branch merge: some unresolvable -> unknown"
                        )
                    break

                if all_back_edge and not any_exit:
                    # All branches reach dispatcher
                    unique_states = set(sub_states)
                    if len(unique_states) == 1 and result["next_state"] is None:
                        result["next_state"] = unique_states.pop()
                    elif len(unique_states) > 1 and result["next_state"] is None:
                        # Different next states per branch — conditional transition
                        result["conditional_states"] = unique_states
                    result["back_edge"] = True
                    if diag_lines is not None:
                        diag_lines.append(
                            f"  walker: branch merge: all back_edge"
                            f" states={set(sub_states)} -> back_edge"
                        )
                elif any_exit and any_back_edge:
                    # Mix of exit and transition — conditional exit
                    result["exit"] = True
                    if sub_states and result["next_state"] is None:
                        result["next_state"] = sub_states[0]
                    if diag_lines is not None:
                        diag_lines.append(
                            f"  walker: branch merge: mixed exit+transition"
                            f" -> conditional exit"
                        )
                elif all_exit:
                    result["exit"] = True
                    if diag_lines is not None:
                        diag_lines.append(
                            f"  walker: branch merge: all exit -> exit"
                        )
            else:
                if diag_lines is not None:
                    diag_lines.append(
                        f"  walker: blk[{current}] nsucc={nsucc} branch_depth={_branch_depth}"
                        f" -> multi-succ stop (too wide or depth limit)"
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
    mba: object,
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
    mba: object,
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

    mop_S_type = _mop_type_value("mop_S", None)
    mop_r_type = _mop_type_value("mop_r", None)
    mop_l_type = _mop_type_value("mop_l", None)
    mop_b_type = _mop_type_value("mop_b", None)
    mop_n_type = _mop_type_value("mop_n", None)

    def _block_ref(mop) -> Optional[int]:
        for attr in ("block_ref", "block_num", "b"):
            value = getattr(mop, attr, None)
            if value is None:
                continue
            try:
                return int(value)
            except (TypeError, ValueError):
                continue
        return None

    def _detect_from_operand(blk, mop, *, block_serial: int):
        mop_type = getattr(mop, "t", None)

        # Direct stack variable (mop_S)
        if mop_type == mop_S_type:
            s = getattr(mop, "s", None)
            if s is not None:
                off = getattr(s, "off", None)
                if off is not None:
                    if diag_lines is not None:
                        diag_lines.append(f"_detect_stkoff: mop_S hit -> stkoff=0x{off:x}")
                    return off, None

        # Register (mop_r) — try to find underlying stack variable.
        if mop_type == mop_r_type:
            reg = getattr(mop, "r", None)
            if diag_lines is not None:
                diag_lines.append(f"_detect_stkoff: mop_r register={reg}")
            insn = getattr(blk, "head", None)
            while insn is not None:
                d = getattr(insn, "d", None)
                if (
                    d is not None
                    and getattr(d, "t", None) == mop_r_type
                    and getattr(d, "r", None) == reg
                ):
                    src = getattr(insn, "l", None)
                    if src is not None and getattr(src, "t", None) == mop_S_type:
                        s = getattr(src, "s", None)
                        if s is not None:
                            off = getattr(s, "off", None)
                            if off is not None:
                                if diag_lines is not None:
                                    diag_lines.append(
                                        f"_detect_stkoff: found m_mov mop_S(0x{off:x}) -> reg{reg}"
                                    )
                                return off, None
                insn = getattr(insn, "next", None)
            if diag_lines is not None:
                diag_lines.append(
                    f"_detect_stkoff: no mop_S source found for reg{reg} in blk[{block_serial}]"
                )

        # Local variable (mop_l) — promoted stack var at higher maturity levels.
        if mop_type == mop_l_type:
            lref = getattr(mop, "l", None)
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
                        return off, idx
                    except Exception as e:
                        if diag_lines is not None:
                            diag_lines.append(
                                f"_detect_stkoff: mop_l lvar[{idx}] stkoff failed: {e}"
                            )

        return None, None

    def _candidate_operands(tail) -> tuple:
        left = getattr(tail, "l", None)
        right = getattr(tail, "r", None)
        if left is None:
            return () if right is None else (right,)
        if right is not None and getattr(left, "t", None) == mop_n_type:
            return (right, left)
        if right is None:
            return (left,)
        return (left, right)

    def _detect_from_block(block_serial: int, visited: Set[int]):
        if block_serial in visited:
            if diag_lines is not None:
                diag_lines.append(f"_detect_stkoff: blk[{block_serial}] cycle while following mop_b")
            return None, None
        visited.add(block_serial)

        blk = mba.get_mblock(block_serial)
        if blk is None:
            if diag_lines is not None:
                diag_lines.append(f"_detect_stkoff: blk[{block_serial}] is None")
            return None, None

        tail = getattr(blk, "tail", None)
        if tail is None:
            if diag_lines is not None:
                diag_lines.append(f"_detect_stkoff: blk[{block_serial}] has no tail")
            return None, None

        operands = _candidate_operands(tail)
        if not operands:
            if diag_lines is not None:
                diag_lines.append(f"_detect_stkoff: blk[{block_serial}] tail has no operands")
            return None, None

        if diag_lines is not None:
            operand_types = tuple(getattr(mop, "t", None) for mop in operands)
            diag_lines.append(
                f"_detect_stkoff: blk[{block_serial}] tail opcode={tail.opcode}"
                f" operand.t={operand_types} (mop_S={mop_S_type}, mop_r={mop_r_type},"
                f" mop_l={mop_l_type}, mop_b={mop_b_type})"
            )

        for mop in operands:
            mop_type = getattr(mop, "t", None)
            if mop_type == mop_b_type:
                target_serial = _block_ref(mop)
                if diag_lines is not None:
                    diag_lines.append(
                        f"_detect_stkoff: mop_b block reference -> blk[{target_serial}]"
                    )
                if target_serial is None:
                    continue
                detected = _detect_from_block(int(target_serial), visited)
                if detected[0] is not None:
                    return detected
                continue
            detected = _detect_from_operand(blk, mop, block_serial=block_serial)
            if detected[0] is not None:
                return detected

        if diag_lines is not None:
            raw_types = tuple(getattr(mop, "t", None) for mop in operands)
            diag_lines.append(f"_detect_stkoff: FAILED - unhandled operand types {raw_types}")
        return None, None

    stkoff, lvar_idx = _detect_from_block(int(dispatcher_entry_serial), set())
    return _return(stkoff, lvar_idx)


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------


@algorithm_metadata(
    algorithm_id="recon.analyze_bst_dispatcher",
    family="compare_chain_interval_dispatch_reconstruction",
    summary="Analyzes BST-style state dispatchers to recover handler states and transitions.",
    use_cases=(
        "Recover handler-entry mappings and successor states from interval/BST dispatch ladders.",
        "Seed dispatcher reports and semantic DAG construction from a resolved BST dispatcher root.",
    ),
    examples=(
        "Walk a JNZ/JZ/JBE ladder to map state constants to handler blocks and terminal exits.",
        "Detect the default block and handler transitions for a state variable dispatched through a BST.",
    ),
    tags=("bst", "dispatcher", "intervals", "state-machine", "analysis"),
    related_paths=(
        "src/d810/backends/hexrays/evidence/bst_analysis.py",
        "src/d810/cfg/flow/compare_chain.py",
    ),
)
def analyze_bst_dispatcher(
    mba: object,
    dispatcher_entry_serial: int,
    state_var_stkoff: Optional[int] = None,
    state_var_lvar_idx: Optional[int] = None,
    max_depth: int = 20,
) -> BSTAnalysisResult:
    """Analyze a BST-style dispatcher and return a structured result.

    Performs two analysis phases:

    Phase 1 — BST walk: starts at *dispatcher_entry_serial* and recursively
    follows jbe/ja/jnz/jz comparisons, collecting handler block serials and
    the state constant associated with each leaf.

    Phase 2 — Handler walk: for each handler identified in phase 1, follows
    the successor chain to find the next-state write (m_mov/m_stx to the state
    variable) and whether the handler loops back to the dispatcher or exits.

    Args:
        mba: The microcode block array.
        dispatcher_entry_serial: Block serial number of the BST root block.
        state_var_stkoff: Stack offset of the state variable.  When None, it
            is auto-detected from the BST root's comparison instruction.
        state_var_lvar_idx: lvar index for mop_l matching (auto-set when
            auto-detection finds a promoted stack variable).
        max_depth: Maximum BST recursion depth (guard against malformed CFGs).

    Returns:
        A populated :class:`BSTAnalysisResult`.
    """
    _init_constants()

    result = BSTAnalysisResult()

    # Auto-detect stkoff / lvar_idx when not provided
    if state_var_stkoff is None:
        detected, detected_lvar_idx = _detect_state_var_stkoff(
            mba, dispatcher_entry_serial, diag=False
        )
        if detected is not None:
            state_var_stkoff = detected
            if state_var_lvar_idx is None:
                state_var_lvar_idx = detected_lvar_idx

    # Phase 1: Pre-header + initial state
    pre_header_serial, initial_state = _find_pre_header_state(
        mba, dispatcher_entry_serial, state_var_stkoff,
        state_var_lvar_idx=state_var_lvar_idx,
    )
    result.pre_header_serial = pre_header_serial
    result.initial_state = initial_state

    # Phase 1 (cont.): BST walk to collect handler_state_map, handler_serials, handler_range_map
    bst_lines: List[str] = []
    bst_visited: set = set()
    handler_state_map: Dict[int, int] = {}
    handler_serials: set = set()
    handler_range_map: Dict[int, Tuple[Optional[int], Optional[int]]] = {}
    bst_node_blocks: BSTNodeMap = BSTNodeMap()

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
        bst_node_blocks=bst_node_blocks,
    )

    result.handler_state_map = handler_state_map
    result.handler_range_map = handler_range_map
    result.bst_node_blocks = bst_node_blocks

    # Phase 1b: Build interval dispatcher (parallel to existing BST walk)
    dispatcher = None
    try:
        dispatch_tree, _dispatch_bst_serials = build_dispatch_tree(
            mba, dispatcher_entry_serial, state_var_stkoff,
        )
        if dispatch_tree is not None:
            emitted = emit_dispatch_intervals(dispatch_tree)
            dispatcher = IntervalDispatcher.from_emitted(emitted)
    except Exception:
        logger.warning(
            "INTERVAL_MAP: build_dispatch_tree failed", exc_info=True
        )
        dispatcher = None
    result.dispatcher = dispatcher
    if dispatcher is not None:
        logger.info("INTERVAL_DISPATCHER_ROWS: %s", dispatcher.to_json())
        try:
            from d810.core.observability import emit as _emit_observation
            from d810.core.observability_events import (
                BstIntervalDispatcherObserved,
            )

            _emit_observation(BstIntervalDispatcherObserved(
                func_ea=int(getattr(mba, "entry_ea", 0) or 0),
                maturity="MMAT_GLBOPT1",
                dispatcher_entry_block=int(dispatcher_entry_serial),
                rows=tuple(dispatcher._rows),
            ))
        except Exception:
            logger.debug(
                "INTERVAL_DISPATCHER_ROWS structured persistence failed",
                exc_info=True,
            )

    # Back-fill handler_state_map from IntervalDispatcher for handlers
    # missed by legacy walk (e.g., JNZ taken branches with range_is_pair=False)
    if dispatcher is not None:
        backfill_point = 0
        backfill_range = 0
        for row in dispatcher._rows:
            if row.target is None or row.target in handler_state_map:
                continue
            handler_serials.add(row.target)
            if row.hi - row.lo == 1:
                # Width-1 interval = exact state match
                handler_state_map[row.target] = row.lo
                backfill_point += 1
            else:
                # Wider interval — register in range map only
                # IntervalRow uses exclusive hi; handler_range_map uses inclusive
                handler_range_map[row.target] = (row.lo, row.hi - 1)
                backfill_range += 1
        if backfill_point or backfill_range:
            logger.info(
                "INTERVAL_BACKFILL: %d point + %d range handlers added",
                backfill_point, backfill_range,
            )
            # Update result after back-fill
            result.handler_state_map = handler_state_map
            result.handler_range_map = handler_range_map

    if result.handler_state_map:
        try:
            from d810.core.observability import emit as _emit_observation
            from d810.core.observability_events import (
                StateDispatcherRowsObserved,
            )

            state_rows = tuple(
                {
                    "state_const": int(state_const),
                    "target_block": int(handler_serial),
                    "dispatcher_entry_block": int(dispatcher_entry_serial),
                    "compare_block": None,
                    "dispatcher_kind": "CONDITIONAL_CHAIN",
                    "branch_kind": "handler_state_map",
                    "confidence": 1.0,
                }
                for handler_serial, state_const
                in sorted(result.handler_state_map.items())
            )
            logger.info(
                "STATE_DISPATCHER_ROWS: emitting %d exact rows",
                len(state_rows),
            )
            _emit_observation(StateDispatcherRowsObserved(
                func_ea=int(getattr(mba, "entry_ea", 0) or 0),
                maturity="MMAT_GLBOPT1",
                dispatcher_entry_block=int(dispatcher_entry_serial),
                dispatcher_kind="CONDITIONAL_CHAIN",
                rows=state_rows,
            ))
        except Exception:
            logger.debug(
                "STATE_DISPATCHER_ROWS structured observation failed",
                exc_info=True,
            )

    # Diagnostic: compare interval dispatcher against legacy handler_state_map.
    # to_handler_state_map() returns {state_const: handler_serial} (lo -> target),
    # while handler_state_map is {handler_serial: state_const}.
    # Invert derived_hsm so both dicts share the same {serial: state} semantics.
    if result.dispatcher is not None:
        derived_hsm_raw = result.dispatcher.to_handler_state_map()
        derived_hsm = {serial: state for state, serial in derived_hsm_raw.items()}
        if derived_hsm != result.handler_state_map:
            logger.warning(
                "INTERVAL_MAP_DIAG: handler_state_map mismatch: "
                "interval=%d entries, legacy=%d entries, "
                "missing_in_interval=%s, extra_in_interval=%s",
                len(derived_hsm), len(result.handler_state_map),
                set(result.handler_state_map.items()) - set(derived_hsm.items()),
                set(derived_hsm.items()) - set(result.handler_state_map.items()),
            )
        else:
            logger.info(
                "INTERVAL_MAP_DIAG: perfect agreement, %d entries",
                len(derived_hsm),
            )

    # Default block: BST successor that is neither a BST node nor a handler
    result.default_block_serial = find_bst_default_block(
        mba, dispatcher_entry_serial, bst_node_blocks, handler_serials,
    )

    # Phase 2: Walk each handler chain
    for h_serial in sorted(handler_serials):
        state_const = handler_state_map.get(h_serial)

        if state_var_stkoff is not None:
            per_handler_visited: set = set()
            walk = _walk_handler_chain(
                mba,
                h_serial,
                dispatcher_entry_serial,
                state_var_stkoff,
                chain_visited=per_handler_visited,
                state_var_lvar_idx=state_var_lvar_idx,
            )
        else:
            walk = {"next_state": None, "back_edge": False, "exit": False, "chain": []}

        next_state = walk.get("next_state")
        is_exit = walk.get("exit") or (
            not walk.get("back_edge") and walk.get("chain")
        )

        if state_const is not None:
            result.transitions[state_const] = next_state
            if is_exit:
                result.exits.add(state_const)
            if walk.get("conditional_states"):
                result.conditional_transitions[state_const] = walk["conditional_states"]

    return result


# -----------------------------------------------------------------------------
# Dispatch tree builder (decode / build / emit)
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class DecodedCond:
    """Decoded BST comparison from a block tail instruction."""

    kind: NodeKind
    imm: int
    taken_serial: int
    fall_serial: int


_MCODE_TO_KIND: dict[int, NodeKind] | None = None


def _get_mcode_to_kind() -> dict[int, NodeKind]:
    global _MCODE_TO_KIND
    if _MCODE_TO_KIND is None:
        _init_constants()
        _MCODE_TO_KIND = {
            opcode: _BST_OPCODE_NAME_TO_KIND[name]
            for opcode, name in OPCODE_MAP.items()
            if name in _BST_OPCODE_NAME_TO_KIND
        }
    return _MCODE_TO_KIND


def extract_cmp_imm_from_jcnd(
    tail_insn,
    state_var_stkoff: int,
) -> int | None:
    """Extract comparison immediate from a jcnd tail instruction.

    Returns the immediate constant if the comparison involves the state
    variable, or None if unrecognized.
    """
    l_mop = getattr(tail_insn, "l", None)
    r_mop = getattr(tail_insn, "r", None)
    if not (
        _mop_matches_stkoff(l_mop, state_var_stkoff)
        or _mop_matches_stkoff(r_mop, state_var_stkoff)
    ):
        return None
    l_val = _get_mop_const_value(l_mop)
    r_val = _get_mop_const_value(r_mop)
    return l_val if l_val is not None else r_val


def decode_dispatch_cond(
    mba,
    blk_serial: int,
    state_var_stkoff: int,
) -> DecodedCond | None:
    """Decode a BST comparison node from an MBA block.

    Returns DecodedCond if the block is a 2-way conditional comparing
    the state variable against a constant. Returns None otherwise.
    """
    blk = mba.get_mblock(blk_serial)
    if blk.nsucc() != 2:
        return None
    tail = blk.tail
    if tail is None:
        return None
    mcode_to_kind = _get_mcode_to_kind()
    kind = mcode_to_kind.get(tail.opcode)
    if kind is None:
        return None
    imm = extract_cmp_imm_from_jcnd(tail, state_var_stkoff)
    if imm is None:
        return None
    fall_serial = blk.succ(0)
    taken_serial = blk.succ(1)
    return DecodedCond(
        kind=kind,
        imm=imm,
        taken_serial=taken_serial,
        fall_serial=fall_serial,
    )


def build_dispatch_tree(
    mba,
    root_serial: int,
    state_var_stkoff: int,
    *,
    max_depth: int = 40,
) -> tuple[Node | None, set[int]]:
    """Walk MBA blocks to build a Node tree for interval emission.

    Returns:
        (root_node, bst_block_serials): The Node tree and set of
        BST comparison block serials visited during construction.
    """
    bst_serials: set[int] = set()
    memo: dict[int, Node] = {}

    def _build(serial: int, depth: int) -> Node | None:
        if depth > max_depth or serial < 0 or serial >= mba.qty:
            return None

        dc = decode_dispatch_cond(mba, serial, state_var_stkoff)

        # Only memoize interior range-split nodes (safe to share).
        # JZ/JNZ chain nodes and TARGET nodes are path-sensitive —
        # memoizing by block serial causes overlapping intervals when
        # the same block is reachable from multiple BST paths.
        memoable = (
            dc is not None
            and dc.kind in (NodeKind.JBE, NodeKind.JA, NodeKind.JB, NodeKind.JAE)
        )

        if memoable and serial in memo:
            return memo[serial]

        if dc is None:
            # TARGET — always fresh, never memoized
            return Node(
                kind=NodeKind.TARGET,
                target=serial,
                block_serial=serial,
            )

        bst_serials.add(serial)

        match dc.kind:
            case NodeKind.JBE | NodeKind.JA | NodeKind.JB | NodeKind.JAE:
                node = Node(
                    kind=dc.kind,
                    imm=dc.imm,
                    yes=_build(dc.taken_serial, depth + 1),
                    no=_build(dc.fall_serial, depth + 1),
                    block_serial=serial,
                )
            case NodeKind.JNZ:
                node = Node(
                    kind=NodeKind.JNZ,
                    imm=dc.imm,
                    target=dc.fall_serial,
                    yes=_build(dc.taken_serial, depth + 1),
                    block_serial=serial,
                )
            case NodeKind.JZ:
                node = Node(
                    kind=NodeKind.JZ,
                    imm=dc.imm,
                    target=dc.taken_serial,
                    no=_build(dc.fall_serial, depth + 1),
                    block_serial=serial,
                )
            case _:
                node = Node(
                    kind=NodeKind.TARGET,
                    target=serial,
                    block_serial=serial,
                )

        if memoable:
            memo[serial] = node

        return node

    root = _build(root_serial, 0)
    return root, bst_serials


# -----------------------------------------------------------------------------
# Provider factory (composition-root wiring)
# -----------------------------------------------------------------------------
def _get_block(mba: object, serial: int) -> object | None:
    """Backend block lookup seam (ticket llr-zeyu).

    Lives in the backend layer where the live-MBA method API is allowed.  The
    ``mba`` argument is whatever the portable caller holds -- a live ``mba_t``
    or a ``_FlowGraphMBAView`` snapshot projection -- both of which expose
    ``get_mblock``; the call is identical to the inlined access it replaces.
    """
    return mba.get_mblock(serial)


def _block_successors(block: object) -> tuple[int, ...]:
    """Backend successor-serial seam (ticket llr-zeyu).

    Equivalent to the inlined ``[blk.succ(i) for i in range(blk.nsucc())]`` the
    portable path analyses used to run; ``block`` is a live ``mblock_t`` or a
    ``_BlockView`` projection, both of which expose ``nsucc``/``succ``.
    """
    return tuple(block.succ(i) for i in range(block.nsucc()))


def build_bst_walker_provider() -> BstWalkerProvider:
    """Bundle this backend's BST evidence seams for the provider registry.

    Single source of truth for which Hex-Rays evidence callables satisfy each
    portable seam.  Called by the composition root (``D810State.start_d810``)
    and by unit-test fixtures, so production and tests inject identical walkers
    into ``d810.capabilities.providers`` (recon reads them via
    ``get_bst_walkers()`` without importing this backend; ticket d81-1w16).
    """
    return BstWalkerProvider(
        detect_state_var_stkoff=_detect_state_var_stkoff,
        dump_dispatcher_node=_dump_dispatcher_node,
        find_pre_header_state=_find_pre_header_state,
        walk_handler_chain=_walk_handler_chain,
        forward_eval_insn=_forward_eval_insn,
        resolve_via_bst_walk=resolve_via_bst_walk,
        get_block=_get_block,
        block_successors=_block_successors,
    )


def _get_function_entry_ea(mba: Any) -> int:
    """Function entry EA off the opaque backend object (live ``mba_t`` or projection).

    Byte-identical to the inlined ``mba.entry_ea`` the portable code used to read; both a
    live ``mba_t`` and a ``FlowGraph`` projection expose ``entry_ea``.
    """
    return int(mba.entry_ea)


def _get_mba_maturity(mba: Any) -> int:
    """Maturity off the opaque backend object. Byte-identical to ``mba.maturity``."""
    return int(mba.maturity)


def _get_block_count(mba: Any) -> int:
    """Block count off the opaque backend object. Byte-identical to ``mba.qty``."""
    return mba.qty


def _block_adjacency(mba: Any, qty: int) -> dict[int, tuple[int, ...]]:
    """Portable ``{serial: (successor_serial, ...)}`` map over ``range(qty)``.

    Byte-identical to the inlined ``mba.get_mblock(serial)`` +
    ``[blk.succ(i) for i in range(blk.nsucc())]`` walk: reuses ``_get_block`` /
    ``_block_successors`` so each lookup makes the identical live call.  Serials
    whose block is ``None`` are omitted (the caller treats a missing key as no
    successors, matching the original ``if blk is not None`` guard).
    """
    adjacency: dict[int, tuple[int, ...]] = {}
    for serial in range(qty):
        blk = _get_block(mba, serial)
        if blk is not None:
            adjacency[serial] = _block_successors(blk)
    return adjacency


def _is_glbopt1(mba: Any) -> bool:
    """GLBOPT1 maturity gate. Byte-identical to ``mba.maturity == MMAT_GLBOPT1``."""
    return int(mba.maturity) == ida_hexrays.MMAT_GLBOPT1


def _glbopt1_maturity(mba: Any) -> int:
    """Return the raw ``MMAT_GLBOPT1`` constant (for allowed-maturity tuples)."""
    return int(ida_hexrays.MMAT_GLBOPT1)


def _mmat_zero(mba: Any) -> int:
    """Return the raw ``MMAT_ZERO`` constant (the missing-maturity default)."""
    return int(ida_hexrays.MMAT_ZERO)


def build_microcode_evidence_provider() -> MicrocodeEvidenceProvider:
    """Bundle this backend's live microcode-evidence seams for the provider registry.

    Single source of truth for which Hex-Rays callables satisfy each
    ``MicrocodeEvidenceProvider`` seam. Called by the composition root
    (``D810State.start_d810``) and by unit-test fixtures, so production and tests inject
    identical accessors into ``d810.capabilities.providers`` (portable analyses/transforms
    read them via ``get_microcode_evidence()`` without importing this backend).
    """
    return MicrocodeEvidenceProvider(
        get_function_entry_ea=_get_function_entry_ea,
        get_mba_maturity=_get_mba_maturity,
        get_block_count=_get_block_count,
        block_adjacency=_block_adjacency,
        is_glbopt1=_is_glbopt1,
        glbopt1_maturity=_glbopt1_maturity,
        mmat_zero=_mmat_zero,
    )


# -----------------------------------------------------------------------------
# m_jtbl conversion helper
# -----------------------------------------------------------------------------
