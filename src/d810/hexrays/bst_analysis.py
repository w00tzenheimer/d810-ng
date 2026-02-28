"""BST dispatcher analysis for d810 unflattening.

This module provides functions for analyzing binary search tree (BST) style
dispatchers found in control-flow-flattened code.  It extracts state machine
information — handler blocks, state constants, and handler-to-handler
transitions — from the microcode block array (mba_t).

Typical usage::

    from d810.hexrays.bst_analysis import analyze_bst_dispatcher

    result = analyze_bst_dispatcher(mba, dispatcher_entry_serial=5)
    # result.handler_state_map  -> {handler_serial: state_const, ...}
    # result.transitions        -> {state_const: next_state_const, ...}
    # result.exits              -> {state_const, ...}  (states that exit)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from d810.core.logging import getLogger
from d810.core.typing import (
    Any,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
)

logger = getLogger(__name__)

# Defer IDA imports until needed — allows module to be imported for CLI --help
idaapi = None


def _ensure_ida_imports() -> None:
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
            logger.warning(
                "Could not import ida_hexrays. Hex-Rays functionality may fail."
            )


# -----------------------------------------------------------------------------
# Constants (lazily initialized)
# -----------------------------------------------------------------------------

OPCODE_MAP: Dict[int, str] = {}
MOP_TYPE_MAP: Dict[int, str] = {}
_maps_initialized = False


def _init_constants() -> None:
    """Initialize constant maps that require IDA imports."""
    global OPCODE_MAP, MOP_TYPE_MAP, _maps_initialized
    if _maps_initialized:
        return

    _ensure_ida_imports()

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
# Result Dataclass
# -----------------------------------------------------------------------------


@dataclass
class BSTAnalysisResult:
    """Result of analyzing a BST dispatcher.

    Attributes:
        handler_state_map: Maps handler block serial -> state constant derived
            from the BST leaf comparison node (jnz/jz).
        handler_range_map: Maps handler block serial -> (value_lo, value_hi)
            representing the BST range propagated to that handler leaf.
        transitions: Maps state constant -> next state constant (or None when
            the transition could not be resolved).
        conditional_transitions: Maps state constant -> set of possible next
            state constants for handlers with conditional (multi-branch) exits.
        exits: Set of state constants whose handlers exit (return) rather than
            loop back to the dispatcher.
        pre_header_serial: Block serial of the pre-header (the block that
            writes the initial state constant before the dispatcher loop).
        initial_state: The initial state constant written in the pre-header,
            or None if it could not be determined.
    """

    handler_state_map: Dict[int, int] = field(default_factory=dict)
    handler_range_map: Dict[int, Tuple[Optional[int], Optional[int]]] = field(
        default_factory=dict
    )
    transitions: Dict[int, Optional[int]] = field(default_factory=dict)
    conditional_transitions: Dict[int, Set[int]] = field(default_factory=dict)
    exits: Set[int] = field(default_factory=set)
    pre_header_serial: Optional[int] = None
    initial_state: Optional[int] = None
    bst_node_blocks: Set[int] = field(default_factory=set)


# -----------------------------------------------------------------------------
# BST lookup
# -----------------------------------------------------------------------------


def resolve_target_via_bst(
    bst_result: BSTAnalysisResult,
    state_value: int,
) -> Optional[int]:
    """Given a concrete state value, find which handler block it dispatches to.

    Checks exact matches first (handler_state_map), then range matches
    (handler_range_map). Returns the handler block serial or None.

    >>> bst = BSTAnalysisResult()
    >>> bst.handler_state_map = {10: 0xAA}
    >>> resolve_target_via_bst(bst, 0xAA)
    10
    """
    for handler_serial, state_const in bst_result.handler_state_map.items():
        if state_const == state_value:
            return handler_serial

    exact_handler_serials = set(bst_result.handler_state_map.keys())
    for handler_serial, (low, high) in bst_result.handler_range_map.items():
        # Skip exact-match handlers — their range entries are artifacts
        # of m_jnz chain propagation, not real range handlers.
        if handler_serial in exact_handler_serials:
            continue
        # Skip degenerate catch-all ranges from linear BST m_jnz chains.
        # _narrow_range_excluding propagates (0, 0xFFFFFFFF) to all handlers
        # when the chain is purely linear — returning the first entry for any
        # unrecognized state would give the wrong handler.  Legitimate BST
        # ranges are narrow; the full 32-bit range is an artifact.
        if (
            low is not None
            and high is not None
            and (high - low) >= 0xFFFF0000
        ):
            continue
        if low is not None and state_value < low:
            continue
        if high is not None and state_value > high:
            continue
        return handler_serial

    return None


def find_bst_default_block(
    mba: "idaapi.mbl_array_t",
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


# -----------------------------------------------------------------------------
# Internal helpers
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
    bst_node_blocks: Optional[Set[int]] = None,
    allow_revisit: bool = False,
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

    is_jbe = opcode is not None and hasattr(idaapi, "m_jbe") and opcode == idaapi.m_jbe
    is_ja = opcode is not None and hasattr(idaapi, "m_ja") and opcode == idaapi.m_ja
    is_jnz = opcode is not None and hasattr(idaapi, "m_jnz") and opcode == idaapi.m_jnz
    is_jz = opcode is not None and hasattr(idaapi, "m_jz") and opcode == idaapi.m_jz

    if is_jbe or is_ja:
        if bst_node_blocks is not None:
            bst_node_blocks.add(serial)  # Track BST node for later NOP
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
                bst_node_blocks=bst_node_blocks,
            )

    elif is_jnz or is_jz:
        if bst_node_blocks is not None:
            bst_node_blocks.add(serial)  # Track BST node for later NOP
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
            if getattr(_tail, "opcode", None) not in _bst_opcodes:
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
            if getattr(_tail, "opcode", None) not in _bst_opcodes:
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


def _resolve_mop_value_in_block(
    mop: "idaapi.mop_t",
    blk: "idaapi.mblock_t",
    insn_before: "idaapi.minsn_t",
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
    mop_r_type = getattr(idaapi, "mop_r", 1)
    mop_l_type = getattr(idaapi, "mop_l", 9)
    if mop_type not in (mop_r_type, mop_l_type):
        return None

    # Opcodes for binary arithmetic/logic ops.
    m_add = getattr(idaapi, "m_add", 28)
    m_sub = getattr(idaapi, "m_sub", 29)
    m_and = getattr(idaapi, "m_and", 21)
    m_or = getattr(idaapi, "m_or", 22)
    m_xor = getattr(idaapi, "m_xor", 31)
    binary_ops = {m_add, m_sub, m_and, m_or, m_xor}

    def _mops_match(a: "idaapi.mop_t", b: "idaapi.mop_t") -> bool:
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
    insns_before: List["idaapi.minsn_t"] = []
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


def _resolve_mop_from_maps(
    mop: "idaapi.mop_t",
    stk_map: Dict[int, int],
    reg_map: Dict[int, int],
    mba: Optional["idaapi.mbl_array_t"] = None,
    state_var_lvar_idx: Optional[int] = None,
    diag_lines: Optional[List[str]] = None,
) -> Optional[int]:
    """Resolve a mop_t to a concrete value using accumulated forward-eval maps.

    Handles: mop_n (literal), mop_S (stk_map via .s.off), mop_r (reg_map),
    mop_l (stk_map via lvar stkoff), mop_d (recursive binop eval).

    Args:
        mop: The operand to resolve.
        stk_map: Accumulated stack-offset -> value map.
        reg_map: Accumulated register -> value map.
        mba: Optional mbl_array_t for mop_l lvar stkoff lookup.
        state_var_lvar_idx: If not None, the lvar index of the state variable.
        diag_lines: Optional list to collect diagnostic strings.

    Returns:
        The resolved integer value, or None if resolution failed.
    """
    _init_constants()
    if mop is None:
        return None

    mop_type = getattr(mop, "t", None)
    mop_n_type = getattr(idaapi, "mop_n", 2)
    mop_S_type = getattr(idaapi, "mop_S", None)
    mop_r_type = getattr(idaapi, "mop_r", 1)
    mop_l_type = getattr(idaapi, "mop_l", 9)
    mop_d_type = getattr(idaapi, "mop_d", 4)

    result: Optional[int] = None

    if mop_type == mop_n_type:
        result = _get_mop_const_value(mop)
    elif mop_S_type is not None and mop_type == mop_S_type:
        off = getattr(mop, "s", None)
        if off is not None:
            off = getattr(off, "off", None)
        if off is not None:
            result = stk_map.get(off)
    elif mop_type == mop_r_type:
        reg = getattr(mop, "r", None)
        if reg is not None:
            result = reg_map.get(reg)
    elif mop_l_type is not None and mop_type == mop_l_type:
        lvar_ref = getattr(mop, "l", None)
        idx = getattr(lvar_ref, "idx", None) if lvar_ref is not None else None
        if idx is not None and state_var_lvar_idx is not None and idx == state_var_lvar_idx:
            # State var itself — look up by its own state in stk_map if available
            pass
        if idx is not None and mba is not None:
            try:
                lvar = mba.vars[idx]
                off = lvar.location.stkoff()
                result = stk_map.get(off)
            except Exception:
                pass
    elif mop_type == mop_d_type:
        nested = getattr(mop, "d", None)
        if nested is not None:
            op = getattr(nested, "opcode", None)
            l_mop = getattr(nested, "l", None)
            r_mop = getattr(nested, "r", None)
            lv = _resolve_mop_from_maps(l_mop, stk_map, reg_map, mba, state_var_lvar_idx)
            if r_mop is not None and getattr(r_mop, "t", None) != 0:
                rv = _resolve_mop_from_maps(r_mop, stk_map, reg_map, mba, state_var_lvar_idx)
            else:
                rv = None
            if lv is not None:
                m_add = getattr(idaapi, "m_add", 28)
                m_sub = getattr(idaapi, "m_sub", 29)
                m_and = getattr(idaapi, "m_and", 21)
                m_or = getattr(idaapi, "m_or", 22)
                m_xor = getattr(idaapi, "m_xor", 31)
                m_mul = getattr(idaapi, "m_mul", 30)
                if rv is not None:
                    if op == m_xor:
                        result = (lv ^ rv) & 0xFFFFFFFF
                    elif op == m_sub:
                        result = (lv - rv) & 0xFFFFFFFF
                    elif op == m_add:
                        result = (lv + rv) & 0xFFFFFFFF
                    elif op == m_and:
                        result = (lv & rv) & 0xFFFFFFFF
                    elif op == m_or:
                        result = (lv | rv) & 0xFFFFFFFF
                    elif op == m_mul:
                        result = (lv * rv) & 0xFFFFFFFF

    if diag_lines is not None:
        diag_lines.append(
            f"  fwd_resolve: mop_t={mop_type} -> {hex(result) if result is not None else 'None'}"
        )
    return result


def _forward_eval_insn(
    insn: "idaapi.minsn_t",
    stk_map: Dict[int, int],
    reg_map: Dict[int, int],
    state_var_stkoff: int,
    mba: Optional["idaapi.mbl_array_t"] = None,
    state_var_lvar_idx: Optional[int] = None,
    diag_lines: Optional[List[str]] = None,
) -> Optional[int]:
    """Evaluate one instruction, updating stk_map/reg_map in-place.

    Returns the resolved constant if this instruction writes the state
    variable; otherwise returns None and updates the maps.

    Args:
        insn: The microcode instruction to evaluate.
        stk_map: Accumulated stack-offset -> value map (mutated in-place).
        reg_map: Accumulated register -> value map (mutated in-place).
        state_var_stkoff: Stack offset of the state variable.
        mba: Optional mbl_array_t for lvar stkoff resolution.
        state_var_lvar_idx: If not None, the lvar index of the state variable.
        diag_lines: Optional list to collect diagnostic strings.

    Returns:
        The state-variable value if this instruction writes it, else None.
    """
    _init_constants()
    if insn is None:
        return None

    op = getattr(insn, "opcode", None)
    if op is None:
        return None

    m_mov_op = getattr(idaapi, "m_mov", None)
    m_add = getattr(idaapi, "m_add", 28)
    m_sub = getattr(idaapi, "m_sub", 29)
    m_and = getattr(idaapi, "m_and", 21)
    m_or = getattr(idaapi, "m_or", 22)
    m_xor = getattr(idaapi, "m_xor", 31)
    m_mul = getattr(idaapi, "m_mul", 30)
    binary_ops = {m_add, m_sub, m_and, m_or, m_xor, m_mul}

    mop_S_type = getattr(idaapi, "mop_S", None)
    mop_r_type = getattr(idaapi, "mop_r", 1)
    mop_l_type = getattr(idaapi, "mop_l", 9)

    def _store_to_dest(dest: "idaapi.mop_t", val: int) -> bool:
        """Store val into the appropriate map based on dest type. Returns True if state var."""
        dest_t = getattr(dest, "t", None)
        is_state = False
        if mop_S_type is not None and dest_t == mop_S_type:
            off = getattr(dest, "s", None)
            if off is not None:
                off = getattr(off, "off", None)
            if off is not None:
                stk_map[off] = val
                if off == state_var_stkoff:
                    is_state = True
        elif dest_t == mop_r_type:
            reg = getattr(dest, "r", None)
            if reg is not None:
                reg_map[reg] = val
        elif mop_l_type is not None and dest_t == mop_l_type:
            lvar_ref = getattr(dest, "l", None)
            idx = getattr(lvar_ref, "idx", None) if lvar_ref is not None else None
            if idx is not None and mba is not None:
                try:
                    lvar = mba.vars[idx]
                    off = lvar.location.stkoff()
                    stk_map[off] = val
                    if off == state_var_stkoff:
                        is_state = True
                except Exception:
                    pass
            if idx is not None and state_var_lvar_idx is not None and idx == state_var_lvar_idx:
                is_state = True
        return is_state

    dest = getattr(insn, "d", None)
    if dest is None:
        return None

    val: Optional[int] = None

    if op == m_mov_op:
        src = getattr(insn, "l", None)
        val = _resolve_mop_from_maps(
            src, stk_map, reg_map, mba, state_var_lvar_idx, diag_lines
        )
    elif op in binary_ops:
        l_mop = getattr(insn, "l", None)
        r_mop = getattr(insn, "r", None)
        lv = _resolve_mop_from_maps(l_mop, stk_map, reg_map, mba, state_var_lvar_idx)
        rv = _resolve_mop_from_maps(r_mop, stk_map, reg_map, mba, state_var_lvar_idx)
        if lv is not None and rv is not None:
            if op == m_xor:
                val = (lv ^ rv) & 0xFFFFFFFF
            elif op == m_sub:
                val = (lv - rv) & 0xFFFFFFFF
            elif op == m_add:
                val = (lv + rv) & 0xFFFFFFFF
            elif op == m_and:
                val = (lv & rv) & 0xFFFFFFFF
            elif op == m_or:
                val = (lv | rv) & 0xFFFFFFFF
            elif op == m_mul:
                val = (lv * rv) & 0xFFFFFFFF
    else:
        return None

    if val is None:
        return None

    val = val & 0xFFFFFFFF
    is_state = _store_to_dest(dest, val)
    if is_state:
        if diag_lines is not None:
            opcode_name = OPCODE_MAP.get(op, f"opcode_{op}")
            diag_lines.append(
                f"  fwd_eval_insn: {opcode_name} -> state_var write 0x{val:x}"
            )
        return val
    return None


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
    mba: "idaapi.mbl_array_t",
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


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------


def analyze_bst_dispatcher(
    mba: "idaapi.mbl_array_t",
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
        mba: The microcode block array (mbl_array_t).
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
    bst_node_blocks: Set[int] = set()

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
# m_jtbl conversion helper
# -----------------------------------------------------------------------------
