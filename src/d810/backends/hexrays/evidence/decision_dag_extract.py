"""Extract a :class:`DecisionDag` route oracle from a live dispatcher condition-chain.

Walks the dispatcher comparison tree from its entry, collecting every
state-variable comparison (range ``ja/jbe/jb/jae`` AND equality ``jz/jnz``) as a
:class:`~d810.analyses.control_flow.route_predicate.RouteComparison`. Comparisons
whose operands are NOT the state variable (a handler's own internal branch, e.g.
``jl var_1C8, #0x80``) are leaves -- the dispatch has finished there.

This is the IDA-coupled adapter for the portable
:mod:`d810.analyses.control_flow.route_predicate`. It mirrors the const / target
extraction of ``condition_chain_analysis`` (``tail.d.b`` = jump target, ``blk.succ(i)`` =
successors, const from ``.l`` or ``.r``) but, unlike ``condition_chain_analysis``'s
single-state ``_walk``, materialises the WHOLE tree so the caller gets
``route`` / ``resolve_paths`` / ``sibling_arms``.
"""

from __future__ import annotations

import ida_hexrays

from d810.analyses.control_flow.route_predicate import RouteComparison, DecisionDag
from d810.core.typing import Optional

__all__ = ["extract_decision_dag"]


def _op_mnemonic_map() -> dict:
    """Live opcode -> route_predicate mnemonic (built lazily; needs ida_hexrays)."""
    out: dict = {}
    for opcode_attr, mnemonic in (
        ("m_ja", "ja"),
        ("m_jae", "jae"),
        ("m_jb", "jb"),
        ("m_jbe", "jbe"),
        ("m_jg", "jg"),
        ("m_jge", "jge"),
        ("m_jl", "jl"),
        ("m_jle", "jle"),
        ("m_jz", "jz"),
        ("m_jnz", "jnz"),
    ):
        opcode = getattr(ida_hexrays, opcode_attr, None)
        if opcode is not None:
            out[int(opcode)] = mnemonic
    return out


# A relational op with the state var on the RIGHT operand is the mirror of the
# same op with the state var on the left (``const <= state`` == ``state >= const``).
_FLIP = {
    "ja": "jb",
    "jb": "ja",
    "jae": "jbe",
    "jbe": "jae",
    "jg": "jl",
    "jl": "jg",
    "jge": "jle",
    "jle": "jge",
    "jz": "jz",
    "jnz": "jnz",
}


def _is_state_var(
    mop,
    state_var_stkoff: Optional[int],
    state_var_lvar_idx: Optional[int],
    state_var_reg: Optional[int] = None,
    state_var_valnum: Optional[int] = None,
) -> bool:
    if mop is None:
        return False
    t = getattr(mop, "t", None)
    if t == ida_hexrays.mop_S:
        s = getattr(mop, "s", None)
        off = getattr(s, "off", None) if s is not None else None
        return (
            state_var_stkoff is not None
            and off is not None
            and int(off) == int(state_var_stkoff)
        )
    if t == ida_hexrays.mop_l and state_var_lvar_idx is not None:
        lref = getattr(mop, "l", None)
        idx = getattr(lref, "idx", None) if lref is not None else None
        return idx is not None and int(idx) == int(state_var_lvar_idx)
    # Register-resident dispatchers (MASM/non-spilled builds) load the state var
    # into a register once and compare that register (``jg eax, #const``).
    if t == ida_hexrays.mop_r and state_var_reg is not None:
        if int(getattr(mop, "r", -1)) != int(state_var_reg):
            return False
        # Register NUMBER alone is not identity: a handler that recomputes into
        # the same register still reads as ``eax``.  Hex-Rays value numbering
        # (``mop_t::valnum``, rendered as ``{N}``) discriminates them -- e.g. in
        # sub_7FFE50C44430 the chain compares ``eax.4{7}`` (the entry load of
        # var_310) while an MBA opaque predicate inside handler blk 99 compares
        # ``eax.4{131}``, locally defined by that block's own ``m_xdu``.  Without
        # this check blk 99 is mistaken for a chain node ``state != 0 -> @default``,
        # and its whole 165,391,921-state cell is credited to the default arm.
        # Gate only when BOTH value numbers are known (non-zero): a caller that
        # supplied ``state_var_reg`` explicitly has no valnum to match against,
        # and mba's value numbering is not always populated, so an unknown valnum
        # must not reject a genuine chain node (ticket lpccp-htcb).
        mop_valnum = int(getattr(mop, "valnum", 0) or 0)
        if state_var_valnum and mop_valnum:
            return mop_valnum == int(state_var_valnum)
        return True
    return False


def _entry_state_alias(
    mba,
    dispatcher_entry_serial: int,
    *,
    state_var_stkoff: Optional[int] = None,
    state_var_reg: Optional[int] = None,
) -> tuple[Optional[int], Optional[int], Optional[int]]:
    """``(stkoff, mreg, valnum)`` for the entry block's stack->register state load.

    The dispatcher entry homes the state variable in BOTH places: it loads the
    stack slot into a register (``xdu %var_310.4, rax.8``) and the condition
    chain below then compares that register.  A dispatcher like
    sub_7FFE50C44430 is therefore DUAL-HOMED -- its BST root compares the STACK
    slot while every deeper node compares the REGISTER -- so an identity that
    carries only one half cannot match the whole chain.

    Scans that one instruction and reports every identity it proves, matching on
    whichever half the caller already knows (or the first such load when it
    knows neither).  The destination's value number rides along so
    :func:`_is_state_var` can tell the dispatcher's register-and-value from the
    same register redefined inside a handler.  ``(None, None, None)`` when the
    entry block has no such load.
    """
    try:
        blk = mba.get_mblock(int(dispatcher_entry_serial))
    except Exception:
        return None, None, None
    if blk is None:
        return None, None, None
    cur = getattr(blk, "head", None)
    while cur is not None:
        d = getattr(cur, "d", None)
        left = getattr(cur, "l", None)
        if (
            d is not None
            and getattr(d, "t", None) == ida_hexrays.mop_r
            and left is not None
            and getattr(left, "t", None) == ida_hexrays.mop_S
        ):
            off = getattr(getattr(left, "s", None), "off", None)
            reg = getattr(d, "r", None)
            if off is not None and reg is not None:
                stkoff_matches = (
                    state_var_stkoff is None or int(off) == int(state_var_stkoff)
                )
                reg_matches = state_var_reg is None or int(reg) == int(state_var_reg)
                if stkoff_matches and reg_matches:
                    valnum = int(getattr(d, "valnum", 0) or 0) or None
                    return int(off), int(reg), valnum
        cur = getattr(cur, "next", None)
    return None, None, None


def _const_value(mop, mask: int) -> Optional[int]:
    if mop is None or getattr(mop, "t", None) != ida_hexrays.mop_n:
        return None
    nnn = getattr(mop, "nnn", None)
    value = getattr(nnn, "value", None) if nnn is not None else None
    return int(value) & mask if value is not None else None


def _block_succs(blk) -> tuple:
    try:
        return tuple(int(blk.succ(i)) for i in range(int(blk.nsucc())))
    except Exception:
        return ()


def _parse_state_comparison(
    blk,
    op_map,
    state_var_stkoff,
    state_var_lvar_idx,
    mask,
    state_var_reg=None,
    state_var_valnum=None,
):
    """``(op, const, true_target)`` if *blk*'s tail compares the state var, else ``None``."""
    tail = getattr(blk, "tail", None)
    if tail is None:
        return None
    op = op_map.get(getattr(tail, "opcode", None))
    if op is None:
        return None
    left = getattr(tail, "l", None)
    right = getattr(tail, "r", None)
    if _is_state_var(
        left, state_var_stkoff, state_var_lvar_idx, state_var_reg, state_var_valnum
    ):
        const = _const_value(right, mask)
    elif _is_state_var(
        right, state_var_stkoff, state_var_lvar_idx, state_var_reg, state_var_valnum
    ):
        const = _const_value(left, mask)
        op = _FLIP.get(op, op)  # state var on the right -> mirror the relation
    else:
        return None  # comparison is not on the state var -> a handler branch / leaf
    if const is None:
        return None
    d_operand = getattr(tail, "d", None)
    target = getattr(d_operand, "b", None) if d_operand is not None else None
    if target is None:
        return None
    return op, const, int(target)


def _descend_to_root(
    mba,
    entry,
    op_map,
    state_var_stkoff,
    state_var_lvar_idx,
    mask,
    max_hops=8,
    state_var_reg=None,
    state_var_valnum=None,
):
    """Follow single-successor blocks from *entry* to the first state-var comparison.

    The dispatcher entry handed in may be a loop header / glue block that flows
    (1-way) into the actual condition-chain root; descend until a state-var comparison is
    found (or the chain forks / ends).
    """
    cur = int(entry)
    for _ in range(int(max_hops) + 1):
        try:
            blk = mba.get_mblock(cur)
        except Exception:
            return cur
        if blk is None:
            return cur
        if (
            _parse_state_comparison(
                blk,
                op_map,
                state_var_stkoff,
                state_var_lvar_idx,
                mask,
                state_var_reg,
                state_var_valnum,
            )
            is not None
        ):
            return cur
        succs = _block_succs(blk)
        if len(succs) != 1:
            return cur
        cur = succs[0]
    return cur


def extract_decision_dag(
    mba,
    *,
    dispatcher_entry_serial: int,
    state_var_stkoff: Optional[int],
    state_var_lvar_idx: Optional[int] = None,
    state_var_reg: Optional[int] = None,
    width: int = 32,
    max_nodes: int = 1024,
) -> DecisionDag:
    """Build the :class:`DecisionDag` for the dispatcher rooted at *dispatcher_entry_serial*.

    Args:
        mba: The live ``mba_t``.
        dispatcher_entry_serial: The condition-chain root block (handlers ``goto`` here).
        state_var_stkoff: The dispatcher state variable's ``mop_S.s.off``, or
            ``None`` for a register-resident state variable.
        state_var_lvar_idx: Its lvar index when the state var is a register/lvar.
        state_var_reg: Explicit mreg identity for a register-resident state
            variable. When absent, stack dispatchers retain the existing
            entry-load auto-detection.
        width: State variable bit-width (default 32).
        max_nodes: Safety bound on the comparison-node count.

    Returns:
        A :class:`DecisionDag` whose nodes are exactly the state-var comparison
        blocks reachable from the root; every other reached block is a leaf
        (handler). ``route`` reproduces the live condition-chain routing.
    """
    op_map = _op_mnemonic_map()
    mask = (1 << int(width)) - 1
    # Register-resident dispatchers compare the state var in a register below the
    # root; detect it so the comparison nodes are recognized (else the DAG
    # collapses to the root leaf and routing degrades to exact-only).
    # Complete the identity from the entry block's stack->register load, in
    # WHICHEVER direction is missing.  Recovery hands down only one half (its
    # contract treats ``state_var_reg`` as "register with no stack home"), but a
    # dual-homed dispatcher needs both: sub_7FFE50C44430's BST root compares the
    # stack slot while its 59 deeper nodes compare the register, so a reg-only
    # identity fails to parse the root, ``_descend_to_root`` cannot walk past a
    # 2-way block, and the whole chain collapses to an empty DAG (lpccp-w81p).
    # Deriving the valnum here regardless of which half the caller supplied also
    # keeps the lpccp-htcb impostor gate armed on the explicit-register path.
    state_var_valnum: Optional[int] = None
    if state_var_stkoff is not None or state_var_reg is not None:
        entry_stkoff, entry_reg, entry_valnum = _entry_state_alias(
            mba,
            int(dispatcher_entry_serial),
            state_var_stkoff=state_var_stkoff,
            state_var_reg=state_var_reg,
        )
        if entry_reg is not None:
            if state_var_stkoff is None:
                state_var_stkoff = entry_stkoff
            if state_var_reg is None:
                state_var_reg = entry_reg
            if int(entry_reg) == int(state_var_reg):
                state_var_valnum = entry_valnum
    root = _descend_to_root(
        mba,
        int(dispatcher_entry_serial),
        op_map,
        state_var_stkoff,
        state_var_lvar_idx,
        mask,
        state_var_reg=state_var_reg,
        state_var_valnum=state_var_valnum,
    )
    nodes: dict[int, RouteComparison] = {}
    visited: set[int] = set()
    stack = [root]
    while stack:
        serial = stack.pop()
        if serial in visited or len(nodes) >= max_nodes:
            continue
        visited.add(serial)
        try:
            blk = mba.get_mblock(serial)
        except Exception:
            blk = None
        if blk is None:
            continue
        parsed = _parse_state_comparison(
            blk,
            op_map,
            state_var_stkoff,
            state_var_lvar_idx,
            mask,
            state_var_reg,
            state_var_valnum,
        )
        if parsed is None:
            continue  # leaf / handler -- not a state-var comparison node
        op, const, true_target = parsed
        false_target = next((s for s in _block_succs(blk) if s != true_target), None)
        if false_target is None:
            continue
        nodes[serial] = RouteComparison(
            serial=serial,
            op=op,
            const=int(const),
            true_target=int(true_target),
            false_target=int(false_target),
        )
        stack.append(int(true_target))
        stack.append(int(false_target))
    return DecisionDag(int(width), nodes, root)
