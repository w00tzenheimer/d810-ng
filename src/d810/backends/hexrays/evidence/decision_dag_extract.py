"""Extract a :class:`DecisionDag` route oracle from a live dispatcher BST.

Walks the dispatcher comparison tree from its entry, collecting every
state-variable comparison (range ``ja/jbe/jb/jae`` AND equality ``jz/jnz``) as a
:class:`~d810.analyses.control_flow.route_predicate.BstComparison`. Comparisons
whose operands are NOT the state variable (a handler's own internal branch, e.g.
``jl var_1C8, #0x80``) are leaves -- the dispatch has finished there.

This is the IDA-coupled adapter for the portable
:mod:`d810.analyses.control_flow.route_predicate`. It mirrors the const / target
extraction of ``bst_analysis`` (``tail.d.b`` = jump target, ``blk.succ(i)`` =
successors, const from ``.l`` or ``.r``) but, unlike ``bst_analysis``'s
single-state ``_walk``, materialises the WHOLE tree so the caller gets
``route`` / ``resolve_paths`` / ``sibling_arms``.
"""
from __future__ import annotations

import ida_hexrays

from d810.analyses.control_flow.route_predicate import BstComparison, DecisionDag
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


def _is_state_var(mop, state_var_stkoff: int, state_var_lvar_idx: Optional[int]) -> bool:
    if mop is None:
        return False
    t = getattr(mop, "t", None)
    if t == ida_hexrays.mop_S:
        s = getattr(mop, "s", None)
        off = getattr(s, "off", None) if s is not None else None
        return off is not None and int(off) == int(state_var_stkoff)
    if t == ida_hexrays.mop_l and state_var_lvar_idx is not None:
        lref = getattr(mop, "l", None)
        idx = getattr(lref, "idx", None) if lref is not None else None
        return idx is not None and int(idx) == int(state_var_lvar_idx)
    return False


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


def _parse_state_comparison(blk, op_map, state_var_stkoff, state_var_lvar_idx, mask):
    """``(op, const, true_target)`` if *blk*'s tail compares the state var, else ``None``."""
    tail = getattr(blk, "tail", None)
    if tail is None:
        return None
    op = op_map.get(getattr(tail, "opcode", None))
    if op is None:
        return None
    left = getattr(tail, "l", None)
    right = getattr(tail, "r", None)
    if _is_state_var(left, state_var_stkoff, state_var_lvar_idx):
        const = _const_value(right, mask)
    elif _is_state_var(right, state_var_stkoff, state_var_lvar_idx):
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
    mba, entry, op_map, state_var_stkoff, state_var_lvar_idx, mask, max_hops=8
):
    """Follow single-successor blocks from *entry* to the first state-var comparison.

    The dispatcher entry handed in may be a loop header / glue block that flows
    (1-way) into the actual BST root; descend until a state-var comparison is
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
                blk, op_map, int(state_var_stkoff), state_var_lvar_idx, mask
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
    state_var_stkoff: int,
    state_var_lvar_idx: Optional[int] = None,
    width: int = 32,
    max_nodes: int = 1024,
) -> DecisionDag:
    """Build the :class:`DecisionDag` for the dispatcher rooted at *dispatcher_entry_serial*.

    Args:
        mba: The live ``mba_t``.
        dispatcher_entry_serial: The BST root block (handlers ``goto`` here).
        state_var_stkoff: The dispatcher state variable's ``mop_S.s.off``.
        state_var_lvar_idx: Its lvar index when the state var is a register/lvar.
        width: State variable bit-width (default 32).
        max_nodes: Safety bound on the comparison-node count.

    Returns:
        A :class:`DecisionDag` whose nodes are exactly the state-var comparison
        blocks reachable from the root; every other reached block is a leaf
        (handler). ``route`` reproduces the live BST routing.
    """
    op_map = _op_mnemonic_map()
    mask = (1 << int(width)) - 1
    root = _descend_to_root(
        mba, int(dispatcher_entry_serial), op_map, int(state_var_stkoff),
        state_var_lvar_idx, mask,
    )
    nodes: dict[int, BstComparison] = {}
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
            blk, op_map, int(state_var_stkoff), state_var_lvar_idx, mask
        )
        if parsed is None:
            continue  # leaf / handler -- not a state-var comparison node
        op, const, true_target = parsed
        false_target = next(
            (s for s in _block_succs(blk) if s != true_target), None
        )
        if false_target is None:
            continue
        nodes[serial] = BstComparison(
            serial=serial,
            op=op,
            const=int(const),
            true_target=int(true_target),
            false_target=int(false_target),
        )
        stack.append(int(true_target))
        stack.append(int(false_target))
    return DecisionDag(int(width), nodes, root)
