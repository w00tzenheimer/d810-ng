"""Rebuild a solved expression into microcode.

Two rules here are not optional, and both cost real debugging to establish:

* **Invalidate the block's dataflow lists after any in-place rewrite.**
  ``mblock_t`` caches ``maybuse``/``maybdef``/``mustbuse``/``mustbdef``/``dnu``
  and ``mba.verify()`` recomputes and compares them (``verify.cpp:1323-1328``).
  Swapping an instruction changes the block's def/use sets, so stale caches
  fail with INTERR 50877 "wrong dnu" -- which looks exactly like a malformed
  instruction and is not. ``install_rewrite`` does this for you.

* **Clamp shift amounts, recursively.** ``verify.cpp:937`` requires a shift's
  amount operand to be exactly one byte or it raises INTERR 50835. Nothing in
  this module emits a shift today (cobra-cli's tokenizer has no shift operator,
  so a shift cannot come back through the CLI path), but the library path can
  return ``Expr::Kind::kShr``, and PR #14's reconstruction has exactly this
  defect. The clamp lives here so the trap is closed before that path opens.
"""

from __future__ import annotations

import ida_hexrays

from d810.hexrays.expr.ast import AstLeaf, AstNode, get_constant_mop
from d810.hexrays.ir.number_operand import safe_make_number

_OP_TO_OPCODE = {
    "+": ida_hexrays.m_add,
    "-": ida_hexrays.m_sub,
    "*": ida_hexrays.m_mul,
    "|": ida_hexrays.m_or,
    "&": ida_hexrays.m_and,
    "^": ida_hexrays.m_xor,
}

_SHIFT_OPCODES = frozenset({ida_hexrays.m_shl, ida_hexrays.m_shr, ida_hexrays.m_sar})

_MAX_CLAMP_DEPTH = 12


class ReconstructionError(Exception):
    """The solved expression could not be turned into microcode."""


def tree_to_ast(
    tree: dict, leaf_snapshots: dict, dest_size: int
) -> AstNode | AstLeaf:
    """Convert an expression tree into a d810 AST over the recorded leaves.

    *leaf_snapshots* maps a leaf name to a :class:`MopSnapshot`, never to a
    live ``mop_t``.  Detection and reconstruction are separated by a solver
    subprocess, and IDA invalidates ``mop_t`` objects when the optimizer runs
    or a block is modified, so anything held across that gap must be a
    snapshot.  ``to_mop()`` materialises a fresh owned operand at use time.
    """
    kind = tree["kind"]

    if kind == "const":
        value = tree["value"] & ((1 << (dest_size * 8)) - 1)
        leaf = AstLeaf(f"const_{tree['value']}")
        leaf.mop = get_constant_mop(value, dest_size)
        return leaf

    if kind == "var":
        name = tree["name"]
        snapshot = leaf_snapshots.get(name)
        if snapshot is None:
            raise ReconstructionError(f"no snapshot recorded for leaf {name!r}")
        leaf = AstLeaf(name)
        leaf.mop = snapshot.to_mop()
        return leaf

    if kind == "un":
        opcode = ida_hexrays.m_bnot if tree["op"] == "~" else ida_hexrays.m_neg
        return AstNode(opcode, tree_to_ast(tree["a"], leaf_snapshots, dest_size))

    opcode = _OP_TO_OPCODE.get(tree["op"])
    if opcode is None:
        raise ReconstructionError(f"no opcode for {tree['op']!r}")
    return AstNode(
        opcode,
        tree_to_ast(tree["a"], leaf_snapshots, dest_size),
        tree_to_ast(tree["b"], leaf_snapshots, dest_size),
    )


def clamp_shift_amounts(ins, depth: int = 0) -> None:
    """Narrow every folded shift amount to the one byte the verifier demands.

    Recursive on purpose: a shift is commonly buried one level down inside a
    ``mop_d``, so the outer opcode is ``m_and``/``m_bnot`` and a top-level-only
    check never fires. IDA's verifier walks sub-instructions, so every level
    must be clamped.
    """
    if ins is None or depth > _MAX_CLAMP_DEPTH:
        return
    if ins.opcode in _SHIFT_OPCODES:
        right = ins.r
        if right is not None and right.t == ida_hexrays.mop_n and right.size != 1:
            # safe_make_number, not make_number: the unanchored two-argument
            # form defaults ea to BADADDR and raises INTERR 51617 when the size
            # exceeds 8.  Anchor to the instruction we are rebuilding.
            safe_make_number(right, right.nnn.value & 0xFF, 1, ea=ins.ea)
    for slot in ("l", "r", "d"):
        operand = getattr(ins, slot, None)
        if operand is not None and operand.t == ida_hexrays.mop_d:
            clamp_shift_amounts(operand.d, depth + 1)


def build_replacement(candidate, tree: dict, original_ins):
    """Build the ``minsn_t`` that would replace *original_ins*."""
    ast = tree_to_ast(tree, candidate.leaf_snapshots, candidate.dest_size)
    if isinstance(ast, AstLeaf):
        # A bare leaf is a move, not an expression; nothing to rebuild.
        raise ReconstructionError("solved expression collapsed to a leaf")

    dest = ida_hexrays.mop_t()
    dest.assign(original_ins.d)
    replacement = ast.create_minsn(original_ins.ea, dest)
    clamp_shift_amounts(replacement)
    return replacement


def install_rewrite(block, original_ins, replacement) -> None:
    """Swap *replacement* in and invalidate the block's cached dataflow lists.

    Skipping ``mark_lists_dirty`` yields INTERR 50877 "wrong dnu" from
    ``mba.verify()``, which reads as a bad instruction but is a stale cache.
    """
    original_ins.swap(replacement)
    block.mark_lists_dirty()
