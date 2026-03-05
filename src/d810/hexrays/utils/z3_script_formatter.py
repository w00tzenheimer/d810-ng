"""Z3 equivalence proof script formatter.

Separated from hexrays_formatters to break the import cycle:
    hexrays_formatters -> ast -> p_ast -> hexrays_formatters
"""
from __future__ import annotations

import ida_hexrays

from d810.hexrays.utils.hexrays_formatters import format_minsn_t
from d810.hexrays.utils.hexrays_helpers import get_mop_index


def _rename_leafs(leaf_list: list) -> list[str]:
    """Assign Z3-style variable names to AST leaf operands.

    Returns a list of ``BitVec`` declaration strings suitable for inclusion
    in a Z3 proof script.

    This is a pure formatting helper -- no Z3 import required.
    """
    known_leaf_list: list = []
    for leaf in leaf_list:
        if leaf.is_constant() or leaf.mop is None:
            continue

        if leaf.mop.t == ida_hexrays.mop_z:
            continue

        leaf_index = get_mop_index(leaf.mop, known_leaf_list)
        if leaf_index == -1:
            known_leaf_list.append(leaf.mop)
            leaf_index = len(known_leaf_list) - 1
        leaf.z3_var_name = "x_{0}".format(leaf_index)

    return [
        "x_{0} = BitVec('x_{0}', {1})".format(i, 8 * leaf.size)
        for i, leaf in enumerate(known_leaf_list)
    ]


def format_z3_equivalence_script(
    original_ins: ida_hexrays.minsn_t,
    new_ins: ida_hexrays.minsn_t,
) -> str | None:
    """Return a Z3 proof script comparing *original_ins* with *new_ins*.

    Returns None when either instruction cannot be converted to an AST.
    The caller is responsible for writing the returned string to a logger.
    """
    from d810.hexrays.ir.minsn_utils import minsn_to_ast

    orig_mba_tree = minsn_to_ast(original_ins)
    new_mba_tree = minsn_to_ast(new_ins)
    if orig_mba_tree is None or new_mba_tree is None:
        return None
    orig_leaf_list = orig_mba_tree.get_leaf_list()
    new_leaf_list = new_mba_tree.get_leaf_list()

    var_def_list = _rename_leafs(orig_leaf_list + new_leaf_list)

    lines: list[str] = []
    lines.append(
        "print('Testing: {0} == {1}')".format(
            format_minsn_t(original_ins), format_minsn_t(new_ins)
        )
    )
    for var_def in var_def_list:
        lines.append("{0}".format(var_def))

    removed_xdu = "{0}".format(orig_mba_tree).replace("xdu", "")
    lines.append("original_expr = {0}".format(removed_xdu))
    removed_xdu = "{0}".format(new_mba_tree).replace("xdu", "")
    lines.append("new_expr = {0}".format(removed_xdu))
    lines.append("prove(original_expr == new_expr)\n")

    return "\n".join(lines)
