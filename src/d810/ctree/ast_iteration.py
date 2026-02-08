"""AST iteration utilities for ctree traversal.

Provides ``get_children()``, ``iterate_all_subitems()``,
``iterate_all_subinstrs()``, ``collect_gotos()``, and ``collect_labels()``.

Ported from herast (herast/tree/ast_iteration.py).
"""
from __future__ import annotations

import typing

from d810.core import getLogger

logger = getLogger("D810.ctree")

# ---------------------------------------------------------------------------
# IDA imports are optional for testing.
# ---------------------------------------------------------------------------
try:
    import idaapi
    from d810.ctree.consts import binary_expressions_ops, unary_expressions_ops

    # Handler mapping: item_op -> children_items_getter
    op2func: dict[int, typing.Callable] = {
        idaapi.cit_expr: lambda x: (x.cexpr,),
        idaapi.cit_return: lambda x: (x.creturn.expr,),
        idaapi.cit_block: lambda x: tuple(i for i in x.cblock),
        idaapi.cit_if: lambda x: (x.cif.ithen, x.cif.ielse, x.cif.expr),
        idaapi.cit_switch: lambda x: tuple(i for i in x.cswitch.cases)
        + (x.cswitch.expr,),
        idaapi.cit_while: lambda x: (x.cwhile.body, x.cwhile.expr),
        idaapi.cit_do: lambda x: (x.cdo.body, x.cdo.expr),
        idaapi.cit_for: lambda x: (x.cfor.body, x.cfor.init, x.cfor.expr, x.cfor.step),
        idaapi.cot_call: lambda x: (x.x,) + tuple(i for i in x.a),
    }

    for _i in unary_expressions_ops:
        op2func[_i] = lambda x: (x.x,)

    for _i in binary_expressions_ops:
        op2func[_i] = lambda x: (x.x, x.y)

    op2func[idaapi.cot_tern] = lambda x: (x.x, x.y, x.z)

except ImportError:
    idaapi = None  # type: ignore[assignment]
    op2func = {}


def get_children(item: typing.Any) -> tuple:
    """Extract child nodes from a ctree item based on its op type."""
    handler = op2func.get(item.op, None)
    if handler is None:
        return ()
    return tuple(c for c in handler(item) if c is not None)


def iterate_all_subitems(item: typing.Any) -> typing.Generator:
    """Yield all items in the subtree rooted at *item* (BFS)."""
    unprocessed_items: list = [item]
    while len(unprocessed_items) != 0:
        current_item = unprocessed_items.pop(0)
        yield current_item
        unprocessed_items += list(get_children(current_item))


def iterate_all_subinstrs(instr: typing.Any) -> typing.Generator:
    """Yield all instruction (non-expression) items in the subtree."""
    unprocessed_items: list = [instr]
    while len(unprocessed_items) != 0:
        current_item = unprocessed_items.pop(0)
        yield current_item
        children = get_children(current_item)
        children = [c for c in children if not c.is_expr()]
        unprocessed_items += children


def collect_gotos(haystack: typing.Any) -> list:
    """Collect all goto instructions in the subtree."""
    gotos: list = []
    if idaapi is None:
        return gotos
    for potential_goto in iterate_all_subinstrs(haystack):
        if potential_goto.op == idaapi.cit_goto:
            gotos.append(potential_goto)
    return gotos


def collect_labels(haystack: typing.Any) -> list:
    """Collect all labeled instructions in the subtree."""
    labels: list = []
    for potential_label in iterate_all_subinstrs(haystack):
        if potential_label.label_num != -1:
            labels.append(potential_label)
    return labels
