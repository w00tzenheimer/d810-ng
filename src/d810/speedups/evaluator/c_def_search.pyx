# distutils: language = c++
# cython: language_level=3, boundscheck=False, wraparound=False

"""Compiled tree walk for recursive microcode definition resolution.

The authority-sensitive definition lookup remains in ``def_search.py``.  This
module only removes Python frame overhead from the bounded AST traversal and
threads the caller-owned cache and node budget through the same algorithm.
"""

import ida_hexrays

from d810.hexrays.expr.ast import AstNode, get_mop_key


cdef object _resolve(
    object ast,
    object blk,
    object ins,
    int depth,
    int max_depth,
    dict cache,
    object resolve_mop_to_ast,
    object instruction_identity,
    list budget,
    object node_budget,
):
    cdef object mop
    cdef object nested
    cdef object mop_key
    cdef object cache_key
    cdef object resolved
    cdef object new_ins
    cdef object result
    cdef object new_left
    cdef object new_right
    cdef object new_ast
    cdef bint is_resolvable

    if depth >= max_depth:
        return ast
    if ast is None:
        return None
    if budget[0] <= 0:
        return ast

    if ast.is_leaf():
        mop = ast.mop
        if mop is None:
            return ast
        is_resolvable = mop.t == ida_hexrays.mop_r or mop.t == ida_hexrays.mop_S
        if not is_resolvable and mop.t == ida_hexrays.mop_d:
            nested = getattr(mop, "d", None)
            if nested is not None and nested.opcode == ida_hexrays.m_ldx:
                is_resolvable = True
        if not is_resolvable or ins is None:
            return ast

        mop_key = get_mop_key(mop)
        cache_key = (mop_key, instruction_identity(blk, ins))
        if cache_key in cache:
            return cache[cache_key]

        budget[0] -= 1
        resolved = resolve_mop_to_ast(mop, blk, ins, node_budget=node_budget)
        if resolved is not None and resolved is not ast:
            new_ins = ins
            if hasattr(resolved, "ins") and resolved.ins is not None:
                new_ins = resolved.ins
            result = _resolve(
                resolved,
                blk,
                new_ins,
                depth + 1,
                max_depth,
                cache,
                resolve_mop_to_ast,
                instruction_identity,
                budget,
                node_budget,
            )
            cache[cache_key] = result
            return result
        cache[cache_key] = ast
        return ast

    new_left = (
        _resolve(
            ast.left,
            blk,
            ins,
            depth,
            max_depth,
            cache,
            resolve_mop_to_ast,
            instruction_identity,
            budget,
            node_budget,
        )
        if ast.left is not None
        else None
    )
    new_right = (
        _resolve(
            ast.right,
            blk,
            ins,
            depth,
            max_depth,
            cache,
            resolve_mop_to_ast,
            instruction_identity,
            budget,
            node_budget,
        )
        if ast.right is not None
        else None
    )

    if new_left is not ast.left or new_right is not ast.right:
        if node_budget is not None:
            node_budget.consume()
        new_ast = AstNode(ast.opcode, new_left, new_right)
        if node_budget is not None:
            node_budget.mark_charged(new_ast)
        new_ast.mop = ast.mop
        new_ast.dst_mop = ast.dst_mop
        new_ast.dest_size = ast.dest_size
        new_ast.ea = ast.ea
        new_ast.func_name = ast.func_name
        return new_ast
    return ast


def recursively_resolve_ast(
    object ast,
    object blk,
    object ins,
    int depth=0,
    int max_depth=10,
    object cache=None,
    object resolve_mop_to_ast=None,
    object instruction_identity=None,
    int resolver_node_budget=4096,
    object node_budget=None,
):
    """Compiled equivalent of the bounded Python recursive resolver."""

    cdef list budget
    if cache is None:
        cache = {}
    budget = cache.get("__resolve_budget__")
    if budget is None:
        budget = [resolver_node_budget]
        cache["__resolve_budget__"] = budget
    if resolve_mop_to_ast is None:
        from d810.evaluator.hexrays_microcode.def_search import resolve_mop_to_ast
    if instruction_identity is None:
        from d810.evaluator.hexrays_microcode.def_search import _microcode_instruction_identity
    return _resolve(
        ast,
        blk,
        ins,
        depth,
        max_depth,
        cache,
        resolve_mop_to_ast,
        instruction_identity,
        budget,
        node_budget,
    )
