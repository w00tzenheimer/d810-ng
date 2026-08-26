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
    object width_of_ast,
    object truncate_ast,
    object terminal_origin,
    object origin_scope,
    list budget,
    object node_budget,
    object call_result_refiner,
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
    cdef object use_width
    cdef object resolved_width
    cdef bint is_resolvable

    if depth >= max_depth:
        return ast
    if ast is None:
        return None
    if budget[0] <= 0:
        return ast

    # Call-result leaves are anchored to their defining instruction and must
    # not be rebound through the physical return register or stack slot.
    from d810.evaluator.hexrays_microcode.def_search import is_call_result_leaf
    if is_call_result_leaf(ast):
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
        use_width = width_of_ast(ast)
        cache_key = (mop_key, use_width, instruction_identity(blk, ins))
        if cache_key in cache:
            return cache[cache_key]

        budget[0] -= 1
        resolved = resolve_mop_to_ast(
            mop,
            blk,
            ins,
            node_budget=node_budget,
            call_result_refiner=call_result_refiner,
        )
        if resolved is not None and resolved is not ast:
            resolved_width = width_of_ast(resolved)
            # Never guess through a missing width or widen a partial-register
            # definition into a wider use.  The Python backend applies the
            # same fail-closed policy through the callbacks above.
            if (
                use_width is None
                or resolved_width is None
                or resolved_width < use_width
            ):
                cache[cache_key] = ast
                return ast

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
                width_of_ast,
                truncate_ast,
                terminal_origin,
                origin_scope,
                budget,
                node_budget,
                call_result_refiner,
            )
            if resolved_width > use_width:
                result = truncate_ast(result, use_width, node_budget)
            cache[cache_key] = result
            return result
        origin = terminal_origin(
            mop,
            blk,
            ins,
            max_predecessor_blocks=1,
            scope=origin_scope,
        )
        if origin is not None:
            ast.proof_origin = origin
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
            width_of_ast,
            truncate_ast,
            terminal_origin,
            origin_scope,
            budget,
            node_budget,
            call_result_refiner,
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
            width_of_ast,
            truncate_ast,
            terminal_origin,
            origin_scope,
            budget,
            node_budget,
            call_result_refiner,
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
    object width_of_ast=None,
    object truncate_ast=None,
    object terminal_origin=None,
    object call_result_refiner=None,
):
    """Compiled equivalent of the bounded Python recursive resolver."""

    cdef list budget
    if cache is None:
        cache = {}
    origin_scope = cache.get("__resolve_origin_scope__")
    if origin_scope is None:
        origin_scope = object()
        cache["__resolve_origin_scope__"] = origin_scope
    budget = cache.get("__resolve_budget__")
    if budget is None:
        budget = [resolver_node_budget]
        cache["__resolve_budget__"] = budget
    if resolve_mop_to_ast is None:
        from d810.evaluator.hexrays_microcode.def_search import resolve_mop_to_ast
    if terminal_origin is None:
        from d810.evaluator.hexrays_microcode.def_search import _terminal_proof_origin
        terminal_origin = _terminal_proof_origin
    if instruction_identity is None:
        from d810.evaluator.hexrays_microcode.def_search import _microcode_instruction_identity
    if width_of_ast is None or truncate_ast is None:
        from d810.evaluator.hexrays_microcode.def_search import (
            _ast_width_bytes,
            _truncate_ast_to_use_width,
        )
        if width_of_ast is None:
            width_of_ast = _ast_width_bytes
        if truncate_ast is None:
            truncate_ast = _truncate_ast_to_use_width
    return _resolve(
        ast,
        blk,
        ins,
        depth,
        max_depth,
        cache,
        resolve_mop_to_ast,
        instruction_identity,
        width_of_ast,
        truncate_ast,
        terminal_origin,
        origin_scope,
        budget,
        node_budget,
        call_result_refiner,
    )
