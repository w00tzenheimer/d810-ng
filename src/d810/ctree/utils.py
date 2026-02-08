"""Utility functions for ctree node construction and manipulation.

Provides factories for creating ctree nodes (``make_num``,
``make_call``, ``make_helper_call``, etc.) and helpers like
``strip_casts``, ``resolve_name_address``.

Ported from herast (herast/tree/utils.py).
"""
from __future__ import annotations

import typing

from d810.core import getLogger
from d810.ctree.ast_iteration import get_children

logger = getLogger("D810.ctree")

# ---------------------------------------------------------------------------
# IDA imports are optional for testing.
# ---------------------------------------------------------------------------
try:
    import idaapi
    import idc
    import idautils
except ImportError:
    idaapi = None  # type: ignore[assignment]
    idc = None  # type: ignore[assignment]
    idautils = None  # type: ignore[assignment]


def get_func_calls_to(fea: int) -> list[int]:
    """Return entry addresses of functions that call *fea*."""
    if idautils is None or idaapi is None:
        return []
    rv = filter(None, [get_func_start(x.frm) for x in idautils.XrefsTo(fea)])
    rv = filter(lambda x: x != idaapi.BADADDR, rv)
    return list(rv)


def get_func_start(addr: int) -> int:
    """Return the start address of the function containing *addr*."""
    if idaapi is None:
        return -1
    func = idaapi.get_func(addr)
    if func is None:
        return idaapi.BADADDR
    return func.start_ea


def is_func_start(addr: int) -> bool:
    """Return True if *addr* is the start of a function."""
    return addr == get_func_start(addr)


def get_cfunc(func_ea: int) -> typing.Any | None:
    """Decompile the function at *func_ea* and return the cfunc_t."""
    if idaapi is None:
        return None
    try:
        cfunc = idaapi.decompile(func_ea)
    except idaapi.DecompilationFailure:
        logger.error("failed to decompile function %s", hex(func_ea))
        return None
    if cfunc is None:
        logger.error("failed to decompile function %s", hex(func_ea))
    return cfunc


def get_following_instr(parent_block: typing.Any, item: typing.Any) -> typing.Any | None:
    """Return the instruction following *item* in *parent_block*."""
    container = parent_block.cinsn.cblock
    item_idx = container.index(item)
    if item_idx is None:
        return None
    if item_idx == len(container) - 1:
        return None
    return container[item_idx + 1]


def resolve_name_address(name: str) -> int:
    """Resolve a symbol name to its address."""
    if idc is None:
        return -1
    return idc.get_name_ea_simple(name)


def remove_instruction_from_ast(unwanted_ins: typing.Any, parent: typing.Any) -> bool:
    """Remove *unwanted_ins* from *parent* (a cblock_t or cfunc_t)."""
    if idaapi is None:
        return False

    assert type(unwanted_ins) is idaapi.cinsn_t, (
        "Removing item must be an instruction (cinsn_t)"
    )

    block = None
    if type(parent) is idaapi.cinsn_t and parent.op == idaapi.cit_block:
        block = parent.cblock
    elif type(parent) is idaapi.cfuncptr_t or type(parent) is idaapi.cfunc_t:
        ins = parent.body.find_parent_of(unwanted_ins).cinsn
        assert type(ins) is idaapi.cinsn_t and ins.op == idaapi.cit_block, (
            "block is not cinsn_t or op != idaapi.cit_block"
        )
        block = ins.cblock
    else:
        raise TypeError("Parent must be cfuncptr_t or cblock_t")

    if unwanted_ins.contains_label():
        return False

    if len(block) <= 1:
        return False

    try:
        return block.remove(unwanted_ins)
    except Exception as e:
        logger.error(
            "Got an exception %s while trying to remove instruction from block", e
        )
        return False


def move_label_to_next_insn(
    parent: typing.Any, cinsn: typing.Any, ctx: typing.Any
) -> bool:
    """Move *cinsn*'s label to the next instruction in *parent*."""
    if idaapi is None:
        return False
    assert type(cinsn) is idaapi.cinsn_t, "must be an instruction (cinsn_t)"

    if cinsn.label_num == -1:
        return False

    children = get_children(parent)
    for i, c in enumerate(children):
        if c == cinsn:
            if i + 1 >= len(children):
                return False
            else:
                next_insn = children[i + 1]
                if next_insn.label_num != -1:
                    for goto in ctx.label2gotos[cinsn.label_num]:
                        goto.cgoto.label_num = next_insn.label_num
                    cinsn.label_num = -1
                else:
                    next_insn.label_num = cinsn.label_num
                    cinsn.label_num = -1
                return True
    return False


def make_cblock(instructions: typing.Any) -> typing.Any:
    """Create a cblock_t from a list of instructions."""
    if idaapi is None:
        return None
    block = idaapi.cblock_t()
    for i in instructions:
        block.push_back(i)
    return block


def make_block_insn(
    instructions: typing.Any, address: int, label_num: int = -1
) -> typing.Any:
    """Create a cit_block cinsn_t from instructions."""
    if idaapi is None:
        return None

    block = None
    if type(instructions) is idaapi.cblock_t:
        block = instructions
    elif type(instructions) in (list, tuple):
        block = make_cblock(instructions)
    else:
        raise TypeError(
            "Trying to make cblock instruction from neither cblock_t nor list|tuple"
        )

    insn = idaapi.cinsn_t()
    insn.ea = address
    insn.op = idaapi.cit_block
    insn.cblock = block
    insn.label_num = label_num
    insn.thisown = False
    return insn


def make_if_instr(
    cond: typing.Any, ithen: typing.Any, ielse: typing.Any = None
) -> typing.Any:
    """Create a cit_if cinsn_t."""
    if idaapi is None:
        return None
    cif = idaapi.cif_t()
    cif.expr = cond
    cif.ithen = ithen
    cif.ielse = ielse
    instr = idaapi.cinsn_t()
    instr.op = idaapi.cit_if
    instr.cif = cif
    instr.label_num = -1
    return instr


def make_cast(x: typing.Any) -> typing.Any:
    """Create a cot_cast cexpr_t."""
    if idaapi is None:
        return None
    new_obj = idaapi.cexpr_t()
    new_obj.op = idaapi.cot_cast
    new_obj.x = x
    return new_obj


def make_obj(obj_ea: int) -> typing.Any:
    """Create a cot_obj cexpr_t."""
    if idaapi is None:
        return None
    new_obj = idaapi.cexpr_t()
    new_obj.op = idaapi.cot_obj
    new_obj.obj_ea = obj_ea
    return new_obj


def make_expr_instr(expr: typing.Any) -> typing.Any:
    """Create a cit_expr cinsn_t wrapping an expression."""
    if idaapi is None:
        return None
    new_item = idaapi.cinsn_t()
    new_item.op = idaapi.cit_expr
    new_item.cexpr = expr
    new_item.thisown = False
    return new_item


def make_arglist(*args: typing.Any) -> typing.Any:
    """Create a carglist_t from arguments."""
    if idaapi is None:
        return None
    arglist = idaapi.carglist_t()
    for arg in args:
        if arg is None:
            logger.warning("argument is None, skipping")
            continue
        if isinstance(arg, idaapi.carg_t):
            arglist.push_back(arg)
        else:
            narg = idaapi.carg_t()
            narg.assign(arg)
            arglist.push_back(narg)
    return arglist


def make_call(call: typing.Any, *args: typing.Any) -> typing.Any:
    """Create a cot_call cexpr_t."""
    if idaapi is None:
        return None
    call_expr = idaapi.cexpr_t()
    call_expr.op = idaapi.cot_call
    call_expr.x = call
    call_expr.a = make_arglist(*args)
    return call_expr


def make_call_helper_expr(
    name: str, *args: typing.Any, retval: typing.Any = None
) -> typing.Any:
    """Create a helper call expression."""
    if idaapi is None:
        return None
    if retval is None:
        retval = idaapi.get_unk_type(8)
    arglist = make_arglist(*args)
    return idaapi.call_helper(retval, arglist, name)


def make_call_helper_instr(name: str, *args: typing.Any) -> typing.Any:
    """Create a cit_expr wrapping a helper call expression."""
    return make_expr_instr(make_call_helper_expr(name, *args))


def strip_casts(expr: typing.Any) -> typing.Any:
    """Strip cast wrappers from an expression."""
    if idaapi is not None and expr.op == idaapi.cot_cast:
        return expr.x
    return expr
