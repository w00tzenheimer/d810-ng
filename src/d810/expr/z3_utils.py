import functools
import logging
import typing

from ida_hexrays import *

from d810.conf.loggers import LevelFlag
from d810.errors import D810Z3Exception
from d810.expr.ast import AstLeaf, AstNode, minsn_to_ast, mop_to_ast
from d810.hexrays.hexrays_formatters import (
    format_minsn_t,
    format_mop_t,
    opcode_to_string,
)
from d810.hexrays.hexrays_helpers import get_mop_index

logger = logging.getLogger("D810.plugin")
z3_file_logger = logging.getLogger("D810.z3_test")
optimizer_logger = logging.getLogger("D810.optimizer")
debug_on = LevelFlag(optimizer_logger.name, logging.DEBUG)

try:
    import z3

    Z3_INSTALLED = True
    # Since version 4.8.2, when Z3 is creating a BitVec, it relies on _str_to_bytes which uses sys.stdout.encoding
    # However, in IDA Pro (7.6sp1) sys.stdout is an object of type IDAPythonStdOut
    # which doesn't have a 'encoding' attribute, thus we set it to something, so that Z3 works
    import sys

    try:
        x = sys.stdout.encoding
    except AttributeError:
        logger.debug("Couldn't find sys.stdout.encoding, setting it to utf-8")
        sys.stdout.encoding = "utf-8"  # type: ignore
except ImportError:
    logger.info("Z3 features disabled. Install Z3 to enable them")
    Z3_INSTALLED = False


@functools.lru_cache(maxsize=1)
def requires_z3_installed(func: typing.Callable[..., typing.Any]):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if not Z3_INSTALLED:
            raise D810Z3Exception("Z3 is not installed")
        return func(*args, **kwargs)

    return wrapper


@requires_z3_installed
@functools.lru_cache(maxsize=1)
def get_solver() -> z3.Solver:
    return z3.Solver()


@requires_z3_installed
def create_z3_vars(leaf_list: list[AstLeaf]):
    known_leaf_list = []
    known_leaf_z3_var_list = []
    for leaf in leaf_list:
        if leaf.is_constant() or leaf.mop is None:
            continue
        leaf_index = get_mop_index(leaf.mop, known_leaf_list)
        if leaf_index == -1:
            known_leaf_list.append(leaf.mop)
            leaf_index = len(known_leaf_list) - 1
            if leaf.mop.size in [1, 2, 4, 8]:
                # Normally, we should create variable based on their size
                # but for now it can cause issue when instructions like XDU are used, hence this ugly fix
                # known_leaf_z3_var_list.append(z3.BitVec("x_{0}".format(leaf_index), 8 * leaf.mop.size))
                known_leaf_z3_var_list.append(z3.BitVec("x_{0}".format(leaf_index), 32))
                pass
            else:
                known_leaf_z3_var_list.append(z3.BitVec("x_{0}".format(leaf_index), 32))
        leaf.z3_var = known_leaf_z3_var_list[leaf_index]
        leaf.z3_var_name = "x_{0}".format(leaf_index)
    return known_leaf_z3_var_list


@requires_z3_installed
def ast_to_z3_expression(ast: AstNode | AstLeaf | None, use_bitvecval=False):
    if ast is None:
        raise ValueError("ast is None")
    if ast.is_leaf():
        ast = typing.cast(AstLeaf, ast)
        if ast.is_constant():
            return z3.BitVecVal(ast.value, 32)
        return ast.z3_var
    ast = typing.cast(AstNode, ast)
    if ast.opcode == m_neg:
        return -(ast_to_z3_expression(ast.left, use_bitvecval))
    elif ast.opcode == m_lnot:
        return not (ast_to_z3_expression(ast.left, use_bitvecval))
    elif ast.opcode == m_bnot:
        return ~(ast_to_z3_expression(ast.left, use_bitvecval))
    elif ast.opcode == m_add:
        return (ast_to_z3_expression(ast.left, use_bitvecval)) + (
            ast_to_z3_expression(ast.right, use_bitvecval)
        )
    elif ast.opcode == m_sub:
        return (ast_to_z3_expression(ast.left, use_bitvecval)) - (
            ast_to_z3_expression(ast.right, use_bitvecval)
        )
    elif ast.opcode == m_mul:
        return (ast_to_z3_expression(ast.left, use_bitvecval)) * (
            ast_to_z3_expression(ast.right, use_bitvecval)
        )
    elif ast.opcode == m_udiv:
        return z3.UDiv(
            ast_to_z3_expression(ast.left, use_bitvecval=True),
            ast_to_z3_expression(ast.right, use_bitvecval=True),
        )
    elif ast.opcode == m_sdiv:
        return (ast_to_z3_expression(ast.left, use_bitvecval)) / (
            ast_to_z3_expression(ast.right, use_bitvecval)
        )
    elif ast.opcode == m_umod:
        return z3.URem(
            ast_to_z3_expression(ast.left, use_bitvecval),
            ast_to_z3_expression(ast.right, use_bitvecval),
        )
    elif ast.opcode == m_smod:
        return (ast_to_z3_expression(ast.left, use_bitvecval)) % (
            ast_to_z3_expression(ast.right, use_bitvecval)
        )
    elif ast.opcode == m_or:
        return (ast_to_z3_expression(ast.left, use_bitvecval)) | (
            ast_to_z3_expression(ast.right, use_bitvecval)
        )
    elif ast.opcode == m_and:
        return (ast_to_z3_expression(ast.left, use_bitvecval)) & (
            ast_to_z3_expression(ast.right, use_bitvecval)
        )
    elif ast.opcode == m_xor:
        return (ast_to_z3_expression(ast.left, use_bitvecval)) ^ (
            ast_to_z3_expression(ast.right, use_bitvecval)
        )
    elif ast.opcode == m_shl:
        return (ast_to_z3_expression(ast.left, use_bitvecval)) << (
            ast_to_z3_expression(ast.right, use_bitvecval)
        )
    elif ast.opcode == m_shr:
        return z3.LShR(
            ast_to_z3_expression(ast.left, use_bitvecval),
            ast_to_z3_expression(ast.right, use_bitvecval),
        )
    elif ast.opcode == m_sar:
        return (ast_to_z3_expression(ast.left, use_bitvecval)) >> (
            ast_to_z3_expression(ast.right, use_bitvecval)
        )
    elif ast.opcode == m_setnz:
        return z3.If(
            (ast_to_z3_expression(ast.left, use_bitvecval)) != z3.BitVecVal(0, 32),
            z3.BitVecVal(1, 32),
            z3.BitVecVal(0, 32),
        )
    elif ast.opcode == m_setz:
        return z3.If(
            (ast_to_z3_expression(ast.left, use_bitvecval)) == z3.BitVecVal(0, 32),
            z3.BitVecVal(1, 32),
            z3.BitVecVal(0, 32),
        )
    elif ast.opcode == m_setae:
        return z3.If(
            z3.UGE(
                ast_to_z3_expression(ast.left, use_bitvecval),
                ast_to_z3_expression(ast.right, use_bitvecval),
            ),
            z3.BitVecVal(1, 32),
            z3.BitVecVal(0, 32),
        )
    elif ast.opcode == m_setb:
        return z3.If(
            z3.ULT(
                ast_to_z3_expression(ast.left, use_bitvecval),
                ast_to_z3_expression(ast.right, use_bitvecval),
            ),
            z3.BitVecVal(1, 32),
            z3.BitVecVal(0, 32),
        )
    elif ast.opcode == m_seta:
        return z3.If(
            z3.UGT(
                ast_to_z3_expression(ast.left, use_bitvecval),
                ast_to_z3_expression(ast.right, use_bitvecval),
            ),
            z3.BitVecVal(1, 32),
            z3.BitVecVal(0, 32),
        )
    elif ast.opcode == m_setbe:
        return z3.If(
            z3.ULE(
                ast_to_z3_expression(ast.left, use_bitvecval),
                ast_to_z3_expression(ast.right, use_bitvecval),
            ),
            z3.BitVecVal(1, 32),
            z3.BitVecVal(0, 32),
        )
    elif ast.opcode == m_setg:
        return z3.If(
            (ast_to_z3_expression(ast.left, use_bitvecval))
            > (ast_to_z3_expression(ast.right, use_bitvecval)),
            z3.BitVecVal(1, 32),
            z3.BitVecVal(0, 32),
        )
    elif ast.opcode == m_setge:
        return z3.If(
            (ast_to_z3_expression(ast.left, use_bitvecval))
            >= (ast_to_z3_expression(ast.right, use_bitvecval)),
            z3.BitVecVal(1, 32),
            z3.BitVecVal(0, 32),
        )
    elif ast.opcode == m_setl:
        return z3.If(
            (ast_to_z3_expression(ast.left, use_bitvecval))
            < (ast_to_z3_expression(ast.right, use_bitvecval)),
            z3.BitVecVal(1, 32),
            z3.BitVecVal(0, 32),
        )
    elif ast.opcode == m_setle:
        return z3.If(
            (ast_to_z3_expression(ast.left, use_bitvecval))
            <= (ast_to_z3_expression(ast.right, use_bitvecval)),
            z3.BitVecVal(1, 32),
            z3.BitVecVal(0, 32),
        )
    elif ast.opcode == m_setp:
        # 1) isolate the low byte
        lo_byte = typing.cast(
            z3.BitVecRef,
            z3.Extract(7, 0, ast_to_z3_expression(ast.left, use_bitvecval)),
        )
        # 2) XOR-reduce the eight single-bit slices to get 1 → odd, 0 → even
        bit0 = typing.cast(z3.BitVecRef, z3.Extract(0, 0, lo_byte))
        parity_bv = bit0  # 1-bit BitVec
        for i in range(1, 8):
            parity_bv = parity_bv ^ z3.Extract(i, i, lo_byte)

        # 3) PF is set (==1) when the parity is EVEN, i.e. parity_bv == 0
        pf_is_set = parity_bv == z3.BitVecVal(0, 1)  # Bool

        # 4) widen to 32-bit {1,0}
        return z3.If(pf_is_set, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
    elif ast.opcode == m_sets:
        val = ast_to_z3_expression(ast.left, use_bitvecval)  # BitVec(32)
        is_negative = val < z3.BitVecVal(
            0, 32
        )  # ordinary “<” is signed-less-than in Z3Py
        return z3.If(is_negative, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
    elif ast.opcode in [m_xdu, m_xds]:
        # Extend or keep the same width; in our simplified model we just forward.
        return ast_to_z3_expression(ast.left, use_bitvecval)
    elif ast.opcode == m_low:
        # Extract the lower half (dest_size) bits of the operand.
        dest_bits = (ast.dest_size or 4) * 8  # default 32-bit
        expr_left = ast_to_z3_expression(ast.left, use_bitvecval)
        # Ensure we do not attempt to extract beyond the source width
        high_bit = min(dest_bits - 1, expr_left.size() - 1)
        extracted = typing.cast(z3.BitVecRef, z3.Extract(high_bit, 0, expr_left))
        # Zero-extend to 32-bit so subsequent operations (which assume 32-bit) do not
        # trigger sort-mismatch errors when combined with other 32-bit expressions.
        if extracted.size() < 32:
            extracted = typing.cast(
                z3.BitVecRef, z3.ZeroExt(32 - extracted.size(), extracted)
            )
        return extracted
    elif ast.opcode == m_high:
        # Extract the upper half of the operand by shifting right by dest_bits
        dest_bits = (ast.dest_size or 4) * 8  # default 32-bit
        expr_left = ast_to_z3_expression(ast.left, use_bitvecval)
        shifted = z3.LShR(expr_left, dest_bits)
        high_bit = min(dest_bits - 1, shifted.size() - 1)
        extracted = typing.cast(z3.BitVecRef, z3.Extract(high_bit, 0, shifted))
        # Zero-extend to 32-bit for consistency with the rest of the engine.
        if extracted.size() < 32:
            extracted = typing.cast(
                z3.BitVecRef, z3.ZeroExt(32 - extracted.size(), extracted)
            )
        return extracted
    raise D810Z3Exception(
        "Z3 evaluation: Unknown opcode {0} for {1}".format(
            opcode_to_string(ast.opcode), ast
        )
    )


@requires_z3_installed
def mop_list_to_z3_expression_list(mop_list: list[mop_t]):
    if debug_on:
        optimizer_logger.debug(
            "mop_list_to_z3_expression_list: mop_list: %s",
            [format_mop_t(mop) for mop in mop_list],
        )
    ast_list = [mop_to_ast(mop) for mop in mop_list]
    ast_leaf_list = []
    for ast in ast_list:
        if ast is None:
            continue
        ast_leaf_list += ast.get_leaf_list()
    _ = create_z3_vars(ast_leaf_list)
    if debug_on:
        optimizer_logger.debug(
            "mop_list_to_z3_expression_list: ast_leaf_list: %s",
            ast_leaf_list,
        )
    return [ast_to_z3_expression(ast) for ast in ast_list]


@requires_z3_installed
def z3_check_mop_equality(
    mop1: mop_t | None, mop2: mop_t | None, solver: z3.Solver | None = None
) -> bool:
    if mop1 is None or mop2 is None:
        return False
    # # Quick positives when both operands share type/size.
    # if mop1.t == mop2.t and mop1.size == mop2.size:
    #     if mop1.t == mop_n:
    #         return mop1.nnn.value == mop2.nnn.value
    #     if mop1.t == mop_r:
    #         return mop1.r == mop2.r
    #     if mop1.t == mop_S:
    #         # Direct comparison of stack var refs suffices.
    #         return mop1.s == mop2.s
    #     if mop1.t == mop_v:
    #         return mop1.g == mop2.g
    #     if mop1.t == mop_d:
    #         return mop1.dstr() == mop2.dstr()
    # If quick checks didn't decide, fall back to Z3 even when types differ.
    if debug_on:
        optimizer_logger.debug(
            "z3_check_mop_equality: mop1.t: %s, mop2.t: %s",
            format_mop_t(mop1),
            format_mop_t(mop2),
        )
        optimizer_logger.debug(
            "z3_check_mop_equality: mop1.dstr(): %s, mop2.dstr(): %s",
            mop1.dstr(),
            mop2.dstr(),
        )
    # If pre-filters don't apply, fall back to Z3.
    exprs = mop_list_to_z3_expression_list([mop1, mop2])
    if len(exprs) != 2:
        return False
    z3_mop1, z3_mop2 = exprs
    _solver = solver if solver is not None else get_solver()
    _solver.push()
    _solver.add(z3.Not(z3_mop1 == z3_mop2))
    is_equal = _solver.check() == z3.unsat
    if debug_on:
        optimizer_logger.debug(
            "z3_mop1: %s, z3_mop2: %s, z3_check_mop_equality: is_equal: %s",
            z3_mop1,
            z3_mop2,
            is_equal,
        )
    _solver.pop()
    return is_equal


@requires_z3_installed
def z3_check_mop_inequality(
    mop1: mop_t | None, mop2: mop_t | None, solver: z3.Solver | None = None
) -> bool:
    if mop1 is None or mop2 is None:
        return True
    # if mop1.t == mop2.t and mop1.size == mop2.size:
    #     # Quick negatives when structure same.
    #     if mop1.t == mop_n:
    #         return mop1.nnn.value != mop2.nnn.value
    #     if mop1.t == mop_r:
    #         return mop1.r != mop2.r
    #     if mop1.t == mop_S:
    #         return mop1.s != mop2.s
    #     if mop1.t == mop_v:
    #         return mop1.g != mop2.g
    #     if mop1.t == mop_d:
    #         return mop1.dstr() != mop2.dstr()
    # Otherwise fall back to Z3 (also handles differing types).
    if debug_on:
        optimizer_logger.debug(
            "z3_check_mop_inequality: mop1.t: %s, mop2.t: %s",
            format_mop_t(mop1),
            format_mop_t(mop2),
        )
        optimizer_logger.debug(
            "z3_check_mop_inequality: mop1.dstr(): %s, mop2.dstr(): %s",
            mop1.dstr(),
            mop2.dstr(),
        )
    # If pre-filters don't apply, fall back to Z3.
    exprs = mop_list_to_z3_expression_list([mop1, mop2])
    if len(exprs) != 2:
        return True
    z3_mop1, z3_mop2 = exprs
    _solver = solver if solver is not None else get_solver()
    _solver.push()
    _solver.add(z3_mop1 == z3_mop2)
    is_unequal = _solver.check() == z3.unsat
    if debug_on:
        optimizer_logger.debug(
            "z3_check_mop_inequality: z3_mop1 ( %s ) != z3_mop2 ( %s ) ? is_unequal: %s",
            z3_mop1,
            z3_mop2,
            is_unequal,
        )
    _solver.pop()
    return is_unequal


@requires_z3_installed
def rename_leafs(leaf_list: list[AstLeaf]) -> list[str]:
    known_leaf_list = []
    for leaf in leaf_list:
        if leaf.is_constant() or leaf.mop is None:
            continue

        if leaf.mop.t == mop_z:
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


@requires_z3_installed
def log_z3_instructions(original_ins: minsn_t, new_ins: minsn_t):
    orig_mba_tree = minsn_to_ast(original_ins)
    new_mba_tree = minsn_to_ast(new_ins)
    if orig_mba_tree is None or new_mba_tree is None:
        return None
    orig_leaf_list = orig_mba_tree.get_leaf_list()
    new_leaf_list = new_mba_tree.get_leaf_list()

    var_def_list = rename_leafs(orig_leaf_list + new_leaf_list)

    z3_file_logger.info(
        "print('Testing: {0} == {1}')".format(
            format_minsn_t(original_ins), format_minsn_t(new_ins)
        )
    )
    for var_def in var_def_list:
        z3_file_logger.info("{0}".format(var_def))

    removed_xdu = "{0}".format(orig_mba_tree).replace("xdu", "")
    z3_file_logger.info("original_expr = {0}".format(removed_xdu))
    removed_xdu = "{0}".format(new_mba_tree).replace("xdu", "")
    z3_file_logger.info("new_expr = {0}".format(removed_xdu))
    z3_file_logger.info("prove(original_expr == new_expr)\n")
