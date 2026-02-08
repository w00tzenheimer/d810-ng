"""Op-to-string mappings and constant definitions for ctree operations.

Provides ``cexpr_op2str``, ``cinsn_op2str``, and the unified ``op2str``
dictionary, plus lists of binary/unary expression opcodes.

Ported from herast (herast/tree/consts.py).
"""
from __future__ import annotations

from d810.core import getLogger

logger = getLogger("D810.ctree")

# ---------------------------------------------------------------------------
# IDA imports are optional so the module can be tested without IDA.
# When IDA is not available we populate empty dicts / lists and the
# constants become hollow -- tests can inject mock values.
# ---------------------------------------------------------------------------
try:
    import idaapi

    cexpr_op2str: dict[int, str] = dict(idaapi.cexpr_t.op_to_typename)
    cinsn_op2str: dict[int, str] = dict(idaapi.cinsn_t.op_to_typename)

    binary_expressions_ops: list[int] = [
        idaapi.cot_comma,
        idaapi.cot_asg,
        idaapi.cot_asgbor,
        idaapi.cot_asgxor,
        idaapi.cot_asgband,
        idaapi.cot_asgadd,
        idaapi.cot_asgsub,
        idaapi.cot_asgmul,
        idaapi.cot_asgsshr,
        idaapi.cot_asgushr,
        idaapi.cot_asgshl,
        idaapi.cot_asgsdiv,
        idaapi.cot_asgudiv,
        idaapi.cot_asgsmod,
        idaapi.cot_asgumod,
        idaapi.cot_lor,
        idaapi.cot_land,
        idaapi.cot_bor,
        idaapi.cot_xor,
        idaapi.cot_band,
        idaapi.cot_eq,
        idaapi.cot_ne,
        idaapi.cot_sge,
        idaapi.cot_uge,
        idaapi.cot_sle,
        idaapi.cot_ule,
        idaapi.cot_sgt,
        idaapi.cot_ugt,
        idaapi.cot_slt,
        idaapi.cot_ult,
        idaapi.cot_sshr,
        idaapi.cot_ushr,
        idaapi.cot_shl,
        idaapi.cot_add,
        idaapi.cot_sub,
        idaapi.cot_mul,
        idaapi.cot_sdiv,
        idaapi.cot_udiv,
        idaapi.cot_smod,
        idaapi.cot_umod,
        idaapi.cot_fadd,
        idaapi.cot_fsub,
        idaapi.cot_fmul,
        idaapi.cot_fdiv,
        idaapi.cot_idx,
    ]

    unary_expressions_ops: list[int] = [
        idaapi.cot_fneg,
        idaapi.cot_neg,
        idaapi.cot_cast,
        idaapi.cot_lnot,
        idaapi.cot_bnot,
        idaapi.cot_ptr,
        idaapi.cot_ref,
        idaapi.cot_postinc,
        idaapi.cot_postdec,
        idaapi.cot_preinc,
        idaapi.cot_predec,
        idaapi.cot_sizeof,
        idaapi.cot_memref,
        idaapi.cot_memptr,
    ]
except ImportError:
    idaapi = None  # type: ignore[assignment]
    cexpr_op2str = {}
    cinsn_op2str = {}
    binary_expressions_ops = []
    unary_expressions_ops = []

op2str: dict[int, str] = {}
op2str.update(cexpr_op2str)
op2str.update(cinsn_op2str)

str2op: dict[str, int] = {v: k for k, v in op2str.items()}


# ---------------------------------------------------------------------------
# Hex-Rays event and maturity constants (for reference, IDA 7.6+)
# ---------------------------------------------------------------------------
class HR_EVENT:
    HXE_FLOWCHART: int = 0
    HXE_STKPNTS: int = 1
    HXE_PROLOG: int = 2
    HXE_MICROCODE: int = 3
    HXE_PREOPTIMIZED: int = 4
    HXE_LOCOPT: int = 5
    HXE_PREALLOC: int = 6
    HXE_GLBOPT: int = 7
    HXE_STRUCTURAL: int = 8
    HXE_MATURITY: int = 9
    HXE_INTERR: int = 10
    HXE_COMBINE: int = 11
    HXE_PRINT_FUNC: int = 12
    HXE_FUNC_PRINTED: int = 13
    HXE_RESOLVE_STKADDRS: int = 14
    HXE_OPEN_PSEUDOCODE: int = 100
    HXE_SWITCH_PSEUDOCODE: int = 101
    HXE_REFRESH_PSEUDOCODE: int = 102
    HXE_CLOSE_PSEUDOCODE: int = 103
    HXE_KEYBOARD: int = 104
    HXE_RIGHT_CLICK: int = 105
    HXE_DOUBLE_CLICK: int = 106
    HXE_CURPOS: int = 107
    HXE_CREATE_HINT: int = 108
    HXE_TEXT_READY: int = 109
    HXE_POPULATING_POPUP: int = 110
    LXE_LVAR_NAME_CHANGED: int = 111
    LXE_LVAR_TYPE_CHANGED: int = 112
    LXE_LVAR_CMT_CHANGED: int = 113
    LXE_LVAR_MAPPING_CHANGED: int = 114
    HXE_CMT_CHANGED: int = 115


class CMAT_LEVEL:
    ZERO: int = 0
    BUILT: int = 1
    TRANS1: int = 2
    NICE: int = 3
    TRANS2: int = 4
    CPA: int = 5
    TRANS3: int = 6
    CASTED: int = 7
    FINAL: int = 8
