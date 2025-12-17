"""
Modern Pythonic representation of IDA Hex-Rays microcode primitives.
Provides type-safe, high-performance dataclasses with IntEnum support and structural pattern matching.
Enhanced with readable property names for operands.
"""

import dataclasses
import enum
import typing
from typing import Optional, Tuple, Union

# Try to import IDA modules, allow module to be imported for unit testing
try:
    import ida_hexrays
    IDA_AVAILABLE = True
except ImportError:
    # Allow module to be imported for unit testing without IDA Pro
    # Mock all IDA constants that are used in module-level code
    IDA_AVAILABLE = False

    # Create a mock ida_hexrays module with necessary attributes
    class _MockIDAHexrays:  # type: ignore
        # Mock minimal IDA types/constants needed for AST construction
        class mop_t:
            pass

        class minsn_t:
            pass

        class mblock_t:
            pass

        class mba_t:
            pass

        # Mock all IDA constants - MUST use unique values so OPCODES_INFO dict works
        # These values must match those in dsl.py and z3_utils.py for consistency
        # Core opcodes (matching z3_utils.py)
        m_add = 0
        m_and = 1
        m_bnot = 2
        m_mul = 3
        m_neg = 4
        m_or = 5
        m_sar = 6
        m_shl = 7
        m_shr = 8
        m_sub = 9
        m_xor = 10
        m_lnot = 11
        m_udiv = 12
        m_sdiv = 13
        m_umod = 14
        m_smod = 15
        m_setnz = 16
        m_setz = 17
        m_setae = 18
        m_setb = 19
        m_seta = 20
        m_setbe = 21
        m_setg = 22
        m_setge = 23
        m_setl = 24
        m_setle = 25
        m_setp = 26
        m_sets = 27
        m_xdu = 28
        m_xds = 29
        m_low = 30
        m_high = 31

        # Additional opcodes not used in Z3 but needed for OPCODES_INFO dict
        m_nop = 32
        m_stx = 33
        m_ldx = 34
        m_ldc = 35
        m_mov = 36
        m_cfadd = 37
        m_ofadd = 38
        m_cfshl = 39
        m_cfshr = 40
        m_seto = 41
        m_jcnd = 42
        m_jnz = 43
        m_jz = 44
        m_jae = 45
        m_jb = 46
        m_ja = 47
        m_jbe = 48
        m_jg = 49
        m_jge = 50
        m_jl = 51
        m_jle = 52
        m_jtbl = 53
        m_ijmp = 54
        m_goto = 55
        m_call = 56
        m_icall = 57
        m_ret = 58
        m_push = 59
        m_pop = 60
        m_und = 61
        m_ext = 62
        m_f2i = 63
        m_f2u = 64
        m_i2f = 65
        m_u2f = 66
        m_f2f = 67
        m_fneg = 68
        m_fadd = 69
        m_fsub = 70
        m_fmul = 71
        m_fdiv = 72

        # Maturity levels
        MMAT_ZERO = 0
        MMAT_GENERATED = 1
        MMAT_PREOPTIMIZED = 2
        MMAT_LOCOPT = 3
        MMAT_CALLS = 4
        MMAT_GLBOPT1 = 5
        MMAT_GLBOPT2 = 6
        MMAT_GLBOPT3 = 7
        MMAT_LVARS = 8

        # Operand types
        mop_z = 0
        mop_r = 1
        mop_n = 2
        mop_str = 3
        mop_d = 4
        mop_S = 5
        mop_v = 6
        mop_b = 7
        mop_f = 8
        mop_l = 9
        mop_a = 10
        mop_h = 11
        mop_c = 12
        mop_fn = 13
        mop_p = 14
        mop_sc = 15

    ida_hexrays = _MockIDAHexrays()

from d810.core import getLogger
from d810.core.cymode import CythonMode

# Try to import Cython hash_mop if CythonMode is enabled
cy_hash_mop = None
if CythonMode().is_enabled():
    try:
        from d810.speedups.cythxr._chexrays_api import hash_mop as cy_hash_mop
    except ImportError:
        pass

logger = getLogger(__name__)

OPCODES_INFO = {
    ida_hexrays.m_nop: {"name": "nop", "nb_operands": 0, "is_commutative": True},
    ida_hexrays.m_stx: {"name": "stx", "nb_operands": 2, "is_commutative": False},
    ida_hexrays.m_ldx: {"name": "ldx", "nb_operands": 2, "is_commutative": False},
    ida_hexrays.m_ldc: {"name": "ldc", "nb_operands": 1, "is_commutative": False},
    ida_hexrays.m_mov: {"name": "mov", "nb_operands": 1, "is_commutative": False, "symbol": ""},
    ida_hexrays.m_neg: {"name": "neg", "nb_operands": 1, "is_commutative": False, "symbol": "-"},
    ida_hexrays.m_lnot: {"name": "lnot", "nb_operands": 1, "is_commutative": False, "symbol": "!"},
    ida_hexrays.m_bnot: {"name": "bnot", "nb_operands": 1, "is_commutative": False, "symbol": "~"},
    ida_hexrays.m_xds: {"name": "xds", "nb_operands": 1, "is_commutative": False, "symbol": "xds"},
    ida_hexrays.m_xdu: {"name": "xdu", "nb_operands": 1, "is_commutative": False, "symbol": "xdu"},
    ida_hexrays.m_low: {"name": "low", "nb_operands": 1, "is_commutative": False, "symbol": "low"},
    ida_hexrays.m_high: {
        "name": "high",
        "nb_operands": 1,
        "is_commutative": False,
        "symbol": "high",
    },
    ida_hexrays.m_add: {"name": "add", "nb_operands": 2, "is_commutative": True, "symbol": "+"},
    ida_hexrays.m_sub: {"name": "sub", "nb_operands": 2, "is_commutative": False, "symbol": "-"},
    ida_hexrays.m_mul: {"name": "mul", "nb_operands": 2, "is_commutative": True, "symbol": "*"},
    ida_hexrays.m_udiv: {
        "name": "udiv",
        "nb_operands": 2,
        "is_commutative": False,
        "symbol": "UDiv",
    },
    ida_hexrays.m_sdiv: {"name": "sdiv", "nb_operands": 2, "is_commutative": False, "symbol": "/"},
    ida_hexrays.m_umod: {
        "name": "umod",
        "nb_operands": 2,
        "is_commutative": False,
        "symbol": "URem",
    },
    ida_hexrays.m_smod: {"name": "smod", "nb_operands": 2, "is_commutative": False, "symbol": "%"},
    ida_hexrays.m_or: {"name": "or", "nb_operands": 2, "is_commutative": True, "symbol": "|"},
    ida_hexrays.m_and: {"name": "and", "nb_operands": 2, "is_commutative": True, "symbol": "&"},
    ida_hexrays.m_xor: {"name": "xor", "nb_operands": 2, "is_commutative": True, "symbol": "^"},
    ida_hexrays.m_shl: {"name": "shl", "nb_operands": 2, "is_commutative": False, "symbol": "<<"},
    ida_hexrays.m_shr: {"name": "shr", "nb_operands": 2, "is_commutative": False, "symbol": "LShR"},
    ida_hexrays.m_sar: {"name": "sar", "nb_operands": 2, "is_commutative": False, "symbol": ">>"},
    ida_hexrays.m_cfadd: {"name": "cfadd", "nb_operands": 2, "is_commutative": True},
    ida_hexrays.m_ofadd: {"name": "ofadd", "nb_operands": 2, "is_commutative": True},
    ida_hexrays.m_cfshl: {"name": "cfshl", "nb_operands": 2, "is_commutative": False},
    ida_hexrays.m_cfshr: {"name": "cfshr", "nb_operands": 2, "is_commutative": False},
    ida_hexrays.m_sets: {"name": "sets", "nb_operands": 2, "is_commutative": False},
    ida_hexrays.m_seto: {"name": "seto", "nb_operands": 2, "is_commutative": False},
    ida_hexrays.m_setp: {"name": "setp", "nb_operands": 2, "is_commutative": False},
    ida_hexrays.m_setnz: {
        "name": "setnz",
        "nb_operands": 2,
        "is_commutative": True,
        "symbol": "!=",
    },
    ida_hexrays.m_setz: {"name": "setz", "nb_operands": 2, "is_commutative": True, "symbol": "=="},
    ida_hexrays.m_seta: {"name": "seta", "nb_operands": 2, "is_commutative": False, "symbol": ">"},
    ida_hexrays.m_setae: {
        "name": "setae",
        "nb_operands": 2,
        "is_commutative": False,
        "symbol": ">=",
    },
    ida_hexrays.m_setb: {"name": "setb", "nb_operands": 2, "is_commutative": False, "symbol": "<"},
    ida_hexrays.m_setbe: {
        "name": "setbe",
        "nb_operands": 2,
        "is_commutative": False,
        "symbol": "<=",
    },
    ida_hexrays.m_setg: {
        "name": "setg",
        "nb_operands": 2,
        "is_commutative": False,
        "symbol": "UGT",
    },
    ida_hexrays.m_setge: {
        "name": "setge",
        "nb_operands": 2,
        "is_commutative": False,
        "symbol": "UGE",
    },
    ida_hexrays.m_setl: {
        "name": "setl",
        "nb_operands": 2,
        "is_commutative": False,
        "symbol": "ULT",
    },
    ida_hexrays.m_setle: {
        "name": "setle",
        "nb_operands": 2,
        "is_commutative": False,
        "symbol": "ULE",
    },
    ida_hexrays.m_jcnd: {"name": "jcnd", "nb_operands": 1, "is_commutative": False},
    ida_hexrays.m_jnz: {"name": "jnz", "nb_operands": 2, "is_commutative": True},
    ida_hexrays.m_jz: {"name": "jz", "nb_operands": 2, "is_commutative": True},
    ida_hexrays.m_jae: {"name": "jae", "nb_operands": 2, "is_commutative": False},
    ida_hexrays.m_jb: {"name": "jb", "nb_operands": 2, "is_commutative": False},
    ida_hexrays.m_ja: {"name": "ja", "nb_operands": 2, "is_commutative": False},
    ida_hexrays.m_jbe: {"name": "jbe", "nb_operands": 2, "is_commutative": False},
    ida_hexrays.m_jg: {"name": "jg", "nb_operands": 2, "is_commutative": False},
    ida_hexrays.m_jge: {"name": "jge", "nb_operands": 2, "is_commutative": False},
    ida_hexrays.m_jl: {"name": "jl", "nb_operands": 2, "is_commutative": False},
    ida_hexrays.m_jle: {"name": "jle", "nb_operands": 2, "is_commutative": False},
    ida_hexrays.m_jtbl: {"name": "jtbl", "nb_operands": 2, "is_commutative": False},
    ida_hexrays.m_ijmp: {"name": "ijmp", "nb_operands": 2, "is_commutative": False},
    ida_hexrays.m_goto: {"name": "goto", "nb_operands": 1, "is_commutative": False},
    ida_hexrays.m_call: {"name": "call", "nb_operands": 2, "is_commutative": False},
    ida_hexrays.m_icall: {"name": "icall", "nb_operands": 2, "is_commutative": False},
    ida_hexrays.m_ret: {"name": "ret", "nb_operands": 0, "is_commutative": False},
    ida_hexrays.m_push: {"name": "push", "nb_operands": 0, "is_commutative": False},
    ida_hexrays.m_pop: {"name": "pop", "nb_operands": 0, "is_commutative": False},
    ida_hexrays.m_und: {"name": "und", "nb_operands": 0, "is_commutative": False},
    ida_hexrays.m_ext: {"name": "ext", "nb_operands": 0, "is_commutative": False},
    ida_hexrays.m_f2i: {"name": "f2i", "nb_operands": 2, "is_commutative": False},
    ida_hexrays.m_f2u: {"name": "f2u", "nb_operands": 2, "is_commutative": False},
    ida_hexrays.m_i2f: {"name": "i2f", "nb_operands": 2, "is_commutative": False},
    ida_hexrays.m_u2f: {"name": "u2f", "nb_operands": 2, "is_commutative": False},
    ida_hexrays.m_f2f: {"name": "f2f", "nb_operands": 2, "is_commutative": False},
    ida_hexrays.m_fneg: {"name": "fneg", "nb_operands": 2, "is_commutative": False},
    ida_hexrays.m_fadd: {"name": "fadd", "nb_operands": 2, "is_commutative": True},
    ida_hexrays.m_fsub: {"name": "fsub", "nb_operands": 2, "is_commutative": False},
    ida_hexrays.m_fmul: {"name": "fmul", "nb_operands": 2, "is_commutative": True},
    ida_hexrays.m_fdiv: {"name": "fdiv", "nb_operands": 2, "is_commutative": False},
}


MATURITY_TO_STRING_DICT: dict[int, str] = {
    ida_hexrays.MMAT_ZERO: "MMAT_ZERO",
    ida_hexrays.MMAT_GENERATED: "MMAT_GENERATED",
    ida_hexrays.MMAT_PREOPTIMIZED: "MMAT_PREOPTIMIZED",
    ida_hexrays.MMAT_LOCOPT: "MMAT_LOCOPT",
    ida_hexrays.MMAT_CALLS: "MMAT_CALLS",
    ida_hexrays.MMAT_GLBOPT1: "MMAT_GLBOPT1",
    ida_hexrays.MMAT_GLBOPT2: "MMAT_GLBOPT2",
    ida_hexrays.MMAT_GLBOPT3: "MMAT_GLBOPT3",
    ida_hexrays.MMAT_LVARS: "MMAT_LVARS",
}
STRING_TO_MATURITY_DICT: dict[str, int] = {
    v: k for k, v in MATURITY_TO_STRING_DICT.items()
}

MOP_TYPE_TO_STRING_DICT: dict[int, str] = {
    ida_hexrays.mop_z: "mop_z",
    ida_hexrays.mop_r: "mop_r",
    ida_hexrays.mop_n: "mop_n",
    ida_hexrays.mop_str: "mop_str",
    ida_hexrays.mop_d: "mop_d",
    ida_hexrays.mop_S: "mop_S",
    ida_hexrays.mop_v: "mop_v",
    ida_hexrays.mop_b: "mop_b",
    ida_hexrays.mop_f: "mop_f",
    ida_hexrays.mop_l: "mop_l",
    ida_hexrays.mop_a: "mop_a",
    ida_hexrays.mop_h: "mop_h",
    ida_hexrays.mop_c: "mop_c",
    ida_hexrays.mop_fn: "mop_fn",
    ida_hexrays.mop_p: "mop_p",
    ida_hexrays.mop_sc: "mop_sc",
}

Z3_SPECIAL_OPERANDS: list[str] = ["UDiv", "URem", "LShR", "UGT", "UGE", "ULT", "ULE"]

BOOLEAN_OPCODES: list[int] = [ida_hexrays.m_lnot, ida_hexrays.m_bnot, ida_hexrays.m_or, ida_hexrays.m_and, ida_hexrays.m_xor]
ARITHMETICAL_OPCODES: list[int] = [
    ida_hexrays.m_neg,
    ida_hexrays.m_add,
    ida_hexrays.m_sub,
    ida_hexrays.m_mul,
    ida_hexrays.m_udiv,
    ida_hexrays.m_sdiv,
    ida_hexrays.m_umod,
    ida_hexrays.m_smod,
]
BIT_OPERATIONS_OPCODES: list[int] = [
    ida_hexrays.m_shl,
    ida_hexrays.m_shr,
    ida_hexrays.m_sar,
    ida_hexrays.m_mov,
    ida_hexrays.m_xds,
    ida_hexrays.m_xdu,
    ida_hexrays.m_low,
    ida_hexrays.m_high,
]
CHECK_OPCODES: list[int] = [
    ida_hexrays.m_sets,
    ida_hexrays.m_seto,
    ida_hexrays.m_setp,
    ida_hexrays.m_setnz,
    ida_hexrays.m_setz,
    ida_hexrays.m_seta,
    ida_hexrays.m_setae,
    ida_hexrays.m_setb,
    ida_hexrays.m_setbe,
    ida_hexrays.m_setg,
    ida_hexrays.m_setge,
    ida_hexrays.m_setl,
    ida_hexrays.m_setle,
]

MBA_RELATED_OPCODES: list[int] = (
    BOOLEAN_OPCODES + ARITHMETICAL_OPCODES + BIT_OPERATIONS_OPCODES + CHECK_OPCODES
)

CONDITIONAL_JUMP_OPCODES: list[int] = [
    ida_hexrays.m_jcnd,
    ida_hexrays.m_jnz,
    ida_hexrays.m_jz,
    ida_hexrays.m_jae,
    ida_hexrays.m_ja,
    ida_hexrays.m_jb,
    ida_hexrays.m_jbe,
    ida_hexrays.m_jg,
    ida_hexrays.m_jge,
    ida_hexrays.m_jl,
    ida_hexrays.m_jle,
    ida_hexrays.m_jtbl,
]
UNCONDITIONAL_JUMP_OPCODES: list[int] = [ida_hexrays.m_goto, ida_hexrays.m_ijmp]
CONTROL_FLOW_OPCODES: list[int] = CONDITIONAL_JUMP_OPCODES + UNCONDITIONAL_JUMP_OPCODES

MINSN_TO_AST_FORBIDDEN_OPCODES: list[int] = CONTROL_FLOW_OPCODES + [
    ida_hexrays.m_ret,
    ida_hexrays.m_nop,
    ida_hexrays.m_stx,
    ida_hexrays.m_push,
    ida_hexrays.m_pop,
    ida_hexrays.m_und,
    ida_hexrays.m_ext,
]

# Import constant tables from d810.core (IDA-independent)
from d810.core.bits import AND_TABLE, MSB_TABLE


# Hex-Rays mop equality checking
_EQUAL_BNOT_CACHE: dict[tuple[int, int], bool] = {}
_EQUAL_BNOT_MAX = 8192
_EQUAL_IGN_CACHE: dict[tuple[int, int], bool] = {}
_EQUAL_IGN_MAX = 8192


def _mop_cache_key(op: ida_hexrays.mop_t) -> str:
    """Stable, cheap key for caching equality checks without using dstr()."""
    t = op.t
    sz = op.size
    # Constants: include value
    if t == ida_hexrays.mop_n:
        try:
            return f"n:{sz}:{op.nnn.value}"
        except Exception:
            return f"n:{sz}:?"
    # Global address
    if t == ida_hexrays.mop_v:
        try:
            return f"v:{sz}:{op.g}"
        except Exception:
            return f"v:{sz}:?"
    # Symbolic reference; prefer start_ea when available (exclude stkvars)
    if t == ida_hexrays.mop_S:
        start_ea = getattr(op.s, "start_ea", None)
        if start_ea is not None:
            return f"S:{sz}:{start_ea}"
        off = getattr(op.s, "off", -1)
        return f"Sstk:{sz}:{off}"
    # Nested instruction: use opcode + identity of the inner instruction
    if t == ida_hexrays.mop_d and op.d is not None:
        try:
            return f"d:{sz}:{op.d.opcode}:{id(op.d)}"
        except Exception:
            return f"d:{sz}:{id(op)}"
    # Register
    if t == ida_hexrays.mop_r:
        return f"r:{sz}:{getattr(op, 'r', '?')}"
    # Memory b form: capture base type; avoid non-existent fields access
    if t == ida_hexrays.mop_b:
        bt = getattr(op.b, "t", -1)
        return f"b:{sz}:{bt}:{id(op)}"
    # Pair
    if t == ida_hexrays.mop_p:
        return f"p:{sz}:{id(op)}"
    # Fallback to type+size+identity
    return f"{t}:{sz}:{id(op)}"


def mop_quick_key_ignore_size(op: ida_hexrays.mop_t) -> str:
    """Cheap signature for grouping operands under ignore-size equality.

    This intentionally ignores the operand size and uses structural fields that
    are compared in equal_mops_ignore_size. It is not a perfect hash: keys may
    collide across non-equal operands, so callers must still verify equality
    within a bucket using equal_mops_ignore_size.
    """
    # Validate SWIG object before accessing attributes
    if not hasattr(op, 't'):
        return f"invalid:{id(op)}"
    t = op.t
    if t == ida_hexrays.mop_n:
        try:
            return f"n:{op.nnn.value}"
        except Exception:
            return "n:?"
    if t == ida_hexrays.mop_v:
        try:
            return f"v:{op.g}"
        except Exception:
            return "v:?"
    if t == ida_hexrays.mop_S:
        start_ea = getattr(op.s, "start_ea", None)
        if start_ea is not None:
            return f"S:{start_ea}"
        off = getattr(op.s, "off", -1)
        return f"Soff:{off}"
    if t == ida_hexrays.mop_r:
        return f"r:{getattr(op, 'r', '?')}"
    if t == ida_hexrays.mop_b:
        bt = getattr(op.b, "t", -1)
        return f"b:{bt}"
    if t == ida_hexrays.mop_d and op.d is not None:
        # Group by opcode only; detailed check is done later
        return f"d:{op.d.opcode}"
    if t == ida_hexrays.mop_p:
        return "p"
    return f"t:{t}"


def structural_mop_hash(op: ida_hexrays.mop_t, func_entry_ea: int = 0) -> int:
    """Use Cython fast hasher if available; fallback to Python quick key.

    This returns a 64-bit int when Cython is present; otherwise a Python hash
    of the quick key which is still cheap and avoids dstr().
    """
    # Validate mop_t object before attempting to hash it
    # Check if the object has the essential 't' attribute to detect invalid SWIG objects
    if not hasattr(op, 't') or not hasattr(op, 'size'):
        # Invalid or freed SWIG object - return a sentinel hash
        return hash(("invalid_mop", id(op)))

    if cy_hash_mop is not None:
        try:
            return int(cy_hash_mop(op, func_entry_ea))
        except Exception:
            # Fall through to Python implementation
            pass
    return hash(mop_quick_key_ignore_size(op))


def equal_bnot_cst(lo: ida_hexrays.mop_t, ro: ida_hexrays.mop_t, mop_size=None) -> bool:
    if (lo.t != ida_hexrays.mop_n) or (ro.t != ida_hexrays.mop_n):
        return False
    if lo.size != ro.size:
        return False
    if mop_size is None:
        mop_size = lo.size
    return lo.nnn.value ^ ro.nnn.value == AND_TABLE[mop_size]


def equal_bnot_mop(lo: ida_hexrays.mop_t, ro: ida_hexrays.mop_t, test_two_sides=True) -> bool:
    # Try cache first (symmetry-aware)
    try:
        h1 = int(structural_mop_hash(lo, 0))
        h2 = int(structural_mop_hash(ro, 0))
        key = (h1, h2) if h1 <= h2 else (h2, h1)
    except Exception:
        key = (id(lo), id(ro)) if id(lo) <= id(ro) else (id(ro), id(lo))
    cached = _EQUAL_BNOT_CACHE.get(key)
    if cached is not None:
        return cached

    result = False
    if lo.t == ida_hexrays.mop_n:
        result = equal_bnot_cst(lo, ro)
    else:
        # Direct ~x pattern
        if (lo.t == ida_hexrays.mop_d) and lo.d.opcode == ida_hexrays.m_bnot:
            if equal_mops_ignore_size(lo.d.l, ro):
                result = True
        # Hex-Rays: ~(-x) == x - 1
        if not result and (lo.t == ida_hexrays.mop_d) and lo.d.opcode == ida_hexrays.m_neg:
            if (ro.t == ida_hexrays.mop_d) and ro.d.opcode == ida_hexrays.m_sub:
                if ro.d.r.t == ida_hexrays.mop_n and ro.d.r.nnn.value == 1:
                    if equal_mops_ignore_size(ro.d.l, lo.d.l):
                        result = True
        # Unsigned extend wrapper
        if not result and (lo.t == ida_hexrays.mop_d) and lo.d.opcode == ida_hexrays.m_xds:
            if equal_bnot_mop(lo.d.l, ro):
                result = True
        # Symmetry
        if not result and test_two_sides:
            result = equal_bnot_mop(ro, lo, test_two_sides=False)

    if len(_EQUAL_BNOT_CACHE) > _EQUAL_BNOT_MAX:
        _EQUAL_BNOT_CACHE.clear()
    _EQUAL_BNOT_CACHE[key] = result
    return result


def equal_ignore_msb_cst(lo: ida_hexrays.mop_t, ro: ida_hexrays.mop_t) -> bool:
    if (lo.t != ida_hexrays.mop_n) or (ro.t != ida_hexrays.mop_n):
        return False
    if lo.size != ro.size:
        return False
    mask = AND_TABLE[lo.size] ^ MSB_TABLE[lo.size]
    return lo.nnn.value & mask == ro.nnn.value & mask


def equal_mops_bypass_xdu(lo: ida_hexrays.mop_t, ro: ida_hexrays.mop_t) -> bool:
    if (lo is None) or (ro is None):
        return False
    if (lo.t == ida_hexrays.mop_d) and (lo.d.opcode == ida_hexrays.m_xdu):
        return equal_mops_bypass_xdu(lo.d.l, ro)
    if (ro.t == ida_hexrays.mop_d) and (ro.d.opcode == ida_hexrays.m_xdu):
        return equal_mops_bypass_xdu(lo, ro.d.l)
    return equal_mops_ignore_size(lo, ro)


def equal_mops_ignore_size(lo: ida_hexrays.mop_t, ro: ida_hexrays.mop_t) -> bool:
    if (lo is None) or (ro is None):
        return False
    # Exact same SWIG object → equal
    if lo is ro:
        return True
    # Cheap type check first
    if lo.t != ro.t:
        return False
    # Symmetry-aware bounded cache using structural hash (fast path)
    try:
        h1 = int(structural_mop_hash(lo, 0))
        h2 = int(structural_mop_hash(ro, 0))
        key = (h1, h2) if h1 <= h2 else (h2, h1)
        cached = _EQUAL_IGN_CACHE.get(key)
        if cached is not None:
            return cached
    except Exception:
        key = None  # fallback
    if lo.t == ida_hexrays.mop_z:
        result = True
    elif lo.t == ida_hexrays.mop_fn:
        result = lo.fpc == ro.fpc
    elif lo.t == ida_hexrays.mop_n:
        result = lo.nnn.value == ro.nnn.value
    elif lo.t == ida_hexrays.mop_S:
        if lo.s == ro.s:
            result = True
        elif lo.s.off == ro.s.off:
            result = True
        else:
            result = False
    elif lo.t == ida_hexrays.mop_v:
        result = lo.g == ro.g
    elif lo.t == ida_hexrays.mop_d:
        result = lo.d.equal_insns(ro.d, ida_hexrays.EQ_IGNSIZE)
        # return lo.d.equal_insns(ro.d, ida_hexrays.EQ_IGNSIZE | ida_hexrays.EQ_IGNCODE)
    elif lo.t == ida_hexrays.mop_b:
        result = lo.b == ro.b
    elif lo.t == ida_hexrays.mop_r:
        result = lo.r == ro.r
    elif lo.t == ida_hexrays.mop_f:
        result = False
    elif lo.t == ida_hexrays.mop_l:
        result = lo.l == ro.l
    elif lo.t == ida_hexrays.mop_a:
        if lo.a.insize != ro.a.insize:
            result = False
        elif lo.a.outsize != ro.a.outsize:
            result = False
        else:
            result = equal_mops_ignore_size(lo.a, ro.a)
        if key is not None:
            if len(_EQUAL_IGN_CACHE) > _EQUAL_IGN_MAX:
                _EQUAL_IGN_CACHE.clear()
            _EQUAL_IGN_CACHE[key] = result
        return result
    elif lo.t == ida_hexrays.mop_h:
        result = ro.helper == lo.helper
    elif lo.t == ida_hexrays.mop_str:
        result = ro.cstr == lo.cstr
    elif lo.t == ida_hexrays.mop_c:
        result = ro.c == lo.c
    elif lo.t == ida_hexrays.mop_p:
        result = equal_mops_ignore_size(
            lo.pair.lop, ro.pair.lop
        ) and equal_mops_ignore_size(lo.pair.hop, ro.pair.hop)
    elif lo.t == ida_hexrays.mop_sc:
        result = False
    else:
        result = False

    if key is not None:
        if len(_EQUAL_IGN_CACHE) > _EQUAL_IGN_MAX:
            _EQUAL_IGN_CACHE.clear()
        _EQUAL_IGN_CACHE[key] = result
    return result


def is_check_mop(lo: ida_hexrays.mop_t) -> bool:
    if lo.t != ida_hexrays.mop_d:
        return False
    if lo.d.opcode in CHECK_OPCODES:
        return True
    if lo.d.opcode in [ida_hexrays.m_xds, ida_hexrays.m_xdu]:
        return is_check_mop(lo.d.l)
    return False


def extract_num_mop(ins: ida_hexrays.minsn_t) -> tuple[ida_hexrays.mop_t, ida_hexrays.mop_t]:
    num_mop = typing.cast(ida_hexrays.mop_t, None)
    other_mop = typing.cast(ida_hexrays.mop_t, None)

    if ins.l.t == ida_hexrays.mop_n:
        num_mop = ins.l
        other_mop = ins.r
    if ins.r.t == ida_hexrays.mop_n:
        num_mop = ins.r
        other_mop = ins.l
    return (num_mop, other_mop)


def check_ins_mop_size_are_ok(ins: ida_hexrays.minsn_t) -> bool:
    """Return *True* when the operand sizes are *semantically* consistent.

    The helper is intentionally conservative (it prefers returning *False* rather
    than letting an inconsistent instruction slip through).  However, for some
    micro-instructions such as *ida_hexrays.m_call* / *m_icall* the operand sizes are not
    required to match the result size  a function can legitimately take
    1-byte, 2-byte … arguments and still return a 4-byte (or 8-byte) value.  In
    that case the previous implementation rejected perfectly valid instructions
    created by the peephole optimizers and the optimiser framework would
    subsequently complain with the misleading message "Invalid original
    instruction".

    In practice we can safely trust Hex-Rays here, therefore any *call*
    instruction is now considered size-OK and short-circuits the rest of the
    checks.

    Usage: This function can be used to check if a created instruction has consistent mop size
    Use it to avoid Hex-Rays decompilation errors when replacing instructions
    """
    # Calls / indirect calls: argument sizes may legitimately differ from the
    # destination size – skip the strict size checks for them.
    if ins.opcode in (ida_hexrays.m_call, ida_hexrays.m_icall, ida_hexrays.m_ret):
        return True

    ins_dest_size = ins.d.size
    if ins.opcode in [ida_hexrays.m_stx, ida_hexrays.m_ldx]:
        if ins.r.t == ida_hexrays.mop_d:
            if not check_ins_mop_size_are_ok(ins.r.d):
                return False
        return True

    if ins.opcode in [ida_hexrays.m_xdu, ida_hexrays.m_xds, ida_hexrays.m_low, ida_hexrays.m_high]:
        if (ins.l.t == ida_hexrays.mop_d) and (not check_ins_mop_size_are_ok(ins.l.d)):
            return False
        return True

    if ins.opcode in [ida_hexrays.m_sar, ida_hexrays.m_shr, ida_hexrays.m_shl]:
        if ins.l.size != ins_dest_size:
            return False
        if (ins.l.t == ida_hexrays.mop_d) and (not check_ins_mop_size_are_ok(ins.l.d)):
            return False
        if (ins.r.t == ida_hexrays.mop_d) and (not check_ins_mop_size_are_ok(ins.r.d)):
            return False
        return True

    if ins.opcode in CHECK_OPCODES:
        if (ins.l.t == ida_hexrays.mop_d) and (not check_ins_mop_size_are_ok(ins.l.d)):
            return False
        if (ins.r.t == ida_hexrays.mop_d) and (not check_ins_mop_size_are_ok(ins.r.d)):
            return False
        return True

    if ins.l is not None:
        if ins.l.size != ins_dest_size:
            return False
        if ins.l.t == ida_hexrays.mop_d and (not check_ins_mop_size_are_ok(ins.l.d)):
            return False

    if ins.r is not None and ins.r.t != ida_hexrays.mop_z:
        if ins.r.size != ins_dest_size:
            return False
        if ins.r.t == ida_hexrays.mop_d and (not check_ins_mop_size_are_ok(ins.r.d)):
            return False
    return True


def check_mop_is_result_of(lo: ida_hexrays.mop_t, mc) -> bool:
    if lo.t != ida_hexrays.mop_d:
        return False
    return lo.d.opcode == mc


def extract_by_opcode_type(ins: ida_hexrays.minsn_t, mc) -> tuple[ida_hexrays.mop_t, ida_hexrays.mop_t]:
    if check_mop_is_result_of(ins.l, mc):
        return (ins.l, ins.r)
    if check_mop_is_result_of(ins.r, mc):
        return (ins.r, ins.l)
    return (typing.cast(ida_hexrays.mop_t, None), typing.cast(ida_hexrays.mop_t, None))


def check_ins_have_same_operands(
    ins1: ida_hexrays.minsn_t, ins2: ida_hexrays.minsn_t, ignore_order=False
) -> bool:
    if equal_mops_ignore_size(ins1.l, ins2.l) and equal_mops_ignore_size(
        ins1.r, ins2.r
    ):
        return True
    if not ignore_order:
        return False
    return equal_mops_ignore_size(ins1.l, ins2.r) and equal_mops_ignore_size(
        ins1.r, ins2.l
    )


def get_mop_index(searched_mop: ida_hexrays.mop_t, mop_list) -> int:
    for i, test_mop in enumerate(mop_list):
        if equal_mops_ignore_size(searched_mop, test_mop):
            return i
    return -1


def append_mop_if_not_in_list(mop: ida_hexrays.mop_t, mop_list) -> bool:
    mop_index = get_mop_index(mop, mop_list)
    if mop_index == -1:
        mop_list.append(mop)
        return True
    return False


def get_blk_index(searched_blk: ida_hexrays.mblock_t, blk_list: list[ida_hexrays.mblock_t]) -> int:
    blk_serial_list = [blk.serial for blk in blk_list]
    try:
        return blk_serial_list.index(searched_blk.serial)
    except ValueError:
        return -1


_mmat_strs = {
    ida_hexrays.MMAT_ZERO: "ida_hexrays.MMAT_ZERO",
    ida_hexrays.MMAT_GENERATED: "ida_hexrays.MMAT_GENERATED",
    ida_hexrays.MMAT_PREOPTIMIZED: "ida_hexrays.MMAT_PREOPTIMIZED",
    ida_hexrays.MMAT_LOCOPT: "ida_hexrays.MMAT_LOCOPT",
    ida_hexrays.MMAT_CALLS: "ida_hexrays.MMAT_CALLS",
    ida_hexrays.MMAT_GLBOPT1: "ida_hexrays.MMAT_GLBOPT1",
    ida_hexrays.MMAT_GLBOPT2: "ida_hexrays.MMAT_GLBOPT2",
    ida_hexrays.MMAT_GLBOPT3: "ida_hexrays.MMAT_GLBOPT3",
    ida_hexrays.MMAT_LVARS: "ida_hexrays.MMAT_LVARS",
}


class MicrocodeHelper:
    """Helper class for working with IDA Hex-Rays microcode operations and maturity levels."""

    # Static class variables
    MMAT: list[tuple[int, str]] = sorted(
        [
            (getattr(ida_hexrays, x), x)
            for x in filter(lambda y: y.startswith("MMAT_"), dir(ida_hexrays))
        ]
    )[1:]
    MOPT: list[tuple[int, str]] = [
        (getattr(ida_hexrays, x), x)
        for x in filter(lambda y: y.startswith("mop_"), dir(ida_hexrays))
    ]
    MCODE: list[tuple[int, str]] = sorted(
        [
            (getattr(ida_hexrays, x), x)
            for x in filter(lambda y: y.startswith("m_"), dir(ida_hexrays))
        ]
    )

    class MatDelta:
        """Enum-like class for maturity level changes."""

        INCREASING = 1
        NEUTRAL = 0
        DECREASING = -1

    @classmethod
    def get_mcode_name(cls, mcode: int) -> typing.Optional[str]:
        """Return the name of the given mcode_t."""
        for value, name in cls.MCODE:
            if mcode == value:
                return name
        return None

    @classmethod
    def get_mopt_name(cls, mopt: int) -> typing.Optional[str]:
        """Return the name of the given mopt_t."""
        for value, name in cls.MOPT:
            if mopt == value:
                return name
        return None

    @classmethod
    def get_mmat(cls, mmat_name: str) -> typing.Optional[int]:
        """Return the mba_maturity_t for the given maturity name."""
        for value, name in cls.MMAT:
            if name == mmat_name:
                return value
        return None

    @classmethod
    def get_mmat_name(cls, mmat: int) -> typing.Optional[str]:
        """Return the maturity name of the given mba_maturity_t."""
        for value, name in cls.MMAT:
            if value == mmat:
                return name
        return None

    @classmethod
    def get_mmat_levels(cls) -> list[int]:
        """Return a list of the microcode maturity levels."""
        return [x[0] for x in cls.MMAT]

    @classmethod
    def diff_mmat(cls, mmat_src: int, mmat_dst: int) -> int:
        """Return an enum indicating maturity growth."""
        direction = mmat_dst - mmat_src
        if direction > 0:
            return cls.MatDelta.INCREASING
        if direction < 0:
            return cls.MatDelta.DECREASING
        return cls.MatDelta.NEUTRAL


# @dataclasses.dataclass
# class MicrocodeOpcode:
#     name: str
#     nb_operands: int
#     is_commutative: bool
#     symbol: typing.Optional[str] = None

#     @property
#     def hexrays_code(self) -> int:
#         return getattr(ida_hexrays, f"m_{self.name}")


# @dataclasses.dataclass(repr=False)
# class MicrocodeInstruction:
#     minsn: ida_hexrays.minsn_t
#     opcode: MicrocodeOpcode

#     @classmethod
#     def from_minsn(cls, minsn: ida_hexrays.minsn_t) -> "MicrocodeInstruction":
#         return cls(minsn, OPCODES_LOOKUP[minsn.opcode])

#     def __repr__(self) -> str:
#         return self.repr(self.minsn)

#     __str__ = __repr__

#     @classmethod
#     def repr(cls, minsn: ida_hexrays.minsn_t) -> str:
#         opcode = OPCODES_LOOKUP[minsn.opcode]
#         if not opcode:
#             return "???"

#         if opcode.nb_operands == 0:
#             return f"m_{opcode.name}"
#         elif opcode.nb_operands == 1:
#             return f"m_{opcode.name}(%s,%s)" % (
#                 MicrocodeHelper.ida_hexrays.get_mopt_name(minsn.l.t),
#                 MicrocodeHelper.ida_hexrays.get_mopt_name(minsn.d.t),
#             )
#         elif opcode.nb_operands == 2:
#             return f"m_{opcode.name}(%s,%s,%s)" % (
#                 MicrocodeHelper.ida_hexrays.get_mopt_name(minsn.l.t),
#                 MicrocodeHelper.ida_hexrays.get_mopt_name(minsn.r.t),
#                 MicrocodeHelper.ida_hexrays.get_mopt_name(minsn.d.t),
#             )
#         return "???"


# OPCODES_LOOKUP: dict[int, MicrocodeOpcode] = {
#     ida_hexrays.m_nop: MicrocodeOpcode("nop", 0, True),
#     ida_hexrays.m_stx: MicrocodeOpcode("stx", 2, False),
#     ida_hexrays.m_ldx: MicrocodeOpcode("ldx", 2, False),
#     ida_hexrays.m_ldc: MicrocodeOpcode("ldc", 1, False),
#     ida_hexrays.m_mov: MicrocodeOpcode("mov", 1, False, ""),
#     ida_hexrays.m_neg: MicrocodeOpcode("neg", 1, False, "-"),
#     ida_hexrays.m_lnot: MicrocodeOpcode("lnot", 1, False, "!"),
#     ida_hexrays.m_bnot: MicrocodeOpcode("bnot", 1, False, "~"),
#     ida_hexrays.m_xds: MicrocodeOpcode("xds", 1, False, "xds"),
#     ida_hexrays.m_xdu: MicrocodeOpcode("xdu", 1, False, "xdu"),
#     ida_hexrays.m_low: MicrocodeOpcode("low", 1, False, "low"),
#     ida_hexrays.m_high: MicrocodeOpcode("high", 1, False, "high"),
#     ida_hexrays.m_add: MicrocodeOpcode("add", 2, True, "+"),
#     ida_hexrays.m_sub: MicrocodeOpcode("sub", 2, False, "-"),
#     ida_hexrays.m_mul: MicrocodeOpcode("mul", 2, True, "*"),
#     ida_hexrays.m_udiv: MicrocodeOpcode("udiv", 2, False, "UDiv"),
#     ida_hexrays.m_sdiv: MicrocodeOpcode("sdiv", 2, False, "/"),
#     ida_hexrays.m_umod: MicrocodeOpcode("umod", 2, False, "URem"),
#     ida_hexrays.m_smod: MicrocodeOpcode("smod", 2, False, "%"),
#     ida_hexrays.m_or: MicrocodeOpcode("or", 2, True, "|"),
#     ida_hexrays.m_and: MicrocodeOpcode("and", 2, True, "&"),
#     ida_hexrays.m_xor: MicrocodeOpcode("xor", 2, True, "^"),
#     ida_hexrays.m_shl: MicrocodeOpcode("shl", 2, False, "<<"),
#     ida_hexrays.m_shr: MicrocodeOpcode("shr", 2, False, "LShR"),
#     ida_hexrays.m_sar: MicrocodeOpcode("sar", 2, False, ">>"),
#     ida_hexrays.m_cfadd: MicrocodeOpcode("cfadd", 2, True),
#     ida_hexrays.m_ofadd: MicrocodeOpcode("ofadd", 2, True),
#     ida_hexrays.m_cfshl: MicrocodeOpcode("cfshl", 2, False),
#     ida_hexrays.m_cfshr: MicrocodeOpcode("cfshr", 2, False),
#     ida_hexrays.m_sets: MicrocodeOpcode("sets", 2, False),
#     ida_hexrays.m_seto: MicrocodeOpcode("seto", 2, False),
#     ida_hexrays.m_setp: MicrocodeOpcode("setp", 2, False),
#     ida_hexrays.m_setnz: MicrocodeOpcode("setnz", 2, True, "!="),
#     ida_hexrays.m_setz: MicrocodeOpcode("setz", 2, True, "=="),
#     ida_hexrays.m_seta: MicrocodeOpcode("seta", 2, False, ">"),
#     ida_hexrays.m_setae: MicrocodeOpcode("setae", 2, False, ">="),
#     ida_hexrays.m_setb: MicrocodeOpcode("setb", 2, False, "<"),
#     ida_hexrays.m_setbe: MicrocodeOpcode("setbe", 2, False, "<="),
#     ida_hexrays.m_setg: MicrocodeOpcode("setg", 2, False, "UGT"),
#     ida_hexrays.m_setge: MicrocodeOpcode("setge", 2, False, "UGE"),
#     ida_hexrays.m_setl: MicrocodeOpcode("setl", 2, False, "ULT"),
#     ida_hexrays.m_setle: MicrocodeOpcode("setle", 2, False, "ULE"),
#     ida_hexrays.m_jcnd: MicrocodeOpcode("jcnd", 1, False),
#     ida_hexrays.m_jnz: MicrocodeOpcode("jnz", 2, True),
#     ida_hexrays.m_jz: MicrocodeOpcode("jz", 2, True),
#     ida_hexrays.m_jae: MicrocodeOpcode("jae", 2, False),
#     ida_hexrays.m_jb: MicrocodeOpcode("jb", 2, False),
#     ida_hexrays.m_ja: MicrocodeOpcode("ja", 2, False),
#     ida_hexrays.m_jbe: MicrocodeOpcode("jbe", 2, False),
#     ida_hexrays.m_jg: MicrocodeOpcode("jg", 2, False),
#     ida_hexrays.m_jge: MicrocodeOpcode("jge", 2, False),
#     ida_hexrays.m_jl: MicrocodeOpcode("jl", 2, False),
#     ida_hexrays.m_jle: MicrocodeOpcode("jle", 2, False),
#     ida_hexrays.m_jtbl: MicrocodeOpcode("jtbl", 2, False),
#     ida_hexrays.m_ijmp: MicrocodeOpcode("ijmp", 2, False),
#     ida_hexrays.m_goto: MicrocodeOpcode("goto", 1, False),
#     ida_hexrays.m_call: MicrocodeOpcode("call", 2, False),
#     ida_hexrays.m_icall: MicrocodeOpcode("icall", 2, False),
#     ida_hexrays.m_ret: MicrocodeOpcode("ret", 0, False),
#     ida_hexrays.m_push: MicrocodeOpcode("push", 0, False),
#     ida_hexrays.m_pop: MicrocodeOpcode("pop", 0, False),
#     ida_hexrays.m_und: MicrocodeOpcode("und", 0, False),
#     ida_hexrays.m_ext: MicrocodeOpcode("ext", 0, False),
#     ida_hexrays.m_f2i: MicrocodeOpcode("f2i", 2, False),
#     ida_hexrays.m_f2u: MicrocodeOpcode("f2u", 2, False),
#     ida_hexrays.m_i2f: MicrocodeOpcode("i2f", 2, False),
#     ida_hexrays.m_u2f: MicrocodeOpcode("u2f", 2, False),
#     ida_hexrays.m_f2f: MicrocodeOpcode("f2f", 2, False),
#     ida_hexrays.m_fneg: MicrocodeOpcode("fneg", 2, False),
#     ida_hexrays.m_fadd: MicrocodeOpcode("fadd", 2, True),
#     ida_hexrays.m_fsub: MicrocodeOpcode("fsub", 2, False),
#     ida_hexrays.m_fmul: MicrocodeOpcode("fmul", 2, True),
#     ida_hexrays.m_fdiv: MicrocodeOpcode("fdiv", 2, False),
# }


def is_rotate_helper_call(ins: ida_hexrays.minsn_t) -> bool:
    """Return True if *ins* is a call to one of Hex-Rays' synthetic rotate
    helpers (`__ROL*` / `__ROR*`).  Thin wrapper so multiple modules can
    share the same definition without import cycles.
    """

    if (
        ins is None
        or ins.opcode != ida_hexrays.m_call
        or ins.l is None
        or ins.l.t != ida_hexrays.mop_h
    ):
        return False

    helper: str = (ins.l.helper or "").lstrip("!")
    return helper.startswith("__ROL") or helper.startswith("__ROR")


def dup_mop(src: ida_hexrays.mop_t) -> ida_hexrays.mop_t:
    """Return a detached copy of a `ida_hexrays.mop_t`.

    Using `ida_hexrays.mop_t.assign` duplicates the underlying C++ object so the new
    operand is safe to attach to another micro-instruction without
    dangling-pointer risks.
    """
    dst = ida_hexrays.mop_t()
    dst.assign(src)
    return dst


def extract_literal_from_mop(
    mop: ida_hexrays.mop_t | None,
) -> list[tuple[int, int]] | None:
    """Return (value, size_bytes) if *mop* ultimately encodes a numeric constant."""

    if mop is None:
        return None
    if mop.t == ida_hexrays.mop_n:
        return [(mop.nnn.value, mop.size)]

    # ida_hexrays.m_ldc wrapper (ida_hexrays.mop_d → ida_hexrays.minsn_t(ldc …))
    if (
        mop.t == ida_hexrays.mop_d
        and mop.d is not None
        and mop.d.opcode == ida_hexrays.m_ldc
        and mop.d.l is not None
        and mop.d.l.t == ida_hexrays.mop_n
    ):
        return [(mop.d.l.nnn.value, mop.d.l.size)]

    # typed-immediate ida_hexrays.mop_f
    if mop.t == ida_hexrays.mop_f and mop.f is not None:
        args = mop.f.args
        if args:
            rval: list[tuple[int, int]] = []
            for arg in args:
                if arg is not None and arg.t == ida_hexrays.mop_n:
                    rval.append((arg.nnn.value, arg.size))
                else:
                    break
            else:
                # for else here means *every* arg is a literal
                # and there was no early break in the for loop
                # which means all the args are literals
                return rval

    return None


# ============================================================================
# Enums for Type Safety
# ============================================================================


class MicrocodeOpcode(enum.IntEnum):
    """Type-safe enumeration of microcode opcodes."""

    NOP = 0x00
    STX = 0x01  # store register to memory
    LDX = 0x02  # load register from memory
    LDC = 0x03  # load constant
    MOV = 0x04  # move
    NEG = 0x05  # negate
    LNOT = 0x06  # logical not
    BNOT = 0x07  # bitwise not
    XDS = 0x08  # extend (signed)
    XDU = 0x09  # extend (unsigned)
    LOW = 0x0A  # take low part
    HIGH = 0x0B  # take high part
    ADD = 0x0C  # addition
    SUB = 0x0D  # subtraction
    MUL = 0x0E  # multiplication
    UDIV = 0x0F  # unsigned division
    SDIV = 0x10  # signed division
    UMOD = 0x11  # unsigned modulo
    SMOD = 0x12  # signed modulo
    OR = 0x13  # bitwise or
    AND = 0x14  # bitwise and
    XOR = 0x15  # bitwise xor
    SHL = 0x16  # shift logical left
    SHR = 0x17  # shift logical right
    SAR = 0x18  # shift arithmetic right
    CFADD = 0x19  # calculate carry bit of (l+r)
    OFADD = 0x1A  # calculate overflow bit of (l+r)
    CFSHL = 0x1B  # calculate carry bit of (l<<r)
    CFSHR = 0x1C  # calculate carry bit of (l>>r)
    SETS = 0x1D  # set sign flag
    SETO = 0x1E  # set overflow flag
    SETP = 0x1F  # set parity flag
    SETNZ = 0x20  # set not zero
    SETZ = 0x21  # set zero
    SETA = 0x22  # set above
    SETAE = 0x23  # set above or equal
    SETB = 0x24  # set below
    SETBE = 0x25  # set below or equal
    SETG = 0x26  # set greater
    SETGE = 0x27  # set greater or equal
    SETL = 0x28  # set less
    SETLE = 0x29  # set less or equal
    JCND = 0x2A  # conditional jump
    JNZ = 0x2B  # jump if not zero
    JZ = 0x2C  # jump if zero
    JAE = 0x2D  # jump if above or equal
    JB = 0x2E  # jump if below
    JA = 0x2F  # jump if above
    JBE = 0x30  # jump if below or equal
    JG = 0x31  # jump if greater
    JGE = 0x32  # jump if greater or equal
    JL = 0x33  # jump if less
    JLE = 0x34  # jump if less or equal
    # Add more opcodes as needed...

    @property
    def name(self) -> str:
        """Get human-readable name for the opcode."""
        return self._name_.lower()

    @property
    def num_operands(self) -> int:
        """Get expected number of operands for this opcode."""
        return _OPCODE_INFO[self].num_operands

    @property
    def is_commutative(self) -> bool:
        """Check if the operation is commutative."""
        return _OPCODE_INFO[self].is_commutative

    @property
    def symbol(self) -> Optional[str]:
        """Get symbol representation (e.g., '+', '-', etc.)."""
        return _OPCODE_INFO[self].symbol

    @property
    def description(self) -> Optional[str]:
        """Get description of the operation."""
        return _OPCODE_INFO[self].description

    @property
    def is_binary_operation(self) -> bool:
        """Check if this is a binary operation (takes two operands)."""
        return self.num_operands == 2

    @property
    def is_unary_operation(self) -> bool:
        """Check if this is a unary operation (takes one operand)."""
        return self.num_operands == 1

    @property
    def is_jump_operation(self) -> bool:
        """Check if this is a jump/branch operation."""
        return self in (
            MicrocodeOpcode.JCND,
            MicrocodeOpcode.JNZ,
            MicrocodeOpcode.JZ,
            MicrocodeOpcode.JAE,
            MicrocodeOpcode.JB,
            MicrocodeOpcode.JA,
            MicrocodeOpcode.JBE,
            MicrocodeOpcode.JG,
            MicrocodeOpcode.JGE,
            MicrocodeOpcode.JL,
            MicrocodeOpcode.JLE,
        )

    @property
    def is_comparison_operation(self) -> bool:
        """Check if this is a comparison operation."""
        return self in (
            MicrocodeOpcode.SETS,
            MicrocodeOpcode.SETO,
            MicrocodeOpcode.SETP,
            MicrocodeOpcode.SETNZ,
            MicrocodeOpcode.SETZ,
            MicrocodeOpcode.SETA,
            MicrocodeOpcode.SETAE,
            MicrocodeOpcode.SETB,
            MicrocodeOpcode.SETBE,
            MicrocodeOpcode.SETG,
            MicrocodeOpcode.SETGE,
            MicrocodeOpcode.SETL,
            MicrocodeOpcode.SETLE,
        )


@dataclasses.dataclass(frozen=True)
class OpcodeInfo:
    """Information about a microcode opcode."""

    num_operands: int
    is_commutative: bool
    symbol: Optional[str] = None
    description: Optional[str] = None


# Opcode information database with descriptions
_OPCODE_INFO = {
    MicrocodeOpcode.NOP: OpcodeInfo(0, True, None, "No operation"),
    MicrocodeOpcode.STX: OpcodeInfo(2, False, None, "Store register to memory"),
    MicrocodeOpcode.LDX: OpcodeInfo(2, False, None, "Load register from memory"),
    MicrocodeOpcode.LDC: OpcodeInfo(1, False, None, "Load constant"),
    MicrocodeOpcode.MOV: OpcodeInfo(1, False, "", "Move/copy value"),
    MicrocodeOpcode.NEG: OpcodeInfo(1, False, "-", "Negate (arithmetic)"),
    MicrocodeOpcode.LNOT: OpcodeInfo(1, False, "!", "Logical NOT"),
    MicrocodeOpcode.BNOT: OpcodeInfo(1, False, "~", "Bitwise NOT"),
    MicrocodeOpcode.XDS: OpcodeInfo(1, False, "xds", "Extend signed"),
    MicrocodeOpcode.XDU: OpcodeInfo(1, False, "xdu", "Extend unsigned"),
    MicrocodeOpcode.LOW: OpcodeInfo(1, False, "low", "Take low part"),
    MicrocodeOpcode.HIGH: OpcodeInfo(1, False, "high", "Take high part"),
    MicrocodeOpcode.ADD: OpcodeInfo(2, True, "+", "Addition"),
    MicrocodeOpcode.SUB: OpcodeInfo(2, False, "-", "Subtraction"),
    MicrocodeOpcode.MUL: OpcodeInfo(2, True, "*", "Multiplication"),
    MicrocodeOpcode.UDIV: OpcodeInfo(2, False, "UDiv", "Unsigned division"),
    MicrocodeOpcode.SDIV: OpcodeInfo(2, False, "/", "Signed division"),
    MicrocodeOpcode.UMOD: OpcodeInfo(2, False, "URem", "Unsigned modulo"),
    MicrocodeOpcode.SMOD: OpcodeInfo(2, False, "%", "Signed modulo"),
    MicrocodeOpcode.OR: OpcodeInfo(2, True, "|", "Bitwise OR"),
    MicrocodeOpcode.AND: OpcodeInfo(2, True, "&", "Bitwise AND"),
    MicrocodeOpcode.XOR: OpcodeInfo(2, True, "^", "Bitwise XOR"),
    MicrocodeOpcode.SHL: OpcodeInfo(2, False, "<<", "Shift left logical"),
    MicrocodeOpcode.SHR: OpcodeInfo(2, False, "LShR", "Shift right logical"),
    MicrocodeOpcode.SAR: OpcodeInfo(2, False, ">>", "Shift right arithmetic"),
    MicrocodeOpcode.CFADD: OpcodeInfo(
        2, True, None, "Calculate carry flag for addition"
    ),
    MicrocodeOpcode.OFADD: OpcodeInfo(
        2, True, None, "Calculate overflow flag for addition"
    ),
    MicrocodeOpcode.CFSHL: OpcodeInfo(
        2, False, None, "Calculate carry flag for shift left"
    ),
    MicrocodeOpcode.CFSHR: OpcodeInfo(
        2, False, None, "Calculate carry flag for shift right"
    ),
    MicrocodeOpcode.SETS: OpcodeInfo(2, False, None, "Set sign flag"),
    MicrocodeOpcode.SETO: OpcodeInfo(2, False, None, "Set overflow flag"),
    MicrocodeOpcode.SETP: OpcodeInfo(2, False, None, "Set parity flag"),
    MicrocodeOpcode.SETNZ: OpcodeInfo(2, True, "!=", "Set if not zero"),
    MicrocodeOpcode.SETZ: OpcodeInfo(2, True, "==", "Set if zero"),
    MicrocodeOpcode.SETA: OpcodeInfo(2, False, ">", "Set if above (unsigned)"),
    MicrocodeOpcode.SETAE: OpcodeInfo(
        2, False, ">=", "Set if above or equal (unsigned)"
    ),
    MicrocodeOpcode.SETB: OpcodeInfo(2, False, "<", "Set if below (unsigned)"),
    MicrocodeOpcode.SETBE: OpcodeInfo(
        2, False, "<=", "Set if below or equal (unsigned)"
    ),
    MicrocodeOpcode.SETG: OpcodeInfo(2, False, "UGT", "Set if greater (signed)"),
    MicrocodeOpcode.SETGE: OpcodeInfo(
        2, False, "UGE", "Set if greater or equal (signed)"
    ),
    MicrocodeOpcode.SETL: OpcodeInfo(2, False, "ULT", "Set if less (signed)"),
    MicrocodeOpcode.SETLE: OpcodeInfo(2, False, "ULE", "Set if less or equal (signed)"),
    MicrocodeOpcode.JCND: OpcodeInfo(1, False, None, "Conditional jump"),
    MicrocodeOpcode.JNZ: OpcodeInfo(2, True, None, "Jump if not zero"),
    MicrocodeOpcode.JZ: OpcodeInfo(2, True, None, "Jump if zero"),
    MicrocodeOpcode.JAE: OpcodeInfo(2, False, None, "Jump if above or equal"),
    MicrocodeOpcode.JB: OpcodeInfo(2, False, None, "Jump if below"),
    MicrocodeOpcode.JA: OpcodeInfo(2, False, None, "Jump if above"),
    MicrocodeOpcode.JBE: OpcodeInfo(2, False, None, "Jump if below or equal"),
    MicrocodeOpcode.JG: OpcodeInfo(2, False, None, "Jump if greater"),
    MicrocodeOpcode.JGE: OpcodeInfo(2, False, None, "Jump if greater or equal"),
    MicrocodeOpcode.JL: OpcodeInfo(2, False, None, "Jump if less"),
    MicrocodeOpcode.JLE: OpcodeInfo(2, False, None, "Jump if less or equal"),
}


class MaturityLevel(enum.IntEnum):
    """Type-safe enumeration of microcode maturity levels."""

    GENERATED = 0  # ida_hexrays.MMAT_GENERATED: immediately after generation
    PREOPTIMIZED = 1  # ida_hexrays.MMAT_PREOPTIMIZED
    LOCOPT = 2  # ida_hexrays.MMAT_LOCOPT: after local optimizations
    CALLS = 3  # ida_hexrays.MMAT_CALLS: after analysis of function calls
    GLBOPT1 = 4  # ida_hexrays.MMAT_GLBOPT1
    GLBOPT2 = 5  # ida_hexrays.MMAT_GLBOPT2
    GLBOPT3 = 6  # ida_hexrays.MMAT_GLBOPT3
    LVARS = 7  # ida_hexrays.MMAT_LVARS

    @property
    def name(self) -> str:
        """Get human-readable name for the maturity level."""
        names = {
            self.GENERATED: "generated",
            self.PREOPTIMIZED: "preoptimized",
            self.LOCOPT: "locopt",
            self.CALLS: "calls",
            self.GLBOPT1: "glbopt1",
            self.GLBOPT2: "glbopt2",
            self.GLBOPT3: "glbopt3",
            self.LVARS: "lvars",
        }
        return names[self]

    @property
    def description(self) -> str:
        """Get description of what happens at this maturity level."""
        descriptions = {
            self.GENERATED: "Raw microcode generated from assembly",
            self.PREOPTIMIZED: "After dead code elimination and basic propagation",
            self.LOCOPT: "After local optimizations and stack variable naming",
            self.CALLS: "After function call analysis and ABI retrieval",
            self.GLBOPT1: "After global optimizations and block merging",
            self.GLBOPT2: "Further global optimizations",
            self.GLBOPT3: "Final global optimizations",
            self.LVARS: "After SSA analysis and local variable renaming",
        }
        return descriptions[self]


class OperandType(enum.IntEnum):
    """Type-safe enumeration of microcode operand types."""

    EMPTY = 0
    REG = 1
    MEM = 2
    GVAR = 3
    STKVAR = 4
    FNUM = 5
    STR = 6
    INS = 7
    FLIST = 8
    SCATTER = 9
    COMMON = 10
    ADDR = 11
    CPTR = 12
    CASES = 13
    HELPER = 14
    CALLINFO = 15
    PAIR = 16

    @property
    def description(self) -> str:
        """Get human-readable description of the operand type."""
        descriptions = {
            self.EMPTY: "Empty/undefined operand",
            self.REG: "Register operand",
            self.MEM: "Memory reference",
            self.GVAR: "Global variable",
            self.STKVAR: "Stack variable",
            self.FNUM: "Floating-point number",
            self.STR: "String literal",
            self.INS: "Nested instruction",
            self.FLIST: "Function argument list",
            self.SCATTER: "Scattered operand",
            self.COMMON: "Common subexpression",
            self.ADDR: "Address operand",
            self.CPTR: "Code pointer",
            self.CASES: "Switch cases",
            self.HELPER: "Helper function",
            self.CALLINFO: "Function call information",
            self.PAIR: "Register pair",
        }
        return descriptions[self]


# ============================================================================
# Core Dataclasses with Enhanced Readability
# ============================================================================


@dataclasses.dataclass
class MicroOperand:
    """
    Modern, type-safe representation of IDA Hex-Rays ida_hexrays.mop_t.
    Supports structural pattern matching and provides friendly representations.
    """

    _internal_mop: ida_hexrays.mop_t

    def __post_init__(self):
        """Initialize after the internal ida_hexrays.mop_t is set."""
        if not isinstance(self._internal_mop, ida_hexrays.mop_t):
            raise TypeError("Internal operand must be an ida_hexrays.mop_t")

    @property
    def t(self) -> OperandType:
        """Get operand type."""
        return OperandType(self._internal_mop._get_t())

    def dstr(self) -> str:
        """Get destination operand."""
        return self._internal_mop.dstr()

    @property
    def size(self) -> int:
        """Get operand size in bytes."""
        return self._internal_mop.size

    # Readable property aliases for common operand types
    @property
    def operand_type(self) -> OperandType:
        """Get operand type (more readable alias for 't')."""
        return self.t

    @property
    def operand_size(self) -> int:
        """Get operand size in bytes (more readable alias for 'size')."""
        return self.size

    @property
    def is_constant(self) -> bool:
        """Check if operand is a constant."""
        return self._internal_mop.is_constant()

    @property
    def is_register(self) -> bool:
        """Check if operand is a register."""
        return self._internal_mop.is_reg()

    @property
    def is_memory_reference(self) -> bool:
        """Check if operand is a memory reference."""
        return self._internal_mop.is_glbaddr()

    @property
    def is_stack_variable(self) -> bool:
        """Check if operand is a stack variable."""
        return self._internal_mop.is_stkaddr()

    @property
    def is_instruction(self) -> bool:
        """Check if operand is a nested instruction."""
        return self._internal_mop.is_insn()

    @property
    def is_floating_point(self) -> bool:
        """Check if operand is a floating-point number."""
        return self._internal_mop.probably_floating()

    @property
    def is_condition_code(self) -> bool:
        """Check if operand is a condition code (flags)."""
        return self._internal_mop.is_cc()

    def value(self, signed: bool = True) -> Union[int, float, None]:
        """Get operand value if it's a constant."""
        if self.is_constant:
            if self.t == OperandType.FNUM:
                return self._internal_mop._get_fpc().value
            else:
                return (
                    self._internal_mop.signed_value()
                    if signed
                    else self._internal_mop.unsigned_value()
                )
        return None

    @property
    def constant_value(self) -> Union[int, float, None]:
        """Get constant value (more readable alias)."""
        return self.value()

    def get_instruction(self) -> Optional["MicroInstruction"]:
        """Get nested instruction if operand is an instruction."""
        if self.is_instruction:
            internal_insn = self._internal_mop._get_d()
            return MicroInstruction(internal_insn) if internal_insn else None
        return None

    @property
    def nested_instruction(self) -> Optional["MicroInstruction"]:
        """Get nested instruction (more readable alias)."""
        return self.get_instruction()

    def equal_mops(self, other: "MicroOperand|ida_hexrays.mop_t", flags: int) -> bool:
        """Check if operands are equal."""
        if isinstance(other, ida_hexrays.mop_t):
            return self._internal_mop.equal_mops(other, flags)
        else:
            return self._internal_mop.equal_mops(other._internal_mop, flags)

    def __str__(self) -> str:
        """Get string representation of the operand."""
        if self.is_constant:
            val = self.value()
            if isinstance(val, float):
                return f"#{val:.6f}"
            else:
                return f"#{val:#x}"
        elif self.is_register:
            return f"reg_{self.size}"
        elif self.is_stack_variable:
            return f"stk_{self.size}"
        elif self.is_memory_reference:
            return f"mem_{self.size}"
        elif self.is_instruction:
            insn = self.get_instruction()
            return f"({insn})" if insn else "(insn)"
        elif self.is_condition_code:
            return f"flags_{self.size}"
        elif self.is_floating_point:
            return f"fp_{self.size}"
        else:
            return f"op_{self.t.name}_{self.size}"

    def __repr__(self) -> str:
        """Get detailed representation."""
        return (
            f"MicroOperand(type={self.t.name}, size={self.size}, "
            f"const={self.is_constant}, reg={self.is_register}, "
            f"mem={self.is_memory_reference}, str='{self}')"
        )

    # Support for structural pattern matching
    def __match_args__(self):
        """Enable pattern matching on key attributes."""
        return ("t", "size", "is_constant", "is_register", "is_memory_reference")


@dataclasses.dataclass
class MicroInstruction:
    """
    Modern, type-safe representation of IDA Hex-Rays ida_hexrays.minsn_t.
    Supports structural pattern matching and provides friendly representations.
    Enhanced with readable operand property names.
    """

    _internal_minsn: ida_hexrays.minsn_t

    def __post_init__(self):
        """Initialize after the internal ida_hexrays.minsn_t is set."""
        if not isinstance(self._internal_minsn, ida_hexrays.minsn_t):
            raise TypeError("Internal instruction must be an ida_hexrays.minsn_t")

    @property
    def opcode(self) -> MicrocodeOpcode:
        """Get instruction opcode."""
        return MicrocodeOpcode(self._internal_minsn.opcode)

    @property
    def ea(self) -> int:
        """Get instruction address."""
        return self._internal_minsn.ea

    # Original properties (for backward compatibility)
    @property
    def l(self) -> Optional[MicroOperand]:
        """Get left operand (original name)."""
        internal_l = self._internal_minsn.l
        return (
            MicroOperand(internal_l) if internal_l and not internal_l.empty() else None
        )

    @property
    def r(self) -> Optional[MicroOperand]:
        """Get right operand (original name)."""
        internal_r = self._internal_minsn.r
        return (
            MicroOperand(internal_r) if internal_r and not internal_r.empty() else None
        )

    @property
    def d(self) -> Optional[MicroOperand]:
        """Get destination operand (original name)."""
        internal_d = self._internal_minsn.d
        return (
            MicroOperand(internal_d) if internal_d and not internal_d.empty() else None
        )

    # Enhanced readable property names
    @property
    def left_operand(self) -> Optional[MicroOperand]:
        """Get left operand (readable name)."""
        return self.l

    @property
    def right_operand(self) -> Optional[MicroOperand]:
        """Get right operand (readable name)."""
        return self.r

    @property
    def destination_operand(self) -> Optional[MicroOperand]:
        """Get destination operand (readable name)."""
        return self.d

    # Context-aware operand access based on opcode type
    @property
    def source_operand(self) -> Optional[MicroOperand]:
        """Get source operand for unary operations like MOV, NEG, etc."""
        if self.opcode.is_unary_operation:
            return self.l
        return None

    @property
    def target_operand(self) -> Optional[MicroOperand]:
        """Get target operand for unary operations like MOV, NEG, etc."""
        if self.opcode.is_unary_operation:
            return self.d
        return None

    @property
    def first_operand(self) -> Optional[MicroOperand]:
        """Get first operand (for binary operations)."""
        if self.opcode.is_binary_operation:
            return self.l
        return None

    @property
    def second_operand(self) -> Optional[MicroOperand]:
        """Get second operand (for binary operations)."""
        if self.opcode.is_binary_operation:
            return self.r
        return None

    @property
    def result_operand(self) -> Optional[MicroOperand]:
        """Get result operand (for binary operations)."""
        if self.opcode.is_binary_operation:
            return self.d
        return None

    # Specialized properties for different instruction types
    @property
    def condition_operand(self) -> Optional[MicroOperand]:
        """Get condition operand for jump operations."""
        if self.opcode.is_jump_operation:
            return self.l
        return None

    @property
    def jump_target(self) -> Optional[MicroOperand]:
        """Get jump target for jump operations."""
        if self.opcode.is_jump_operation:
            return self.r
        return None

    @property
    def comparison_left(self) -> Optional[MicroOperand]:
        """Get left side of comparison for comparison operations."""
        if self.opcode.is_comparison_operation:
            return self.l
        return None

    @property
    def comparison_right(self) -> Optional[MicroOperand]:
        """Get right side of comparison for comparison operations."""
        if self.opcode.is_comparison_operation:
            return self.r
        return None

    @property
    def comparison_result(self) -> Optional[MicroOperand]:
        """Get result of comparison for comparison operations."""
        if self.opcode.is_comparison_operation:
            return self.d
        return None

    # Instruction properties
    @property
    def is_call(self) -> bool:
        """Check if instruction is a call."""
        return (
            self._internal_minsn.is_unknown_call()
            or self._internal_minsn.contains_call()
        )

    @property
    def is_jump(self) -> bool:
        """Check if instruction is a jump."""
        return self.opcode.is_jump_operation

    @property
    def is_comparison(self) -> bool:
        """Check if instruction is a comparison."""
        return self.opcode.is_comparison_operation

    @property
    def is_arithmetic(self) -> bool:
        """Check if instruction is an arithmetic operation."""
        return self.opcode in (
            MicrocodeOpcode.ADD,
            MicrocodeOpcode.SUB,
            MicrocodeOpcode.MUL,
            MicrocodeOpcode.UDIV,
            MicrocodeOpcode.SDIV,
            MicrocodeOpcode.UMOD,
            MicrocodeOpcode.SMOD,
        )

    @property
    def is_logical(self) -> bool:
        """Check if instruction is a logical operation."""
        return self.opcode in (
            MicrocodeOpcode.OR,
            MicrocodeOpcode.AND,
            MicrocodeOpcode.XOR,
            MicrocodeOpcode.LNOT,
            MicrocodeOpcode.BNOT,
        )

    @property
    def is_shift(self) -> bool:
        """Check if instruction is a shift operation."""
        return self.opcode in (
            MicrocodeOpcode.SHL,
            MicrocodeOpcode.SHR,
            MicrocodeOpcode.SAR,
        )

    @property
    def has_side_effects(self) -> bool:
        """Check if instruction has side effects."""
        return self._internal_minsn.has_side_effects()

    def get_all_operands(self) -> Tuple[Optional[MicroOperand], ...]:
        """Get all non-None operands in order."""
        operands = []
        if self.l:
            operands.append(self.l)
        if self.r:
            operands.append(self.r)
        if self.d:
            operands.append(self.d)
        return tuple(operands)

    def __str__(self) -> str:
        """Get string representation of the instruction."""
        op_name = self.opcode.name
        op_sym = self.opcode.symbol

        # Use readable operand names based on instruction type
        if self.opcode.is_unary_operation:
            # Unary operations: source -> target
            if self.source_operand and self.target_operand:
                if op_sym:
                    return f"{self.target_operand} = {op_sym}{self.source_operand}"
                else:
                    return f"{self.target_operand} = {op_name}({self.source_operand})"
            elif self.source_operand:
                return f"{op_name} {self.source_operand}"

        elif self.opcode.is_binary_operation:
            # Binary operations: first OP second -> result
            if self.first_operand and self.second_operand and self.result_operand:
                if op_sym:
                    return f"{self.result_operand} = {self.first_operand} {op_sym} {self.second_operand}"
                else:
                    return f"{self.result_operand} = {op_name}({self.first_operand}, {self.second_operand})"
            elif self.first_operand and self.second_operand:
                if op_sym:
                    return f"{self.first_operand} {op_sym} {self.second_operand}"
                else:
                    return f"{op_name}({self.first_operand}, {self.second_operand})"

        elif self.opcode.is_jump_operation:
            # Jump operations: condition ? target
            if self.condition_operand and self.jump_target:
                return f"if {self.condition_operand} jump to {self.jump_target}"
            elif self.condition_operand:
                return f"jump if {self.condition_operand}"

        elif self.opcode.is_comparison_operation:
            # Comparison operations: left OP right -> result
            if (
                self.comparison_left
                and self.comparison_right
                and self.comparison_result
            ):
                if op_sym:
                    return f"{self.comparison_result} = {self.comparison_left} {op_sym} {self.comparison_right}"
                else:
                    return f"{self.comparison_result} = {op_name}({self.comparison_left}, {self.comparison_right})"

        # Fallback to generic representation
        operands = []
        if self.l:
            operands.append(str(self.l))
        if self.r:
            operands.append(str(self.r))
        if self.d and self.opcode not in (
            MicrocodeOpcode.MOV,
            MicrocodeOpcode.NEG,
            MicrocodeOpcode.LNOT,
            MicrocodeOpcode.BNOT,
        ):
            operands.append(str(self.d))

        if operands:
            return f"{op_name} {', '.join(operands)}"
        else:
            return op_name

    def __repr__(self) -> str:
        """Get detailed representation."""
        return (
            f"MicroInstruction(opcode={self.opcode.name}, ea={self.ea:#x}, "
            f"left={self.left_operand}, right={self.right_operand}, "
            f"destination={self.destination_operand})"
        )

    # Support for structural pattern matching
    def __match_args__(self):
        """Enable pattern matching on key attributes."""
        return ("opcode", "ea", "left_operand", "right_operand", "destination_operand")


# ============================================================================
# Factory Functions and Utilities
# ============================================================================


def create_operand_from_internal(internal_mop: ida_hexrays.mop_t) -> MicroOperand:
    """Create a MicroOperand from an internal ida_hexrays.mop_t."""
    return MicroOperand(internal_mop)


def create_instruction_from_internal(
    internal_minsn: ida_hexrays.minsn_t,
) -> MicroInstruction:
    """Create a MicroInstruction from an internal ida_hexrays.minsn_t."""
    return MicroInstruction(internal_minsn)


def create_constant_operand(value: Union[int, float], size: int = 4) -> MicroOperand:
    """Create a constant operand."""
    mop = ida_hexrays.mop_t()
    if isinstance(value, float):
        # For floating point, we'd need to handle it differently
        # This is a simplified version
        mop.make_number(int(value), size)
    else:
        mop.make_number(value, size)
    return MicroOperand(mop)


def create_register_operand(reg: int, size: int = 4) -> MicroOperand:
    """Create a register operand."""
    mop = ida_hexrays.mop_t()
    mop.make_reg(reg)
    return MicroOperand(mop)


def create_instruction(
    opcode: MicrocodeOpcode,
    ea: int = 0,
    left: Optional[MicroOperand] = None,
    right: Optional[MicroOperand] = None,
    destination: Optional[MicroOperand] = None,
) -> MicroInstruction:
    """Create a microinstruction with the given operands using readable names."""
    minsn = ida_hexrays.minsn_t(ea)
    minsn.opcode = opcode.value

    if left:
        minsn.l = left._internal_mop
    if right:
        minsn.r = right._internal_mop
    if destination:
        minsn.d = destination._internal_mop

    return MicroInstruction(minsn)


# ============================================================================
# Enhanced Pattern Matching Examples
# ============================================================================


def analyze_instruction_enhanced(insn: MicroInstruction) -> str:
    """
    Enhanced example function showing how to use structural pattern matching
    with readable property names.
    """
    match insn:
        # Arithmetic operations with readable names
        case MicroInstruction(
            opcode=MicrocodeOpcode.ADD,
            first_operand=first,
            second_operand=second,
            result_operand=result,
        ):
            return f"Addition: {result} = {first} + {second}"

        case MicroInstruction(
            opcode=MicrocodeOpcode.SUB,
            first_operand=first,
            second_operand=second,
            result_operand=result,
        ):
            return f"Subtraction: {result} = {first} - {second}"

        # Unary operations with readable names
        case MicroInstruction(
            opcode=MicrocodeOpcode.MOV, source_operand=source, target_operand=target
        ):
            return f"Move: {target} = {source}"

        case MicroInstruction(
            opcode=MicrocodeOpcode.NEG, source_operand=source, target_operand=target
        ):
            return f"Negate: {target} = -{source}"

        # Jump operations with readable names
        case MicroInstruction(
            opcode=MicrocodeOpcode.JZ, condition_operand=condition, jump_target=target
        ):
            return f"Jump if zero: if {condition} == 0 jump to {target}"

        # Comparison operations with readable names
        case MicroInstruction(
            opcode=MicrocodeOpcode.SETZ,
            comparison_left=left,
            comparison_right=right,
            comparison_result=result,
        ):
            return f"Set zero: {result} = ({left} == {right})"

        # Call operations
        case MicroInstruction(is_call=True):
            return "Function call instruction"

        # Generic patterns
        case MicroInstruction(is_arithmetic=True, first_operand=op) if (
            op and op.is_constant
        ):
            return f"Arithmetic with constant: {insn.opcode.name} with constant {op.value()}"

        case MicroInstruction(is_jump=True):
            return "Jump instruction"

        case _:
            return f"Unknown instruction: {insn}"


def analyze_operand_enhanced(op: MicroOperand) -> str:
    """
    Enhanced example function showing how to use structural pattern matching
    with readable property names.
    """
    match op:
        case MicroOperand(is_constant=True, operand_size=size):
            val = op.constant_value
            return f"Constant {size}-byte value: {val}"

        case MicroOperand(is_register=True, operand_size=size):
            return f"Register operand, size: {size} bytes"

        case MicroOperand(is_memory_reference=True, operand_size=size):
            return f"Memory reference, size: {size} bytes"

        case MicroOperand(is_stack_variable=True, operand_size=size):
            return f"Stack variable, size: {size} bytes"

        case MicroOperand(is_instruction=True):
            nested_insn = op.nested_instruction
            return f"Nested instruction: {nested_insn}"

        case MicroOperand(is_condition_code=True, operand_size=size):
            return f"Condition code (flags), size: {size} bytes"

        case MicroOperand(is_floating_point=True, operand_size=size):
            return f"Floating-point operand, size: {size} bytes"

        case _:
            return f"Unknown operand type: {op.operand_type.name}"


# ============================================================================
# Performance Optimization
# ============================================================================


@dataclasses.dataclass(frozen=True, slots=True)
class CachedOpcodeInfo:
    """Frozen dataclass for cached opcode information to improve performance."""

    num_operands: int
    is_commutative: bool
    symbol: Optional[str] = None
    description: Optional[str] = None


# Cache for frequently accessed opcode information
_OPCODE_CACHE: dict[MicrocodeOpcode, CachedOpcodeInfo] = {
    opcode: CachedOpcodeInfo(
        info.num_operands, info.is_commutative, info.symbol, info.description
    )
    for opcode, info in _OPCODE_INFO.items()
}


def get_opcode_info(opcode: MicrocodeOpcode) -> CachedOpcodeInfo:
    """Get cached opcode information for better performance."""
    return _OPCODE_CACHE.get(opcode, CachedOpcodeInfo(0, False))


# ============================================================================
# Example Usage
# ============================================================================

if __name__ == "__main__":
    # Example usage of the enhanced microcode representation

    # Create some operands
    const_op = create_constant_operand(42, 4)
    reg_op = create_register_operand(1, 4)  # Assuming register 1 exists

    # Create an instruction using readable parameter names
    add_insn = create_instruction(
        MicrocodeOpcode.ADD, ea=0x1000, left=const_op, right=reg_op, destination=reg_op
    )

    # Use enhanced pattern matching to analyze the instruction
    result = analyze_instruction_enhanced(add_insn)
    print(f"Enhanced analysis result: {result}")

    # Analyze operands with enhanced function
    print(f"Constant operand analysis: {analyze_operand_enhanced(const_op)}")
    print(f"Register operand analysis: {analyze_operand_enhanced(reg_op)}")

    # Demonstrate enhanced string representations
    print(f"Instruction: {add_insn}")
    print(f"Instruction repr: {repr(add_insn)}")
    print(f"Constant operand: {const_op}")
    print(f"Register operand: {reg_op}")

    # Demonstrate readable property access
    print(f"Instruction opcode: {add_insn.opcode.name}")
    print(f"Is arithmetic: {add_insn.is_arithmetic}")
    print(f"First operand: {add_insn.first_operand}")
    print(f"Second operand: {add_insn.second_operand}")
    print(f"Result operand: {add_insn.result_operand}")

    # Demonstrate opcode properties
    print(
        f"ADD opcode info: operands={MicrocodeOpcode.ADD.num_operands}, "
        f"commutative={MicrocodeOpcode.ADD.is_commutative}, "
        f"symbol='{MicrocodeOpcode.ADD.symbol}', "
        f"description='{MicrocodeOpcode.ADD.description}'"
    )

    # Example of different instruction types
    print("\n--- Different Instruction Types ---")

    # Move instruction
    mov_insn = create_instruction(
        MicrocodeOpcode.MOV, ea=0x1004, left=const_op, right=reg_op, destination=reg_op
    )
    print(f"Move instruction: {mov_insn}")
    print(f"Source: {mov_insn.source_operand}, Target: {mov_insn.target_operand}")

    # Comparison instruction
    cmp_insn = create_instruction(
        MicrocodeOpcode.SETZ, ea=0x1008, left=const_op, right=reg_op, destination=reg_op
    )
    print(f"Comparison instruction: {cmp_insn}")
    print(
        f"Comparison left: {cmp_insn.comparison_left}, "
        f"Comparison right: {cmp_insn.comparison_right}, "
        f"Comparison result: {cmp_insn.comparison_result}"
    )
