import abc
import collections
import contextlib
import dataclasses
import logging
import threading
import time
import typing
import weakref

import ida_hexrays
from ida_hexrays import *
from ida_hexrays import (
    EQ_IGNSIZE,
    m_ldx,
    m_stx,
    m_xds,
    m_xdu,
    mop_a,
    mop_b,
    mop_c,
    mop_d,
    mop_f,
    mop_fn,
    mop_h,
    mop_l,
    mop_n,
    mop_p,
    mop_r,
    mop_S,
    mop_sc,
    mop_str,
    mop_v,
    mop_z,
)

logger = logging.getLogger("D810")

OPCODES_INFO = {
    m_nop: {"name": "nop", "nb_operands": 0, "is_commutative": True},
    m_stx: {"name": "stx", "nb_operands": 2, "is_commutative": False},
    m_ldx: {"name": "ldx", "nb_operands": 2, "is_commutative": False},
    m_ldc: {"name": "ldc", "nb_operands": 1, "is_commutative": False},
    m_mov: {"name": "mov", "nb_operands": 1, "is_commutative": False, "symbol": ""},
    m_neg: {"name": "neg", "nb_operands": 1, "is_commutative": False, "symbol": "-"},
    m_lnot: {"name": "lnot", "nb_operands": 1, "is_commutative": False, "symbol": "!"},
    m_bnot: {"name": "bnot", "nb_operands": 1, "is_commutative": False, "symbol": "~"},
    m_xds: {"name": "xds", "nb_operands": 1, "is_commutative": False, "symbol": "xds"},
    m_xdu: {"name": "xdu", "nb_operands": 1, "is_commutative": False, "symbol": "xdu"},
    m_low: {"name": "low", "nb_operands": 1, "is_commutative": False, "symbol": "low"},
    m_high: {
        "name": "high",
        "nb_operands": 1,
        "is_commutative": False,
        "symbol": "high",
    },
    m_add: {"name": "add", "nb_operands": 2, "is_commutative": True, "symbol": "+"},
    m_sub: {"name": "sub", "nb_operands": 2, "is_commutative": False, "symbol": "-"},
    m_mul: {"name": "mul", "nb_operands": 2, "is_commutative": True, "symbol": "*"},
    m_udiv: {
        "name": "udiv",
        "nb_operands": 2,
        "is_commutative": False,
        "symbol": "UDiv",
    },
    m_sdiv: {"name": "sdiv", "nb_operands": 2, "is_commutative": False, "symbol": "/"},
    m_umod: {
        "name": "umod",
        "nb_operands": 2,
        "is_commutative": False,
        "symbol": "URem",
    },
    m_smod: {"name": "smod", "nb_operands": 2, "is_commutative": False, "symbol": "%"},
    m_or: {"name": "or", "nb_operands": 2, "is_commutative": True, "symbol": "|"},
    m_and: {"name": "and", "nb_operands": 2, "is_commutative": True, "symbol": "&"},
    m_xor: {"name": "xor", "nb_operands": 2, "is_commutative": True, "symbol": "^"},
    m_shl: {"name": "shl", "nb_operands": 2, "is_commutative": False, "symbol": "<<"},
    m_shr: {"name": "shr", "nb_operands": 2, "is_commutative": False, "symbol": "LShR"},
    m_sar: {"name": "sar", "nb_operands": 2, "is_commutative": False, "symbol": ">>"},
    m_cfadd: {"name": "cfadd", "nb_operands": 2, "is_commutative": True},
    m_ofadd: {"name": "ofadd", "nb_operands": 2, "is_commutative": True},
    m_cfshl: {"name": "cfshl", "nb_operands": 2, "is_commutative": False},
    m_cfshr: {"name": "cfshr", "nb_operands": 2, "is_commutative": False},
    m_sets: {"name": "sets", "nb_operands": 2, "is_commutative": False},
    m_seto: {"name": "seto", "nb_operands": 2, "is_commutative": False},
    m_setp: {"name": "setp", "nb_operands": 2, "is_commutative": False},
    m_setnz: {
        "name": "setnz",
        "nb_operands": 2,
        "is_commutative": True,
        "symbol": "!=",
    },
    m_setz: {"name": "setz", "nb_operands": 2, "is_commutative": True, "symbol": "=="},
    m_seta: {"name": "seta", "nb_operands": 2, "is_commutative": False, "symbol": ">"},
    m_setae: {
        "name": "setae",
        "nb_operands": 2,
        "is_commutative": False,
        "symbol": ">=",
    },
    m_setb: {"name": "setb", "nb_operands": 2, "is_commutative": False, "symbol": "<"},
    m_setbe: {
        "name": "setbe",
        "nb_operands": 2,
        "is_commutative": False,
        "symbol": "<=",
    },
    m_setg: {
        "name": "setg",
        "nb_operands": 2,
        "is_commutative": False,
        "symbol": "UGT",
    },
    m_setge: {
        "name": "setge",
        "nb_operands": 2,
        "is_commutative": False,
        "symbol": "UGE",
    },
    m_setl: {
        "name": "setl",
        "nb_operands": 2,
        "is_commutative": False,
        "symbol": "ULT",
    },
    m_setle: {
        "name": "setle",
        "nb_operands": 2,
        "is_commutative": False,
        "symbol": "ULE",
    },
    m_jcnd: {"name": "jcnd", "nb_operands": 1, "is_commutative": False},
    m_jnz: {"name": "jnz", "nb_operands": 2, "is_commutative": True},
    m_jz: {"name": "jz", "nb_operands": 2, "is_commutative": True},
    m_jae: {"name": "jae", "nb_operands": 2, "is_commutative": False},
    m_jb: {"name": "jb", "nb_operands": 2, "is_commutative": False},
    m_ja: {"name": "ja", "nb_operands": 2, "is_commutative": False},
    m_jbe: {"name": "jbe", "nb_operands": 2, "is_commutative": False},
    m_jg: {"name": "jg", "nb_operands": 2, "is_commutative": False},
    m_jge: {"name": "jge", "nb_operands": 2, "is_commutative": False},
    m_jl: {"name": "jl", "nb_operands": 2, "is_commutative": False},
    m_jle: {"name": "jle", "nb_operands": 2, "is_commutative": False},
    m_jtbl: {"name": "jtbl", "nb_operands": 2, "is_commutative": False},
    m_ijmp: {"name": "ijmp", "nb_operands": 2, "is_commutative": False},
    m_goto: {"name": "goto", "nb_operands": 1, "is_commutative": False},
    m_call: {"name": "call", "nb_operands": 2, "is_commutative": False},
    m_icall: {"name": "icall", "nb_operands": 2, "is_commutative": False},
    m_ret: {"name": "ret", "nb_operands": 0, "is_commutative": False},
    m_push: {"name": "push", "nb_operands": 0, "is_commutative": False},
    m_pop: {"name": "pop", "nb_operands": 0, "is_commutative": False},
    m_und: {"name": "und", "nb_operands": 0, "is_commutative": False},
    m_ext: {"name": "ext", "nb_operands": 0, "is_commutative": False},
    m_f2i: {"name": "f2i", "nb_operands": 2, "is_commutative": False},
    m_f2u: {"name": "f2u", "nb_operands": 2, "is_commutative": False},
    m_i2f: {"name": "i2f", "nb_operands": 2, "is_commutative": False},
    m_u2f: {"name": "u2f", "nb_operands": 2, "is_commutative": False},
    m_f2f: {"name": "f2f", "nb_operands": 2, "is_commutative": False},
    m_fneg: {"name": "fneg", "nb_operands": 2, "is_commutative": False},
    m_fadd: {"name": "fadd", "nb_operands": 2, "is_commutative": True},
    m_fsub: {"name": "fsub", "nb_operands": 2, "is_commutative": False},
    m_fmul: {"name": "fmul", "nb_operands": 2, "is_commutative": True},
    m_fdiv: {"name": "fdiv", "nb_operands": 2, "is_commutative": False},
}


MATURITY_TO_STRING_DICT = {
    MMAT_ZERO: "MMAT_ZERO",
    MMAT_GENERATED: "MMAT_GENERATED",
    MMAT_PREOPTIMIZED: "MMAT_PREOPTIMIZED",
    MMAT_LOCOPT: "MMAT_LOCOPT",
    MMAT_CALLS: "MMAT_CALLS",
    MMAT_GLBOPT1: "MMAT_GLBOPT1",
    MMAT_GLBOPT2: "MMAT_GLBOPT2",
    MMAT_GLBOPT3: "MMAT_GLBOPT3",
    MMAT_LVARS: "MMAT_LVARS",
}
STRING_TO_MATURITY_DICT = {v: k for k, v in MATURITY_TO_STRING_DICT.items()}

MOP_TYPE_TO_STRING_DICT = {
    mop_z: "mop_z",
    mop_r: "mop_r",
    mop_n: "mop_n",
    mop_str: "mop_str",
    mop_d: "mop_d",
    mop_S: "mop_S",
    mop_v: "mop_v",
    mop_b: "mop_b",
    mop_f: "mop_f",
    mop_l: "mop_l",
    mop_a: "mop_a",
    mop_h: "mop_h",
    mop_c: "mop_c",
    mop_fn: "mop_fn",
    mop_p: "mop_p",
    mop_sc: "mop_sc",
}

Z3_SPECIAL_OPERANDS = ["UDiv", "URem", "LShR", "UGT", "UGE", "ULT", "ULE"]

BOOLEAN_OPCODES = [m_lnot, m_bnot, m_or, m_and, m_xor]
ARITHMETICAL_OPCODES = [m_neg, m_add, m_sub, m_mul, m_udiv, m_sdiv, m_umod, m_smod]
BIT_OPERATIONS_OPCODES = [m_shl, m_shr, m_sar, m_mov, m_xds, m_xdu, m_low, m_high]
CHECK_OPCODES = [
    m_sets,
    m_seto,
    m_setp,
    m_setnz,
    m_setz,
    m_seta,
    m_setae,
    m_setb,
    m_setbe,
    m_setg,
    m_setge,
    m_setl,
    m_setle,
]

MBA_RELATED_OPCODES = (
    BOOLEAN_OPCODES + ARITHMETICAL_OPCODES + BIT_OPERATIONS_OPCODES + CHECK_OPCODES
)

CONDITIONAL_JUMP_OPCODES = [
    m_jcnd,
    m_jnz,
    m_jz,
    m_jae,
    m_ja,
    m_jb,
    m_jbe,
    m_jg,
    m_jge,
    m_jl,
    m_jle,
    m_jtbl,
]
UNCONDITIONAL_JUMP_OPCODES = [m_goto, m_ijmp]
CONTROL_FLOW_OPCODES = CONDITIONAL_JUMP_OPCODES + UNCONDITIONAL_JUMP_OPCODES

MINSN_TO_AST_FORBIDDEN_OPCODES = CONTROL_FLOW_OPCODES + [
    m_ret,
    m_nop,
    m_stx,
    m_push,
    m_pop,
    m_und,
    m_ext,
]

SUB_TABLE = {
    1: 0x100,
    2: 0x10000,
    4: 0x100000000,
    8: 0x10000000000000000,
    16: 0x100000000000000000000000000000000,
}
# The AND_TABLE is an all-ones mask (equivalent to -1 in two's complement).
# XORing with an all-ones mask is the same as a bitwise NOT (~).
AND_TABLE = {
    1: 0xFF,
    2: 0xFFFF,
    4: 0xFFFFFFFF,
    8: 0xFFFFFFFFFFFFFFFF,
    16: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
}
MSB_TABLE = {
    1: 0x80,
    2: 0x8000,
    4: 0x80000000,
    8: 0x8000000000000000,
    16: 0x80000000000000000000000000000000,
}


# Hex-Rays mop equality checking
def equal_bnot_cst(lo: mop_t, ro: mop_t, mop_size=None) -> bool:
    if (lo.t != mop_n) or (ro.t != mop_n):
        return False
    if lo.size != ro.size:
        return False
    if mop_size is None:
        mop_size = lo.size
    return lo.nnn.value ^ ro.nnn.value == AND_TABLE[mop_size]


def equal_bnot_mop(lo: mop_t, ro: mop_t, test_two_sides=True) -> bool:
    if lo.t == mop_n:
        return equal_bnot_cst(lo, ro)

    # We first check for a bnot operand
    if (lo.t == mop_d) and lo.d.opcode == m_bnot:
        if equal_mops_ignore_size(lo.d.l, ro):
            return True

    # Otherwise Hexrays may have optimized using ~(-x) = x - 1
    if (lo.t == mop_d) and lo.d.opcode == m_neg:
        if (ro.t == mop_d) and ro.d.opcode == m_sub:
            if ro.d.r.t == mop_n and ro.d.r.nnn.value == 1:
                if equal_mops_ignore_size(ro.d.l, lo.d.l):
                    return True

    if (lo.t == mop_d) and lo.d.opcode == m_xds:
        if equal_bnot_mop(lo.d.l, ro):
            return True

    if test_two_sides:
        return equal_bnot_mop(ro, lo, test_two_sides=False)
    return False


def equal_ignore_msb_cst(lo: mop_t, ro: mop_t) -> bool:
    if (lo.t != mop_n) or (ro.t != mop_n):
        return False
    if lo.size != ro.size:
        return False
    mask = AND_TABLE[lo.size] ^ MSB_TABLE[lo.size]
    return lo.nnn.value & mask == ro.nnn.value & mask


def equal_mops_bypass_xdu(lo: mop_t, ro: mop_t) -> bool:
    if (lo is None) or (ro is None):
        return False
    if (lo.t == mop_d) and (lo.d.opcode == m_xdu):
        return equal_mops_bypass_xdu(lo.d.l, ro)
    if (ro.t == mop_d) and (ro.d.opcode == m_xdu):
        return equal_mops_bypass_xdu(lo, ro.d.l)
    return equal_mops_ignore_size(lo, ro)


def equal_mops_ignore_size(lo: mop_t, ro: mop_t) -> bool:
    if (lo is None) or (ro is None):
        return False
    if lo.t != ro.t:
        return False
    if lo.t == mop_z:
        return True
    elif lo.t == mop_fn:
        return lo.fpc == ro.fpc
    elif lo.t == mop_n:
        return lo.nnn.value == ro.nnn.value
    elif lo.t == mop_S:
        if lo.s == ro.s:
            return True
        if lo.s.off == ro.s.off:
            # Is it right?
            return True
        return False
    elif lo.t == mop_v:
        return lo.g == ro.g
    elif lo.t == mop_d:
        return lo.d.equal_insns(ro.d, EQ_IGNSIZE)
        # return lo.d.equal_insns(ro.d, EQ_IGNSIZE | EQ_IGNCODE)
    elif lo.t == mop_b:
        return lo.b == ro.b
    elif lo.t == mop_r:
        return lo.r == ro.r
    elif lo.t == mop_f:
        return False
    elif lo.t == mop_l:
        return lo.l == ro.l
    elif lo.t == mop_a:
        if lo.a.insize != ro.a.insize:
            return False
        if lo.a.outsize != ro.a.outsize:
            return False
        return equal_mops_ignore_size(lo.a, ro.a)
    elif lo.t == mop_h:
        return ro.helper == lo.helper
    elif lo.t == mop_str:
        return ro.cstr == lo.cstr
    elif lo.t == mop_c:
        return ro.c == lo.c
    elif lo.t == mop_p:
        return equal_mops_ignore_size(
            lo.pair.lop, ro.pair.lop
        ) and equal_mops_ignore_size(lo.pair.hop, ro.pair.hop)
    elif lo.t == mop_sc:
        return False
    else:
        return False


def is_check_mop(lo: mop_t) -> bool:
    if lo.t != mop_d:
        return False
    if lo.d.opcode in CHECK_OPCODES:
        return True
    if lo.d.opcode in [m_xds, m_xdu]:
        return is_check_mop(lo.d.l)
    return False


def extract_num_mop(ins: minsn_t) -> tuple[mop_t, mop_t]:
    num_mop = typing.cast(mop_t, None)
    other_mop = typing.cast(mop_t, None)

    if ins.l.t == mop_n:
        num_mop = ins.l
        other_mop = ins.r
    if ins.r.t == mop_n:
        num_mop = ins.r
        other_mop = ins.l
    return (num_mop, other_mop)


def check_ins_mop_size_are_ok(ins: minsn_t) -> bool:
    """
    This function can be used to check if a created instruction has consistent mop size
    Use it to avoid Hex-Rays decompilation errors when replacing instructions

    :param ins:
    :return:
    """
    ins_dest_size = ins.d.size
    if ins.opcode in [m_stx, m_ldx]:
        if ins.r.t == mop_d:
            if not check_ins_mop_size_are_ok(ins.r.d):
                return False
        return True

    if ins.opcode in [m_xdu, m_xds, m_low, m_high]:
        if (ins.l.t == mop_d) and (not check_ins_mop_size_are_ok(ins.l.d)):
            return False
        return True

    if ins.opcode in [m_sar, m_shr, m_shl]:
        if ins.l.size != ins_dest_size:
            return False
        if (ins.l.t == mop_d) and (not check_ins_mop_size_are_ok(ins.l.d)):
            return False
        if (ins.r.t == mop_d) and (not check_ins_mop_size_are_ok(ins.r.d)):
            return False
        return True

    if ins.opcode in CHECK_OPCODES:
        if (ins.l.t == mop_d) and (not check_ins_mop_size_are_ok(ins.l.d)):
            return False
        if (ins.r.t == mop_d) and (not check_ins_mop_size_are_ok(ins.r.d)):
            return False
        return True

    if ins.l is not None:
        if ins.l.size != ins_dest_size:
            return False
        if ins.l.t == mop_d and (not check_ins_mop_size_are_ok(ins.l.d)):
            return False

    if ins.r is not None and ins.r.t != mop_z:
        if ins.r.size != ins_dest_size:
            return False
        if ins.r.t == mop_d and (not check_ins_mop_size_are_ok(ins.r.d)):
            return False
    return True


def check_mop_is_result_of(lo: mop_t, mc) -> bool:
    if lo.t != mop_d:
        return False
    return lo.d.opcode == mc


def extract_by_opcode_type(ins: minsn_t, mc) -> tuple[mop_t, mop_t]:
    if check_mop_is_result_of(ins.l, mc):
        return (ins.l, ins.r)
    if check_mop_is_result_of(ins.r, mc):
        return (ins.r, ins.l)
    return (typing.cast(mop_t, None), typing.cast(mop_t, None))


def check_ins_have_same_operands(
    ins1: minsn_t, ins2: minsn_t, ignore_order=False
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


def get_mop_index(searched_mop: mop_t, mop_list) -> int:
    for i, test_mop in enumerate(mop_list):
        if equal_mops_ignore_size(searched_mop, test_mop):
            return i
    return -1


def append_mop_if_not_in_list(mop: mop_t, mop_list) -> bool:
    mop_index = get_mop_index(mop, mop_list)
    if mop_index == -1:
        mop_list.append(mop)
        return True
    return False


def get_blk_index(searched_blk: mblock_t, blk_list: List[mblock_t]) -> int:
    blk_serial_list = [blk.serial for blk in blk_list]
    try:
        return blk_serial_list.index(searched_blk.serial)
    except ValueError:
        return -1


_mmat_strs = {
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


class MicrocodeHelper:
    """Helper class for working with IDA Hex-Rays microcode operations and maturity levels."""

    # Static class variables
    MMAT: List[Tuple[int, str]] = sorted(
        [
            (getattr(ida_hexrays, x), x)
            for x in filter(lambda y: y.startswith("MMAT_"), dir(ida_hexrays))
        ]
    )[1:]
    MOPT: List[Tuple[int, str]] = [
        (getattr(ida_hexrays, x), x)
        for x in filter(lambda y: y.startswith("mop_"), dir(ida_hexrays))
    ]
    MCODE: List[Tuple[int, str]] = sorted(
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
    def get_mmat_levels(cls) -> List[int]:
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


@dataclasses.dataclass
class MicrocodeOpcode:
    name: str
    nb_operands: int
    is_commutative: bool
    symbol: typing.Optional[str] = None

    @property
    def hexrays_code(self) -> int:
        return getattr(ida_hexrays, f"m_{self.name}")


@dataclasses.dataclass(repr=False)
class MicrocodeInstruction:
    minsn: ida_hexrays.minsn_t
    opcode: MicrocodeOpcode

    @classmethod
    def from_minsn(cls, minsn: ida_hexrays.minsn_t) -> "MicrocodeInstruction":
        return cls(minsn, OPCODES_LOOKUP[minsn.opcode])

    def __repr__(self) -> str:
        return self.repr(self.minsn)

    __str__ = __repr__

    @classmethod
    def repr(cls, minsn: ida_hexrays.minsn_t) -> str:
        opcode = OPCODES_LOOKUP[minsn.opcode]
        if not opcode:
            return "???"

        if opcode.nb_operands == 0:
            return f"m_{opcode.name}"
        elif opcode.nb_operands == 1:
            return f"m_{opcode.name}(%s,%s)" % (
                MicrocodeHelper.get_mopt_name(minsn.l.t),
                MicrocodeHelper.get_mopt_name(minsn.d.t),
            )
        elif opcode.nb_operands == 2:
            return f"m_{opcode.name}(%s,%s,%s)" % (
                MicrocodeHelper.get_mopt_name(minsn.l.t),
                MicrocodeHelper.get_mopt_name(minsn.r.t),
                MicrocodeHelper.get_mopt_name(minsn.d.t),
            )
        return "???"


OPCODES_LOOKUP: dict[int, MicrocodeOpcode] = {
    ida_hexrays.m_nop: MicrocodeOpcode("nop", 0, True),
    ida_hexrays.m_stx: MicrocodeOpcode("stx", 2, False),
    ida_hexrays.m_ldx: MicrocodeOpcode("ldx", 2, False),
    ida_hexrays.m_ldc: MicrocodeOpcode("ldc", 1, False),
    ida_hexrays.m_mov: MicrocodeOpcode("mov", 1, False, ""),
    ida_hexrays.m_neg: MicrocodeOpcode("neg", 1, False, "-"),
    ida_hexrays.m_lnot: MicrocodeOpcode("lnot", 1, False, "!"),
    ida_hexrays.m_bnot: MicrocodeOpcode("bnot", 1, False, "~"),
    ida_hexrays.m_xds: MicrocodeOpcode("xds", 1, False, "xds"),
    ida_hexrays.m_xdu: MicrocodeOpcode("xdu", 1, False, "xdu"),
    ida_hexrays.m_low: MicrocodeOpcode("low", 1, False, "low"),
    ida_hexrays.m_high: MicrocodeOpcode("high", 1, False, "high"),
    ida_hexrays.m_add: MicrocodeOpcode("add", 2, True, "+"),
    ida_hexrays.m_sub: MicrocodeOpcode("sub", 2, False, "-"),
    ida_hexrays.m_mul: MicrocodeOpcode("mul", 2, True, "*"),
    ida_hexrays.m_udiv: MicrocodeOpcode("udiv", 2, False, "UDiv"),
    ida_hexrays.m_sdiv: MicrocodeOpcode("sdiv", 2, False, "/"),
    ida_hexrays.m_umod: MicrocodeOpcode("umod", 2, False, "URem"),
    ida_hexrays.m_smod: MicrocodeOpcode("smod", 2, False, "%"),
    ida_hexrays.m_or: MicrocodeOpcode("or", 2, True, "|"),
    ida_hexrays.m_and: MicrocodeOpcode("and", 2, True, "&"),
    ida_hexrays.m_xor: MicrocodeOpcode("xor", 2, True, "^"),
    ida_hexrays.m_shl: MicrocodeOpcode("shl", 2, False, "<<"),
    ida_hexrays.m_shr: MicrocodeOpcode("shr", 2, False, "LShR"),
    ida_hexrays.m_sar: MicrocodeOpcode("sar", 2, False, ">>"),
    ida_hexrays.m_cfadd: MicrocodeOpcode("cfadd", 2, True),
    ida_hexrays.m_ofadd: MicrocodeOpcode("ofadd", 2, True),
    ida_hexrays.m_cfshl: MicrocodeOpcode("cfshl", 2, False),
    ida_hexrays.m_cfshr: MicrocodeOpcode("cfshr", 2, False),
    ida_hexrays.m_sets: MicrocodeOpcode("sets", 2, False),
    ida_hexrays.m_seto: MicrocodeOpcode("seto", 2, False),
    ida_hexrays.m_setp: MicrocodeOpcode("setp", 2, False),
    ida_hexrays.m_setnz: MicrocodeOpcode("setnz", 2, True, "!="),
    ida_hexrays.m_setz: MicrocodeOpcode("setz", 2, True, "=="),
    ida_hexrays.m_seta: MicrocodeOpcode("seta", 2, False, ">"),
    ida_hexrays.m_setae: MicrocodeOpcode("setae", 2, False, ">="),
    ida_hexrays.m_setb: MicrocodeOpcode("setb", 2, False, "<"),
    ida_hexrays.m_setbe: MicrocodeOpcode("setbe", 2, False, "<="),
    ida_hexrays.m_setg: MicrocodeOpcode("setg", 2, False, "UGT"),
    ida_hexrays.m_setge: MicrocodeOpcode("setge", 2, False, "UGE"),
    ida_hexrays.m_setl: MicrocodeOpcode("setl", 2, False, "ULT"),
    ida_hexrays.m_setle: MicrocodeOpcode("setle", 2, False, "ULE"),
    ida_hexrays.m_jcnd: MicrocodeOpcode("jcnd", 1, False),
    ida_hexrays.m_jnz: MicrocodeOpcode("jnz", 2, True),
    ida_hexrays.m_jz: MicrocodeOpcode("jz", 2, True),
    ida_hexrays.m_jae: MicrocodeOpcode("jae", 2, False),
    ida_hexrays.m_jb: MicrocodeOpcode("jb", 2, False),
    ida_hexrays.m_ja: MicrocodeOpcode("ja", 2, False),
    ida_hexrays.m_jbe: MicrocodeOpcode("jbe", 2, False),
    ida_hexrays.m_jg: MicrocodeOpcode("jg", 2, False),
    ida_hexrays.m_jge: MicrocodeOpcode("jge", 2, False),
    ida_hexrays.m_jl: MicrocodeOpcode("jl", 2, False),
    ida_hexrays.m_jle: MicrocodeOpcode("jle", 2, False),
    ida_hexrays.m_jtbl: MicrocodeOpcode("jtbl", 2, False),
    ida_hexrays.m_ijmp: MicrocodeOpcode("ijmp", 2, False),
    ida_hexrays.m_goto: MicrocodeOpcode("goto", 1, False),
    ida_hexrays.m_call: MicrocodeOpcode("call", 2, False),
    ida_hexrays.m_icall: MicrocodeOpcode("icall", 2, False),
    ida_hexrays.m_ret: MicrocodeOpcode("ret", 0, False),
    ida_hexrays.m_push: MicrocodeOpcode("push", 0, False),
    ida_hexrays.m_pop: MicrocodeOpcode("pop", 0, False),
    ida_hexrays.m_und: MicrocodeOpcode("und", 0, False),
    ida_hexrays.m_ext: MicrocodeOpcode("ext", 0, False),
    ida_hexrays.m_f2i: MicrocodeOpcode("f2i", 2, False),
    ida_hexrays.m_f2u: MicrocodeOpcode("f2u", 2, False),
    ida_hexrays.m_i2f: MicrocodeOpcode("i2f", 2, False),
    ida_hexrays.m_u2f: MicrocodeOpcode("u2f", 2, False),
    ida_hexrays.m_f2f: MicrocodeOpcode("f2f", 2, False),
    ida_hexrays.m_fneg: MicrocodeOpcode("fneg", 2, False),
    ida_hexrays.m_fadd: MicrocodeOpcode("fadd", 2, True),
    ida_hexrays.m_fsub: MicrocodeOpcode("fsub", 2, False),
    ida_hexrays.m_fmul: MicrocodeOpcode("fmul", 2, True),
    ida_hexrays.m_fdiv: MicrocodeOpcode("fdiv", 2, False),
}


K = typing.TypeVar("K")
V = typing.TypeVar("V")


class OverweightError(Exception):
    pass


Eviction: typing.TypeAlias = typing.Callable[["Cache"], None]


class Cache(typing.MutableMapping[K, V]):
    """
    https://google.github.io/guava/releases/16.0/api/docs/com/google/common/cache/CacheBuilder.html
    """

    @abc.abstractmethod
    def reap(self) -> None:
        pass

    class Stats(typing.NamedTuple):
        seq: int
        size: int
        weight: float
        hits: int
        misses: int
        max_size_ever: int
        max_weight_ever: float

    @property
    @abc.abstractmethod
    def stats(self) -> Stats:
        raise NotImplementedError


def LRU(cache: "Cache") -> None:  # noqa
    cache._kill(cache._root.lru_next)  # type: ignore  # noqa


def LRI(cache: "Cache") -> None:  # noqa
    cache._kill(cache._root.ins_next)  # type: ignore  # noqa


def LFU(cache: "Cache") -> None:  # noqa
    cache._kill(cache._root.lfu_prev)  # type: ignore  # noqa


class CacheImpl(Cache[K, V]):
    SKIP = object()
    """
    https://google.github.io/guava/releases/16.0/api/docs/com/google/common/cache/CacheBuilder.html
    """

    class Link:
        __slots__ = [
            "seq",
            "ins_prev",
            "ins_next",
            "lru_prev",
            "lru_next",
            "lfu_prev",
            "lfu_next",
            "key",
            "value",
            "weight",
            "written",
            "accessed",
            "hits",
            "unlinked",
        ]

        seq: int
        ins_prev: "CacheImpl.Link"
        ins_next: "CacheImpl.Link"
        lru_prev: "CacheImpl.Link"
        lru_next: "CacheImpl.Link"
        lfu_prev: "CacheImpl.Link"
        lfu_next: "CacheImpl.Link"
        key: typing.Any | weakref.ref
        value: typing.Any | weakref.ref
        weight: float
        written: float
        accessed: float
        hits: int
        unlinked: bool

        def __repr__(self) -> str:
            return (
                f"Link@{self.seq!s}("
                f'ins_prev={("@" + str(self.ins_prev.seq)) if self.ins_prev is not None else None}, '
                f'ins_next={("@" + str(self.ins_next.seq)) if self.ins_next is not None else None}, '
                f'lru_prev={("@" + str(self.lru_prev.seq)) if self.lru_prev is not None else None}, '
                f'lru_next={("@" + str(self.lru_next.seq)) if self.lru_next is not None else None}, '
                f'lfu_prev={("@" + str(self.lfu_prev.seq)) if self.lfu_prev is not None else None}, '
                f'lfu_next={("@" + str(self.lfu_next.seq)) if self.lfu_next is not None else None}, '
                f"key={self.key!r}, "
                f"value={self.value!r}, "
                f"weight={self.weight}, "
                f"written={self.written}, "
                f"accessed={self.accessed}, "
                f"hits={self.hits}, "
                f"unlinked={self.unlinked})"
            )

    _cache: typing.MutableMapping[typing.Any, Link]

    DEFAULT_MAX_SIZE = 256

    def __init__(
        self,
        *,
        max_size: int = DEFAULT_MAX_SIZE,
        max_weight: float | None = None,
        identity_keys: bool = False,
        expire_after_access: float | None = None,
        expire_after_write: float | None = None,
        removal_listener: (
            typing.Callable[[K | weakref.ref, V | weakref.ref], None] | None
        ) = None,
        clock: typing.Callable[[], float] | None = None,
        weak_keys: bool = False,
        weak_values: bool = False,
        weigher: typing.Callable[[V], float] = lambda _: 1.0,
        lock: threading.RLock | None = None,
        raise_overweight: bool = False,
        eviction: Eviction = LRU,
        track_frequency: bool | None = None,
    ) -> None:
        super().__init__()

        if clock is None:
            if expire_after_access is not None or expire_after_write is not None:
                clock = time.time
            else:
                clock = lambda: 0.0  # noqa

        self._max_size = max_size
        self._max_weight = max_weight
        self._identity_keys = identity_keys
        self._expire_after_access = expire_after_access
        self._expire_after_write = expire_after_write
        self._removal_listener = removal_listener
        self._clock = clock
        self._weak_keys = weak_keys
        self._weak_values = weak_values
        self._weigher = weigher
        self._lock = lock or threading.RLock()
        self._raise_overweight = raise_overweight
        self._eviction = eviction
        self._track_frequency = (
            track_frequency if track_frequency is not None else (eviction is LFU)
        )

        if weak_keys and not identity_keys:
            self._cache = weakref.WeakKeyDictionary()
        else:
            self._cache = {}

        self._root = CacheImpl.Link()
        self._root.seq = 0
        self._root.ins_next = self._root.ins_prev = self._root
        self._root.lru_next = self._root.lru_prev = self._root
        if self._track_frequency:
            self._root.lfu_next = self._root.lfu_prev = self._root

        weak_dead: collections.deque[CacheImpl.Link] | None
        if weak_keys or weak_values:
            weak_dead = collections.deque()
            weak_dead_ref = weakref.ref(weak_dead)
        else:
            weak_dead = None
            weak_dead_ref = None
        self._weak_dead = weak_dead
        self._weak_dead_ref = weak_dead_ref

        self._seq = 0
        self._size = 0
        self._weight = 0.0
        self._hits = 0
        self._misses = 0
        self._max_size_ever = 0
        self._max_weight_ever = 0.0

    def _unlink(self, link: Link) -> None:
        if link is self._root:
            raise TypeError
        if link.unlinked:
            return

        link.ins_prev.ins_next = link.ins_next
        link.ins_next.ins_prev = link.ins_prev
        link.ins_next = link.ins_prev = link

        link.lru_prev.lru_next = link.lru_next
        link.lru_next.lru_prev = link.lru_prev
        link.lru_next = link.lru_prev = link

        if self._track_frequency:
            link.lfu_prev.lfu_next = link.lfu_next
            link.lfu_next.lfu_prev = link.lfu_prev
            link.lfu_next = link.lfu_prev = link

        if self._removal_listener is not None:
            try:
                self._removal_listener(link.key, link.value)
            except Exception:
                logger.exception("Removal listener raised exception")

        self._size -= 1
        self._weight -= link.weight
        link.key = link.value = None
        link.unlinked = True

    def _kill(self, link: Link) -> None:
        if link is self._root:
            raise RuntimeError

        key = link.key
        if self._weak_keys:
            if key is not None:
                key = key()
            if key is None:
                key = self.SKIP

        if key is not self.SKIP:
            cache_key = id(key) if self._identity_keys else key
            cache_link = self._cache.get(cache_key)
            if cache_link is link:
                del self._cache[cache_key]

        self._unlink(link)

    def _reap(self) -> None:
        if self._weak_dead is not None:
            while True:
                try:
                    link = self._weak_dead.popleft()
                except IndexError:
                    break
                self._kill(link)

        clock = None

        if self._expire_after_write is not None:
            clock = self._clock()
            deadline = clock - self._expire_after_write

            while self._root.ins_next is not self._root:
                link = self._root.ins_next
                if link.written > deadline:
                    break
                self._kill(link)

        if self._expire_after_access is not None:
            if clock is None:
                clock = self._clock()
            deadline = clock - self._expire_after_access

            while self._root.lru_next is not self._root:
                link = self._root.lru_next
                if link.accessed > deadline:
                    break
                self._kill(link)

    def reap(self) -> None:
        with self._lock:
            self._reap()

    def _get_link(self, key: K) -> tuple[Link, V]:
        cache_key = id(key) if self._identity_keys else key

        link = self._cache[cache_key]
        if link.unlinked:
            raise Exception

        def fail():
            with contextlib.suppress(KeyError):
                del self._cache[cache_key]
            self._unlink(link)
            raise KeyError(key)

        if self._identity_keys:
            link_key = link.key
            if self._weak_keys:
                link_key = link_key()
                if link_key is None:
                    fail()
            if key is not link_key:
                fail()

        value = link.value
        if self._weak_values:
            if value is not None:
                value = value()
            if value is None:
                fail()

        return link, value  # type: ignore

    def __getitem__(self, key: K) -> V:
        with self._lock:
            self._reap()

            try:
                link, value = self._get_link(key)
            except KeyError:
                self._misses += 1
                raise KeyError(key) from None

            if link.lru_next is not self._root:
                link.lru_prev.lru_next = link.lru_next
                link.lru_next.lru_prev = link.lru_prev

                lru_last = self._root.lru_prev
                lru_last.lru_next = self._root.lru_prev = link
                link.lru_prev = lru_last
                link.lru_next = self._root

            if self._track_frequency:
                lfu_pos = link.lfu_prev
                while lfu_pos is not self._root and lfu_pos.hits <= link.hits:
                    lfu_pos = lfu_pos.lfu_prev

                if link.lfu_prev is not lfu_pos:
                    link.lfu_prev.lfu_next = link.lfu_next
                    link.lfu_next.lfu_prev = link.lfu_prev

                    lfu_last = lfu_pos.lfu_prev
                    lfu_last.lfu_next = lfu_pos.lfu_prev = link
                    link.lfu_prev = lfu_last
                    link.lfu_next = lfu_pos

            link.accessed = self._clock()
            link.hits += 1
            self._hits += 1
            return value

    @staticmethod
    def _weak_die(
        dead_ref: weakref.ref, link: Link, key_ref: weakref.ref
    ) -> None:  # noqa
        dead = dead_ref()
        if dead is not None:
            dead.append(link)

    @property
    def _full(self) -> bool:
        if self._max_size is not None and self._size >= self._max_size:
            return True
        if self._max_weight is not None and self._weight >= self._max_weight:
            return True
        return False

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            while True:
                link = self._root.ins_prev
                if link is self._root:
                    break
                if link.unlinked:
                    raise TypeError
                self._unlink(link)

    def __setitem__(self, key: K, value: V) -> None:
        weight = self._weigher(value)

        with self._lock:
            self._reap()

            if self._max_weight is not None and weight > self._max_weight:
                if self._raise_overweight:
                    raise OverweightError
                else:
                    return

            try:
                existing_link, existing_value = self._get_link(key)
            except KeyError:
                pass
            else:
                self._unlink(existing_link)

            while self._full:
                self._eviction(self)

            link = CacheImpl.Link()

            self._seq += 1
            link.seq = self._seq

            def make_ref(o, b):
                if not b:
                    return o
                return weakref.ref(o, functools.partial(CacheImpl._weak_die, self._weak_dead_ref, link))  # type: ignore  # noqa

            link.key = make_ref(key, self._weak_keys)
            link.value = make_ref(value, self._weak_values)

            link.weight = weight
            link.written = link.accessed = self._clock()
            link.hits = 0
            link.unlinked = False

            ins_last = self._root.ins_prev
            ins_last.ins_next = self._root.ins_prev = link
            link.ins_prev = ins_last
            link.ins_next = self._root

            lru_last = self._root.lru_prev
            lru_last.lru_next = self._root.lru_prev = link
            link.lru_prev = lru_last
            link.lru_next = self._root

            if self._track_frequency:
                lfu_last = self._root.lfu_prev
                lfu_last.lfu_next = self._root.lfu_prev = link
                link.lfu_prev = lfu_last
                link.lfu_next = self._root

            self._weight += weight
            self._size += 1
            self._max_size_ever = max(self._size, self._max_size_ever)
            self._max_weight_ever = max(self._weight, self._max_weight_ever)

            cache_key = id(key) if self._identity_keys else key
            self._cache[cache_key] = link

    def __delitem__(self, key: K) -> None:
        with self._lock:
            self._reap()

            link, value = self._get_link(key)

            cache_key = id(key) if self._identity_keys else key
            del self._cache[cache_key]

            self._unlink(link)

    def __len__(self) -> int:
        with self._lock:
            self._reap()

            return self._size

    def __contains__(self, key: K) -> bool:  # type: ignore
        with self._lock:
            self._reap()

            try:
                self._get_link(key)
            except KeyError:
                return False
            else:
                return True

    def __iter__(self) -> typing.Iterator[K]:
        with self._lock:
            self._reap()

            link = self._root.ins_prev
            while link is not self._root:
                key = link.key
                if self._weak_keys:
                    if key is not None:
                        key = key()
                    if key is not None:
                        yield key
                else:
                    yield key  # type: ignore

                nxt = link.ins_prev
                if nxt is link:
                    raise ValueError
                link = nxt

    @property
    def stats(self) -> Cache.Stats:
        with self._lock:
            return Cache.Stats(
                self._seq,
                self._size,
                self._weight,
                self._hits,
                self._misses,
                self._max_size_ever,
                self._max_weight_ever,
            )
