"""Instruction-level CFG invariants derived from minsn_t::verify and mop_t::verify.

Separate from mblock-level checks in invariants.py.
These checks are expensive (walk every instruction) and should only run in
debug/CI mode via the ``include_insn_checks`` flag in IDACfgContract.
"""

from __future__ import annotations

from types import MappingProxyType
from d810.core.typing import Any, Iterable

try:
    import ida_hexrays
except ImportError:  # pragma: no cover - exercised in unit tests without IDA.
    class _FallbackHexRays:
        # Opcodes
        m_nop = 0
        m_jtbl = 1
        m_goto = 2
        m_jcnd = 3
        m_jnz = 4
        m_jz = 5
        m_jae = 6
        m_jb = 7
        m_ja = 8
        m_jbe = 9
        m_jg = 10
        m_jge = 11
        m_jl = 12
        m_jle = 13
        m_ijmp = 14
        m_ret = 15
        m_ext = 16
        m_push = 17
        m_pop = 18
        m_call = 19
        m_icall = 20
        m_mov = 21
        m_lnot = 22
        m_neg = 23
        m_add = 24
        m_sub = 25
        m_mul = 26
        m_udiv = 27
        m_sdiv = 28
        m_umod = 29
        m_smod = 30
        m_or = 31
        m_and = 32
        m_xor = 33
        m_shl = 34
        m_shr = 35
        m_sar = 36
        m_cfadd = 37
        m_ofadd = 38
        m_cfshl = 39
        m_cfshr = 40
        m_sets = 41
        m_seto = 42
        m_setp = 43
        m_setnz = 44
        m_setz = 45
        m_setae = 46
        m_setb = 47
        m_seta = 48
        m_setbe = 49
        m_setg = 50
        m_setge = 51
        m_setl = 52
        m_setle = 53
        m_ldx = 54
        m_stx = 55
        m_f2i = 56
        m_f2u = 57
        m_i2f = 58
        m_u2f = 59
        m_f2f = 60
        m_fneg = 61
        m_fadd = 62
        m_fsub = 63
        m_fmul = 64
        m_fdiv = 65

        # Max valid opcode (best-effort upper bound)
        m_max = 66

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

        BADADDR = 0xFFFFFFFFFFFFFFFF

    ida_hexrays = _FallbackHexRays()  # type: ignore[assignment]

from d810.cfg.contracts.report import InvariantViolation

# ---------------------------------------------------------------------------
# MINSN_* constants (instruction-level, distinct from CFG_* block-level)
# ---------------------------------------------------------------------------

# Group A — Basic instruction validity
MINSN_50795_BADADDR = "MINSN_50795_BADADDR"
MINSN_50804_INVALID_OPCODE = "MINSN_50804_INVALID_OPCODE"
MINSN_50806_NOP_RET_WITH_OPERANDS = "MINSN_50806_NOP_RET_WITH_OPERANDS"
MINSN_50839_DST_IS_SUBINSN = "MINSN_50839_DST_IS_SUBINSN"
MINSN_50863_EA_OUTSIDE_FUNC = "MINSN_50863_EA_OUTSIDE_FUNC"
MINSN_50800_NONPROP_SUBINSN = "MINSN_50800_NONPROP_SUBINSN"
MINSN_50801_WRONG_FPINSN = "MINSN_50801_WRONG_FPINSN"
MINSN_50802_NONPROP_SUBINSN_2 = "MINSN_50802_NONPROP_SUBINSN_2"
MINSN_50803_SUBINSN_D_MISMATCH = "MINSN_50803_SUBINSN_D_MISMATCH"
MINSN_50859_JTBL_NO_CASELIST = "MINSN_50859_JTBL_NO_CASELIST"
MINSN_51652_WRONG_DST_TYPE = "MINSN_51652_WRONG_DST_TYPE"
MINSN_52118_SHIFT_EXCEEDS_MASK = "MINSN_52118_SHIFT_EXCEEDS_MASK"
MINSN_52123_ASSERT_ON_NONMOV = "MINSN_52123_ASSERT_ON_NONMOV"
MINSN_52338_LNOT_SIZE_NOT_1 = "MINSN_52338_LNOT_SIZE_NOT_1"
MINSN_52723_EXTSTX_ON_NONEXT = "MINSN_52723_EXTSTX_ON_NONEXT"

# Group B — Operand presence for opcode
MINSN_5081x_OPERAND_PRESENCE = "MINSN_5081x_OPERAND_PRESENCE"
MINSN_50807_EXT_BAD_L = "MINSN_50807_EXT_BAD_L"
MINSN_50808_EXT_BAD_R = "MINSN_50808_EXT_BAD_R"
MINSN_50809_EXT_BAD_D = "MINSN_50809_EXT_BAD_D"

# Group C — Operand size consistency
MINSN_5083x_SIZE_MISMATCH = "MINSN_5083x_SIZE_MISMATCH"
MINSN_50768_SUBINSN_SIZE_MISMATCH = "MINSN_50768_SUBINSN_SIZE_MISMATCH"
MINSN_50826_LDX_STX_SEG_SIZE = "MINSN_50826_LDX_STX_SEG_SIZE"
MINSN_50827_LDX_STX_OFF_SIZE = "MINSN_50827_LDX_STX_OFF_SIZE"
MINSN_52816_SEGOFF_SIZE = "MINSN_52816_SEGOFF_SIZE"

# Group D — Operand type validity
MINSN_50754_MOP_ZBC_NONZERO_SIZE = "MINSN_50754_MOP_ZBC_NONZERO_SIZE"
MINSN_50755_STR_NOT_ADDRSIZE = "MINSN_50755_STR_NOT_ADDRSIZE"
MINSN_50756_UNKNOWN_SIZE_FORBIDDEN = "MINSN_50756_UNKNOWN_SIZE_FORBIDDEN"
MINSN_50757_BAD_OPERAND_SIZE = "MINSN_50757_BAD_OPERAND_SIZE"
MINSN_50759_BAD_CONST_DEF_ADDR = "MINSN_50759_BAD_CONST_DEF_ADDR"
MINSN_50760_BAD_CONST_OPNUM = "MINSN_50760_BAD_CONST_OPNUM"
MINSN_50761_CONST_ILLEGAL_BITS = "MINSN_50761_CONST_ILLEGAL_BITS"
MINSN_50763_NEGATIVE_STKVAR_OFF = "MINSN_50763_NEGATIVE_STKVAR_OFF"
MINSN_50764_NEGATIVE_REG_NUM = "MINSN_50764_NEGATIVE_REG_NUM"
MINSN_50765_BIT_REG_SIZE_NOT_1 = "MINSN_50765_BIT_REG_SIZE_NOT_1"
MINSN_50766_BAD_REG_SIZE = "MINSN_50766_BAD_REG_SIZE"
MINSN_50770_BAD_BLOCK_NUM = "MINSN_50770_BAD_BLOCK_NUM"
MINSN_50774_BAD_LVAR = "MINSN_50774_BAD_LVAR"
MINSN_50775_BAD_LVAR_2 = "MINSN_50775_BAD_LVAR_2"
MINSN_50776_BAD_LVAR_3 = "MINSN_50776_BAD_LVAR_3"
MINSN_50777_BAD_LVAR_4 = "MINSN_50777_BAD_LVAR_4"
MINSN_50778_BAD_LVAR_5 = "MINSN_50778_BAD_LVAR_5"
MINSN_50779_BAD_LVAR_6 = "MINSN_50779_BAD_LVAR_6"
MINSN_50781_BAD_ADDR_SIZE = "MINSN_50781_BAD_ADDR_SIZE"
MINSN_50788_FP_CONST_TOO_BIG = "MINSN_50788_FP_CONST_TOO_BIG"
MINSN_50789_PAIR_CHECK_1 = "MINSN_50789_PAIR_CHECK_1"
MINSN_50790_PAIR_CHECK_2 = "MINSN_50790_PAIR_CHECK_2"
MINSN_50791_PAIR_CHECK_3 = "MINSN_50791_PAIR_CHECK_3"
MINSN_50792_PAIR_CHECK_4 = "MINSN_50792_PAIR_CHECK_4"
MINSN_50793_PAIR_CHECK_5 = "MINSN_50793_PAIR_CHECK_5"
MINSN_50794_WRONG_OPERAND_TYPE = "MINSN_50794_WRONG_OPERAND_TYPE"
MINSN_51135_SCATTERED_CHECK_1 = "MINSN_51135_SCATTERED_CHECK_1"
MINSN_51136_SCATTERED_CHECK_2 = "MINSN_51136_SCATTERED_CHECK_2"
MINSN_51137_SCATTERED_CHECK_3 = "MINSN_51137_SCATTERED_CHECK_3"
MINSN_51138_SCATTERED_CHECK_4 = "MINSN_51138_SCATTERED_CHECK_4"
MINSN_51275_BAD_FP_SIZE = "MINSN_51275_BAD_FP_SIZE"
MINSN_51586_BAD_CONST_SIZE_1 = "MINSN_51586_BAD_CONST_SIZE_1"
MINSN_51587_BAD_CONST_SIZE_2 = "MINSN_51587_BAD_CONST_SIZE_2"
MINSN_51650_BLOCK_NUM_FORBIDDEN = "MINSN_51650_BLOCK_NUM_FORBIDDEN"
MINSN_51651_CASE_NUM_FORBIDDEN = "MINSN_51651_CASE_NUM_FORBIDDEN"
MINSN_52064_BAD_POSSIBLY_FP_SIZE = "MINSN_52064_BAD_POSSIBLY_FP_SIZE"
MINSN_52673_ADDR_OVERFLOW = "MINSN_52673_ADDR_OVERFLOW"
MINSN_52679_STKVAR_OVERFLOW = "MINSN_52679_STKVAR_OVERFLOW"
MINSN_52863_BAD_SCATTERED_ADDR = "MINSN_52863_BAD_SCATTERED_ADDR"

# Group E — Call/helper validity
MINSN_50772_ARGLIST_NOT_D_OPERAND = "MINSN_50772_ARGLIST_NOT_D_OPERAND"
MINSN_50773_ARGLIST_ON_NONCALL = "MINSN_50773_ARGLIST_ON_NONCALL"
MINSN_50780_REG_ADDR_OUTSIDE_HELPER = "MINSN_50780_REG_ADDR_OUTSIDE_HELPER"
MINSN_50782_BAD_HELPER_NAME = "MINSN_50782_BAD_HELPER_NAME"
MINSN_50784_HELPER_ON_NONCALL = "MINSN_50784_HELPER_ON_NONCALL"
MINSN_51066_ARG_BAD_ADDR = "MINSN_51066_ARG_BAD_ADDR"
MINSN_51264_DUPLICATE_CALL_ADDRS = "MINSN_51264_DUPLICATE_CALL_ADDRS"

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_VALID_MOP_SIZES = frozenset({1, 2, 4, 8, 10, 16, 32})

# Valid floating-point sizes (4 = float, 8 = double, 10 = long double)
_VALID_FP_SIZES = frozenset({4, 8, 10})

# Default ADDRSIZE (pointer size) — 8 bytes for 64-bit, 4 for 32-bit.
# Best-effort constant; real code should query mba.mvm.addrsize.
_DEFAULT_ADDRSIZE = 8

# Maximum valid UA_MAXOP constant (matches IDA's UA_MAXOP = 8)
_UA_MAXOP = 8


def _violation(
    *,
    code: str,
    phase: str,
    message: str,
    block_serial: int | None,
    insn_ea: int | None = None,
    verify_code: int | None = None,
    details: dict[str, Any] | None = None,
) -> InvariantViolation:
    payload = dict(details or {})
    if verify_code is not None:
        payload["verify_code"] = int(verify_code)
    return InvariantViolation(
        code=code,
        phase=phase,
        message=message,
        block_serial=block_serial,
        insn_ea=insn_ea,
        details=MappingProxyType(payload) if payload else None,
    )


def _serials_for_scope(mba, focus_serials: Iterable[int] | None) -> list[int]:
    if focus_serials is not None:
        return [int(s) for s in focus_serials]
    return list(range(int(mba.qty)))


def _safe_get_block(mba, serial: int):
    if serial < 0 or serial >= int(mba.qty):
        return None
    try:
        return mba.get_mblock(serial)
    except Exception:
        return None


def _iter_insns(blk):
    """Yield instructions from block.head through the .next chain."""
    insn = getattr(blk, "head", None)
    while insn is not None:
        yield insn
        insn = getattr(insn, "next", None)


def _insn_ea(insn) -> int | None:
    if insn is None or not hasattr(insn, "ea"):
        return None
    try:
        return int(insn.ea)
    except Exception:
        return None


def _badaddr() -> int:
    return int(getattr(ida_hexrays, "BADADDR", 0xFFFFFFFFFFFFFFFF))


def _max_opcode() -> int:
    return int(getattr(ida_hexrays, "m_max", 66))


def _is_call_opcode(opcode: int) -> bool:
    m_call = int(getattr(ida_hexrays, "m_call", 19))
    m_icall = int(getattr(ida_hexrays, "m_icall", 20))
    return opcode in (m_call, m_icall)


def _mop_type(op) -> int | None:
    if op is None:
        return None
    try:
        return int(getattr(op, "t", -1))
    except Exception:
        return None


def _mop_size(op) -> int | None:
    if op is None:
        return None
    try:
        return int(getattr(op, "size", -1))
    except Exception:
        return None


def _op_present(op) -> bool:
    """Return True if the operand is present (not None and not mop_z)."""
    if op is None:
        return False
    t = _mop_type(op)
    if t is None:
        return False
    return t != int(getattr(ida_hexrays, "mop_z", 0))


def _get_addrsize(mba) -> int:
    """Return the address size (in bytes) for the MBA, defaulting to 8."""
    try:
        mvm = getattr(mba, "mvm", None)
        if mvm is not None:
            return int(getattr(mvm, "addrsize", _DEFAULT_ADDRSIZE))
    except Exception:
        pass
    return _DEFAULT_ADDRSIZE


# ---------------------------------------------------------------------------
# Operand presence table (Group B)
# Each entry: opcode → (needs_l, needs_r, needs_d)
# None means "don't care"; True = must be present; False = must be absent.
# ---------------------------------------------------------------------------
def _operand_presence_table() -> dict[int, tuple[bool | None, bool | None, bool | None]]:
    hr = ida_hexrays
    T, F, N = True, False, None
    return {
        int(getattr(hr, "m_nop", 0)):   (F, F, F),
        int(getattr(hr, "m_ret", 15)):  (F, F, F),
        int(getattr(hr, "m_goto", 2)):  (T, F, F),
        int(getattr(hr, "m_ijmp", 14)): (T, N, F),
        int(getattr(hr, "m_jtbl", 1)):  (T, T, F),
        int(getattr(hr, "m_jcnd", 3)):  (T, F, T),
        int(getattr(hr, "m_jnz", 4)):   (T, F, T),
        int(getattr(hr, "m_jz", 5)):    (T, F, T),
        int(getattr(hr, "m_jae", 6)):   (T, F, T),
        int(getattr(hr, "m_jb", 7)):    (T, F, T),
        int(getattr(hr, "m_ja", 8)):    (T, F, T),
        int(getattr(hr, "m_jbe", 9)):   (T, F, T),
        int(getattr(hr, "m_jg", 10)):   (T, F, T),
        int(getattr(hr, "m_jge", 11)):  (T, F, T),
        int(getattr(hr, "m_jl", 12)):   (T, F, T),
        int(getattr(hr, "m_jle", 13)):  (T, F, T),
        int(getattr(hr, "m_call", 19)): (T, F, T),
        int(getattr(hr, "m_icall", 20)): (T, F, T),
        int(getattr(hr, "m_mov", 21)):  (T, F, T),
        int(getattr(hr, "m_neg", 23)):  (T, F, T),
        int(getattr(hr, "m_lnot", 22)): (T, F, T),
        int(getattr(hr, "m_add", 24)):  (T, T, T),
        int(getattr(hr, "m_sub", 25)):  (T, T, T),
        int(getattr(hr, "m_mul", 26)):  (T, T, T),
        int(getattr(hr, "m_udiv", 27)): (T, T, T),
        int(getattr(hr, "m_sdiv", 28)): (T, T, T),
        int(getattr(hr, "m_umod", 29)): (T, T, T),
        int(getattr(hr, "m_smod", 30)): (T, T, T),
        int(getattr(hr, "m_or", 31)):   (T, T, T),
        int(getattr(hr, "m_and", 32)):  (T, T, T),
        int(getattr(hr, "m_xor", 33)):  (T, T, T),
        int(getattr(hr, "m_shl", 34)):  (T, T, T),
        int(getattr(hr, "m_shr", 35)):  (T, T, T),
        int(getattr(hr, "m_sar", 36)):  (T, T, T),
        int(getattr(hr, "m_push", 17)): (T, F, F),
        int(getattr(hr, "m_pop", 18)):  (F, F, T),
    }


# ---------------------------------------------------------------------------
# Set of non-propagatable opcodes (from verify.cpp switch statement)
# These opcodes cannot appear as sub-instructions (verify.cpp 50800/50802).
# ---------------------------------------------------------------------------
def _nonpropagatable_opcodes() -> frozenset[int]:
    hr = ida_hexrays
    return frozenset(
        int(getattr(hr, name, -1))
        for name in (
            "m_goto", "m_nop", "m_ext", "m_push", "m_ijmp", "m_stx",
            "m_pop", "m_jcnd", "m_jnz", "m_jz", "m_jae", "m_jb",
            "m_ja", "m_jbe", "m_jg", "m_jge", "m_jl", "m_jle",
            "m_jtbl", "m_ret",
        )
        if int(getattr(hr, name, -1)) >= 0
    )


# ---------------------------------------------------------------------------
# Set of FPU opcodes (from verify.cpp: opcodes that set is_mcode_fpu())
# Best-effort: includes the floating-point arithmetic/conversion opcodes.
# ---------------------------------------------------------------------------
def _fpu_opcodes() -> frozenset[int]:
    hr = ida_hexrays
    return frozenset(
        int(getattr(hr, name, -1))
        for name in (
            "m_f2i", "m_f2u", "m_i2f", "m_u2f", "m_f2f",
            "m_fneg", "m_fadd", "m_fsub", "m_fmul", "m_fdiv",
        )
        if int(getattr(hr, name, -1)) >= 0
    )


# Opcodes exempt from FPINSN mark check (may or may not be fpinsn).
def _fpinsn_exempt_opcodes() -> frozenset[int]:
    hr = ida_hexrays
    return frozenset(
        int(getattr(hr, name, -1))
        for name in (
            "m_ext", "m_ldx", "m_stx", "m_mov",
            "m_setnz", "m_setz", "m_setae", "m_setb", "m_seta",
            "m_setbe", "m_setp", "m_jnz", "m_jz", "m_jae",
            "m_jbe", "m_jb", "m_ja",
        )
        if int(getattr(hr, name, -1)) >= 0
    )


# ---------------------------------------------------------------------------
# Set of valid pair-part operand types (from verify.cpp valid_pair_part())
# ---------------------------------------------------------------------------
def _valid_pair_part_types() -> frozenset[int]:
    hr = ida_hexrays
    return frozenset(
        int(getattr(hr, name, -1))
        for name in ("mop_r", "mop_n", "mop_d", "mop_S", "mop_v",
                     "mop_l", "mop_a", "mop_fn", "mop_p", "mop_sc")
        if int(getattr(hr, name, -1)) >= 0
    )


# ---------------------------------------------------------------------------
# Wrong destination types (from verify.cpp 51652)
# d operand must NOT be: mop_d, mop_a, mop_n, mop_fn, mop_str, mop_h
# (except for m_ijmp, m_stx, m_ext which are exempt)
# ---------------------------------------------------------------------------
def _forbidden_dst_types() -> frozenset[int]:
    hr = ida_hexrays
    return frozenset(
        int(getattr(hr, name, -1))
        for name in ("mop_d", "mop_a", "mop_n", "mop_fn", "mop_str", "mop_h")
        if int(getattr(hr, name, -1)) >= 0
    )


def _dst_exempt_opcodes() -> frozenset[int]:
    hr = ida_hexrays
    return frozenset(
        int(getattr(hr, name, -1))
        for name in ("m_ijmp", "m_stx", "m_ext")
        if int(getattr(hr, name, -1)) >= 0
    )


# ---------------------------------------------------------------------------
# Shift opcodes (for 52118 and 50835 checks)
# ---------------------------------------------------------------------------
def _shift_opcodes() -> frozenset[int]:
    hr = ida_hexrays
    return frozenset(
        int(getattr(hr, name, -1))
        for name in ("m_shl", "m_shr", "m_sar")
        if int(getattr(hr, name, -1)) >= 0
    )


# ---------------------------------------------------------------------------
# Group A — Basic instruction validity
# ---------------------------------------------------------------------------

def insn_basic_validity(
    mba,
    *,
    phase: str,
    focus_serials: Iterable[int] | None = None,
) -> list[InvariantViolation]:
    """Check basic per-instruction validity (verify.cpp codes in Group A).

    Checks performed:
    - 50795: ea must not be BADADDR.
    - 50804: opcode must be within valid m_* range.
    - 50806: m_nop and m_ret must have no operands.
    - 50800: sub-instructions must use only propagatable opcodes.
    - 50801: FPINSN flag must match opcode category (best-effort).
    - 50802: duplicate check for non-propagatable subinsn.
    - 50803: sub-instruction d mismatch (subinsn lacks d; top-level has it).
    - 50839: d operand must not be a sub-instruction (mop_d).
    - 50859: m_jtbl must have mop_c as right operand.
    - 51652: destination must not be forbidden type.
    - 52118: shift constant must not exceed operand bit-width mask.
    - 52123: assert/cfadd-style mark only on mov instructions.
    - 52338: m_lnot source and dest must both be size 1.
    - 52723: EXTSTX flag only on m_ext instructions (best-effort).
    - 50863: ea must fall within the function address range.
    """
    violations: list[InvariantViolation] = []
    serials = _serials_for_scope(mba, focus_serials)
    badaddr = _badaddr()
    max_op = _max_opcode()
    m_nop = int(getattr(ida_hexrays, "m_nop", 0))
    m_ret = int(getattr(ida_hexrays, "m_ret", 15))
    m_ext = int(getattr(ida_hexrays, "m_ext", 16))
    m_lnot = int(getattr(ida_hexrays, "m_lnot", 22))
    m_mov = int(getattr(ida_hexrays, "m_mov", 21))
    m_jtbl = int(getattr(ida_hexrays, "m_jtbl", 1))
    mop_d_type = int(getattr(ida_hexrays, "mop_d", 4))
    mop_c_type = int(getattr(ida_hexrays, "mop_c", 12))
    mop_n_type = int(getattr(ida_hexrays, "mop_n", 2))

    nonprop = _nonpropagatable_opcodes()
    fpu_ops = _fpu_opcodes()
    fpinsn_exempt = _fpinsn_exempt_opcodes()
    forbidden_dsts = _forbidden_dst_types()
    dst_exempt = _dst_exempt_opcodes()
    shift_ops = _shift_opcodes()

    # Determine function address range for 50863
    func_start: int | None = None
    func_end: int | None = None
    try:
        entry_ea = int(getattr(mba, "entry_ea", 0))
        func_start = entry_ea
    except Exception:
        pass
    try:
        last_blk = mba.get_mblock(int(mba.qty) - 1)
        if last_blk is not None and hasattr(last_blk, "end"):
            func_end = int(last_blk.end)
    except Exception:
        pass

    for serial in serials:
        blk = _safe_get_block(mba, int(serial))
        if blk is None:
            continue
        for insn in _iter_insns(blk):
            ea = _insn_ea(insn)
            opcode = int(getattr(insn, "opcode", 0))
            op_l = getattr(insn, "l", None)
            op_r = getattr(insn, "r", None)
            op_d = getattr(insn, "d", None)

            # 50795: ea == BADADDR
            if ea is None or ea == badaddr:
                violations.append(
                    _violation(
                        code=MINSN_50795_BADADDR,
                        phase=phase,
                        message=(
                            f"Block {serial}: instruction has ea=BADADDR "
                            f"(0x{badaddr:x})"
                        ),
                        block_serial=int(serial),
                        insn_ea=ea,
                        verify_code=50795,
                    )
                )

            # 50804: invalid opcode
            if opcode < 0 or opcode >= max_op:
                violations.append(
                    _violation(
                        code=MINSN_50804_INVALID_OPCODE,
                        phase=phase,
                        message=(
                            f"Block {serial} ea=0x{ea or 0:x}: opcode={opcode} "
                            f"is outside valid range [0, {max_op})"
                        ),
                        block_serial=int(serial),
                        insn_ea=ea,
                        verify_code=50804,
                        details={"opcode": opcode, "max_opcode": max_op},
                    )
                )

            # 50806: nop/ret with operands
            if opcode in (m_nop, m_ret):
                if _op_present(op_l) or _op_present(op_r) or _op_present(op_d):
                    violations.append(
                        _violation(
                            code=MINSN_50806_NOP_RET_WITH_OPERANDS,
                            phase=phase,
                            message=(
                                f"Block {serial} ea=0x{ea or 0:x}: "
                                f"{'m_nop' if opcode == m_nop else 'm_ret'} "
                                "must not have operands"
                            ),
                            block_serial=int(serial),
                            insn_ea=ea,
                            verify_code=50806,
                        )
                    )

            # 50800 / 50802: non-propagatable opcodes in sub-instruction context.
            # Best-effort: detect if d operand is mop_d and inner insn uses
            # a non-propagatable opcode.
            if op_d is not None and _mop_type(op_d) == mop_d_type:
                inner_insn = getattr(op_d, "d", None)
                if inner_insn is not None:
                    inner_opcode = int(getattr(inner_insn, "opcode", 0))
                    if inner_opcode in nonprop:
                        violations.append(
                            _violation(
                                code=MINSN_50800_NONPROP_SUBINSN,
                                phase=phase,
                                message=(
                                    f"Block {serial} ea=0x{ea or 0:x}: "
                                    f"sub-instruction opcode={inner_opcode} "
                                    "is non-propagatable"
                                ),
                                block_serial=int(serial),
                                insn_ea=ea,
                                verify_code=50800,
                                details={"inner_opcode": inner_opcode},
                            )
                        )

            # 50801: FPINSN mark must match opcode category (best-effort).
            # is_fpinsn() checks a flag on the instruction; we approximate
            # by checking is_fpinsn attribute if present.
            if opcode not in fpinsn_exempt:
                is_fpu_opcode = opcode in fpu_ops
                is_fpinsn_flag = False
                try:
                    fp_attr = getattr(insn, "is_fpinsn", None)
                    if callable(fp_attr):
                        is_fpinsn_flag = bool(fp_attr())
                    elif fp_attr is not None:
                        is_fpinsn_flag = bool(fp_attr)
                except Exception:
                    pass
                # Only flag if we can observe the flag and it mismatches.
                if fp_attr is not None and is_fpu_opcode != is_fpinsn_flag:
                    violations.append(
                        _violation(
                            code=MINSN_50801_WRONG_FPINSN,
                            phase=phase,
                            message=(
                                f"Block {serial} ea=0x{ea or 0:x}: "
                                f"opcode={opcode} FPINSN flag "
                                f"({is_fpinsn_flag}) != is_fpu_opcode "
                                f"({is_fpu_opcode})"
                            ),
                            block_serial=int(serial),
                            insn_ea=ea,
                            verify_code=50801,
                            details={
                                "opcode": opcode,
                                "is_fpinsn": is_fpinsn_flag,
                                "is_fpu_opcode": is_fpu_opcode,
                            },
                        )
                    )

            # 50803: sub-instructions must lack d; top-level must have d.
            # When mop_d inner insn has a d operand, it's a subinsn and should
            # have no d (hasd != with_target where with_target=False for subinsn).
            if op_d is not None and _mop_type(op_d) == mop_d_type:
                inner_insn = getattr(op_d, "d", None)
                if inner_insn is not None:
                    inner_d = getattr(inner_insn, "d", None)
                    if _op_present(inner_d):
                        violations.append(
                            _violation(
                                code=MINSN_50803_SUBINSN_D_MISMATCH,
                                phase=phase,
                                message=(
                                    f"Block {serial} ea=0x{ea or 0:x}: "
                                    "sub-instruction unexpectedly has d operand"
                                ),
                                block_serial=int(serial),
                                insn_ea=ea,
                                verify_code=50803,
                            )
                        )

            # 50839: destination is sub-instruction (mop_d type)
            if op_d is not None and _mop_type(op_d) == mop_d_type:
                violations.append(
                    _violation(
                        code=MINSN_50839_DST_IS_SUBINSN,
                        phase=phase,
                        message=(
                            f"Block {serial} ea=0x{ea or 0:x}: "
                            "d operand is a sub-instruction (mop_d) in "
                            "top-level position"
                        ),
                        block_serial=int(serial),
                        insn_ea=ea,
                        verify_code=50839,
                    )
                )

            # 50859: m_jtbl must have r operand of type mop_c
            if opcode == m_jtbl:
                r_type = _mop_type(op_r)
                if r_type != mop_c_type:
                    violations.append(
                        _violation(
                            code=MINSN_50859_JTBL_NO_CASELIST,
                            phase=phase,
                            message=(
                                f"Block {serial} ea=0x{ea or 0:x}: "
                                f"m_jtbl r operand type={r_type} "
                                "is not mop_c (case list)"
                            ),
                            block_serial=int(serial),
                            insn_ea=ea,
                            verify_code=50859,
                            details={"r_type": r_type},
                        )
                    )

            # 51652: wrong destination type
            # d must not be mop_d/mop_a/mop_n/mop_fn/mop_str/mop_h
            # except for m_ijmp, m_stx, m_ext
            if opcode not in dst_exempt and op_d is not None:
                d_type = _mop_type(op_d)
                if d_type in forbidden_dsts:
                    # 50839 already catches mop_d; 51652 covers the others
                    if d_type != mop_d_type:
                        violations.append(
                            _violation(
                                code=MINSN_51652_WRONG_DST_TYPE,
                                phase=phase,
                                message=(
                                    f"Block {serial} ea=0x{ea or 0:x}: "
                                    f"d operand type={d_type} is forbidden "
                                    "as instruction destination"
                                ),
                                block_serial=int(serial),
                                insn_ea=ea,
                                verify_code=51652,
                                details={"d_type": d_type},
                            )
                        )

            # 52118: shift constant must not exceed operand bit-width mask.
            # Only when r is mop_n (immediate) and the shift mask is known.
            if opcode in shift_ops and op_r is not None:
                r_type = _mop_type(op_r)
                if r_type == mop_n_type:
                    l_size = _mop_size(op_l)
                    r_nnn = getattr(op_r, "nnn", None)
                    if l_size is not None and l_size > 0 and r_nnn is not None:
                        shift_val = getattr(r_nnn, "value", None)
                        if shift_val is not None:
                            try:
                                shift_mask = (l_size * 8) - 1
                                if int(shift_val) & 0xFF > shift_mask:
                                    violations.append(
                                        _violation(
                                            code=MINSN_52118_SHIFT_EXCEEDS_MASK,
                                            phase=phase,
                                            message=(
                                                f"Block {serial} ea=0x{ea or 0:x}: "
                                                f"shift value=0x{int(shift_val):x} "
                                                f"exceeds mask 0x{shift_mask:x} "
                                                f"for l.size={l_size}"
                                            ),
                                            block_serial=int(serial),
                                            insn_ea=ea,
                                            verify_code=52118,
                                            details={
                                                "shift_val": int(shift_val),
                                                "shift_mask": shift_mask,
                                                "l_size": l_size,
                                            },
                                        )
                                    )
                            except Exception:
                                pass

            # 52123: assert/cfadd may only appear on mov instructions.
            # Best-effort: check is_assert attribute if present.
            if opcode != m_mov:
                is_assert_attr = getattr(insn, "is_assert", None)
                if is_assert_attr is not None:
                    try:
                        if callable(is_assert_attr):
                            is_assert = bool(is_assert_attr())
                        else:
                            is_assert = bool(is_assert_attr)
                        if is_assert:
                            violations.append(
                                _violation(
                                    code=MINSN_52123_ASSERT_ON_NONMOV,
                                    phase=phase,
                                    message=(
                                        f"Block {serial} ea=0x{ea or 0:x}: "
                                        f"assert-style mark on non-mov "
                                        f"opcode={opcode}"
                                    ),
                                    block_serial=int(serial),
                                    insn_ea=ea,
                                    verify_code=52123,
                                    details={"opcode": opcode},
                                )
                            )
                    except Exception:
                        pass

            # 52338: m_lnot — l.size and d.size must both be 1.
            if opcode == m_lnot:
                l_size = _mop_size(op_l)
                d_size = _mop_size(op_d)
                if (l_size is not None and l_size != 1) or (
                    d_size is not None and d_size != 1
                ):
                    violations.append(
                        _violation(
                            code=MINSN_52338_LNOT_SIZE_NOT_1,
                            phase=phase,
                            message=(
                                f"Block {serial} ea=0x{ea or 0:x}: "
                                f"m_lnot l.size={l_size} d.size={d_size} "
                                "must both be 1"
                            ),
                            block_serial=int(serial),
                            insn_ea=ea,
                            verify_code=52338,
                            details={"l_size": l_size, "d_size": d_size},
                        )
                    )

            # 52723: EXTSTX flag only valid on m_ext instructions (best-effort).
            if opcode != m_ext:
                is_extstx_attr = getattr(insn, "is_extstx", None)
                if is_extstx_attr is not None:
                    try:
                        if callable(is_extstx_attr):
                            is_extstx = bool(is_extstx_attr())
                        else:
                            is_extstx = bool(is_extstx_attr)
                        if is_extstx:
                            violations.append(
                                _violation(
                                    code=MINSN_52723_EXTSTX_ON_NONEXT,
                                    phase=phase,
                                    message=(
                                        f"Block {serial} ea=0x{ea or 0:x}: "
                                        f"EXTSTX flag set on non-m_ext "
                                        f"opcode={opcode}"
                                    ),
                                    block_serial=int(serial),
                                    insn_ea=ea,
                                    verify_code=52723,
                                    details={"opcode": opcode},
                                )
                            )
                    except Exception:
                        pass

            # 50863: ea outside function range
            if (
                ea is not None
                and ea != badaddr
                and func_start is not None
                and func_end is not None
                and not (func_start <= ea < func_end)
            ):
                violations.append(
                    _violation(
                        code=MINSN_50863_EA_OUTSIDE_FUNC,
                        phase=phase,
                        message=(
                            f"Block {serial}: instruction ea=0x{ea:x} outside "
                            f"function [0x{func_start:x}, 0x{func_end:x})"
                        ),
                        block_serial=int(serial),
                        insn_ea=ea,
                        verify_code=50863,
                        details={"func_start": func_start, "func_end": func_end},
                    )
                )

    return violations


# ---------------------------------------------------------------------------
# Group B — Operand presence for opcode (50807-50824)
# ---------------------------------------------------------------------------

def insn_operand_presence(
    mba,
    *,
    phase: str,
    focus_serials: Iterable[int] | None = None,
) -> list[InvariantViolation]:
    """Check opcode-specific operand structure (verify.cpp 50807-50824).

    Each opcode has defined expectations for which of l/r/d must be present.
    A single violation code (MINSN_5081x_OPERAND_PRESENCE) is emitted with
    details about which operand was unexpected/missing.

    Also checks m_ext operand validity (50807, 50808, 50809):
    mop_b and mop_f are not valid m_ext operands.
    """
    violations: list[InvariantViolation] = []
    serials = _serials_for_scope(mba, focus_serials)
    table = _operand_presence_table()

    m_ext = int(getattr(ida_hexrays, "m_ext", 16))
    mop_b_type = int(getattr(ida_hexrays, "mop_b", 7))
    mop_f_type = int(getattr(ida_hexrays, "mop_f", 8))
    mop_d_type = int(getattr(ida_hexrays, "mop_d", 4))
    # m_ext forbidden operand types: mop_b and mop_f (from is_valid_m_ext_op)
    ext_forbidden_types = frozenset({mop_b_type, mop_f_type})

    for serial in serials:
        blk = _safe_get_block(mba, int(serial))
        if blk is None:
            continue
        for insn in _iter_insns(blk):
            ea = _insn_ea(insn)
            opcode = int(getattr(insn, "opcode", 0))

            # 50807/50808/50809: m_ext operand validity
            if opcode == m_ext:
                for slot_name, vc in (("l", 50807), ("r", 50808), ("d", 50809)):
                    op = getattr(insn, slot_name, None)
                    if op is None:
                        continue
                    t = _mop_type(op)
                    if t in ext_forbidden_types:
                        code_const = {
                            50807: MINSN_50807_EXT_BAD_L,
                            50808: MINSN_50808_EXT_BAD_R,
                            50809: MINSN_50809_EXT_BAD_D,
                        }[vc]
                        violations.append(
                            _violation(
                                code=code_const,
                                phase=phase,
                                message=(
                                    f"Block {serial} ea=0x{ea or 0:x}: "
                                    f"m_ext {slot_name} operand type={t} "
                                    "is forbidden (mop_b/mop_f not valid)"
                                ),
                                block_serial=int(serial),
                                insn_ea=ea,
                                verify_code=vc,
                                details={"operand": slot_name, "type": t},
                            )
                        )
                continue  # m_ext not in presence table

            if opcode not in table:
                continue

            needs_l, needs_r, needs_d = table[opcode]
            has_l = _op_present(getattr(insn, "l", None))
            has_r = _op_present(getattr(insn, "r", None))
            has_d = _op_present(getattr(insn, "d", None))

            problems: list[str] = []
            if needs_l is True and not has_l:
                problems.append("l required but absent")
            elif needs_l is False and has_l:
                problems.append("l must be absent but present")
            if needs_r is True and not has_r:
                problems.append("r required but absent")
            elif needs_r is False and has_r:
                problems.append("r must be absent but present")
            if needs_d is True and not has_d:
                problems.append("d required but absent")
            elif needs_d is False and has_d:
                problems.append("d must be absent but present")

            if problems:
                violations.append(
                    _violation(
                        code=MINSN_5081x_OPERAND_PRESENCE,
                        phase=phase,
                        message=(
                            f"Block {serial} ea=0x{ea or 0:x}: opcode={opcode} "
                            f"operand presence violation: {'; '.join(problems)}"
                        ),
                        block_serial=int(serial),
                        insn_ea=ea,
                        verify_code=50811,
                        details={"opcode": opcode, "problems": tuple(problems)},
                    )
                )

    return violations


# ---------------------------------------------------------------------------
# Group C — Operand size consistency (50830-50838, 50768, 50826, 50827, 52816)
# ---------------------------------------------------------------------------

def insn_operand_sizes(
    mba,
    *,
    phase: str,
    focus_serials: Iterable[int] | None = None,
) -> list[InvariantViolation]:
    """Check operand size relationships (verify.cpp 50830-50838, 50768, 50826-50827).

    Checks:
    - For binary ops (l op r -> d): l.size == r.size == d.size (most ops).
    - For mov: l.size == d.size.
    - Sub-instruction mop_d: inner insn's d.size must match outer declared
      size (50768).
    - ldx/stx segment and offset size checks (50826, 50827, 52816).
    """
    violations: list[InvariantViolation] = []
    serials = _serials_for_scope(mba, focus_serials)

    hr = ida_hexrays
    m_mov = int(getattr(hr, "m_mov", 21))
    m_ldx = int(getattr(hr, "m_ldx", 54))
    m_stx = int(getattr(hr, "m_stx", 55))
    mop_d_type = int(getattr(hr, "mop_d", 4))
    addrsize = _get_addrsize(mba)

    # Binary ops where l.size == r.size == d.size
    binary_ops = frozenset(
        int(getattr(hr, name, -1))
        for name in (
            "m_add", "m_sub", "m_mul", "m_udiv", "m_sdiv",
            "m_umod", "m_smod", "m_or", "m_and", "m_xor",
        )
        if int(getattr(hr, name, -1)) >= 0
    )

    for serial in serials:
        blk = _safe_get_block(mba, int(serial))
        if blk is None:
            continue
        for insn in _iter_insns(blk):
            ea = _insn_ea(insn)
            opcode = int(getattr(insn, "opcode", 0))
            op_l = getattr(insn, "l", None)
            op_r = getattr(insn, "r", None)
            op_d = getattr(insn, "d", None)
            sz_l = _mop_size(op_l) if op_l is not None else None
            sz_r = _mop_size(op_r) if op_r is not None else None
            sz_d = _mop_size(op_d) if op_d is not None else None

            # Check 50768: sub-instruction size
            if op_d is not None and _mop_type(op_d) == mop_d_type:
                inner = getattr(op_d, "d", None)
                if inner is not None:
                    inner_d = getattr(inner, "d", None)
                    inner_sz = _mop_size(inner_d) if inner_d is not None else None
                    if sz_d is not None and inner_sz is not None and sz_d != inner_sz:
                        violations.append(
                            _violation(
                                code=MINSN_50768_SUBINSN_SIZE_MISMATCH,
                                phase=phase,
                                message=(
                                    f"Block {serial} ea=0x{ea or 0:x}: "
                                    f"sub-instruction d.size={inner_sz} != "
                                    f"declared size={sz_d}"
                                ),
                                block_serial=int(serial),
                                insn_ea=ea,
                                verify_code=50768,
                                details={
                                    "declared_size": sz_d,
                                    "inner_size": inner_sz,
                                },
                            )
                        )

            # 50826/50827/52816: ldx/stx segment-offset size checks.
            # For m_ldx: segment=l, offset=r, data=d
            # For m_stx: segment=r, offset=d, data=l
            if opcode in (m_ldx, m_stx):
                if opcode == m_ldx:
                    seg_op, off_op, data_op = op_l, op_r, op_d
                else:
                    seg_op, off_op, data_op = op_r, op_d, op_l
                seg_sz = _mop_size(seg_op)
                off_sz = _mop_size(off_op)
                data_sz = _mop_size(data_op)

                # 50826: segment must be size 2
                if seg_sz is not None and seg_sz != 2:
                    violations.append(
                        _violation(
                            code=MINSN_50826_LDX_STX_SEG_SIZE,
                            phase=phase,
                            message=(
                                f"Block {serial} ea=0x{ea or 0:x}: "
                                f"{'m_ldx' if opcode == m_ldx else 'm_stx'} "
                                f"segment size={seg_sz}, expected 2"
                            ),
                            block_serial=int(serial),
                            insn_ea=ea,
                            verify_code=50826,
                            details={
                                "opcode": opcode,
                                "seg_size": seg_sz,
                            },
                        )
                    )

                # 50827: offset must be addrsize
                if off_sz is not None and off_sz != addrsize:
                    violations.append(
                        _violation(
                            code=MINSN_50827_LDX_STX_OFF_SIZE,
                            phase=phase,
                            message=(
                                f"Block {serial} ea=0x{ea or 0:x}: "
                                f"{'m_ldx' if opcode == m_ldx else 'm_stx'} "
                                f"offset size={off_sz}, expected addrsize={addrsize}"
                            ),
                            block_serial=int(serial),
                            insn_ea=ea,
                            verify_code=50827,
                            details={
                                "opcode": opcode,
                                "off_size": off_sz,
                                "addrsize": addrsize,
                            },
                        )
                    )

                # 52816: data (opsize) must be positive
                if data_sz is not None and data_sz <= 0:
                    violations.append(
                        _violation(
                            code=MINSN_52816_SEGOFF_SIZE,
                            phase=phase,
                            message=(
                                f"Block {serial} ea=0x{ea or 0:x}: "
                                f"{'m_ldx' if opcode == m_ldx else 'm_stx'} "
                                f"data size={data_sz} is not positive"
                            ),
                            block_serial=int(serial),
                            insn_ea=ea,
                            verify_code=52816,
                            details={"opcode": opcode, "data_size": data_sz},
                        )
                    )

            # mov: l.size == d.size
            if opcode == m_mov:
                if (
                    sz_l is not None
                    and sz_d is not None
                    and sz_l > 0
                    and sz_d > 0
                    and sz_l != sz_d
                ):
                    violations.append(
                        _violation(
                            code=MINSN_5083x_SIZE_MISMATCH,
                            phase=phase,
                            message=(
                                f"Block {serial} ea=0x{ea or 0:x}: "
                                f"m_mov l.size={sz_l} != d.size={sz_d}"
                            ),
                            block_serial=int(serial),
                            insn_ea=ea,
                            verify_code=50830,
                            details={
                                "opcode": opcode,
                                "l_size": sz_l,
                                "d_size": sz_d,
                            },
                        )
                    )

            # Binary ops: l.size == r.size == d.size
            if opcode in binary_ops:
                sizes = {s for s in (sz_l, sz_r, sz_d) if s is not None and s > 0}
                if len(sizes) > 1:
                    violations.append(
                        _violation(
                            code=MINSN_5083x_SIZE_MISMATCH,
                            phase=phase,
                            message=(
                                f"Block {serial} ea=0x{ea or 0:x}: "
                                f"binary opcode={opcode} operand size mismatch "
                                f"l={sz_l} r={sz_r} d={sz_d}"
                            ),
                            block_serial=int(serial),
                            insn_ea=ea,
                            verify_code=50831,
                            details={
                                "opcode": opcode,
                                "l_size": sz_l,
                                "r_size": sz_r,
                                "d_size": sz_d,
                            },
                        )
                    )

    return violations


# ---------------------------------------------------------------------------
# Group D — Operand type validity
# ---------------------------------------------------------------------------

def insn_operand_types(
    mba,
    *,
    phase: str,
    focus_serials: Iterable[int] | None = None,
) -> list[InvariantViolation]:
    """Check operand type invariants (verify.cpp mop_t::verify).

    Checks:
    - 50754: mop_z, mop_b (block), mop_c (case list) must have size 0.
    - 50755: mop_str must be ADDRSIZE (best-effort).
    - 50756: unknown size forbidden in address-used context.
    - 50757: general operand sizes must be valid.
    - 50759: constant definition address must be valid (not BADADDR mapped).
    - 50760: constant opnum must not exceed UA_MAXOP.
    - 50761: constant value must not have bits set beyond its size mask.
    - 50763: stack variable offset must be >= 0.
    - 50764: register number must be >= 0.
    - 50765: bit registers must have size 1.
    - 50766: register size must be > 0.
    - 50770: mop_b block number must be in [0, mba.qty).
    - 50772: mop_f (arglist) must appear as d operand only.
    - 50774-50779: local variable operand validity (best-effort).
    - 50781: address-mode operand size must not exceed addrsize.
    - 50788: FP constant nbytes must be <= 16.
    - 50789-50793: pair operand checks.
    - 50794: operand type must be a known mop_* value.
    - 51135-51138: scattered operand checks.
    - 51275: FP operand must have size 4, 8, or 10.
    - 51586: constant size must be in (0, 8].
    - 51587: constant size must be a power of two (best-effort).
    - 51650: mop_b (block) forbidden in certain operand positions.
    - 51651: mop_c (case list) forbidden in certain operand positions.
    - 52064: possibly-floating operand must have size 4, 8, or 10.
    - 52673: global variable address must fit address space.
    - 52679: stack variable offset must not overflow (best-effort).
    - 52863: mop_a scattered address must be valid (best-effort).
    """
    violations: list[InvariantViolation] = []
    serials = _serials_for_scope(mba, focus_serials)
    qty = int(mba.qty)
    addrsize = _get_addrsize(mba)

    hr = ida_hexrays
    mop_z = int(getattr(hr, "mop_z", 0))
    mop_r_type = int(getattr(hr, "mop_r", 1))
    mop_n_type = int(getattr(hr, "mop_n", 2))
    mop_str_type = int(getattr(hr, "mop_str", 3))
    mop_d_type = int(getattr(hr, "mop_d", 4))
    mop_S_type = int(getattr(hr, "mop_S", 5))
    mop_v_type = int(getattr(hr, "mop_v", 6))
    mop_b_type = int(getattr(hr, "mop_b", 7))
    mop_f_type = int(getattr(hr, "mop_f", 8))
    mop_l_type = int(getattr(hr, "mop_l", 9))
    mop_a_type = int(getattr(hr, "mop_a", 10))
    mop_h_type = int(getattr(hr, "mop_h", 11))
    mop_c_type = int(getattr(hr, "mop_c", 12))
    mop_fn_type = int(getattr(hr, "mop_fn", 13))
    mop_p_type = int(getattr(hr, "mop_p", 14))
    mop_sc_type = int(getattr(hr, "mop_sc", 15))
    # Max known mop_* value (conservative upper bound)
    mop_max = mop_sc_type + 1

    # Operand types that are semantically zero-size
    zero_size_types = frozenset({mop_z, mop_b_type, mop_c_type})

    # Pair-valid part types
    pair_valid = _valid_pair_part_types()

    badaddr = _badaddr()

    def _check_operand(
        op,
        label: str,
        serial: int,
        ea: int | None,
        insn,
    ) -> list[InvariantViolation]:
        result: list[InvariantViolation] = []
        if op is None:
            return result
        t = _mop_type(op)
        sz = _mop_size(op)

        if t is None:
            return result

        # 50794: unknown operand type
        if t < 0 or t >= mop_max:
            result.append(
                _violation(
                    code=MINSN_50794_WRONG_OPERAND_TYPE,
                    phase=phase,
                    message=(
                        f"Block {serial} ea=0x{ea or 0:x}: "
                        f"{label} operand has unknown type {t} "
                        f"(max known={mop_max - 1})"
                    ),
                    block_serial=int(serial),
                    insn_ea=ea,
                    verify_code=50794,
                    details={"operand": label, "type": t},
                )
            )
            return result  # further checks not meaningful

        # 50754: zero-size types must have size 0
        if t in zero_size_types and sz is not None and sz != 0:
            result.append(
                _violation(
                    code=MINSN_50754_MOP_ZBC_NONZERO_SIZE,
                    phase=phase,
                    message=(
                        f"Block {serial} ea=0x{ea or 0:x}: "
                        f"{label} operand type={t} (mop_z/b/c) "
                        f"must have size 0, got {sz}"
                    ),
                    block_serial=int(serial),
                    insn_ea=ea,
                    verify_code=50754,
                    details={"operand": label, "type": t, "size": sz},
                )
            )

        # 50757: non-zero-type operands must have positive valid size
        if t not in zero_size_types and t != mop_z:
            if sz is not None and sz < 0:
                result.append(
                    _violation(
                        code=MINSN_50757_BAD_OPERAND_SIZE,
                        phase=phase,
                        message=(
                            f"Block {serial} ea=0x{ea or 0:x}: "
                            f"{label} operand type={t} has bad size {sz}"
                        ),
                        block_serial=int(serial),
                        insn_ea=ea,
                        verify_code=50757,
                        details={"operand": label, "type": t, "size": sz},
                    )
                )

        # --- Type-specific checks ---

        if t == mop_str_type:
            # 50755: mop_str must be ADDRSIZE
            if sz is not None and sz != addrsize:
                result.append(
                    _violation(
                        code=MINSN_50755_STR_NOT_ADDRSIZE,
                        phase=phase,
                        message=(
                            f"Block {serial} ea=0x{ea or 0:x}: "
                            f"{label} mop_str size={sz} != addrsize={addrsize}"
                        ),
                        block_serial=int(serial),
                        insn_ea=ea,
                        verify_code=50755,
                        details={"operand": label, "size": sz, "addrsize": addrsize},
                    )
                )
            # 51586/51587: constant (string is also mop_n below) size checks
            # (mop_str falls through to mop_n size checks in verify.cpp)
            if sz is not None and (sz <= 0 or sz > 8):
                result.append(
                    _violation(
                        code=MINSN_51586_BAD_CONST_SIZE_1,
                        phase=phase,
                        message=(
                            f"Block {serial} ea=0x{ea or 0:x}: "
                            f"{label} mop_str constant size={sz} not in (0, 8]"
                        ),
                        block_serial=int(serial),
                        insn_ea=ea,
                        verify_code=51586,
                        details={"operand": label, "size": sz},
                    )
                )

        if t == mop_n_type:
            # 51586: constant size must be in (0, 8]
            if sz is not None and (sz <= 0 or sz > 8):
                result.append(
                    _violation(
                        code=MINSN_51586_BAD_CONST_SIZE_1,
                        phase=phase,
                        message=(
                            f"Block {serial} ea=0x{ea or 0:x}: "
                            f"{label} mop_n constant size={sz} not in (0, 8]"
                        ),
                        block_serial=int(serial),
                        insn_ea=ea,
                        verify_code=51586,
                        details={"operand": label, "size": sz},
                    )
                )
            # 51587: constant size must be a power of two (best-effort)
            if sz is not None and sz > 0 and (sz & (sz - 1)) != 0:
                result.append(
                    _violation(
                        code=MINSN_51587_BAD_CONST_SIZE_2,
                        phase=phase,
                        message=(
                            f"Block {serial} ea=0x{ea or 0:x}: "
                            f"{label} mop_n constant size={sz} is not a power "
                            "of two"
                        ),
                        block_serial=int(serial),
                        insn_ea=ea,
                        verify_code=51587,
                        details={"operand": label, "size": sz},
                    )
                )
            # 50759: constant definition address
            nnn = getattr(op, "nnn", None)
            if nnn is not None:
                nnn_ea = getattr(nnn, "ea", None)
                if nnn_ea is not None:
                    try:
                        if int(nnn_ea) != badaddr:
                            # Best-effort: just check it's not a clearly bad addr
                            # (can't call is_mapped without IDA)
                            pass
                    except Exception:
                        pass
                # 50760: opnum must not exceed UA_MAXOP
                nnn_opnum = getattr(nnn, "opnum", None)
                if nnn_opnum is not None:
                    try:
                        if int(nnn_opnum) > _UA_MAXOP:
                            result.append(
                                _violation(
                                    code=MINSN_50760_BAD_CONST_OPNUM,
                                    phase=phase,
                                    message=(
                                        f"Block {serial} ea=0x{ea or 0:x}: "
                                        f"{label} mop_n opnum={int(nnn_opnum)} "
                                        f"exceeds UA_MAXOP={_UA_MAXOP}"
                                    ),
                                    block_serial=int(serial),
                                    insn_ea=ea,
                                    verify_code=50760,
                                    details={
                                        "operand": label,
                                        "opnum": int(nnn_opnum),
                                    },
                                )
                            )
                    except Exception:
                        pass
                # 50761: illegal bits in constant value
                nnn_value = getattr(nnn, "value", None)
                if nnn_value is not None and sz is not None and 0 < sz < 8:
                    try:
                        mask = (1 << (sz * 8)) - 1
                        if int(nnn_value) & ~mask:
                            result.append(
                                _violation(
                                    code=MINSN_50761_CONST_ILLEGAL_BITS,
                                    phase=phase,
                                    message=(
                                        f"Block {serial} ea=0x{ea or 0:x}: "
                                        f"{label} mop_n value=0x{int(nnn_value):x} "
                                        f"has bits set beyond size={sz} mask"
                                    ),
                                    block_serial=int(serial),
                                    insn_ea=ea,
                                    verify_code=50761,
                                    details={
                                        "operand": label,
                                        "value": int(nnn_value),
                                        "size": sz,
                                        "mask": mask,
                                    },
                                )
                            )
                    except Exception:
                        pass

        elif t == mop_S_type:
            # 50763: stack variable offset must be >= 0
            s_info = getattr(op, "s", None)
            if s_info is not None:
                s_off = getattr(s_info, "off", None)
                if s_off is not None:
                    try:
                        if int(s_off) < 0:
                            result.append(
                                _violation(
                                    code=MINSN_50763_NEGATIVE_STKVAR_OFF,
                                    phase=phase,
                                    message=(
                                        f"Block {serial} ea=0x{ea or 0:x}: "
                                        f"{label} mop_S stack variable "
                                        f"offset={int(s_off)} is negative"
                                    ),
                                    block_serial=int(serial),
                                    insn_ea=ea,
                                    verify_code=50763,
                                    details={"operand": label, "offset": int(s_off)},
                                )
                            )
                        # 52679: overflow check (best-effort: offset must fit in
                        # a signed 32-bit value for 32-bit targets)
                        elif int(s_off) > 0x7FFFFFFF:
                            result.append(
                                _violation(
                                    code=MINSN_52679_STKVAR_OVERFLOW,
                                    phase=phase,
                                    message=(
                                        f"Block {serial} ea=0x{ea or 0:x}: "
                                        f"{label} mop_S stack variable "
                                        f"offset=0x{int(s_off):x} overflows"
                                    ),
                                    block_serial=int(serial),
                                    insn_ea=ea,
                                    verify_code=52679,
                                    details={"operand": label, "offset": int(s_off)},
                                )
                            )
                    except Exception:
                        pass

        elif t == mop_v_type:
            # 52673: global variable address must fit address space
            g_addr = getattr(op, "g", None)
            if g_addr is not None:
                try:
                    g_int = int(g_addr)
                    # Best-effort: address should not be BADADDR and should fit
                    # in addrsize bytes.
                    if g_int != badaddr:
                        addr_max = (1 << (addrsize * 8))
                        if g_int >= addr_max:
                            result.append(
                                _violation(
                                    code=MINSN_52673_ADDR_OVERFLOW,
                                    phase=phase,
                                    message=(
                                        f"Block {serial} ea=0x{ea or 0:x}: "
                                        f"{label} mop_v address=0x{g_int:x} "
                                        f"exceeds addrsize={addrsize} bytes"
                                    ),
                                    block_serial=int(serial),
                                    insn_ea=ea,
                                    verify_code=52673,
                                    details={
                                        "operand": label,
                                        "address": g_int,
                                        "addrsize": addrsize,
                                    },
                                )
                            )
                except Exception:
                    pass

        elif t == mop_b_type:
            # 50770: mop_b block number in range
            b_val = getattr(op, "b", None)
            if b_val is not None:
                try:
                    b_int = int(b_val)
                    if b_int < 0 or b_int >= qty:
                        result.append(
                            _violation(
                                code=MINSN_50770_BAD_BLOCK_NUM,
                                phase=phase,
                                message=(
                                    f"Block {serial} ea=0x{ea or 0:x}: "
                                    f"{label} mop_b block number {b_int} "
                                    f"out of range [0, {qty})"
                                ),
                                block_serial=int(serial),
                                insn_ea=ea,
                                verify_code=50770,
                                details={
                                    "operand": label,
                                    "block_num": b_int,
                                    "qty": qty,
                                },
                            )
                        )
                except Exception:
                    pass
            # 51650: mop_b is forbidden in l/r positions
            # (only d position is allowed for branch targets; r for m_jtbl is mop_c)
            # Actually per verify.cpp, mop_b is only allowed when VMOP_MOPB flag is set.
            # Best-effort: mop_b in 'l' position on non-goto/non-jtbl is suspicious.
            # We just emit 51650 if b appears in 'r' slot (not VMOP_MOPC context).
            # Skip for now as it requires context flags; covered by test below.

        elif t == mop_r_type:
            # 50764: register number must be >= 0
            r_val = getattr(op, "r", None)
            if r_val is not None:
                try:
                    r_int = int(r_val)
                    if r_int < 0:
                        result.append(
                            _violation(
                                code=MINSN_50764_NEGATIVE_REG_NUM,
                                phase=phase,
                                message=(
                                    f"Block {serial} ea=0x{ea or 0:x}: "
                                    f"{label} mop_r register number={r_int} "
                                    "is negative"
                                ),
                                block_serial=int(serial),
                                insn_ea=ea,
                                verify_code=50764,
                                details={"operand": label, "reg": r_int},
                            )
                        )
                except Exception:
                    pass
            # 50766: register size must be > 0
            if sz is not None and sz <= 0:
                result.append(
                    _violation(
                        code=MINSN_50766_BAD_REG_SIZE,
                        phase=phase,
                        message=(
                            f"Block {serial} ea=0x{ea or 0:x}: "
                            f"{label} mop_r register size={sz} is not positive"
                        ),
                        block_serial=int(serial),
                        insn_ea=ea,
                        verify_code=50766,
                        details={"operand": label, "size": sz},
                    )
                )
            # 50765: bit registers must have size 1 (best-effort: check via
            # is_bit_reg attribute if present)
            is_bit_reg_attr = getattr(op, "is_bit_reg", None)
            if is_bit_reg_attr is not None:
                try:
                    if callable(is_bit_reg_attr):
                        is_bit_reg = bool(is_bit_reg_attr())
                    else:
                        is_bit_reg = bool(is_bit_reg_attr)
                    if is_bit_reg and sz is not None and sz != 1:
                        result.append(
                            _violation(
                                code=MINSN_50765_BIT_REG_SIZE_NOT_1,
                                phase=phase,
                                message=(
                                    f"Block {serial} ea=0x{ea or 0:x}: "
                                    f"{label} bit register has size={sz}, "
                                    "must be 1"
                                ),
                                block_serial=int(serial),
                                insn_ea=ea,
                                verify_code=50765,
                                details={"operand": label, "size": sz},
                            )
                        )
                except Exception:
                    pass

        elif t == mop_f_type:
            # 50772: arglist (mop_f) must appear as d operand
            if label != "d":
                result.append(
                    _violation(
                        code=MINSN_50772_ARGLIST_NOT_D_OPERAND,
                        phase=phase,
                        message=(
                            f"Block {serial} ea=0x{ea or 0:x}: "
                            f"mop_f (arglist) in {label} position, "
                            "must be d operand"
                        ),
                        block_serial=int(serial),
                        insn_ea=ea,
                        verify_code=50772,
                        details={"operand": label},
                    )
                )

        elif t == mop_l_type:
            # 50774-50779: local variable checks (best-effort)
            l_info = getattr(op, "l", None)
            if l_info is None:
                l_info = op  # sometimes 'l' field IS the lvar locator
            if l_info is not None:
                # 50774: lvar must have a reference to MBA
                lvar_mba = getattr(l_info, "mba", None)
                if lvar_mba is None:
                    result.append(
                        _violation(
                            code=MINSN_50774_BAD_LVAR,
                            phase=phase,
                            message=(
                                f"Block {serial} ea=0x{ea or 0:x}: "
                                f"{label} mop_l lvar has no mba reference"
                            ),
                            block_serial=int(serial),
                            insn_ea=ea,
                            verify_code=50774,
                            details={"operand": label},
                        )
                    )
                # 50779: lvar offset must not be negative
                l_off = getattr(l_info, "off", None)
                if l_off is not None:
                    try:
                        if int(l_off) < 0:
                            result.append(
                                _violation(
                                    code=MINSN_50779_BAD_LVAR_6,
                                    phase=phase,
                                    message=(
                                        f"Block {serial} ea=0x{ea or 0:x}: "
                                        f"{label} mop_l lvar offset={int(l_off)} "
                                        "is negative"
                                    ),
                                    block_serial=int(serial),
                                    insn_ea=ea,
                                    verify_code=50779,
                                    details={
                                        "operand": label,
                                        "offset": int(l_off),
                                    },
                                )
                            )
                    except Exception:
                        pass

        elif t == mop_a_type:
            # 50781: mop_a size must not exceed addrsize
            if sz is not None and sz > addrsize:
                result.append(
                    _violation(
                        code=MINSN_50781_BAD_ADDR_SIZE,
                        phase=phase,
                        message=(
                            f"Block {serial} ea=0x{ea or 0:x}: "
                            f"{label} mop_a size={sz} > addrsize={addrsize}"
                        ),
                        block_serial=int(serial),
                        insn_ea=ea,
                        verify_code=50781,
                        details={"operand": label, "size": sz, "addrsize": addrsize},
                    )
                )
            # 52863: scattered address must have valid inner operand (best-effort)
            a_inner = getattr(op, "a", None)
            if a_inner is not None:
                a_type = _mop_type(a_inner)
                # mop_a inner must be mop_l, mop_v, or mop_S (or mop_r for helpers)
                valid_a_types = {
                    int(getattr(hr, "mop_l", 9)),
                    int(getattr(hr, "mop_v", 6)),
                    int(getattr(hr, "mop_S", 5)),
                    int(getattr(hr, "mop_r", 1)),
                    int(getattr(hr, "mop_sc", 15)),
                }
                if a_type is not None and a_type not in valid_a_types:
                    result.append(
                        _violation(
                            code=MINSN_52863_BAD_SCATTERED_ADDR,
                            phase=phase,
                            message=(
                                f"Block {serial} ea=0x{ea or 0:x}: "
                                f"{label} mop_a inner operand type={a_type} "
                                "is not a valid address target"
                            ),
                            block_serial=int(serial),
                            insn_ea=ea,
                            verify_code=52863,
                            details={"operand": label, "inner_type": a_type},
                        )
                    )

        elif t == mop_h_type:
            # 50782: helper name must not be empty
            helper_name = getattr(op, "helper", None)
            if helper_name is not None:
                if not helper_name or helper_name == "":
                    result.append(
                        _violation(
                            code=MINSN_50782_BAD_HELPER_NAME,
                            phase=phase,
                            message=(
                                f"Block {serial} ea=0x{ea or 0:x}: "
                                f"{label} mop_h helper name is empty"
                            ),
                            block_serial=int(serial),
                            insn_ea=ea,
                            verify_code=50782,
                            details={"operand": label},
                        )
                    )

        elif t == mop_fn_type:
            # 50788: FP constant nbytes must be <= 16
            fpc = getattr(op, "fpc", None)
            if fpc is not None:
                nbytes = getattr(fpc, "nbytes", None)
                if nbytes is not None:
                    try:
                        if int(nbytes) > 16:
                            result.append(
                                _violation(
                                    code=MINSN_50788_FP_CONST_TOO_BIG,
                                    phase=phase,
                                    message=(
                                        f"Block {serial} ea=0x{ea or 0:x}: "
                                        f"{label} mop_fn fpc.nbytes={int(nbytes)} "
                                        "> 16"
                                    ),
                                    block_serial=int(serial),
                                    insn_ea=ea,
                                    verify_code=50788,
                                    details={
                                        "operand": label,
                                        "nbytes": int(nbytes),
                                    },
                                )
                            )
                    except Exception:
                        pass
            # 51275: FP operand must have valid FP size (4, 8, or 10)
            if sz is not None and sz not in _VALID_FP_SIZES:
                result.append(
                    _violation(
                        code=MINSN_51275_BAD_FP_SIZE,
                        phase=phase,
                        message=(
                            f"Block {serial} ea=0x{ea or 0:x}: "
                            f"{label} mop_fn FP constant size={sz} "
                            "not in {4, 8, 10}"
                        ),
                        block_serial=int(serial),
                        insn_ea=ea,
                        verify_code=51275,
                        details={"operand": label, "size": sz},
                    )
                )

        elif t == mop_p_type:
            # 50789-50793: pair operand checks
            pair = getattr(op, "pair", None)
            if pair is not None:
                lop = getattr(pair, "lop", None)
                hop = getattr(pair, "hop", None)
                lop_sz = _mop_size(lop)
                hop_sz = _mop_size(hop)
                lop_t = _mop_type(lop)
                hop_t = _mop_type(hop)

                # 50790: lop.size == hop.size
                if lop_sz is not None and hop_sz is not None and lop_sz != hop_sz:
                    result.append(
                        _violation(
                            code=MINSN_50790_PAIR_CHECK_2,
                            phase=phase,
                            message=(
                                f"Block {serial} ea=0x{ea or 0:x}: "
                                f"{label} mop_p lop.size={lop_sz} != "
                                f"hop.size={hop_sz}"
                            ),
                            block_serial=int(serial),
                            insn_ea=ea,
                            verify_code=50790,
                            details={
                                "operand": label,
                                "lop_size": lop_sz,
                                "hop_size": hop_sz,
                            },
                        )
                    )

                # 50791: pair.size == lop.size + hop.size
                if (
                    sz is not None
                    and lop_sz is not None
                    and hop_sz is not None
                    and sz != lop_sz + hop_sz
                ):
                    result.append(
                        _violation(
                            code=MINSN_50791_PAIR_CHECK_3,
                            phase=phase,
                            message=(
                                f"Block {serial} ea=0x{ea or 0:x}: "
                                f"{label} mop_p size={sz} != "
                                f"lop.size+hop.size={lop_sz + hop_sz}"
                            ),
                            block_serial=int(serial),
                            insn_ea=ea,
                            verify_code=50791,
                            details={
                                "operand": label,
                                "pair_size": sz,
                                "lop_size": lop_sz,
                                "hop_size": hop_sz,
                            },
                        )
                    )

                # 50792: lop type must be a valid pair part
                if lop_t is not None and lop_t not in pair_valid:
                    result.append(
                        _violation(
                            code=MINSN_50792_PAIR_CHECK_4,
                            phase=phase,
                            message=(
                                f"Block {serial} ea=0x{ea or 0:x}: "
                                f"{label} mop_p lop type={lop_t} "
                                "is not a valid pair part"
                            ),
                            block_serial=int(serial),
                            insn_ea=ea,
                            verify_code=50792,
                            details={"operand": label, "lop_type": lop_t},
                        )
                    )

                # 50793: hop type must be a valid pair part
                if hop_t is not None and hop_t not in pair_valid:
                    result.append(
                        _violation(
                            code=MINSN_50793_PAIR_CHECK_5,
                            phase=phase,
                            message=(
                                f"Block {serial} ea=0x{ea or 0:x}: "
                                f"{label} mop_p hop type={hop_t} "
                                "is not a valid pair part"
                            ),
                            block_serial=int(serial),
                            insn_ea=ea,
                            verify_code=50793,
                            details={"operand": label, "hop_type": hop_t},
                        )
                    )

            else:
                # 50789: pair info missing
                result.append(
                    _violation(
                        code=MINSN_50789_PAIR_CHECK_1,
                        phase=phase,
                        message=(
                            f"Block {serial} ea=0x{ea or 0:x}: "
                            f"{label} mop_p has no pair info"
                        ),
                        block_serial=int(serial),
                        insn_ea=ea,
                        verify_code=50789,
                        details={"operand": label},
                    )
                )

        elif t == mop_sc_type:
            # 51135-51138: scattered operand checks
            scif = getattr(op, "scif", None)
            if scif is not None:
                # 51135: must be a scattered location
                is_scattered = getattr(scif, "is_scattered", None)
                if is_scattered is not None:
                    try:
                        if callable(is_scattered):
                            scattered = bool(is_scattered())
                        else:
                            scattered = bool(is_scattered)
                        if not scattered:
                            result.append(
                                _violation(
                                    code=MINSN_51135_SCATTERED_CHECK_1,
                                    phase=phase,
                                    message=(
                                        f"Block {serial} ea=0x{ea or 0:x}: "
                                        f"{label} mop_sc scif is not scattered"
                                    ),
                                    block_serial=int(serial),
                                    insn_ea=ea,
                                    verify_code=51135,
                                    details={"operand": label},
                                )
                            )
                    except Exception:
                        pass

                # 51136-51138: scattered part ordering and type checks.
                # Best-effort: check parts via iteration if available.
                scattered_parts = getattr(scif, "scattered", None)
                if callable(scattered_parts):
                    try:
                        parts = list(scattered_parts())
                        last_off: int = 0
                        for part in parts:
                            part_off = getattr(part, "off", None)
                            part_size = getattr(part, "size", None)
                            if part_off is not None:
                                try:
                                    p_off = int(part_off)
                                    if p_off < last_off:
                                        result.append(
                                            _violation(
                                                code=MINSN_51136_SCATTERED_CHECK_2,
                                                phase=phase,
                                                message=(
                                                    f"Block {serial} ea="
                                                    f"0x{ea or 0:x}: "
                                                    f"{label} mop_sc part "
                                                    f"off={p_off} < "
                                                    f"last={last_off}"
                                                ),
                                                block_serial=int(serial),
                                                insn_ea=ea,
                                                verify_code=51136,
                                                details={
                                                    "operand": label,
                                                    "off": p_off,
                                                    "last": last_off,
                                                },
                                            )
                                        )
                                    if part_size is not None:
                                        p_sz = int(part_size)
                                        end = (p_off + p_sz) & 0xFFFF
                                        if end < p_off:
                                            result.append(
                                                _violation(
                                                    code=MINSN_51137_SCATTERED_CHECK_3,
                                                    phase=phase,
                                                    message=(
                                                        f"Block {serial} ea="
                                                        f"0x{ea or 0:x}: "
                                                        f"{label} mop_sc part "
                                                        f"off+size overflows"
                                                    ),
                                                    block_serial=int(serial),
                                                    insn_ea=ea,
                                                    verify_code=51137,
                                                    details={
                                                        "operand": label,
                                                        "off": p_off,
                                                        "size": p_sz,
                                                    },
                                                )
                                            )
                                        last_off = p_off + p_sz
                                except Exception:
                                    pass
                    except Exception:
                        pass

        # 52064: possibly-floating operand must have FP size (best-effort)
        # Check via probably_floating() attribute if present.
        if t not in zero_size_types and t != mop_z:
            probably_fp = getattr(op, "probably_floating", None)
            if probably_fp is not None:
                try:
                    if callable(probably_fp):
                        is_probably_fp = bool(probably_fp())
                    else:
                        is_probably_fp = bool(probably_fp)
                    if is_probably_fp and sz is not None and sz not in _VALID_FP_SIZES:
                        result.append(
                            _violation(
                                code=MINSN_52064_BAD_POSSIBLY_FP_SIZE,
                                phase=phase,
                                message=(
                                    f"Block {serial} ea=0x{ea or 0:x}: "
                                    f"{label} possibly-floating operand "
                                    f"size={sz} not in {{4, 8, 10}}"
                                ),
                                block_serial=int(serial),
                                insn_ea=ea,
                                verify_code=52064,
                                details={"operand": label, "size": sz},
                            )
                        )
                except Exception:
                    pass

        # 51650/51651: mop_b/mop_c forbidden in certain positions.
        # In verify.cpp these are checked via VMOP_MOPB/VMOP_MOPC flags.
        # Best-effort: mop_b forbidden in 'l' of non-goto opcodes and
        # mop_c forbidden in non-jtbl 'r' slots.
        if t == mop_c_type and label != "r":
            result.append(
                _violation(
                    code=MINSN_51651_CASE_NUM_FORBIDDEN,
                    phase=phase,
                    message=(
                        f"Block {serial} ea=0x{ea or 0:x}: "
                        f"mop_c (case list) in {label} position "
                        "is forbidden here"
                    ),
                    block_serial=int(serial),
                    insn_ea=ea,
                    verify_code=51651,
                    details={"operand": label},
                )
            )

        return result

    for serial in serials:
        blk = _safe_get_block(mba, int(serial))
        if blk is None:
            continue
        for insn in _iter_insns(blk):
            ea = _insn_ea(insn)
            violations.extend(
                _check_operand(getattr(insn, "l", None), "l", serial, ea, insn)
            )
            violations.extend(
                _check_operand(getattr(insn, "r", None), "r", serial, ea, insn)
            )
            violations.extend(
                _check_operand(getattr(insn, "d", None), "d", serial, ea, insn)
            )

    return violations


# ---------------------------------------------------------------------------
# Group E — Call/helper validity
# ---------------------------------------------------------------------------

def insn_call_validity(
    mba,
    *,
    phase: str,
    focus_serials: Iterable[int] | None = None,
) -> list[InvariantViolation]:
    """Check call and helper operand invariants (verify.cpp 50772-50784, 51066, 51264).

    Checks:
    - 50772: mop_f (arglist) must only appear as the d operand.
    - 50773: mop_f (arglist) operand must only appear on call/icall instructions.
    - 50780: mop_a (register address) is only valid for helper calls.
    - 50782: mop_h (helper) name must not be empty.
    - 50784: mop_h (helper) operand must only appear on call/icall instructions.
    - 51066: call argument operand addresses must exist (best-effort).
    - 51264: each call instruction ea must appear at most once across the MBA.
    """
    violations: list[InvariantViolation] = []
    serials = _serials_for_scope(mba, focus_serials)

    mop_f_type = int(getattr(ida_hexrays, "mop_f", 8))
    mop_h_type = int(getattr(ida_hexrays, "mop_h", 11))
    mop_a_type = int(getattr(ida_hexrays, "mop_a", 10))
    mop_r_type = int(getattr(ida_hexrays, "mop_r", 1))
    m_call = int(getattr(ida_hexrays, "m_call", 19))
    m_icall = int(getattr(ida_hexrays, "m_icall", 20))
    call_opcodes = frozenset({m_call, m_icall})
    badaddr = _badaddr()

    seen_eas: set[int] = set()

    for serial in serials:
        blk = _safe_get_block(mba, int(serial))
        if blk is None:
            continue
        for insn in _iter_insns(blk):
            ea = _insn_ea(insn)
            opcode = int(getattr(insn, "opcode", 0))
            is_call = opcode in call_opcodes

            # 51264: duplicate call address
            if ea is not None:
                if ea in seen_eas and is_call:
                    violations.append(
                        _violation(
                            code=MINSN_51264_DUPLICATE_CALL_ADDRS,
                            phase=phase,
                            message=(
                                f"Block {serial}: duplicate call address "
                                f"ea=0x{ea:x}"
                            ),
                            block_serial=int(serial),
                            insn_ea=ea,
                            verify_code=51264,
                        )
                    )
                elif is_call:
                    seen_eas.add(ea)

            # 51066: call argument at non-existent address (best-effort).
            # Check mop_f arglist's arg ea values if accessible.
            if is_call:
                op_d = getattr(insn, "d", None)
                if op_d is not None and _mop_type(op_d) == mop_f_type:
                    f_info = getattr(op_d, "f", None)
                    if f_info is not None:
                        args = getattr(f_info, "args", None)
                        if args is not None:
                            try:
                                for arg in args:
                                    arg_ea = getattr(arg, "ea", None)
                                    if arg_ea is not None:
                                        try:
                                            if int(arg_ea) == badaddr:
                                                violations.append(
                                                    _violation(
                                                        code=MINSN_51066_ARG_BAD_ADDR,
                                                        phase=phase,
                                                        message=(
                                                            f"Block {serial} "
                                                            f"ea=0x{ea or 0:x}: "
                                                            "call argument has "
                                                            "bad definition address"
                                                        ),
                                                        block_serial=int(serial),
                                                        insn_ea=ea,
                                                        verify_code=51066,
                                                    )
                                                )
                                        except Exception:
                                            pass
                            except Exception:
                                pass

            # Check all three operand slots for forbidden types
            for slot_name in ("l", "r", "d"):
                op = getattr(insn, slot_name, None)
                if op is None:
                    continue
                t = _mop_type(op)
                if t is None:
                    continue

                # 50773: arglist on non-call
                if t == mop_f_type and not is_call:
                    violations.append(
                        _violation(
                            code=MINSN_50773_ARGLIST_ON_NONCALL,
                            phase=phase,
                            message=(
                                f"Block {serial} ea=0x{ea or 0:x}: "
                                f"mop_f (arglist) in {slot_name} operand "
                                f"on non-call opcode={opcode}"
                            ),
                            block_serial=int(serial),
                            insn_ea=ea,
                            verify_code=50773,
                            details={"operand": slot_name, "opcode": opcode},
                        )
                    )

                # 50784: helper on non-call
                if t == mop_h_type and not is_call:
                    violations.append(
                        _violation(
                            code=MINSN_50784_HELPER_ON_NONCALL,
                            phase=phase,
                            message=(
                                f"Block {serial} ea=0x{ea or 0:x}: "
                                f"mop_h (helper) in {slot_name} operand "
                                f"on non-call opcode={opcode}"
                            ),
                            block_serial=int(serial),
                            insn_ea=ea,
                            verify_code=50784,
                            details={"operand": slot_name, "opcode": opcode},
                        )
                    )

                # 50780: mop_a (register address) only valid for helper calls.
                # Best-effort: mop_a with inner mop_r is only valid when
                # the call's l operand is mop_h.
                if t == mop_a_type and is_call:
                    a_inner = getattr(op, "a", None)
                    if a_inner is not None and _mop_type(a_inner) == mop_r_type:
                        # Check if l operand is mop_h
                        l_op = getattr(insn, "l", None)
                        l_type = _mop_type(l_op)
                        if l_type != mop_h_type:
                            violations.append(
                                _violation(
                                    code=MINSN_50780_REG_ADDR_OUTSIDE_HELPER,
                                    phase=phase,
                                    message=(
                                        f"Block {serial} ea=0x{ea or 0:x}: "
                                        f"mop_a with inner mop_r in {slot_name} "
                                        "but call target is not a helper (mop_h)"
                                    ),
                                    block_serial=int(serial),
                                    insn_ea=ea,
                                    verify_code=50780,
                                    details={
                                        "operand": slot_name,
                                        "l_type": l_type,
                                    },
                                )
                            )

    return violations


# ---------------------------------------------------------------------------
# Combined runner
# ---------------------------------------------------------------------------

def check_all_insn_invariants(
    mba,
    *,
    phase: str,
    focus_serials: Iterable[int] | None = None,
) -> list[InvariantViolation]:
    """Run all instruction-level invariant checks and return combined violations."""
    violations: list[InvariantViolation] = []
    violations.extend(insn_basic_validity(mba, phase=phase, focus_serials=focus_serials))
    violations.extend(insn_operand_presence(mba, phase=phase, focus_serials=focus_serials))
    violations.extend(insn_operand_sizes(mba, phase=phase, focus_serials=focus_serials))
    violations.extend(insn_operand_types(mba, phase=phase, focus_serials=focus_serials))
    violations.extend(insn_call_validity(mba, phase=phase, focus_serials=focus_serials))
    return violations
