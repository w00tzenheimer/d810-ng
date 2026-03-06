"""Unit tests for insn_invariants.py — instruction-level CFG invariant checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from d810.core.typing import Any

import pytest

from d810.cfg.contracts import insn_invariants as inv

_HR = inv.ida_hexrays


# ---------------------------------------------------------------------------
# Mock infrastructure
# ---------------------------------------------------------------------------

@dataclass
class _Mop:
    t: int
    size: int = 4
    b: int | None = None
    r: int | None = None
    g: int | None = None
    nnn: Any = None
    s: Any = None
    l: Any = None
    a: Any = None
    helper: str | None = None
    fpc: Any = None
    pair: Any = None
    scif: Any = None

    def is_mblock(self) -> bool:
        return self.t == int(getattr(_HR, "mop_b", 7))


@dataclass
class _Insn:
    opcode: int
    ea: int = 0x401000
    l: _Mop | None = None
    r: _Mop | None = None
    d: _Mop | None = None
    next: object | None = field(default=None, repr=False)
    prev: object | None = field(default=None, repr=False)


class _Block:
    def __init__(self, serial: int, insns: list[_Insn] | None = None):
        self.serial = serial
        self.start = 0x401000
        self.end = 0x402000
        self._insns = insns or []
        # Wire up linked list
        self.head: _Insn | None = None
        self.tail: _Insn | None = None
        if self._insns:
            self.head = self._insns[0]
            self.tail = self._insns[-1]
            for i in range(len(self._insns) - 1):
                self._insns[i].next = self._insns[i + 1]
                self._insns[i + 1].prev = self._insns[i]


class _MBA:
    def __init__(self, blocks: list[_Block], entry_ea: int = 0x401000):
        self._blocks = {blk.serial: blk for blk in blocks}
        self.qty = len(blocks)
        self.entry_ea = entry_ea

    def get_mblock(self, serial: int) -> _Block | None:
        return self._blocks.get(int(serial))


def _simple_mba(*insn_lists: list[_Insn], entry_ea: int = 0x401000) -> _MBA:
    blocks = [_Block(i, insns) for i, insns in enumerate(insn_lists)]
    return _MBA(blocks, entry_ea=entry_ea)


def _codes(violations) -> set[str]:
    return {v.code for v in violations}


def _mop_z() -> _Mop:
    return _Mop(t=int(getattr(_HR, "mop_z", 0)), size=0)


def _mop_r(size: int = 4) -> _Mop:
    return _Mop(t=int(getattr(_HR, "mop_r", 1)), size=size)


def _mop_b(block_num: int = 1, size: int = 0) -> _Mop:
    return _Mop(t=int(getattr(_HR, "mop_b", 7)), size=size, b=block_num)


def _mop_n(size: int = 4) -> _Mop:
    return _Mop(t=int(getattr(_HR, "mop_n", 2)), size=size)


def _mop_f(size: int = 0) -> _Mop:
    return _Mop(t=int(getattr(_HR, "mop_f", 8)), size=size)


def _mop_h(size: int = 0) -> _Mop:
    return _Mop(t=int(getattr(_HR, "mop_h", 11)), size=size)


# ---------------------------------------------------------------------------
# Group A — insn_basic_validity
# ---------------------------------------------------------------------------

class TestInsnBasicValidity:
    def test_clean_nop_no_violations(self):
        m_nop = int(getattr(_HR, "m_nop", 0))
        mba = _simple_mba([_Insn(m_nop, ea=0x401000)])
        viols = inv.insn_basic_validity(mba, phase="test")
        assert not viols

    def test_clean_add_no_violations(self):
        m_add = int(getattr(_HR, "m_add", 24))
        insn = _Insn(m_add, ea=0x401010, l=_mop_r(4), r=_mop_r(4), d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_basic_validity(mba, phase="test")
        assert not viols

    def test_50795_badaddr_detected(self):
        m_nop = int(getattr(_HR, "m_nop", 0))
        badaddr = int(getattr(_HR, "BADADDR", 0xFFFFFFFFFFFFFFFF))
        mba = _simple_mba([_Insn(m_nop, ea=badaddr)])
        viols = inv.insn_basic_validity(mba, phase="test")
        assert inv.MINSN_50795_BADADDR in _codes(viols)

    def test_50804_invalid_opcode_detected(self):
        mba = _simple_mba([_Insn(9999, ea=0x401000)])
        viols = inv.insn_basic_validity(mba, phase="test")
        assert inv.MINSN_50804_INVALID_OPCODE in _codes(viols)

    def test_50804_valid_opcode_no_violation(self):
        m_mov = int(getattr(_HR, "m_mov", 21))
        mba = _simple_mba([_Insn(m_mov, ea=0x401000, l=_mop_r(4), d=_mop_r(4))])
        viols = inv.insn_basic_validity(mba, phase="test")
        assert inv.MINSN_50804_INVALID_OPCODE not in _codes(viols)

    def test_50806_nop_with_operands_detected(self):
        m_nop = int(getattr(_HR, "m_nop", 0))
        mba = _simple_mba([_Insn(m_nop, ea=0x401000, l=_mop_r(4))])
        viols = inv.insn_basic_validity(mba, phase="test")
        assert inv.MINSN_50806_NOP_RET_WITH_OPERANDS in _codes(viols)

    def test_50806_ret_with_operands_detected(self):
        m_ret = int(getattr(_HR, "m_ret", 15))
        mba = _simple_mba([_Insn(m_ret, ea=0x401000, d=_mop_r(4))])
        viols = inv.insn_basic_validity(mba, phase="test")
        assert inv.MINSN_50806_NOP_RET_WITH_OPERANDS in _codes(viols)

    def test_50806_nop_without_operands_clean(self):
        m_nop = int(getattr(_HR, "m_nop", 0))
        mba = _simple_mba([_Insn(m_nop, ea=0x401000)])
        viols = inv.insn_basic_validity(mba, phase="test")
        assert inv.MINSN_50806_NOP_RET_WITH_OPERANDS not in _codes(viols)

    def test_50839_d_is_subinsn_detected(self):
        m_mov = int(getattr(_HR, "m_mov", 21))
        mop_d_type = int(getattr(_HR, "mop_d", 4))
        insn = _Insn(m_mov, ea=0x401000, l=_mop_r(4), d=_Mop(t=mop_d_type, size=4))
        mba = _simple_mba([insn])
        viols = inv.insn_basic_validity(mba, phase="test")
        assert inv.MINSN_50839_DST_IS_SUBINSN in _codes(viols)

    def test_50839_normal_d_clean(self):
        m_mov = int(getattr(_HR, "m_mov", 21))
        insn = _Insn(m_mov, ea=0x401000, l=_mop_r(4), d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_basic_validity(mba, phase="test")
        assert inv.MINSN_50839_DST_IS_SUBINSN not in _codes(viols)

    def test_50863_ea_outside_func_detected(self):
        m_nop = int(getattr(_HR, "m_nop", 0))
        # Block end = 0x402000, entry_ea = 0x401000, insn at 0x500000
        mba = _simple_mba([_Insn(m_nop, ea=0x500000)], entry_ea=0x401000)
        viols = inv.insn_basic_validity(mba, phase="test")
        assert inv.MINSN_50863_EA_OUTSIDE_FUNC in _codes(viols)

    def test_50863_ea_inside_func_clean(self):
        m_nop = int(getattr(_HR, "m_nop", 0))
        mba = _simple_mba([_Insn(m_nop, ea=0x401500)], entry_ea=0x401000)
        viols = inv.insn_basic_validity(mba, phase="test")
        assert inv.MINSN_50863_EA_OUTSIDE_FUNC not in _codes(viols)


# ---------------------------------------------------------------------------
# Group B — insn_operand_presence
# ---------------------------------------------------------------------------

class TestInsnOperandPresence:
    def test_clean_goto_has_l_no_violation(self):
        m_goto = int(getattr(_HR, "m_goto", 2))
        insn = _Insn(m_goto, ea=0x401000, l=_mop_b(1))
        mba = _simple_mba([insn], [_Insn(int(getattr(_HR, "m_nop", 0)), ea=0x401010)])
        viols = inv.insn_operand_presence(mba, phase="test")
        assert inv.MINSN_5081x_OPERAND_PRESENCE not in _codes(viols)

    def test_goto_missing_l_detected(self):
        m_goto = int(getattr(_HR, "m_goto", 2))
        insn = _Insn(m_goto, ea=0x401000)  # l is absent
        mba = _simple_mba([insn])
        viols = inv.insn_operand_presence(mba, phase="test")
        assert inv.MINSN_5081x_OPERAND_PRESENCE in _codes(viols)

    def test_nop_with_l_detected(self):
        m_nop = int(getattr(_HR, "m_nop", 0))
        insn = _Insn(m_nop, ea=0x401000, l=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_presence(mba, phase="test")
        assert inv.MINSN_5081x_OPERAND_PRESENCE in _codes(viols)

    def test_add_all_present_clean(self):
        m_add = int(getattr(_HR, "m_add", 24))
        insn = _Insn(m_add, ea=0x401000, l=_mop_r(4), r=_mop_r(4), d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_presence(mba, phase="test")
        assert inv.MINSN_5081x_OPERAND_PRESENCE not in _codes(viols)

    def test_add_missing_r_detected(self):
        m_add = int(getattr(_HR, "m_add", 24))
        insn = _Insn(m_add, ea=0x401000, l=_mop_r(4), d=_mop_r(4))  # r absent
        mba = _simple_mba([insn])
        viols = inv.insn_operand_presence(mba, phase="test")
        assert inv.MINSN_5081x_OPERAND_PRESENCE in _codes(viols)


# ---------------------------------------------------------------------------
# Group C — insn_operand_sizes
# ---------------------------------------------------------------------------

class TestInsnOperandSizes:
    def test_clean_mov_same_size_no_violation(self):
        m_mov = int(getattr(_HR, "m_mov", 21))
        insn = _Insn(m_mov, ea=0x401000, l=_mop_r(4), d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_sizes(mba, phase="test")
        assert inv.MINSN_5083x_SIZE_MISMATCH not in _codes(viols)

    def test_mov_size_mismatch_detected(self):
        m_mov = int(getattr(_HR, "m_mov", 21))
        insn = _Insn(m_mov, ea=0x401000, l=_mop_r(4), d=_mop_r(8))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_sizes(mba, phase="test")
        assert inv.MINSN_5083x_SIZE_MISMATCH in _codes(viols)

    def test_add_same_sizes_clean(self):
        m_add = int(getattr(_HR, "m_add", 24))
        insn = _Insn(m_add, ea=0x401000, l=_mop_r(4), r=_mop_r(4), d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_sizes(mba, phase="test")
        assert inv.MINSN_5083x_SIZE_MISMATCH not in _codes(viols)

    def test_add_mismatched_sizes_detected(self):
        m_add = int(getattr(_HR, "m_add", 24))
        insn = _Insn(m_add, ea=0x401000, l=_mop_r(4), r=_mop_r(4), d=_mop_r(8))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_sizes(mba, phase="test")
        assert inv.MINSN_5083x_SIZE_MISMATCH in _codes(viols)


# ---------------------------------------------------------------------------
# Group D — insn_operand_types
# ---------------------------------------------------------------------------

class TestInsnOperandTypes:
    def test_clean_reg_operand_no_violation(self):
        m_mov = int(getattr(_HR, "m_mov", 21))
        insn = _Insn(m_mov, ea=0x401000, l=_mop_r(4), d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_types(mba, phase="test")
        assert not viols

    def test_50754_mop_b_nonzero_size_detected(self):
        m_goto = int(getattr(_HR, "m_goto", 2))
        insn = _Insn(m_goto, ea=0x401000, l=_Mop(t=int(getattr(_HR, "mop_b", 7)), size=4, b=1))
        mba = _simple_mba([insn], [_Insn(int(getattr(_HR, "m_nop", 0)), ea=0x401010)])
        viols = inv.insn_operand_types(mba, phase="test")
        assert inv.MINSN_50754_MOP_ZBC_NONZERO_SIZE in _codes(viols)

    def test_50754_mop_b_zero_size_clean(self):
        m_goto = int(getattr(_HR, "m_goto", 2))
        # qty=2: block 1 is the valid goto target
        insn = _Insn(m_goto, ea=0x401000, l=_mop_b(1, size=0))
        mba = _simple_mba([insn], [_Insn(int(getattr(_HR, "m_nop", 0)), ea=0x401010)])
        viols = inv.insn_operand_types(mba, phase="test")
        assert inv.MINSN_50754_MOP_ZBC_NONZERO_SIZE not in _codes(viols)

    def test_50757_negative_size_detected(self):
        m_mov = int(getattr(_HR, "m_mov", 21))
        bad_op = _Mop(t=int(getattr(_HR, "mop_r", 1)), size=-1)
        insn = _Insn(m_mov, ea=0x401000, l=bad_op, d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_types(mba, phase="test")
        assert inv.MINSN_50757_BAD_OPERAND_SIZE in _codes(viols)

    def test_50770_bad_block_num_detected(self):
        m_goto = int(getattr(_HR, "m_goto", 2))
        # qty=1 block; block number 99 is out of range
        insn = _Insn(m_goto, ea=0x401000, l=_mop_b(99, size=0))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_types(mba, phase="test")
        assert inv.MINSN_50770_BAD_BLOCK_NUM in _codes(viols)

    def test_50770_valid_block_num_clean(self):
        m_goto = int(getattr(_HR, "m_goto", 2))
        # qty=2 blocks: block 0 has the goto, block 1 is the target (valid)
        insn = _Insn(m_goto, ea=0x401000, l=_mop_b(1, size=0))
        mba = _simple_mba([insn], [_Insn(int(getattr(_HR, "m_nop", 0)), ea=0x401010)])
        viols = inv.insn_operand_types(mba, phase="test")
        assert inv.MINSN_50770_BAD_BLOCK_NUM not in _codes(viols)

    def test_50794_unknown_type_detected(self):
        m_mov = int(getattr(_HR, "m_mov", 21))
        bad_op = _Mop(t=999, size=4)
        insn = _Insn(m_mov, ea=0x401000, l=bad_op, d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_types(mba, phase="test")
        assert inv.MINSN_50794_WRONG_OPERAND_TYPE in _codes(viols)

    def test_50794_known_type_clean(self):
        m_mov = int(getattr(_HR, "m_mov", 21))
        insn = _Insn(m_mov, ea=0x401000, l=_mop_r(4), d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_types(mba, phase="test")
        assert inv.MINSN_50794_WRONG_OPERAND_TYPE not in _codes(viols)


# ---------------------------------------------------------------------------
# Group E — insn_call_validity
# ---------------------------------------------------------------------------

class TestInsnCallValidity:
    def test_clean_call_with_arglist_no_violation(self):
        m_call = int(getattr(_HR, "m_call", 19))
        insn = _Insn(m_call, ea=0x401000, l=_mop_r(4), d=_mop_f())
        mba = _simple_mba([insn])
        viols = inv.insn_call_validity(mba, phase="test")
        assert inv.MINSN_50773_ARGLIST_ON_NONCALL not in _codes(viols)

    def test_50773_arglist_on_noncall_detected(self):
        m_mov = int(getattr(_HR, "m_mov", 21))
        insn = _Insn(m_mov, ea=0x401000, l=_mop_r(4), d=_mop_f())
        mba = _simple_mba([insn])
        viols = inv.insn_call_validity(mba, phase="test")
        assert inv.MINSN_50773_ARGLIST_ON_NONCALL in _codes(viols)

    def test_50784_helper_on_noncall_detected(self):
        m_mov = int(getattr(_HR, "m_mov", 21))
        insn = _Insn(m_mov, ea=0x401000, l=_mop_h(), d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_call_validity(mba, phase="test")
        assert inv.MINSN_50784_HELPER_ON_NONCALL in _codes(viols)

    def test_50784_helper_on_call_clean(self):
        m_call = int(getattr(_HR, "m_call", 19))
        insn = _Insn(m_call, ea=0x401000, l=_mop_h(), d=_mop_f())
        mba = _simple_mba([insn])
        viols = inv.insn_call_validity(mba, phase="test")
        assert inv.MINSN_50784_HELPER_ON_NONCALL not in _codes(viols)

    def test_51264_no_duplicate_eas_clean(self):
        m_call = int(getattr(_HR, "m_call", 19))
        insn1 = _Insn(m_call, ea=0x401000, l=_mop_r(4), d=_mop_f())
        insn2 = _Insn(m_call, ea=0x401010, l=_mop_r(4), d=_mop_f())
        mba = _simple_mba([insn1, insn2])
        viols = inv.insn_call_validity(mba, phase="test")
        assert inv.MINSN_51264_DUPLICATE_CALL_ADDRS not in _codes(viols)

    def test_51264_duplicate_call_ea_detected(self):
        m_call = int(getattr(_HR, "m_call", 19))
        insn1 = _Insn(m_call, ea=0x401000, l=_mop_r(4), d=_mop_f())
        insn2 = _Insn(m_call, ea=0x401000, l=_mop_r(4), d=_mop_f())  # same ea
        mba = _simple_mba([insn1], [insn2])
        viols = inv.insn_call_validity(mba, phase="test")
        assert inv.MINSN_51264_DUPLICATE_CALL_ADDRS in _codes(viols)


# ---------------------------------------------------------------------------
# focus_serials filtering
# ---------------------------------------------------------------------------

class TestFocusSerials:
    def test_focus_serials_limits_scope(self):
        m_nop = int(getattr(_HR, "m_nop", 0))
        badaddr = int(getattr(_HR, "BADADDR", 0xFFFFFFFFFFFFFFFF))
        # block 0: clean; block 1: BADADDR ea
        insn_bad = _Insn(m_nop, ea=badaddr)
        mba = _simple_mba(
            [_Insn(m_nop, ea=0x401000)],
            [insn_bad],
        )
        # Focus on block 0 only — should see no violation
        viols = inv.insn_basic_validity(mba, phase="test", focus_serials=[0])
        assert not viols

    def test_focus_serials_catches_bad_block(self):
        m_nop = int(getattr(_HR, "m_nop", 0))
        badaddr = int(getattr(_HR, "BADADDR", 0xFFFFFFFFFFFFFFFF))
        insn_bad = _Insn(m_nop, ea=badaddr)
        mba = _simple_mba(
            [_Insn(m_nop, ea=0x401000)],
            [insn_bad],
        )
        # Focus on block 1 — should catch violation
        viols = inv.insn_basic_validity(mba, phase="test", focus_serials=[1])
        assert inv.MINSN_50795_BADADDR in _codes(viols)


# ---------------------------------------------------------------------------
# Group A new checks — insn_basic_validity (new codes)
# ---------------------------------------------------------------------------

class TestInsnBasicValidityNew:
    def test_50859_jtbl_without_caselist_detected(self):
        m_jtbl = int(getattr(_HR, "m_jtbl", 1))
        mop_r_t = int(getattr(_HR, "mop_r", 1))
        # r operand is mop_r, not mop_c — violation
        insn = _Insn(m_jtbl, ea=0x401000, l=_mop_r(4), r=_Mop(t=mop_r_t, size=4))
        mba = _simple_mba([insn])
        viols = inv.insn_basic_validity(mba, phase="test")
        assert inv.MINSN_50859_JTBL_NO_CASELIST in _codes(viols)

    def test_50859_jtbl_with_caselist_clean(self):
        m_jtbl = int(getattr(_HR, "m_jtbl", 1))
        mop_c_t = int(getattr(_HR, "mop_c", 12))
        # r operand is mop_c — valid
        insn = _Insn(m_jtbl, ea=0x401000, l=_mop_r(4), r=_Mop(t=mop_c_t, size=0))
        mba = _simple_mba([insn])
        viols = inv.insn_basic_validity(mba, phase="test")
        assert inv.MINSN_50859_JTBL_NO_CASELIST not in _codes(viols)

    def test_51652_wrong_dst_type_detected(self):
        m_mov = int(getattr(_HR, "m_mov", 21))
        mop_str_t = int(getattr(_HR, "mop_str", 3))
        # d is mop_str — forbidden destination
        insn = _Insn(m_mov, ea=0x401000, l=_mop_r(4), d=_Mop(t=mop_str_t, size=4))
        mba = _simple_mba([insn])
        viols = inv.insn_basic_validity(mba, phase="test")
        assert inv.MINSN_51652_WRONG_DST_TYPE in _codes(viols)

    def test_51652_normal_dst_clean(self):
        m_mov = int(getattr(_HR, "m_mov", 21))
        insn = _Insn(m_mov, ea=0x401000, l=_mop_r(4), d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_basic_validity(mba, phase="test")
        assert inv.MINSN_51652_WRONG_DST_TYPE not in _codes(viols)

    def test_52338_lnot_bad_size_detected(self):
        m_lnot = int(getattr(_HR, "m_lnot", 22))
        # l.size=4 and d.size=4 — both should be 1
        insn = _Insn(m_lnot, ea=0x401000, l=_mop_r(4), d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_basic_validity(mba, phase="test")
        assert inv.MINSN_52338_LNOT_SIZE_NOT_1 in _codes(viols)

    def test_52338_lnot_correct_size_clean(self):
        m_lnot = int(getattr(_HR, "m_lnot", 22))
        insn = _Insn(m_lnot, ea=0x401000, l=_mop_r(1), d=_mop_r(1))
        mba = _simple_mba([insn])
        viols = inv.insn_basic_validity(mba, phase="test")
        assert inv.MINSN_52338_LNOT_SIZE_NOT_1 not in _codes(viols)

    def test_52118_shift_exceeds_mask_detected(self):
        m_shl = int(getattr(_HR, "m_shl", 34))
        mop_n_t = int(getattr(_HR, "mop_n", 2))

        class _NNN:
            value = 100  # shift by 100, which exceeds 8*4-1=31 for l.size=4

        # r is mop_n with a large shift value
        r_op = _Mop(t=mop_n_t, size=1, nnn=_NNN())
        insn = _Insn(m_shl, ea=0x401000, l=_mop_r(4), r=r_op, d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_basic_validity(mba, phase="test")
        assert inv.MINSN_52118_SHIFT_EXCEEDS_MASK in _codes(viols)

    def test_52118_shift_within_mask_clean(self):
        m_shl = int(getattr(_HR, "m_shl", 34))
        mop_n_t = int(getattr(_HR, "mop_n", 2))

        class _NNN:
            value = 3  # shift by 3, within 31 for l.size=4

        r_op = _Mop(t=mop_n_t, size=1, nnn=_NNN())
        insn = _Insn(m_shl, ea=0x401000, l=_mop_r(4), r=r_op, d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_basic_validity(mba, phase="test")
        assert inv.MINSN_52118_SHIFT_EXCEEDS_MASK not in _codes(viols)


# ---------------------------------------------------------------------------
# Group B new checks — insn_operand_presence (m_ext)
# ---------------------------------------------------------------------------

class TestInsnOperandPresenceNew:
    def test_50807_ext_bad_l_mopb_detected(self):
        m_ext = int(getattr(_HR, "m_ext", 16))
        mop_b_t = int(getattr(_HR, "mop_b", 7))
        # m_ext with mop_b in l — forbidden
        insn = _Insn(m_ext, ea=0x401000, l=_Mop(t=mop_b_t, size=0, b=0))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_presence(mba, phase="test")
        assert inv.MINSN_50807_EXT_BAD_L in _codes(viols)

    def test_50808_ext_bad_r_mopf_detected(self):
        m_ext = int(getattr(_HR, "m_ext", 16))
        mop_f_t = int(getattr(_HR, "mop_f", 8))
        insn = _Insn(m_ext, ea=0x401000, r=_Mop(t=mop_f_t, size=0))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_presence(mba, phase="test")
        assert inv.MINSN_50808_EXT_BAD_R in _codes(viols)

    def test_50809_ext_bad_d_mopf_detected(self):
        m_ext = int(getattr(_HR, "m_ext", 16))
        mop_f_t = int(getattr(_HR, "mop_f", 8))
        insn = _Insn(m_ext, ea=0x401000, d=_Mop(t=mop_f_t, size=0))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_presence(mba, phase="test")
        assert inv.MINSN_50809_EXT_BAD_D in _codes(viols)

    def test_ext_with_reg_operands_clean(self):
        m_ext = int(getattr(_HR, "m_ext", 16))
        insn = _Insn(m_ext, ea=0x401000, l=_mop_r(4), r=_mop_r(4), d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_presence(mba, phase="test")
        ext_codes = {
            inv.MINSN_50807_EXT_BAD_L,
            inv.MINSN_50808_EXT_BAD_R,
            inv.MINSN_50809_EXT_BAD_D,
        }
        assert not ext_codes.intersection(_codes(viols))


# ---------------------------------------------------------------------------
# Group C new checks — insn_operand_sizes (ldx/stx)
# ---------------------------------------------------------------------------

class TestInsnOperandSizesNew:
    def test_50826_ldx_bad_seg_size_detected(self):
        m_ldx = int(getattr(_HR, "m_ldx", 54))
        # ldx: seg=l, off=r, data=d. seg.size should be 2.
        insn = _Insn(m_ldx, ea=0x401000,
                     l=_mop_r(4),  # seg size=4, wrong (should be 2)
                     r=_mop_r(8),  # off size=8 (addrsize)
                     d=_mop_r(4))  # data
        mba = _simple_mba([insn])
        viols = inv.insn_operand_sizes(mba, phase="test")
        assert inv.MINSN_50826_LDX_STX_SEG_SIZE in _codes(viols)

    def test_50826_ldx_correct_seg_size_clean(self):
        m_ldx = int(getattr(_HR, "m_ldx", 54))
        insn = _Insn(m_ldx, ea=0x401000,
                     l=_mop_r(2),  # seg size=2 (correct)
                     r=_mop_r(8),  # off size=8 (addrsize)
                     d=_mop_r(4))  # data
        mba = _simple_mba([insn])
        viols = inv.insn_operand_sizes(mba, phase="test")
        assert inv.MINSN_50826_LDX_STX_SEG_SIZE not in _codes(viols)

    def test_52816_ldx_zero_data_size_detected(self):
        m_ldx = int(getattr(_HR, "m_ldx", 54))
        insn = _Insn(m_ldx, ea=0x401000,
                     l=_mop_r(2),  # seg
                     r=_mop_r(8),  # off
                     d=_mop_r(0))  # data size=0 — invalid
        mba = _simple_mba([insn])
        viols = inv.insn_operand_sizes(mba, phase="test")
        assert inv.MINSN_52816_SEGOFF_SIZE in _codes(viols)


# ---------------------------------------------------------------------------
# Group D new checks — insn_operand_types (new codes)
# ---------------------------------------------------------------------------

class TestInsnOperandTypesNew:
    def test_50755_str_wrong_size_detected(self):
        m_mov = int(getattr(_HR, "m_mov", 21))
        mop_str_t = int(getattr(_HR, "mop_str", 3))
        # mop_str size=4, but addrsize default=8
        insn = _Insn(m_mov, ea=0x401000, l=_Mop(t=mop_str_t, size=4), d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_types(mba, phase="test")
        assert inv.MINSN_50755_STR_NOT_ADDRSIZE in _codes(viols)

    def test_50764_negative_reg_number_detected(self):
        m_mov = int(getattr(_HR, "m_mov", 21))
        mop_r_t = int(getattr(_HR, "mop_r", 1))
        bad_reg = _Mop(t=mop_r_t, size=4, r=-1)
        insn = _Insn(m_mov, ea=0x401000, l=bad_reg, d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_types(mba, phase="test")
        assert inv.MINSN_50764_NEGATIVE_REG_NUM in _codes(viols)

    def test_50766_zero_reg_size_detected(self):
        m_mov = int(getattr(_HR, "m_mov", 21))
        mop_r_t = int(getattr(_HR, "mop_r", 1))
        bad_reg = _Mop(t=mop_r_t, size=0)
        insn = _Insn(m_mov, ea=0x401000, l=bad_reg, d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_types(mba, phase="test")
        assert inv.MINSN_50766_BAD_REG_SIZE in _codes(viols)

    def test_50760_const_opnum_exceeds_uamaxop_detected(self):
        m_mov = int(getattr(_HR, "m_mov", 21))
        mop_n_t = int(getattr(_HR, "mop_n", 2))

        class _NNN:
            ea = None
            opnum = 100  # > UA_MAXOP=8
            value = 0

        bad_const = _Mop(t=mop_n_t, size=4, nnn=_NNN())
        insn = _Insn(m_mov, ea=0x401000, l=bad_const, d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_types(mba, phase="test")
        assert inv.MINSN_50760_BAD_CONST_OPNUM in _codes(viols)

    def test_50761_const_illegal_bits_detected(self):
        m_mov = int(getattr(_HR, "m_mov", 21))
        mop_n_t = int(getattr(_HR, "mop_n", 2))

        class _NNN:
            ea = None
            opnum = 0
            value = 0x1FF  # bits set above byte mask for size=1

        bad_const = _Mop(t=mop_n_t, size=1, nnn=_NNN())
        insn = _Insn(m_mov, ea=0x401000, l=bad_const, d=_mop_r(1))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_types(mba, phase="test")
        assert inv.MINSN_50761_CONST_ILLEGAL_BITS in _codes(viols)

    def test_51586_const_size_too_large_detected(self):
        m_mov = int(getattr(_HR, "m_mov", 21))
        mop_n_t = int(getattr(_HR, "mop_n", 2))

        class _NNN:
            ea = None
            opnum = 0
            value = 0

        bad_const = _Mop(t=mop_n_t, size=16, nnn=_NNN())  # size > 8
        insn = _Insn(m_mov, ea=0x401000, l=bad_const, d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_types(mba, phase="test")
        assert inv.MINSN_51586_BAD_CONST_SIZE_1 in _codes(viols)

    def test_51587_const_size_non_pow2_detected(self):
        m_mov = int(getattr(_HR, "m_mov", 21))
        mop_n_t = int(getattr(_HR, "mop_n", 2))

        class _NNN:
            ea = None
            opnum = 0
            value = 0

        bad_const = _Mop(t=mop_n_t, size=3, nnn=_NNN())  # 3 is not a power of 2
        insn = _Insn(m_mov, ea=0x401000, l=bad_const, d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_types(mba, phase="test")
        assert inv.MINSN_51587_BAD_CONST_SIZE_2 in _codes(viols)

    def test_50763_negative_stkvar_offset_detected(self):
        m_mov = int(getattr(_HR, "m_mov", 21))
        mop_S_t = int(getattr(_HR, "mop_S", 5))

        class _SInfo:
            off = -1

        stkvar = _Mop(t=mop_S_t, size=4, s=_SInfo())
        insn = _Insn(m_mov, ea=0x401000, l=stkvar, d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_types(mba, phase="test")
        assert inv.MINSN_50763_NEGATIVE_STKVAR_OFF in _codes(viols)

    def test_50772_arglist_not_d_operand_detected(self):
        m_call = int(getattr(_HR, "m_call", 19))
        mop_f_t = int(getattr(_HR, "mop_f", 8))
        # mop_f in l position — must be d
        insn = _Insn(m_call, ea=0x401000, l=_Mop(t=mop_f_t, size=0), d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_types(mba, phase="test")
        assert inv.MINSN_50772_ARGLIST_NOT_D_OPERAND in _codes(viols)

    def test_50788_fp_const_too_big_detected(self):
        m_mov = int(getattr(_HR, "m_mov", 21))
        mop_fn_t = int(getattr(_HR, "mop_fn", 13))

        class _FPC:
            nbytes = 32  # > 16

        bad_fp = _Mop(t=mop_fn_t, size=4, fpc=_FPC())
        insn = _Insn(m_mov, ea=0x401000, l=bad_fp, d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_types(mba, phase="test")
        assert inv.MINSN_50788_FP_CONST_TOO_BIG in _codes(viols)

    def test_50790_pair_size_mismatch_detected(self):
        m_mov = int(getattr(_HR, "m_mov", 21))
        mop_p_t = int(getattr(_HR, "mop_p", 14))
        mop_r_t = int(getattr(_HR, "mop_r", 1))

        class _Pair:
            class lop:
                t = mop_r_t
                size = 4

            class hop:
                t = mop_r_t
                size = 8  # lop.size != hop.size

        pair_op = _Mop(t=mop_p_t, size=12, pair=_Pair())
        insn = _Insn(m_mov, ea=0x401000, l=pair_op, d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_types(mba, phase="test")
        assert inv.MINSN_50790_PAIR_CHECK_2 in _codes(viols)

    def test_50789_pair_missing_info_detected(self):
        m_mov = int(getattr(_HR, "m_mov", 21))
        mop_p_t = int(getattr(_HR, "mop_p", 14))
        pair_op = _Mop(t=mop_p_t, size=8, pair=None)  # no pair info
        insn = _Insn(m_mov, ea=0x401000, l=pair_op, d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_types(mba, phase="test")
        assert inv.MINSN_50789_PAIR_CHECK_1 in _codes(viols)

    def test_51651_case_list_in_l_detected(self):
        m_mov = int(getattr(_HR, "m_mov", 21))
        mop_c_t = int(getattr(_HR, "mop_c", 12))
        # mop_c in l position is forbidden
        insn = _Insn(m_mov, ea=0x401000, l=_Mop(t=mop_c_t, size=0), d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_types(mba, phase="test")
        assert inv.MINSN_51651_CASE_NUM_FORBIDDEN in _codes(viols)

    def test_50774_lvar_no_mba_detected(self):
        m_mov = int(getattr(_HR, "m_mov", 21))
        mop_l_t = int(getattr(_HR, "mop_l", 9))

        class _LInfo:
            mba = None
            off = 0

        lvar_op = _Mop(t=mop_l_t, size=4, l=_LInfo())
        insn = _Insn(m_mov, ea=0x401000, l=lvar_op, d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_types(mba, phase="test")
        assert inv.MINSN_50774_BAD_LVAR in _codes(viols)

    def test_51275_bad_fp_size_detected(self):
        m_mov = int(getattr(_HR, "m_mov", 21))
        mop_fn_t = int(getattr(_HR, "mop_fn", 13))

        class _FPC:
            nbytes = 4  # <= 16, so no 50788

        # size=7 is not in {4, 8, 10}
        bad_fp = _Mop(t=mop_fn_t, size=7, fpc=_FPC())
        insn = _Insn(m_mov, ea=0x401000, l=bad_fp, d=_mop_r(4))
        mba = _simple_mba([insn])
        viols = inv.insn_operand_types(mba, phase="test")
        assert inv.MINSN_51275_BAD_FP_SIZE in _codes(viols)


# ---------------------------------------------------------------------------
# Group E new checks — insn_call_validity (new codes)
# ---------------------------------------------------------------------------

class TestInsnCallValidityNew:
    def test_50772_arglist_not_d_in_call_validity(self):
        m_call = int(getattr(_HR, "m_call", 19))
        mop_f_t = int(getattr(_HR, "mop_f", 8))
        # mop_f in l on a call — not the d slot
        insn = _Insn(m_call, ea=0x401000, l=_Mop(t=mop_f_t, size=0), d=_mop_f())
        mba = _simple_mba([insn])
        # call_validity checks 50773/50784/51264; 50772 is in operand_types
        viols = inv.insn_operand_types(mba, phase="test")
        assert inv.MINSN_50772_ARGLIST_NOT_D_OPERAND in _codes(viols)

    def test_50782_empty_helper_name_detected(self):
        m_call = int(getattr(_HR, "m_call", 19))
        mop_h_t = int(getattr(_HR, "mop_h", 11))
        # mop_h with empty helper name
        h_op = _Mop(t=mop_h_t, size=0, helper="")
        insn = _Insn(m_call, ea=0x401000, l=h_op, d=_mop_f())
        mba = _simple_mba([insn])
        viols = inv.insn_operand_types(mba, phase="test")
        assert inv.MINSN_50782_BAD_HELPER_NAME in _codes(viols)

    def test_50782_nonempty_helper_name_clean(self):
        m_call = int(getattr(_HR, "m_call", 19))
        mop_h_t = int(getattr(_HR, "mop_h", 11))
        h_op = _Mop(t=mop_h_t, size=0, helper="__some_helper")
        insn = _Insn(m_call, ea=0x401000, l=h_op, d=_mop_f())
        mba = _simple_mba([insn])
        viols = inv.insn_operand_types(mba, phase="test")
        assert inv.MINSN_50782_BAD_HELPER_NAME not in _codes(viols)
