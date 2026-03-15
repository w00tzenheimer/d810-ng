"""Unit tests for _resolve_mop_via_def_use integration in MicroCodeInterpreter.

These tests run WITHOUT IDA by mocking the ida_hexrays module and all IDA
objects. They verify the logic of the def-use resolution method in isolation.
"""

from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock, patch, PropertyMock

import pytest


# ---------------------------------------------------------------------------
# Build a minimal ida_hexrays mock that satisfies all constants used by emulator.py
# ---------------------------------------------------------------------------

def _make_ida_hexrays_mock():
    mod = types.ModuleType("ida_hexrays")

    # mop type constants
    mod.mop_z = 0
    mod.mop_r = 1
    mod.mop_n = 2
    mod.mop_S = 3
    mod.mop_v = 4
    mod.mop_d = 5
    mod.mop_a = 6
    mod.mop_f = 7

    # Maturity constants
    mod.MMAT_GENERATED = 0
    mod.MMAT_PREOPTIMIZED = 1
    mod.MMAT_LOCOPT = 2
    mod.MMAT_CALLS = 3
    mod.MMAT_GLBOPT1 = 5
    mod.MMAT_GLBOPT2 = 6
    mod.MMAT_GLBOPT3 = 7
    mod.MMAT_LVARS = 8

    # Opcode constants (we only need a few)
    _opcodes = [
        "m_nop", "m_stx", "m_ldx", "m_ldc",
        "m_mov", "m_neg", "m_lnot", "m_bnot", "m_xds", "m_xdu",
        "m_low", "m_high",
        "m_add", "m_sub", "m_mul", "m_udiv", "m_sdiv", "m_umod", "m_smod",
        "m_or", "m_and", "m_xor", "m_shl", "m_shr", "m_sar",
        "m_cfadd", "m_ofadd", "m_cfshl", "m_cfshr",
        "m_call", "m_icall", "m_goto", "m_jcnd",
        "m_ret", "m_push", "m_pop",
    ]
    for i, name in enumerate(_opcodes):
        setattr(mod, name, i)

    # GC constant
    mod.GC_REGS_AND_STKVARS = 0
    mod.CHF_PASSTHRU = 1

    # minsn_t / mblock_t / mba_t / mop_t as MagicMock classes
    mod.minsn_t = MagicMock
    mod.mblock_t = MagicMock
    mod.mba_t = MagicMock
    mod.mop_t = MagicMock

    return mod


_IDA_HEXRAYS_MOCK = _make_ida_hexrays_mock()

# Patch before any d810 imports
sys.modules.setdefault("ida_hexrays", _IDA_HEXRAYS_MOCK)
sys.modules.setdefault("idaapi", MagicMock())
sys.modules.setdefault("idc", MagicMock())
sys.modules.setdefault("idautils", MagicMock())

# Also stub out heavy d810 sub-modules that import IDA internals
for _mod_name in [
    "d810.speedups",
    "d810.speedups.cythxr",
    "d810.speedups.cythxr._chexrays_api",
]:
    sys.modules.setdefault(_mod_name, MagicMock())


# ---------------------------------------------------------------------------
# Helpers to build fake IDA objects
# ---------------------------------------------------------------------------

IDA = _IDA_HEXRAYS_MOCK  # shorthand


def _make_mop(t, size=4, r=None, s_off=None):
    """Build a fake mop_t with the given type and fields."""
    mop = MagicMock()
    mop.t = t
    mop.size = size
    if r is not None:
        mop.r = r
    if s_off is not None:
        s = MagicMock()
        s.off = s_off
        mop.s = s
    return mop


def _make_minsn(opcode, ea=0x1000, lhs_mop=None, dst_mop=None):
    """Build a fake minsn_t."""
    ins = MagicMock()
    ins.opcode = opcode
    ins.ea = ea
    ins.l = lhs_mop or MagicMock()
    ins.r = MagicMock()
    ins.d = dst_mop or MagicMock()
    ins.next = None
    return ins


def _make_mblock(serial, mba, head_ins=None, maturity=IDA.MMAT_GLBOPT1):
    """Build a fake mblock_t."""
    blk = MagicMock()
    blk.serial = serial
    blk.mba = mba
    blk.head = head_ins
    return blk


def _make_mba(maturity=IDA.MMAT_GLBOPT1):
    """Build a fake mba_t."""
    mba = MagicMock()
    mba.maturity = maturity
    return mba


# ---------------------------------------------------------------------------
# Import the real classes under test (after mocks are in sys.modules)
# ---------------------------------------------------------------------------

from d810.evaluator.hexrays_microcode.emulator import (  # noqa: E402
    MicroCodeEnvironment,
    MicroCodeInterpreter,
)
from d810.evaluator.hexrays_microcode.chains import DefSite  # noqa: E402


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestResolveViaDef:

    def _make_interp(self):
        return MicroCodeInterpreter(symbolic_mode=False)

    def _make_env_no_blk(self):
        env = MicroCodeEnvironment()
        # cur_blk is None by default
        return env

    def _make_env_with_blk(self, mba, blk):
        env = MicroCodeEnvironment()
        # Manually set cur_blk (set_cur_flow requires a real ins, use a mock)
        env.cur_blk = blk
        env.cur_ins = None
        return env

    # --- Test 1: no cur_blk → None ---
    def test_returns_none_when_no_cur_blk(self):
        interp = self._make_interp()
        env = self._make_env_no_blk()
        mop = _make_mop(IDA.mop_r, size=4, r=0)
        result = interp._resolve_mop_via_def_use(mop, env)
        assert result is None

    # --- Test 2: maturity too low → None ---
    def test_returns_none_when_maturity_too_low(self):
        interp = self._make_interp()
        mba = _make_mba(maturity=IDA.MMAT_LOCOPT)  # < MMAT_GLBOPT1
        blk = _make_mblock(serial=0, mba=mba)
        env = self._make_env_with_blk(mba, blk)
        mop = _make_mop(IDA.mop_r, size=4, r=0)
        result = interp._resolve_mop_via_def_use(mop, env)
        assert result is None

    # --- Test 3: zero defs → None ---
    def test_returns_none_when_no_defs(self):
        interp = self._make_interp()
        mba = _make_mba()
        blk = _make_mblock(serial=1, mba=mba)
        env = self._make_env_with_blk(mba, blk)
        mop = _make_mop(IDA.mop_r, size=4, r=2)

        with patch(
            "d810.evaluator.hexrays_microcode.chains.find_reaching_defs_for_reg",
            return_value=[],
        ):
            result = interp._resolve_mop_via_def_use(mop, env)

        assert result is None

    # --- Test 4: multiple defs → None (phi-like) ---
    def test_returns_none_when_multiple_defs(self):
        interp = self._make_interp()
        mba = _make_mba()
        blk = _make_mblock(serial=1, mba=mba)
        env = self._make_env_with_blk(mba, blk)
        mop = _make_mop(IDA.mop_r, size=4, r=2)

        two_defs = [
            DefSite(block_serial=0, ins_ea=0x1000, ins_opcode=IDA.m_mov),
            DefSite(block_serial=2, ins_ea=0x2000, ins_opcode=IDA.m_mov),
        ]
        with patch(
            "d810.evaluator.hexrays_microcode.chains.find_reaching_defs_for_reg",
            return_value=two_defs,
        ):
            result = interp._resolve_mop_via_def_use(mop, env)

        assert result is None

    # --- Test 5: single m_mov def resolves register correctly ---
    def test_resolves_single_mov_def_for_reg(self):
        interp = self._make_interp()
        mba = _make_mba()

        # Defining instruction: mov #0x42, dst_reg
        lhs_mop = _make_mop(IDA.mop_n, size=4)
        lhs_mop.nnn = MagicMock()
        lhs_mop.nnn.value = 0x42

        dst_mop = _make_mop(IDA.mop_r, size=4, r=2)
        def_ins = _make_minsn(opcode=IDA.m_mov, ea=0x1000, lhs_mop=lhs_mop, dst_mop=dst_mop)

        def_blk = _make_mblock(serial=0, mba=mba, head_ins=def_ins)
        mba.get_mblock.return_value = def_blk

        # The block under evaluation
        blk = _make_mblock(serial=1, mba=mba)
        env = self._make_env_with_blk(mba, blk)
        mop = _make_mop(IDA.mop_r, size=4, r=2)

        one_def = [DefSite(block_serial=0, ins_ea=0x1000, ins_opcode=IDA.m_mov)]
        with patch(
            "d810.evaluator.hexrays_microcode.chains.find_reaching_defs_for_reg",
            return_value=one_def,
        ):
            result = interp._resolve_mop_via_def_use(mop, env)

        assert result == 0x42

    # --- Test 6: single m_mov def resolves stack variable correctly ---
    def test_resolves_single_mov_def_for_stkvar(self):
        interp = self._make_interp()
        mba = _make_mba()

        lhs_mop = _make_mop(IDA.mop_n, size=4)
        lhs_mop.nnn = MagicMock()
        lhs_mop.nnn.value = 0xDEAD

        dst_mop = _make_mop(IDA.mop_S, size=4, s_off=0x10)
        def_ins = _make_minsn(opcode=IDA.m_mov, ea=0x2000, lhs_mop=lhs_mop, dst_mop=dst_mop)

        def_blk = _make_mblock(serial=0, mba=mba, head_ins=def_ins)
        mba.get_mblock.return_value = def_blk

        blk = _make_mblock(serial=1, mba=mba)
        env = self._make_env_with_blk(mba, blk)
        mop = _make_mop(IDA.mop_S, size=4, s_off=0x10)

        one_def = [DefSite(block_serial=0, ins_ea=0x2000, ins_opcode=IDA.m_mov)]
        with patch(
            "d810.evaluator.hexrays_microcode.chains.find_reaching_defs_for_stkvar",
            return_value=one_def,
        ):
            result = interp._resolve_mop_via_def_use(mop, env)

        assert result == 0xDEAD & 0xFFFFFFFF

    # --- Test 7: cache hit — second call returns same value without re-evaluating ---
    def test_cache_hit_avoids_requery(self):
        interp = self._make_interp()
        mba = _make_mba()

        lhs_mop = _make_mop(IDA.mop_n, size=4)
        lhs_mop.nnn = MagicMock()
        lhs_mop.nnn.value = 0x99

        dst_mop = _make_mop(IDA.mop_r, size=4, r=3)
        def_ins = _make_minsn(opcode=IDA.m_mov, ea=0x3000, lhs_mop=lhs_mop, dst_mop=dst_mop)

        def_blk = _make_mblock(serial=0, mba=mba, head_ins=def_ins)
        mba.get_mblock.return_value = def_blk

        blk = _make_mblock(serial=1, mba=mba)
        env = self._make_env_with_blk(mba, blk)
        mop = _make_mop(IDA.mop_r, size=4, r=3)

        one_def = [DefSite(block_serial=0, ins_ea=0x3000, ins_opcode=IDA.m_mov)]

        call_count = {"n": 0}

        def _fake_find(*args, **kwargs):
            call_count["n"] += 1
            return one_def

        with patch(
            "d810.evaluator.hexrays_microcode.chains.find_reaching_defs_for_reg",
            side_effect=_fake_find,
        ):
            r1 = interp._resolve_mop_via_def_use(mop, env)
            r2 = interp._resolve_mop_via_def_use(mop, env)

        assert r1 == 0x99
        assert r2 == 0x99
        # Chain was only queried once; second call hit the cache.
        assert call_count["n"] == 1

    # --- Test 8: cache is cleared at eval_instruction entry ---
    def test_cache_cleared_at_eval_instruction(self):
        interp = self._make_interp()
        # Pre-populate cache with a stale entry
        interp._def_use_cache[(IDA.mop_r, 5, 4)] = 0xBAD

        # eval_instruction with a None ins short-circuits but should still clear
        interp.eval_instruction(blk=MagicMock(), ins=None)
        # Cache should be empty
        assert interp._def_use_cache == {}
