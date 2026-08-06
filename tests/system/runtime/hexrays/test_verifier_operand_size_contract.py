"""Runtime contract: d810's operand-size guards must agree with IDA's verifier.

Every assertion here is derived from the SDK's own rules, not from d810's
behaviour, so the test fails when d810 drifts from what Hex-Rays actually
enforces.  Source of truth is ``ida-sdk/src/verifier/verify.cpp``::

    case m_shl: case m_shr: case m_sar:
      if ( r.size != 1 ) MINSN_INTERR(50835);          // shift AMOUNT is 1 byte

    case m_cfadd: case m_ofadd: case m_setp: ... case m_seto:
      if ( l.size != r.size ) MINSN_INTERR(50832);     // binary flag ops
      [[fallthrough]];
    case m_sets:
      if ( d.size != 1 ) MINSN_INTERR(50833);          // 1-byte flag dest

    case m_cfshl: case m_cfshr:
      if ( r.size != 1 || d.size != 1 ) MINSN_INTERR(50834);

plus ``hexrays.hpp``::

    m_sets = 0x1D, // sets  l,          d=byte  SF=1          Sign
    inline bool is_mcode_set1(mcode_t mcode) { return mcode == m_sets; }

``m_sets`` is the ONLY unary member of the flag family: it is the fallthrough
label, so it never reaches the ``l.size != r.size`` comparison, and the SDK
ships ``is_mcode_set1()`` to single it out.

These live in ``system/runtime`` rather than ``unit`` deliberately -- real
``ida_hexrays`` constants and real ``minsn_t``/``mop_t`` objects, no stubbing.
``hexrays_helpers`` builds ``OPCODES_INFO`` from every ``m_*`` constant at
import time, so a mocked ``ida_hexrays`` cannot exercise this code honestly.

Regression cover for three guard defects, each of which silently DISCARDED
correct rewrites rather than failing loudly:
  * ``m_sets`` rejected as malformed for lacking an ``r`` operand.
  * folded shift amounts rebuilt at the destination width (INTERR 50835).
  * flag opcodes folded whole-instruction at their 1-byte destination width.
"""

from __future__ import annotations

import os
import platform

import ida_hexrays
import pytest

from d810.hexrays.utils.hexrays_helpers import CHECK_OPCODES, check_ins_mop_size_are_ok
from d810.optimizers.microcode.instructions.peephole.fold_constant_subtree import (
    _SET_OPCODES,
    _SHIFT_OPCODES,
    _clamp_shift_amount,
)

# --- SDK-derived oracles ---------------------------------------------------

# verify.cpp: these compare l.size against r.size, so both operands exist.
_BINARY_FLAG_OPCODES = (
    ida_hexrays.m_cfadd,
    ida_hexrays.m_ofadd,
    ida_hexrays.m_setp,
    ida_hexrays.m_setz,
    ida_hexrays.m_setnz,
    ida_hexrays.m_setae,
    ida_hexrays.m_setb,
    ida_hexrays.m_seta,
    ida_hexrays.m_setbe,
    ida_hexrays.m_setg,
    ida_hexrays.m_setge,
    ida_hexrays.m_setl,
    ida_hexrays.m_setle,
    ida_hexrays.m_seto,
)

# verify.cpp: r.size must be 1 (INTERR 50835).
_SDK_SHIFT_OPCODES = (ida_hexrays.m_shl, ida_hexrays.m_shr, ida_hexrays.m_sar)


def _get_default_binary() -> str:
    """Binary the class-scoped ``ida_database`` fixture should open."""
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


def _num(value: int, size: int) -> ida_hexrays.mop_t:
    mop = ida_hexrays.mop_t()
    mop.make_number(value, size)
    return mop


# NOTE: mop_t.make_reg() SEGFAULTS outside a live decompilation (no processor
# context to validate the register number).  make_number / erase / minsn_t /
# create_from_insn are all safe, and check_ins_mop_size_are_ok only reads
# ``.t`` and ``.size``, so numeric operands exercise it faithfully.


def _empty() -> ida_hexrays.mop_t:
    mop = ida_hexrays.mop_t()
    mop.erase()
    return mop


def _insn(opcode: int, l=None, r=None, d=None, ea: int = 0x1000):
    ins = ida_hexrays.minsn_t(ea)
    ins.opcode = opcode
    ins.l = l if l is not None else _empty()
    ins.r = r if r is not None else _empty()
    ins.d = d if d is not None else _empty()
    return ins


def _nested(inner: ida_hexrays.minsn_t, size: int) -> ida_hexrays.mop_t:
    """Wrap a sub-instruction as a mop_d operand, the way create_minsn does."""
    mop = ida_hexrays.mop_t()
    mop.create_from_insn(inner)
    mop.size = size
    return mop


@pytest.mark.usefixtures("ida_database")
class TestSetsIsUnary:
    """m_sets carries l + d only; demanding an r operand rejects valid microcode.

    ``mop_t.make_number`` / ``minsn_t`` construction SEGFAULT without an open
    database (no kernel context), so this class takes the class-scoped
    ``ida_database`` fixture.  Verified: identical constructions succeed under
    an open IDB and crash without one.
    """

    binary_name = _get_default_binary()

    def test_sets_without_r_operand_is_size_ok(self) -> None:
        # sets (eax.4), sf.1  -- exactly the shape Hex-Rays emits.
        ins = _insn(
            ida_hexrays.m_sets,
            l=_num(0x1234, 4),
            r=None,  # mop_z: m_sets has no right operand
            d=_num(0x1234, 1),
        )
        assert check_ins_mop_size_are_ok(ins), (
            "m_sets is unary (hexrays.hpp: 'sets l, d=byte'); requiring a "
            "non-mop_z r rejects valid microcode and discards the rewrite"
        )

    def test_sets_is_the_only_unary_member_of_the_family(self) -> None:
        """Guard the SDK distinction: is_mcode_set1() matches m_sets alone."""
        assert ida_hexrays.m_sets not in _BINARY_FLAG_OPCODES
        for opcode in _BINARY_FLAG_OPCODES:
            missing_r = _insn(
                opcode,
                l=_num(0x1234, 4),
                r=None,
                d=_num(0x1234, 1),
            )
            assert not check_ins_mop_size_are_ok(missing_r), (
                f"opcode {opcode} is binary per verify.cpp (l.size vs r.size); "
                "a missing r operand must still be rejected"
            )

    def test_whole_flag_family_is_size_checked(self) -> None:
        """Every flag opcode the SDK special-cases is treated as check-like."""
        for opcode in (*_BINARY_FLAG_OPCODES, ida_hexrays.m_sets):
            assert opcode in CHECK_OPCODES, (
                f"opcode {opcode} has a 1-byte flag destination with wider "
                "sources; strict d.size == l.size matching does not apply"
            )


@pytest.mark.usefixtures("ida_database")
class TestShiftAmountIsOneByte:
    """verify.cpp INTERR 50835: m_shl/m_shr/m_sar require r.size == 1."""

    binary_name = _get_default_binary()

    def test_d810_shift_set_matches_the_sdk(self) -> None:
        assert set(_SHIFT_OPCODES) == set(_SDK_SHIFT_OPCODES)

    @pytest.mark.parametrize("opcode", _SDK_SHIFT_OPCODES)
    def test_top_level_wide_amount_is_clamped(self, opcode: int) -> None:
        # shr %r.4, #0x6F57001.4, %d.4 -- the amount came back at dst width.
        ins = _insn(
            opcode,
            l=_num(0x1234, 4),
            r=_num(0x6F57001, 4),
            d=_num(0x1234, 4),
        )
        _clamp_shift_amount(ins)
        assert ins.r.size == 1, "shift amount must be narrowed to one byte"
        assert ins.r.nnn.value == (0x6F57001 & 0xFF)

    @pytest.mark.parametrize("opcode", _SDK_SHIFT_OPCODES)
    def test_nested_wide_amount_is_clamped(self, opcode: int) -> None:
        """The regression: create_minsn buries the shift under and/bnot.

        A top-level-only clamp never fires here because the outer opcode is
        m_and, and IDA's verifier walks sub-instructions.
        """
        inner = _insn(
            opcode,
            l=_num(0x1234, 4),
            r=_num(0xDD0C2B0B, 4),
            d=_num(0x1234, 4),
            ea=0x2000,
        )
        outer = _insn(
            ida_hexrays.m_and,
            l=_nested(inner, 4),
            r=_num(2, 4),
            d=_num(0x1234, 4),
        )
        _clamp_shift_amount(outer)
        assert outer.l.d.r.size == 1, (
            "a shift nested in a mop_d must be clamped too; the verifier "
            "walks sub-instructions"
        )
        assert outer.l.d.r.nnn.value == (0xDD0C2B0B & 0xFF)

    def test_non_shift_amounts_are_untouched(self) -> None:
        ins = _insn(
            ida_hexrays.m_and,
            l=_num(0x1234, 4),
            r=_num(0x10, 4),
            d=_num(0x1234, 4),
        )
        _clamp_shift_amount(ins)
        assert ins.r.size == 4, "only shift AMOUNT operands are one byte"


class TestFlagOpcodesAreNotWholeInstructionFolded:
    """Folding at dst_size (1) mis-evaluates flag ops -- see verify.cpp 50832/50833."""

    @pytest.mark.parametrize(
        "opcode",
        (
            ida_hexrays.m_cfadd,
            ida_hexrays.m_ofadd,
            ida_hexrays.m_cfshl,
            ida_hexrays.m_cfshr,
            ida_hexrays.m_sets,
            ida_hexrays.m_seto,
        ),
    )
    def test_carry_overflow_sign_opcodes_are_excluded(self, opcode: int) -> None:
        """These share the 1-byte-dest / wider-source shape of the set* family.

        Whole-instruction replacement evaluates the expression at ``dst_size``,
        so ``ofadd #a.4, #b.4, of.1`` folded to the low BYTE of ``a + b``
        instead of the overflow flag -- silently wrong, not merely mis-sized.
        """
        assert opcode in _SET_OPCODES

    def test_set_family_is_excluded(self) -> None:
        for opcode in _BINARY_FLAG_OPCODES:
            assert opcode in _SET_OPCODES
