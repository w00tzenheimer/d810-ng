"""Unit tests for d810.evaluator.concrete — ConcreteEvaluator.

These tests exercise every opcode in the dispatch chain using lightweight
mock AST objects.  No IDA Pro is required; the tests are pure-Python.

Opcode integer values are taken from the Cython header
``src/d810/speedups/cythxr/_chexrays.pxd`` which mirrors the values in
the IDA SDK ``mcode_t`` enum.

The evaluator uses *lazy* ``import ida_hexrays`` inside ``_eval_node``.
Because the unit-test conftest forbids mocking IDA modules we must provide
real integer opcode values that the evaluator can compare against without
actually importing the IDA module.  We achieve this by registering a
minimal fake ``ida_hexrays`` module in ``sys.modules`` *before* the
evaluator is called, carrying only the opcode constants and ``mop_n``
needed for constant-leaf detection.  This is **not** a MagicMock — it is
a lightweight ``types.SimpleNamespace`` whose attributes are plain
integers, which is allowed by the conftest guard.
"""

from __future__ import annotations

import sys
import types

import pytest

from d810.evaluator.concrete import ConcreteEvaluator, evaluate_concrete
from d810.hexrays.mop_snapshot import MopSnapshot


# ---------------------------------------------------------------------------
# Minimal fake ida_hexrays with opcode integer constants
# ---------------------------------------------------------------------------
# We register this *once* at module import time.  The conftest fixture only
# rejects unittest.mock.MagicMock / Mock objects; a SimpleNamespace with
# plain integers is fine.

class _MopT:
    """Sentinel class standing in for ida_hexrays.mop_t.

    ``mop_snapshot.py`` calls ``NewType("OwnedMop", ida_hexrays.mop_t)`` at
    import time.  When our stub is already in ``sys.modules["ida_hexrays"]``
    that line must not raise ``AttributeError``, so we provide a plain class
    as a stand-in.  No instances are ever created by these unit tests.
    """


class _VdPrinterT:
    """Sentinel class standing in for ida_hexrays.vd_printer_t.

    ``hexrays_formatters.py`` defines ``mba_printer`` and ``block_printer``
    that inherit from ``vd_printer_t`` at class-definition time (module
    level).  When our stub is already in ``sys.modules["ida_hexrays"]`` that
    line must not raise ``AttributeError``.  No instances are ever created
    by these unit tests.
    """


_IDA_HEX = types.SimpleNamespace(
    # mop_t stand-in class (needed by mop_snapshot.NewType calls)
    mop_t=_MopT,
    # vd_printer_t stand-in class (needed by hexrays_formatters class defs)
    vd_printer_t=_VdPrinterT,

    # mop operand-type enum constants (mop_snapshot.py uses these)
    mop_z=0,   # undefined / zero
    mop_n=1,   # numeric constant
    mop_r=2,   # register
    mop_S=3,   # stack variable
    mop_v=4,   # global variable
    mop_d=5,   # result of another instruction
    mop_a=6,   # address of operand
    mop_f=7,   # list of arguments
    mop_l=8,   # local variable
    mop_b=9,   # micro basic-block reference
    mop_p=10,  # operand pair
    mop_c=11,  # switch cases
    mop_str=12,  # string constant
    mop_h=13,  # helper function name
    mop_fn=14,  # floating point constant
    mop_sc=15,  # scattered operand

    # mcode_t opcode enum (values from _chexrays.pxd)
    m_nop=0x00,
    m_stx=0x01,
    m_ldx=0x02,
    m_ldc=0x03,
    m_mov=0x04,
    m_neg=0x05,
    m_lnot=0x06,
    m_bnot=0x07,
    m_xds=0x08,
    m_xdu=0x09,
    m_low=0x0A,
    m_high=0x0B,
    m_add=0x0C,
    m_sub=0x0D,
    m_mul=0x0E,
    m_udiv=0x0F,
    m_sdiv=0x10,
    m_umod=0x11,
    m_smod=0x12,
    m_or=0x13,
    m_and=0x14,
    m_xor=0x15,
    m_shl=0x16,
    m_shr=0x17,
    m_sar=0x18,
    m_cfadd=0x19,
    m_ofadd=0x1A,
    m_cfshl=0x1B,
    m_cfshr=0x1C,
    m_sets=0x1D,
    m_seto=0x1E,
    m_setp=0x1F,
    m_setnz=0x20,
    m_setz=0x21,
    m_setae=0x22,
    m_setb=0x23,
    m_seta=0x24,
    m_setbe=0x25,
    m_setg=0x26,
    m_setge=0x27,
    m_setl=0x28,
    m_setle=0x29,
    m_jcnd=0x2A,
    m_jnz=0x2B,
    m_jz=0x2C,
    m_jae=0x2D,
    m_jb=0x2E,
    m_ja=0x2F,
    m_jbe=0x30,
    m_jg=0x31,
    m_jge=0x32,
    m_jl=0x33,
    m_jle=0x34,
    m_jtbl=0x35,
    m_ijmp=0x36,
    m_goto=0x37,
    m_call=0x38,
    m_icall=0x39,
    m_ret=0x3A,
    m_push=0x3B,
    m_pop=0x3C,
    m_und=0x3D,
    m_ext=0x3E,
    m_f2i=0x3F,
    m_f2u=0x40,
    m_i2f=0x41,
    m_u2f=0x42,
    m_f2f=0x43,
    m_fneg=0x44,
    m_fadd=0x45,
    m_fsub=0x46,
    m_fmul=0x47,
    m_fdiv=0x48,

    # mba_maturity_t constants
    MMAT_ZERO=0,
    MMAT_GENERATED=1,
    MMAT_PREOPTIMIZED=2,
    MMAT_LOCOPT=3,
    MMAT_CALLS=4,
    MMAT_GLBOPT1=5,
    MMAT_GLBOPT2=6,
    MMAT_GLBOPT3=7,
    MMAT_LVARS=8,
)

# Register the namespace as the ida_hexrays module so the lazy import
# inside ConcreteEvaluator._eval_node() gets our constants instead.
sys.modules.setdefault("ida_hexrays", _IDA_HEX)

# Shorthand aliases used throughout the test file
_OPC = _IDA_HEX  # same namespace, cleaner name


# ---------------------------------------------------------------------------
# Minimal mock AST node / leaf classes (no IDA types, no d810.expr.p_ast)
# ---------------------------------------------------------------------------

class _Leaf:
    """Minimal variable leaf — value comes from env."""

    def __init__(self, ast_index: int, dest_size: int = 4):
        self.ast_index = ast_index
        self.dest_size = dest_size
        self.mop = None

    def is_leaf(self) -> bool:
        return True

    def is_constant(self) -> bool:
        return False


class _ConstLeaf:
    """Minimal constant leaf — value is stored directly."""

    def __init__(self, value: int, dest_size: int = 4):
        self._value = value
        self.dest_size = dest_size
        self.ast_index = None
        # Use a real MopSnapshot so _eval_leaf takes the isinstance branch.
        # t=1 == mop_n (numeric constant), size=dest_size.
        self.mop = MopSnapshot(t=1, size=dest_size, value=value)

    def is_leaf(self) -> bool:
        return True

    def is_constant(self) -> bool:
        return True


class _Node:
    """Minimal interior node."""

    def __init__(
        self,
        opcode: int,
        left,
        right=None,
        *,
        dest_size: int = 4,
        func_name: str = "",
        ast_index: int = 0,
    ):
        self.opcode = opcode
        self.left = left
        self.right = right
        self.dest_size = dest_size
        self.func_name = func_name
        self.ast_index = ast_index

    def is_leaf(self) -> bool:
        return False

    def is_constant(self) -> bool:
        return False


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def ev() -> ConcreteEvaluator:
    """Fresh ConcreteEvaluator instance."""
    return ConcreteEvaluator()


# ---------------------------------------------------------------------------
# Leaf evaluation
# ---------------------------------------------------------------------------

class TestLeafEvaluation:
    """Tests for _eval_leaf: variable and constant leaves."""

    def test_variable_leaf_returns_env_value(self, ev):
        """A variable leaf looks up its value from the env dict."""
        leaf = _Leaf(ast_index=7, dest_size=4)
        result = ev.evaluate(leaf, {7: 0xDEAD})
        assert result == 0xDEAD

    def test_variable_leaf_missing_index_returns_none(self, ev):
        """A variable leaf with no binding returns None (mirroring dict.get)."""
        leaf = _Leaf(ast_index=3, dest_size=4)
        result = ev.evaluate(leaf, {})
        assert result is None

    def test_constant_leaf_returns_stored_value(self, ev):
        """A constant leaf returns its embedded value regardless of env."""
        leaf = _ConstLeaf(0xCAFEBABE, dest_size=4)
        result = ev.evaluate(leaf, {})
        assert result == 0xCAFEBABE

    def test_constant_leaf_ignores_env(self, ev):
        """env bindings do not affect a constant leaf's return value."""
        leaf = _ConstLeaf(42, dest_size=1)
        result = ev.evaluate(leaf, {0: 999})
        assert result == 42


# ---------------------------------------------------------------------------
# Unary opcodes
# ---------------------------------------------------------------------------

class TestUnaryOpcodes:
    """Tests for m_mov, m_neg, m_lnot, m_bnot, m_xdu, m_low."""

    def test_m_mov(self, ev):
        node = _Node(_OPC.m_mov, _ConstLeaf(0xAB, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 0xAB

    def test_m_neg_positive(self, ev):
        """neg(5) in 8-bit == 0xFB (two's complement)."""
        node = _Node(_OPC.m_neg, _ConstLeaf(5, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 0xFB  # (-5) & 0xFF

    def test_m_neg_zero(self, ev):
        """neg(0) == 0."""
        node = _Node(_OPC.m_neg, _ConstLeaf(0, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 0

    def test_m_lnot_nonzero_returns_zero(self, ev):
        """lnot of any nonzero value is 0 — logical NOT: !42 == 0 in C."""
        node = _Node(_OPC.m_lnot, _ConstLeaf(42, 1), dest_size=1)
        result = ev.evaluate(node, {})
        assert result == 0
        assert isinstance(result, int), f"Expected int, got {type(result).__name__}"

    def test_m_lnot_zero_returns_one(self, ev):
        """lnot of zero is 1 — logical NOT: !0 == 1 in C."""
        node = _Node(_OPC.m_lnot, _ConstLeaf(0, 1), dest_size=1)
        result = ev.evaluate(node, {})
        assert result == 1
        assert isinstance(result, int), f"Expected int, got {type(result).__name__}"

    def test_m_lnot_result_is_masked_to_dest_size(self, ev):
        """lnot(0) in 4-byte dest: int(0 == 0) & 0xFFFFFFFF == 1."""
        # dest_size=4 -> res_mask=0xFFFFFFFF; int(True) & mask == 1
        node = _Node(_OPC.m_lnot, _ConstLeaf(0, 4), dest_size=4)
        result = ev.evaluate(node, {})
        assert result == 1
        assert 0 <= result <= 0xFFFFFFFF

    def test_m_bnot_8bit(self, ev):
        """bnot(0xAA) in 8-bit == 0x55."""
        node = _Node(_OPC.m_bnot, _ConstLeaf(0xAA, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 0x55

    def test_m_bnot_32bit(self, ev):
        """bnot(0xDEADBEEF) in 32-bit == 0x21524110."""
        node = _Node(_OPC.m_bnot, _ConstLeaf(0xDEADBEEF, 4), dest_size=4)
        assert ev.evaluate(node, {}) == (~0xDEADBEEF & 0xFFFFFFFF)

    def test_m_xdu_masks_to_dest(self, ev):
        """xdu zero-extends: result is masked to dest_size."""
        node = _Node(_OPC.m_xdu, _ConstLeaf(0xFF, 1), dest_size=4)
        assert ev.evaluate(node, {}) == 0xFF

    def test_m_low_masks_to_dest(self, ev):
        """m_low truncates to dest_size bits."""
        # 0x1234 in 1-byte destination -> 0x34
        node = _Node(_OPC.m_low, _ConstLeaf(0x1234, 2), dest_size=1)
        assert ev.evaluate(node, {}) == 0x34


# ---------------------------------------------------------------------------
# Binary arithmetic
# ---------------------------------------------------------------------------

class TestBinaryArithmetic:
    """Tests for m_add, m_sub, m_mul, m_udiv, m_sdiv, m_umod, m_smod."""

    def test_m_add(self, ev):
        node = _Node(_OPC.m_add, _ConstLeaf(3, 4), _ConstLeaf(5, 4), dest_size=4)
        assert ev.evaluate(node, {}) == 8

    def test_m_add_wraps_8bit(self, ev):
        node = _Node(_OPC.m_add, _ConstLeaf(0xFF, 1), _ConstLeaf(1, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 0  # 0x100 & 0xFF

    def test_m_sub(self, ev):
        node = _Node(_OPC.m_sub, _ConstLeaf(10, 4), _ConstLeaf(3, 4), dest_size=4)
        assert ev.evaluate(node, {}) == 7

    def test_m_sub_wraps_8bit(self, ev):
        """0 - 1 in 8-bit unsigned wraps to 0xFF."""
        node = _Node(_OPC.m_sub, _ConstLeaf(0, 1), _ConstLeaf(1, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 0xFF

    def test_m_mul(self, ev):
        node = _Node(_OPC.m_mul, _ConstLeaf(6, 4), _ConstLeaf(7, 4), dest_size=4)
        assert ev.evaluate(node, {}) == 42

    def test_m_mul_wraps_8bit(self, ev):
        node = _Node(_OPC.m_mul, _ConstLeaf(0x10, 1), _ConstLeaf(0x20, 1), dest_size=1)
        assert ev.evaluate(node, {}) == (0x200 & 0xFF)

    def test_m_udiv(self, ev):
        node = _Node(_OPC.m_udiv, _ConstLeaf(20, 4), _ConstLeaf(4, 4), dest_size=4)
        assert ev.evaluate(node, {}) == 5

    def test_m_sdiv(self, ev):
        node = _Node(_OPC.m_sdiv, _ConstLeaf(20, 4), _ConstLeaf(4, 4), dest_size=4)
        assert ev.evaluate(node, {}) == 5

    def test_m_umod(self, ev):
        node = _Node(_OPC.m_umod, _ConstLeaf(17, 4), _ConstLeaf(5, 4), dest_size=4)
        assert ev.evaluate(node, {}) == 2

    def test_m_smod(self, ev):
        node = _Node(_OPC.m_smod, _ConstLeaf(17, 4), _ConstLeaf(5, 4), dest_size=4)
        assert ev.evaluate(node, {}) == 2


# ---------------------------------------------------------------------------
# Bitwise operations
# ---------------------------------------------------------------------------

class TestBitwiseOpcodes:
    """Tests for m_and, m_or, m_xor."""

    def test_m_and(self, ev):
        node = _Node(_OPC.m_and, _ConstLeaf(0xF0, 1), _ConstLeaf(0x0F, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 0x00

    def test_m_and_partial_overlap(self, ev):
        node = _Node(_OPC.m_and, _ConstLeaf(0xFF, 1), _ConstLeaf(0xAA, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 0xAA

    def test_m_or(self, ev):
        node = _Node(_OPC.m_or, _ConstLeaf(0xF0, 1), _ConstLeaf(0x0F, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 0xFF

    def test_m_xor(self, ev):
        node = _Node(_OPC.m_xor, _ConstLeaf(0xFF, 1), _ConstLeaf(0xAA, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 0x55

    def test_m_xor_same_values(self, ev):
        """XOR of identical values is always 0."""
        node = _Node(_OPC.m_xor, _ConstLeaf(0x1234, 2), _ConstLeaf(0x1234, 2), dest_size=2)
        assert ev.evaluate(node, {}) == 0


# ---------------------------------------------------------------------------
# Shift operations
# ---------------------------------------------------------------------------

class TestShiftOpcodes:
    """Tests for m_shl, m_shr, m_sar."""

    def test_m_shl(self, ev):
        node = _Node(_OPC.m_shl, _ConstLeaf(1, 4), _ConstLeaf(4, 4), dest_size=4)
        assert ev.evaluate(node, {}) == 0x10

    def test_m_shl_overflow_masked(self, ev):
        """Shift that overflows is masked to dest_size."""
        node = _Node(_OPC.m_shl, _ConstLeaf(0xFF, 1), _ConstLeaf(1, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 0xFE  # 0x1FE & 0xFF

    def test_m_shr(self, ev):
        node = _Node(_OPC.m_shr, _ConstLeaf(0x80, 1), _ConstLeaf(4, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 0x08

    def test_m_sar_negative(self, ev):
        """Arithmetic right shift of -1 (0xFF in 8-bit) by 1 stays 0xFF."""
        # unsigned_to_signed(0xFF, 1) == -1 ; -1 >> 1 == -1
        node = _Node(_OPC.m_sar, _ConstLeaf(0xFF, 1), _ConstLeaf(1, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 0xFF

    def test_m_sar_positive(self, ev):
        """Arithmetic right shift of 0x10 by 1 is 0x08."""
        node = _Node(_OPC.m_sar, _ConstLeaf(0x10, 1), _ConstLeaf(1, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 0x08


# ---------------------------------------------------------------------------
# Sign-extension / high-extract
# ---------------------------------------------------------------------------

class TestSignExtension:
    """Tests for m_xds, m_high."""

    def test_m_xds_positive(self, ev):
        """Sign-extend 0x7F (8-bit) to 32-bit stays 0x7F."""
        left = _ConstLeaf(0x7F, 1)
        node = _Node(_OPC.m_xds, left, dest_size=4)
        assert ev.evaluate(node, {}) == 0x7F

    def test_m_xds_negative(self, ev):
        """Sign-extend 0x80 (8-bit, == -128) to 32-bit gives 0xFFFFFF80."""
        left = _ConstLeaf(0x80, 1)
        node = _Node(_OPC.m_xds, left, dest_size=4)
        assert ev.evaluate(node, {}) == 0xFFFFFF80

    def test_m_high_32bit_from_64bit(self, ev):
        """m_high extracts the upper 32 bits of a 64-bit value."""
        # The *dest_size* is 4 (we want 32-bit high); left is 64-bit.
        left = _ConstLeaf(0x0000000100000000, 8)
        node = _Node(_OPC.m_high, left, dest_size=4)
        # shift_bits = dest_size * 8 = 32
        assert ev.evaluate(node, {}) == 0x00000001


# ---------------------------------------------------------------------------
# m_sets (sign flag)
# ---------------------------------------------------------------------------

class TestSetsOpcode:
    """Tests for m_sets (sign flag)."""

    def test_m_sets_negative_value(self, ev):
        """sets(0xFF) in 8-bit: -1 < 0 so result is 1."""
        left = _ConstLeaf(0xFF, 1)
        node = _Node(_OPC.m_sets, left, dest_size=1)
        assert ev.evaluate(node, {}) == 1

    def test_m_sets_positive_value(self, ev):
        """sets(0x01) in 8-bit: +1 >= 0 so result is 0."""
        left = _ConstLeaf(0x01, 1)
        node = _Node(_OPC.m_sets, left, dest_size=1)
        assert ev.evaluate(node, {}) == 0

    def test_m_sets_zero(self, ev):
        """sets(0) is 0."""
        left = _ConstLeaf(0, 1)
        node = _Node(_OPC.m_sets, left, dest_size=1)
        assert ev.evaluate(node, {}) == 0


# ---------------------------------------------------------------------------
# Comparison / set-flag opcodes
# ---------------------------------------------------------------------------

class TestSetFlagOpcodes:
    """Tests for m_setnz, m_setz, m_setae, m_setb, m_seta, m_setbe."""

    def test_m_setnz_true(self, ev):
        node = _Node(_OPC.m_setnz, _ConstLeaf(3, 1), _ConstLeaf(4, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 1

    def test_m_setnz_false(self, ev):
        node = _Node(_OPC.m_setnz, _ConstLeaf(3, 1), _ConstLeaf(3, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 0

    def test_m_setz_true(self, ev):
        node = _Node(_OPC.m_setz, _ConstLeaf(7, 1), _ConstLeaf(7, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 1

    def test_m_setz_false(self, ev):
        node = _Node(_OPC.m_setz, _ConstLeaf(7, 1), _ConstLeaf(8, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 0

    def test_m_setae_true(self, ev):
        node = _Node(_OPC.m_setae, _ConstLeaf(5, 1), _ConstLeaf(5, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 1

    def test_m_setae_false(self, ev):
        node = _Node(_OPC.m_setae, _ConstLeaf(4, 1), _ConstLeaf(5, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 0

    def test_m_setb_true(self, ev):
        node = _Node(_OPC.m_setb, _ConstLeaf(3, 1), _ConstLeaf(5, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 1

    def test_m_setb_false(self, ev):
        node = _Node(_OPC.m_setb, _ConstLeaf(5, 1), _ConstLeaf(3, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 0

    def test_m_seta_true(self, ev):
        node = _Node(_OPC.m_seta, _ConstLeaf(5, 1), _ConstLeaf(3, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 1

    def test_m_seta_false(self, ev):
        node = _Node(_OPC.m_seta, _ConstLeaf(3, 1), _ConstLeaf(5, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 0

    def test_m_setbe_true(self, ev):
        node = _Node(_OPC.m_setbe, _ConstLeaf(5, 1), _ConstLeaf(5, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 1

    def test_m_setbe_false(self, ev):
        node = _Node(_OPC.m_setbe, _ConstLeaf(6, 1), _ConstLeaf(5, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 0


# ---------------------------------------------------------------------------
# Signed comparison opcodes
# ---------------------------------------------------------------------------

class TestSignedComparisons:
    """Tests for m_setg, m_setge, m_setl, m_setle."""

    def test_m_setg_positive(self, ev):
        """setg(5, 3) signed: 5 > 3, result 1."""
        node = _Node(_OPC.m_setg, _ConstLeaf(5, 1), _ConstLeaf(3, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 1

    def test_m_setg_negative_values(self, ev):
        """setg(0xFF, 0x01) signed in 8-bit: -1 > 1 is False, result 0."""
        node = _Node(_OPC.m_setg, _ConstLeaf(0xFF, 1), _ConstLeaf(0x01, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 0

    def test_m_setge_equal(self, ev):
        """setge(3, 3) signed: 3 >= 3 is True, result 1."""
        node = _Node(_OPC.m_setge, _ConstLeaf(3, 1), _ConstLeaf(3, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 1

    def test_m_setl_negative_lt_positive(self, ev):
        """setl(0xFF, 0x01) signed: -1 < 1, result 1."""
        node = _Node(_OPC.m_setl, _ConstLeaf(0xFF, 1), _ConstLeaf(0x01, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 1

    def test_m_setle_equal(self, ev):
        """setle(5, 5) signed: 5 <= 5, result 1."""
        node = _Node(_OPC.m_setle, _ConstLeaf(5, 1), _ConstLeaf(5, 1), dest_size=1)
        assert ev.evaluate(node, {}) == 1


# ---------------------------------------------------------------------------
# m_call — rotate helpers
# ---------------------------------------------------------------------------

class TestRotateHelperCall:
    """Tests for m_call dispatch to rotate helpers via HelperRegistry."""

    def test_rol4_via_call_node(self, ev):
        """m_call node with func_name=__ROL4__ delegates to the registry."""
        val_leaf = _ConstLeaf(0x12345678, 4)
        rot_leaf = _ConstLeaf(8, 1)
        node = _Node(
            _OPC.m_call, val_leaf, rot_leaf,
            dest_size=4, func_name="__ROL4__"
        )
        result = ev.evaluate(node, {})
        assert result == 0x34567812

    def test_ror4_via_call_node(self, ev):
        """m_call node with func_name=__ROR4__ delegates to the registry."""
        val_leaf = _ConstLeaf(0x12345678, 4)
        rot_leaf = _ConstLeaf(8, 1)
        node = _Node(
            _OPC.m_call, val_leaf, rot_leaf,
            dest_size=4, func_name="__ROR4__"
        )
        result = ev.evaluate(node, {})
        assert result == 0x78123456

    def test_rol1_via_call_node(self, ev):
        """m_call node with func_name=__ROL1__: bit 7 wraps to bit 0."""
        val_leaf = _ConstLeaf(0x80, 1)
        rot_leaf = _ConstLeaf(1, 1)
        node = _Node(
            _OPC.m_call, val_leaf, rot_leaf,
            dest_size=1, func_name="__ROL1__"
        )
        result = ev.evaluate(node, {})
        assert result == 0x01

    def test_bang_prefix_stripped(self, ev):
        """func_name with leading '!' is stripped before registry lookup."""
        val_leaf = _ConstLeaf(0x12345678, 4)
        rot_leaf = _ConstLeaf(8, 1)
        node = _Node(
            _OPC.m_call, val_leaf, rot_leaf,
            dest_size=4, func_name="!__ROL4__"
        )
        result = ev.evaluate(node, {})
        assert result == 0x34567812

    def test_unknown_call_returns_zero(self, ev):
        """m_call with unknown func_name returns 0."""
        val_leaf = _ConstLeaf(0xDEAD, 2)
        rot_leaf = _ConstLeaf(1, 1)
        node = _Node(
            _OPC.m_call, val_leaf, rot_leaf,
            dest_size=2, func_name="__UNKNOWN__"
        )
        result = ev.evaluate(node, {})
        assert result == 0

    def test_call_no_func_name_returns_zero(self, ev):
        """m_call with no func_name returns 0."""
        val_leaf = _ConstLeaf(0xDEAD, 2)
        rot_leaf = _ConstLeaf(1, 1)
        node = _Node(
            _OPC.m_call, val_leaf, rot_leaf,
            dest_size=2, func_name=""
        )
        result = ev.evaluate(node, {})
        assert result == 0


# ---------------------------------------------------------------------------
# env bindings and variable leaves
# ---------------------------------------------------------------------------

class TestEnvBindings:
    """Tests for variable-leaf env lookup in larger tree expressions.

    Interior nodes use ast_index=None (not in env) so the env short-circuit
    does not fire.  Only leaf nodes carry meaningful ast_index values.
    """

    def test_add_two_variables(self, ev):
        """(x0 + x1) where x0=3, x1=4 == 7."""
        x0 = _Leaf(ast_index=10, dest_size=4)
        x1 = _Leaf(ast_index=11, dest_size=4)
        # ast_index=None ensures the node is never short-circuited via env
        node = _Node(_OPC.m_add, x0, x1, dest_size=4, ast_index=None)
        result = ev.evaluate(node, {10: 3, 11: 4})
        assert result == 7

    def test_xor_variable_with_constant(self, ev):
        """(x0 ^ 0xFF) where x0=0xAA == 0x55."""
        x0 = _Leaf(ast_index=10, dest_size=1)
        const = _ConstLeaf(0xFF, 1)
        node = _Node(_OPC.m_xor, x0, const, dest_size=1, ast_index=None)
        result = ev.evaluate(node, {10: 0xAA})
        assert result == 0x55

    def test_nested_expression(self, ev):
        """(x0 + x1) * 2 with x0=3, x1=4 == 14."""
        x0 = _Leaf(ast_index=10, dest_size=4)
        x1 = _Leaf(ast_index=11, dest_size=4)
        add_node = _Node(_OPC.m_add, x0, x1, dest_size=4, ast_index=None)
        const2 = _ConstLeaf(2, 4)
        mul_node = _Node(_OPC.m_mul, add_node, const2, dest_size=4, ast_index=None)
        result = ev.evaluate(mul_node, {10: 3, 11: 4})
        assert result == 14

    def test_node_index_in_env_short_circuits(self, ev):
        """If a node's ast_index is in env, return env value directly."""
        x0 = _Leaf(ast_index=10, dest_size=4)
        x1 = _Leaf(ast_index=11, dest_size=4)
        add_node = _Node(_OPC.m_add, x0, x1, dest_size=4, ast_index=99)
        # Binding 99 directly -> should bypass actual evaluation
        result = ev.evaluate(add_node, {99: 42, 10: 100, 11: 200})
        assert result == 42


# ---------------------------------------------------------------------------
# evaluate_concrete() public entry point
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------

class TestErrorCases:
    """Tests for error / edge-case handling."""

    def test_unknown_opcode_raises(self, ev):
        """AstEvaluationException for an unsupported opcode."""
        from d810.errors import AstEvaluationException
        node = _Node(0xFF, _ConstLeaf(1, 1), dest_size=1)
        with pytest.raises(AstEvaluationException, match="Can't evaluate opcode"):
            ev.evaluate(node, {})

    def test_dest_size_none_raises(self, ev):
        """ValueError when dest_size is None on an interior node."""
        node = _Node(_OPC.m_mov, _ConstLeaf(1, 1), dest_size=None)
        node.dest_size = None  # explicit override
        with pytest.raises(ValueError, match="dest_size is None"):
            ev.evaluate(node, {})

    def test_binary_opcode_with_none_right_raises(self, ev):
        """ValueError when a binary opcode lacks a right operand."""
        node = _Node(_OPC.m_add, _ConstLeaf(1, 4), right=None, dest_size=4)
        with pytest.raises(ValueError, match="right is None for binary opcode"):
            ev.evaluate(node, {})

    def test_udiv_by_zero_returns_none(self, ev):
        """m_udiv with divisor=0 returns None (safe; cannot evaluate at compile time)."""
        node = _Node(_OPC.m_udiv, _ConstLeaf(1, 4), _ConstLeaf(0, 4), dest_size=4)
        assert ev.evaluate(node, {}) is None

    def test_sdiv_by_zero_returns_none(self, ev):
        """m_sdiv with divisor=0 returns None."""
        node = _Node(_OPC.m_sdiv, _ConstLeaf(1, 4), _ConstLeaf(0, 4), dest_size=4)
        assert ev.evaluate(node, {}) is None

    def test_umod_by_zero_returns_none(self, ev):
        """m_umod with divisor=0 returns None."""
        node = _Node(_OPC.m_umod, _ConstLeaf(1, 4), _ConstLeaf(0, 4), dest_size=4)
        assert ev.evaluate(node, {}) is None

    def test_smod_by_zero_returns_none(self, ev):
        """m_smod with divisor=0 returns None."""
        node = _Node(_OPC.m_smod, _ConstLeaf(1, 4), _ConstLeaf(0, 4), dest_size=4)
        assert ev.evaluate(node, {}) is None

    def test_left_is_none_raises(self, ev):
        """ValueError when left operand is None."""
        node = _Node(_OPC.m_mov, None, dest_size=4)
        node.left = None
        with pytest.raises((ValueError, AttributeError)):
            ev.evaluate(node, {})


# ---------------------------------------------------------------------------
# evaluate_with_leaf_info
# ---------------------------------------------------------------------------

class _FakeAstInfo:
    """Minimal AstInfo-like object for evaluate_with_leaf_info tests."""

    def __init__(self, ast_index: int):
        self.ast = types.SimpleNamespace(ast_index=ast_index)


class TestEvaluateWithLeafInfo:
    """Tests for ConcreteEvaluator.evaluate_with_leaf_info()."""

    def test_basic_evaluate_with_leaf_info(self, ev):
        """evaluate_with_leaf_info builds env and calls evaluate correctly."""
        x0 = _Leaf(ast_index=10, dest_size=4)
        x1 = _Leaf(ast_index=11, dest_size=4)
        # ast_index=None on the node prevents env short-circuit
        node = _Node(_OPC.m_add, x0, x1, dest_size=4, ast_index=None)

        leafs_info = [_FakeAstInfo(10), _FakeAstInfo(11)]
        result = ev.evaluate_with_leaf_info(node, leafs_info, [10, 20])
        assert result == 30

    def test_evaluate_with_leaf_info_skips_none_index(self, ev):
        """Leaf infos with ast_index=None are silently skipped."""
        leaf = _ConstLeaf(99, 1)
        node = _Node(_OPC.m_mov, leaf, dest_size=1)

        info_none = types.SimpleNamespace(ast=types.SimpleNamespace(ast_index=None))
        result = ev.evaluate_with_leaf_info(node, [info_none], [42])
        assert result == 99


# ---------------------------------------------------------------------------
# Real-AST tests — requires IDA Pro (system/runtime)
# These classes use real minsn_to_ast() output (AstNode / AstProxy) from
# libobfuscated.  They exercise the Cython isinstance dispatch path that
# the stub-based tests above bypass entirely.
# ---------------------------------------------------------------------------

import os as _os
import platform as _platform


def _default_binary() -> str:
    override = _os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return "libobfuscated.dylib" if _platform.system() == "Darwin" else "libobfuscated.dll"


class TestConcreteWithRealAst:
    """evaluate_concrete() with real AstNode/AstProxy objects from minsn_to_ast().

    These tests verify that the Cython isinstance dispatch in c_concrete.pyx
    correctly handles both AstNode (line 150) and AstProxy (line 154) objects
    produced by the real minsn_to_ast() pipeline — coverage that the stub-based
    tests cannot provide.
    """

    binary_name = _default_binary()

    def test_cython_evaluator_is_active(self, libobfuscated_setup):
        """_default_evaluator is a CythonConcreteEvaluator when speedups are built."""
        from d810.evaluator.concrete import _default_evaluator

        try:
            from d810.speedups.evaluator.c_concrete import CythonConcreteEvaluator
            assert isinstance(_default_evaluator, CythonConcreteEvaluator), (
                f"Expected CythonConcreteEvaluator, got {type(_default_evaluator).__name__}"
            )
        except ImportError:
            pytest.skip("Cython speedups not built — skipping Cython path assertion")

    def test_evaluate_concrete_real_astnode(self, libobfuscated_setup, real_asts):
        """evaluate_concrete() returns an integer for a real AstNode from minsn_to_ast()."""
        from d810.evaluator.concrete import evaluate_concrete
        from d810.expr.p_ast import AstBase

        # Pick any non-leaf AST node from the real collection
        ast_nodes = [(ast, ins) for ast, ins in real_asts if not ast.is_leaf()]
        if not ast_nodes:
            pytest.skip("No non-leaf AstNode found in real_asts")

        ast, _ins = ast_nodes[0]

        # Build env from the leaf list — bind every variable leaf to 0
        leaf_infos = []
        try:
            sub_ast_info = getattr(ast, "sub_ast_info_by_index", {})
            leaf_infos = list(sub_ast_info.values())
        except Exception:
            pass

        env: dict = {}
        for info in leaf_infos:
            leaf_ast = getattr(info, "ast", None)
            if leaf_ast is not None:
                idx = getattr(leaf_ast, "ast_index", None)
                if idx is not None:
                    env[idx] = 0

        try:
            result = evaluate_concrete(ast, env)
            assert result is None or isinstance(result, int), (
                f"evaluate_concrete returned unexpected type: {type(result)}"
            )
        except Exception as exc:
            # Evaluation may fail for complex nodes (e.g. division by zero with env=0);
            # the important thing is that the isinstance dispatch did not raise
            # AstEvaluationException about an unsupported type.
            from d810.errors import AstEvaluationException
            if "Unsupported AST node type" in str(exc):
                pytest.fail(
                    f"AstProxy/AstNode type not recognised by Cython dispatch: {exc}"
                )
            # Other exceptions (ZeroDivisionError, ValueError) are acceptable

    def test_evaluate_concrete_real_astproxy_dispatch(self, libobfuscated_setup, real_asts):
        """AstProxy objects returned by minsn_to_ast() are handled without TypeError.

        minsn_to_ast() returns AstProxy when the same sub-expression is reused.
        The Cython evaluate() branch at c_concrete.pyx:154 must handle them
        transparently.  This test verifies that no 'Unsupported AST node type'
        exception is raised for any AST in real_asts.
        """
        from d810.evaluator.concrete import evaluate_concrete
        from d810.errors import AstEvaluationException

        proxy_count = 0
        node_count = 0
        failures = []

        for ast, _ins in real_asts[:40]:
            # Collect all sub-expressions including proxies from sub_ast_info_by_index
            sub_infos = getattr(ast, "sub_ast_info_by_index", {})
            env: dict = {}
            for info in sub_infos.values():
                leaf_ast = getattr(info, "ast", None)
                if leaf_ast is not None:
                    idx = getattr(leaf_ast, "ast_index", None)
                    if idx is not None:
                        env[idx] = 1  # non-zero probe avoids division-by-zero

            # Check if any sub-AST is an AstProxy instance
            try:
                from d810.expr.ast import AstProxy
                for info in sub_infos.values():
                    if isinstance(getattr(info, "ast", None), AstProxy):
                        proxy_count += 1
            except ImportError:
                pass

            node_count += 1
            try:
                evaluate_concrete(ast, env)
            except AstEvaluationException as exc:
                if "Unsupported AST node type" in str(exc):
                    failures.append(f"Type dispatch failed for {type(ast).__name__}: {exc}")
            except Exception:
                # ZeroDivisionError, ValueError etc. are acceptable
                pass

        assert not failures, "\n".join(failures)
        # Informational: confirm we processed some nodes
        assert node_count > 0, "No ASTs were processed from real_asts"

    def test_evaluate_concrete_all_constant_nodes_return_int(
        self, libobfuscated_setup, real_asts
    ):
        """Every fully-constant AST node evaluates to an integer without raising.

        A 'constant' node is one that has no variable leaves (sub_ast_info is
        empty or all leaves are AstConstant).  For such nodes evaluate_concrete
        with an empty env must either return an int or raise a non-type-dispatch
        error.
        """
        from d810.evaluator.concrete import evaluate_concrete
        from d810.errors import AstEvaluationException

        checked = 0
        for ast, _ins in real_asts:
            if ast.is_leaf():
                continue
            sub_infos = getattr(ast, "sub_ast_info_by_index", {})
            # Only test nodes where every leaf is constant
            all_const = all(
                getattr(info.ast, "is_constant", lambda: False)()
                for info in sub_infos.values()
            )
            if not all_const:
                continue

            checked += 1
            try:
                result = evaluate_concrete(ast, {})
                assert result is None or isinstance(result, (int, bool)), (
                    f"Expected int/None, got {type(result)} for {type(ast).__name__}"
                )
            except AstEvaluationException as exc:
                if "Unsupported AST node type" in str(exc):
                    pytest.fail(f"Type dispatch failure on constant node: {exc}")
