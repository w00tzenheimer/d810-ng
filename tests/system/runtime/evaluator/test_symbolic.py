"""Unit tests for d810.evaluator.symbolic — probe_is_constant.

All tests are pure-Python; no IDA Pro is required.

The concrete evaluator uses a lazy ``import ida_hexrays`` inside
``_eval_node``.  We register a minimal ``types.SimpleNamespace`` fake in
``sys.modules`` before the evaluator is exercised — the same technique used
in ``test_concrete.py``.  This is **not** a ``MagicMock``; it is a plain
namespace with integer opcode constants, which passes the conftest guard.
"""

from __future__ import annotations

import sys
import types

import pytest

# ---------------------------------------------------------------------------
# Minimal fake ida_hexrays — must be in sys.modules before any evaluator call
# ---------------------------------------------------------------------------

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

sys.modules.setdefault("ida_hexrays", _IDA_HEX)

_OPC = _IDA_HEX

# ---------------------------------------------------------------------------
# Import the function under test AFTER the fake module is registered
# ---------------------------------------------------------------------------

from d810.evaluator.symbolic import probe_is_constant  # noqa: E402
from d810.hexrays.mop_snapshot import MopSnapshot  # noqa: E402


# ---------------------------------------------------------------------------
# Minimal mock AST node / leaf helpers (no IDA types, no d810.expr.p_ast)
# ---------------------------------------------------------------------------


class _Leaf:
    """Variable leaf — value comes from env binding."""

    def __init__(self, ast_index: int, dest_size: int = 4) -> None:
        self.ast_index = ast_index
        self.dest_size = dest_size
        self.mop = None

    def is_leaf(self) -> bool:
        return True

    def is_constant(self) -> bool:
        return False


class _ConstLeaf:
    """Constant leaf — value is embedded in a real MopSnapshot."""

    def __init__(self, value: int, dest_size: int = 4) -> None:
        self._value = value
        self.ast_index = None
        self.dest_size = dest_size
        # Use a real MopSnapshot so _eval_leaf takes the isinstance branch.
        # t=1 == mop_n (numeric constant), size=dest_size.
        self.mop = MopSnapshot(t=1, size=dest_size, value=value)

    def is_leaf(self) -> bool:
        return True

    def is_constant(self) -> bool:
        return True


class _Node:
    """Interior AST node."""

    def __init__(
        self,
        opcode: int,
        left: object,
        right: object = None,
        *,
        dest_size: int = 4,
        func_name: str = "",
        ast_index: int | None = None,
    ) -> None:
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


def _info(ast_index: int) -> object:
    """Build a minimal AstInfo-like object with a nested ``ast`` namespace."""
    return types.SimpleNamespace(ast=types.SimpleNamespace(ast_index=ast_index))


def _info_none() -> object:
    """AstInfo-like object whose ast_index is None (should be skipped)."""
    return types.SimpleNamespace(ast=types.SimpleNamespace(ast_index=None))


# ---------------------------------------------------------------------------
# Tests: constant expression (no variable leaves)
# ---------------------------------------------------------------------------


class TestConstantExpression:
    """probe_is_constant correctly identifies purely constant expressions."""

    def test_pure_constant_add(self):
        """5 + 3 has no variable leaves; both probes return 8."""
        node = _Node(_OPC.m_add, _ConstLeaf(5, 4), _ConstLeaf(3, 4), dest_size=4)
        is_const, value = probe_is_constant(node, [])
        assert is_const is True
        assert value == 8

    def test_pure_constant_xor(self):
        """0xFF ^ 0xAA == 0x55, no variable leaves."""
        node = _Node(_OPC.m_xor, _ConstLeaf(0xFF, 1), _ConstLeaf(0xAA, 1), dest_size=1)
        is_const, value = probe_is_constant(node, [])
        assert is_const is True
        assert value == 0x55

    def test_single_constant_leaf(self):
        """A single constant leaf (via m_mov) always returns the same value."""
        node = _Node(_OPC.m_mov, _ConstLeaf(42, 1), dest_size=1)
        is_const, value = probe_is_constant(node, [])
        assert is_const is True
        assert value == 42

    def test_constant_with_leaf_info_list_skips_none_index(self):
        """AstInfo entries with ast_index=None are silently skipped."""
        node = _Node(_OPC.m_mov, _ConstLeaf(7, 1), dest_size=1)
        is_const, value = probe_is_constant(node, [_info_none()])
        assert is_const is True
        assert value == 7


# ---------------------------------------------------------------------------
# Tests: variable expression (produces different values at different probes)
# ---------------------------------------------------------------------------


class TestVariableExpression:
    """probe_is_constant returns (False, None) for non-constant expressions."""

    def test_variable_plus_constant_not_constant(self):
        """x + 3 at probe=0 gives 3; at probe=0xFFFFFFFF gives 0x100000002.

        These are different, so the result is (False, None).
        """
        x = _Leaf(ast_index=10, dest_size=4)
        const = _ConstLeaf(3, 4)
        node = _Node(_OPC.m_add, x, const, dest_size=4, ast_index=None)
        is_const, value = probe_is_constant(node, [_info(10)])
        assert is_const is False
        assert value is None

    def test_variable_mov_not_constant(self):
        """mov(x) just returns x; 0 != 0xFFFFFFFF."""
        x = _Leaf(ast_index=5, dest_size=4)
        node = _Node(_OPC.m_mov, x, dest_size=4, ast_index=None)
        is_const, value = probe_is_constant(node, [_info(5)])
        assert is_const is False
        assert value is None

    def test_multiple_variable_leaves_not_constant(self):
        """x + y at uniform probes: when x=y=0 gives 0, x=y=0xFFFFFFFF gives 0x1FFFFFFFE."""
        x = _Leaf(ast_index=10, dest_size=4)
        y = _Leaf(ast_index=11, dest_size=4)
        node = _Node(_OPC.m_add, x, y, dest_size=4, ast_index=None)
        is_const, value = probe_is_constant(node, [_info(10), _info(11)])
        assert is_const is False
        assert value is None


# ---------------------------------------------------------------------------
# Tests: custom probe_values
# ---------------------------------------------------------------------------


class TestCustomProbeValues:
    """probe_is_constant respects caller-provided probe_values."""

    def test_single_probe_always_reports_constant(self):
        """With only one probe value, any expression is trivially 'constant'."""
        x = _Leaf(ast_index=10, dest_size=4)
        node = _Node(_OPC.m_mov, x, dest_size=4, ast_index=None)
        is_const, value = probe_is_constant(node, [_info(10)], probe_values=[0])
        # Only one probe → only one result in the set → must be True
        assert is_const is True
        assert value == 0

    def test_two_equal_probes_reports_constant(self):
        """If all probe values are the same, the set has size 1."""
        x = _Leaf(ast_index=10, dest_size=4)
        node = _Node(_OPC.m_mov, x, dest_size=4, ast_index=None)
        is_const, value = probe_is_constant(node, [_info(10)], probe_values=[5, 5])
        assert is_const is True
        assert value == 5

    def test_custom_probes_distinguish_variable(self):
        """Custom probes [1, 2] detect that x is not constant."""
        x = _Leaf(ast_index=10, dest_size=4)
        node = _Node(_OPC.m_mov, x, dest_size=4, ast_index=None)
        is_const, value = probe_is_constant(node, [_info(10)], probe_values=[1, 2])
        assert is_const is False
        assert value is None

    def test_default_probes_are_0_and_0xffffffff(self):
        """Omitting probe_values uses [0, 0xFFFFFFFF] as defaults."""
        # x + 3 at 0 -> 3; at 0xFFFFFFFF -> wraps for 4-byte dest:
        #   (0xFFFFFFFF + 3) & 0xFFFFFFFF == 2  (different from 3)
        x = _Leaf(ast_index=10, dest_size=4)
        const = _ConstLeaf(3, 4)
        node = _Node(_OPC.m_add, x, const, dest_size=4, ast_index=None)
        is_const, value = probe_is_constant(node, [_info(10)])
        assert is_const is False
        assert value is None


# ---------------------------------------------------------------------------
# Tests: evaluation errors return (False, None)
# ---------------------------------------------------------------------------


class TestEvaluationErrors:
    """Evaluation errors are caught and return (False, None)."""

    def test_unsupported_opcode_returns_false(self):
        """AstEvaluationException for an unknown opcode -> (False, None)."""
        node = _Node(0xFF, _ConstLeaf(1, 1), dest_size=1)
        is_const, value = probe_is_constant(node, [])
        assert is_const is False
        assert value is None

    def test_division_by_zero_returns_false(self):
        """ZeroDivisionError during evaluation -> (False, None)."""
        node = _Node(_OPC.m_udiv, _ConstLeaf(5, 4), _ConstLeaf(0, 4), dest_size=4)
        is_const, value = probe_is_constant(node, [])
        assert is_const is False
        assert value is None


# ---------------------------------------------------------------------------
# Tests: edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge cases for probe_is_constant."""

    def test_x_xor_x_is_always_zero(self):
        """x ^ x is always 0 regardless of x — probe correctly identifies this.

        Both probes (0 ^ 0 == 0, 0xFFFFFFFF ^ 0xFFFFFFFF == 0) agree, so the
        pre-filter reports (True, 0).  This is a correct heuristic result; a
        subsequent Z3 check would confirm the tautology.
        """
        x = _Leaf(ast_index=10, dest_size=4)
        # We use two separate _Leaf objects but bind both to the same ast_index
        # to simulate x ^ x where both leaves refer to the same variable.
        x2 = _Leaf(ast_index=10, dest_size=4)
        node = _Node(_OPC.m_xor, x, x2, dest_size=4, ast_index=None)
        # Both leaves share ast_index=10, so env = {10: probe} binds both.
        is_const, value = probe_is_constant(node, [_info(10), _info(10)])
        assert is_const is True
        assert value == 0

    def test_empty_leaf_info_list_with_pure_constant(self):
        """Empty leaf_info_list with a constant node still works."""
        node = _Node(_OPC.m_mov, _ConstLeaf(0xDEAD, 2), dest_size=2)
        is_const, value = probe_is_constant(node, [])
        assert is_const is True
        assert value == 0xDEAD

    def test_probe_values_empty_list_returns_true_none(self):
        """An empty probe_values list yields no evaluations — set is empty.

        When the result set is empty, ``len(results) == 0 != 1``, so the
        function returns (False, None).  No probe was ever run.
        """
        node = _Node(_OPC.m_mov, _ConstLeaf(1, 1), dest_size=1)
        is_const, value = probe_is_constant(node, [], probe_values=[])
        # len({}) == 0, not 1 — so (False, None)
        assert is_const is False
        assert value is None


# ---------------------------------------------------------------------------
# Tests: importable from d810.evaluator public API
# ---------------------------------------------------------------------------


class TestPublicAPIExport:
    """probe_is_constant is accessible from the d810.evaluator package."""

    def test_importable_from_package(self):
        """from d810.evaluator import probe_is_constant works."""
        from d810.evaluator import probe_is_constant as _pic  # noqa: F401

        assert callable(_pic)

    def test_package_all_includes_probe_is_constant(self):
        """probe_is_constant appears in d810.evaluator.__all__."""
        import d810.evaluator as _mod

        assert "probe_is_constant" in _mod.__all__
