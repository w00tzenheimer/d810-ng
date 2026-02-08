"""Unit tests for the GlobalConstantInliner flow optimization rule.

These tests run without IDA Pro by mocking the required IDA modules.
They verify the pure-logic helpers (_is_constant_global, _read_constant_value,
_looks_like_pointer, _replace_with_immediate) as well as the class attributes
and initialization of GlobalConstantInliner.
"""

from __future__ import annotations

import sys
import types
from typing import Optional
from unittest import mock

import pytest

# ---------------------------------------------------------------------------
# Mock IDA modules before importing the module under test.
# ---------------------------------------------------------------------------
# The module under test and its transitive dependencies import many IDA
# modules at module level.  We install stub modules with explicit attributes.
#
# IMPORTANT: We use plain ``types.ModuleType`` (NOT a custom ``__getattr__``
# subclass) so that ``hasattr()`` behaves normally.  A catch-all
# ``__getattr__`` that never raises ``AttributeError`` poisons ``hasattr``
# for every downstream test file, preventing them from setting their own
# stub values.


def _make_stub_class(name: str) -> type:
    """Create a trivial class usable as a base (e.g. ``class Foo(mod.bar_t)``)."""
    return type(name, (), {"__init__": lambda self, *a, **kw: None})


def _ensure_ida_stubs() -> list[str]:
    """Install plain-module IDA stubs into ``sys.modules``.

    Only touches modules that are not already present.  Returns names of
    modules that were newly created so callers can track them.
    """
    needed = [
        "ida_bytes",
        "ida_hexrays",
        "ida_segment",
        "ida_xref",
        "idaapi",
        "idc",
        "ida_diskio",
    ]
    installed: list[str] = []
    for name in needed:
        if name not in sys.modules:
            sys.modules[name] = types.ModuleType(name)
            installed.append(name)
    return installed


_INSTALLED_MOCKS = _ensure_ida_stubs()

# --- ida_hexrays attributes ------------------------------------------------
# All attributes use ``if not hasattr`` guards to avoid overwriting values
# that earlier-loaded test modules may have already set.  The exact numeric
# values are arbitrary stubs; consistency within this file is ensured because
# every test reads from the same ``_ida_hexrays`` reference.
_ida_hexrays = sys.modules["ida_hexrays"]

# Default values for all attributes needed by the module under test and its
# transitive imports.  The dict maps attribute name -> fallback value.
_IDA_HEXRAYS_DEFAULTS: dict[str, object] = {
    # Maturity constants
    "MMAT_ZERO": 0, "MMAT_GENERATED": 1, "MMAT_PREOPTIMIZED": 2,
    "MMAT_LOCOPT": 3, "MMAT_CALLS": 4, "MMAT_GLBOPT1": 5,
    "MMAT_GLBOPT2": 6, "MMAT_GLBOPT3": 0, "MMAT_LVARS": 7,
    "CMAT_FINAL": 8,
    # Operand types
    "mop_z": 0, "mop_n": 1, "mop_r": 2, "mop_v": 6,
    "mop_a": 0, "mop_b": 0, "mop_c": 0, "mop_d": 0,
    "mop_S": 5, "mop_l": 7, "mop_f": 0, "mop_fn": 0,
    "mop_h": 0, "mop_p": 0, "mop_sc": 0, "mop_str": 0,
    # Opcodes that matter for this module
    "m_mov": 0x10, "m_ldx": 0x11, "m_ldc": 0x12,
    # Opcodes accessed by transitive imports.  Every opcode MUST have a
    # unique value -- if two opcodes share the same value (e.g. both 0),
    # downstream tests that rely on opcode identity will break.  The values
    # below are sequential starting at 0x100, well above the real IDA range,
    # so they cannot collide with each other or with test_table_utils stubs.
    "m_nop": 0x100, "m_stx": 0x101, "m_and": 0x102, "m_or": 0x103,
    "m_xor": 0x104, "m_add": 0x105, "m_sub": 0x106, "m_mul": 0x107,
    "m_udiv": 0x108, "m_sdiv": 0x109, "m_umod": 0x10A, "m_smod": 0x10B,
    "m_neg": 0x10C, "m_bnot": 0x10D, "m_lnot": 0x10E,
    "m_shl": 0x10F, "m_shr": 0x110, "m_sar": 0x111, "m_ext": 0x112,
    "m_low": 0x113, "m_high": 0x114, "m_xds": 0x115, "m_xdu": 0x116,
    "m_und": 0x117, "m_push": 0x118, "m_pop": 0x119, "m_ret": 0x11A,
    "m_goto": 0x11B, "m_jz": 0x11C, "m_jnz": 0x11D, "m_jcnd": 0x11E,
    "m_jae": 0x11F, "m_jbe": 0x120, "m_ja": 0x121, "m_jb": 0x122,
    "m_jg": 0x123, "m_jge": 0x124, "m_jl": 0x125, "m_jle": 0x126,
    "m_jtbl": 0x127, "m_ijmp": 0x128, "m_call": 0x129, "m_icall": 0x12A,
    "m_setz": 0x12B, "m_setnz": 0x12C, "m_seto": 0x12D, "m_setp": 0x12E,
    "m_sets": 0x12F, "m_seta": 0x130, "m_setae": 0x131, "m_setb": 0x132,
    "m_setbe": 0x133, "m_setg": 0x134, "m_setge": 0x135, "m_setl": 0x136,
    "m_setle": 0x137, "m_cfshl": 0x138, "m_cfshr": 0x139,
    "m_cfadd": 0x13A, "m_ofadd": 0x13B,
    "m_f2i": 0x13C, "m_f2u": 0x13D, "m_i2f": 0x13E, "m_u2f": 0x13F,
    "m_f2f": 0x140, "m_fneg": 0x141, "m_fadd": 0x142, "m_fsub": 0x143,
    "m_fmul": 0x144, "m_fdiv": 0x145,
}
for _attr, _val in _IDA_HEXRAYS_DEFAULTS.items():
    if not hasattr(_ida_hexrays, _attr):
        setattr(_ida_hexrays, _attr, _val)

# Stub type used as a base class by transitive imports
if not hasattr(_ida_hexrays, "vd_printer_t"):
    _ida_hexrays.vd_printer_t = _make_stub_class("vd_printer_t")

# --- idaapi attributes -----------------------------------------------------
_idaapi = sys.modules["idaapi"]
_IDAAPI_DEFAULTS: dict[str, object] = {
    "BADADDR": 0xFFFFFFFFFFFFFFFF,
    "SEGPERM_WRITE": 0x2,
    "SEGPERM_READ": 0x4,
    "SEGPERM_EXEC": 0x1,
    "get_byte": lambda ea: 0,
    "get_word": lambda ea: 0,
    "get_dword": lambda ea: 0,
    "get_qword": lambda ea: 0,
}
for _attr, _val in _IDAAPI_DEFAULTS.items():
    if not hasattr(_idaapi, _attr):
        setattr(_idaapi, _attr, _val)

# --- ida_segment attributes ------------------------------------------------
_ida_segment = sys.modules["ida_segment"]
if not hasattr(_ida_segment, "getseg"):
    _ida_segment.getseg = lambda ea: None
if not hasattr(_ida_segment, "get_segm_name"):
    _ida_segment.get_segm_name = lambda seg: ""

# --- ida_bytes attributes --------------------------------------------------
_ida_bytes_mod = sys.modules["ida_bytes"]
if not hasattr(_ida_bytes_mod, "get_bytes"):
    _ida_bytes_mod.get_bytes = lambda ea, size: None
if not hasattr(_ida_bytes_mod, "get_flags"):
    _ida_bytes_mod.get_flags = lambda ea: 0
if not hasattr(_ida_bytes_mod, "is_code"):
    _ida_bytes_mod.is_code = lambda flags: False

# --- ida_xref attributes ---------------------------------------------------
_ida_xref = sys.modules["ida_xref"]
if not hasattr(_ida_xref, "XREF_ALL"):
    _ida_xref.XREF_ALL = 0
if not hasattr(_ida_xref, "dr_W"):
    _ida_xref.dr_W = 2
if not hasattr(_ida_xref, "xrefblk_t"):
    _ida_xref.xrefblk_t = _make_stub_class("xrefblk_t")


# Now it is safe to import the module under test.
from d810.optimizers.microcode.flow.global_const_inline import (  # noqa: E402
    GlobalConstantInliner,
    _is_constant_global,
    _looks_like_pointer,
    _read_constant_value,
    _replace_with_immediate,
)


# ---------------------------------------------------------------------------
# Lightweight test helpers
# ---------------------------------------------------------------------------


class _MockSegment:
    """Minimal stand-in for ``ida_segment.segment_t``."""

    def __init__(self, name: str = ".rodata", perm: int = 0x4):
        self._name = name
        self.perm = perm


class _MockXrefblk:
    """Minimal stand-in for ``ida_xref.xrefblk_t``."""

    def __init__(self, xrefs: Optional[list[int]] = None):
        self._xrefs = xrefs or []
        self._idx = -1
        self.type = 0

    def first_to(self, ea: int, flags: int) -> bool:
        self._idx = 0
        if self._idx < len(self._xrefs):
            self.type = self._xrefs[self._idx]
            return True
        return False

    def next_to(self) -> bool:
        self._idx += 1
        if self._idx < len(self._xrefs):
            self.type = self._xrefs[self._idx]
            return True
        return False


# ====================================================================== #
# Tests for class attributes                                              #
# ====================================================================== #


class TestGlobalConstantInlinerAttributes:
    """Verify class-level attributes and initialisation."""

    def test_description_is_set(self):
        rule = GlobalConstantInliner()
        assert rule.DESCRIPTION is not None
        assert "constant" in rule.DESCRIPTION.lower()

    def test_uses_deferred_cfg(self):
        rule = GlobalConstantInliner()
        assert rule.USES_DEFERRED_CFG is True

    def test_safe_maturities_is_none(self):
        """SAFE_MATURITIES=None means safe at any maturity."""
        rule = GlobalConstantInliner()
        assert rule.SAFE_MATURITIES is None

    def test_maturities_include_preoptimized(self):
        rule = GlobalConstantInliner()
        assert _ida_hexrays.MMAT_PREOPTIMIZED in rule.maturities

    def test_maturities_include_locopt(self):
        rule = GlobalConstantInliner()
        assert _ida_hexrays.MMAT_LOCOPT in rule.maturities


# ====================================================================== #
# Tests for _is_constant_global                                           #
# ====================================================================== #


class TestIsConstantGlobal:
    """Tests for the _is_constant_global helper."""

    def _make_seg(self, name: str, perm: int = 0x4) -> _MockSegment:
        return _MockSegment(name=name, perm=perm)

    def test_rodata_is_constant(self):
        seg = self._make_seg(".rodata")
        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.getseg",
            return_value=seg,
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.get_segm_name",
            return_value=".rodata",
        ):
            assert _is_constant_global(0x1000) is True

    def test_rdata_is_constant(self):
        seg = self._make_seg(".rdata")
        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.getseg",
            return_value=seg,
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.get_segm_name",
            return_value=".rdata",
        ):
            assert _is_constant_global(0x1000) is True

    def test_const_section_is_constant(self):
        seg = self._make_seg("__const")
        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.getseg",
            return_value=seg,
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.get_segm_name",
            return_value="__const",
        ):
            assert _is_constant_global(0x1000) is True

    def test_cstring_is_constant(self):
        seg = self._make_seg("__cstring")
        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.getseg",
            return_value=seg,
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.get_segm_name",
            return_value="__cstring",
        ):
            assert _is_constant_global(0x1000) is True

    def test_data_const_is_constant(self):
        seg = self._make_seg("__DATA_CONST")
        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.getseg",
            return_value=seg,
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.get_segm_name",
            return_value="__DATA_CONST",
        ):
            assert _is_constant_global(0x1000) is True

    def test_cfstring_is_constant(self):
        seg = self._make_seg("__cfstring")
        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.getseg",
            return_value=seg,
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.get_segm_name",
            return_value="__cfstring",
        ):
            assert _is_constant_global(0x1000) is True

    def test_no_segment_returns_false(self):
        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.getseg",
            return_value=None,
        ):
            assert _is_constant_global(0x1000) is False

    def test_writable_segment_returns_false(self):
        seg = self._make_seg(".text", perm=0x6)  # R+W
        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.getseg",
            return_value=seg,
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.get_segm_name",
            return_value=".text",
        ):
            assert _is_constant_global(0x1000) is False

    def test_data_section_no_write_xrefs_is_constant(self):
        """A .data address with no write xrefs should be treated as constant."""
        seg = self._make_seg(".data", perm=0x6)
        mock_xref = _MockXrefblk(xrefs=[])

        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.getseg",
            return_value=seg,
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.get_segm_name",
            return_value=".data",
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_xref.xrefblk_t",
            return_value=mock_xref,
        ):
            assert _is_constant_global(0x1000) is True

    def test_data_section_with_write_xrefs_is_not_constant(self):
        """A .data address with write xrefs should NOT be treated as constant."""
        seg = self._make_seg(".data", perm=0x6)
        # dr_W = 2 (from ida_xref mock)
        mock_xref = _MockXrefblk(xrefs=[2])

        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.getseg",
            return_value=seg,
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.get_segm_name",
            return_value=".data",
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_xref.xrefblk_t",
            return_value=mock_xref,
        ):
            assert _is_constant_global(0x1000) is False

    def test_non_writable_unknown_segment_is_constant(self):
        """Segment with unknown name but no WRITE perm should be constant."""
        seg = self._make_seg(".unknown", perm=0x4)  # R only
        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.getseg",
            return_value=seg,
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.get_segm_name",
            return_value=".unknown",
        ):
            assert _is_constant_global(0x1000) is True


# ====================================================================== #
# Tests for _read_constant_value                                          #
# ====================================================================== #


class TestReadConstantValue:
    """Tests for _read_constant_value at various sizes."""

    def test_read_1_byte(self):
        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.idaapi.get_byte",
            return_value=0x42,
        ):
            assert _read_constant_value(0x1000, 1) == 0x42

    def test_read_2_bytes(self):
        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.idaapi.get_word",
            return_value=0xBEEF,
        ):
            assert _read_constant_value(0x1000, 2) == 0xBEEF

    def test_read_4_bytes(self):
        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.idaapi.get_dword",
            return_value=0xDEADBEEF,
        ):
            assert _read_constant_value(0x1000, 4) == 0xDEADBEEF

    def test_read_8_bytes(self):
        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.idaapi.get_qword",
            return_value=0x0123456789ABCDEF,
        ):
            assert _read_constant_value(0x1000, 8) == 0x0123456789ABCDEF

    def test_read_3_bytes_fallback(self):
        """Unusual size falls back to ida_bytes.get_bytes."""
        raw = b"\x01\x02\x03"
        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_bytes.get_bytes",
            return_value=raw,
        ):
            val = _read_constant_value(0x1000, 3)
            assert val == int.from_bytes(raw, byteorder="little")

    def test_read_fallback_returns_zero_on_none(self):
        """When get_bytes returns None, the result should be 0."""
        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_bytes.get_bytes",
            return_value=None,
        ):
            assert _read_constant_value(0x1000, 5) == 0


# ====================================================================== #
# Tests for _looks_like_pointer                                           #
# ====================================================================== #


class TestLooksLikePointer:
    """Tests for the _looks_like_pointer heuristic."""

    def test_small_sizes_never_pointer(self):
        """Values < 4 bytes should never be treated as pointers."""
        assert _looks_like_pointer(0xFFFF, 1) is False
        assert _looks_like_pointer(0xFFFF, 2) is False
        assert _looks_like_pointer(0xFFFF, 3) is False

    def test_zero_is_not_pointer(self):
        """Zero could be NULL, but we treat it as a valid constant."""
        assert _looks_like_pointer(0, 4) is False
        assert _looks_like_pointer(0, 8) is False

    def test_value_in_segment_is_pointer(self):
        """If value falls inside a known segment, it is a pointer."""
        seg = _MockSegment(".text")
        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.getseg",
            return_value=seg,
        ):
            assert _looks_like_pointer(0x401000, 4) is True

    def test_value_not_in_segment_is_not_pointer(self):
        """If value does not fall inside any segment, it is not a pointer."""
        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.getseg",
            return_value=None,
        ):
            assert _looks_like_pointer(0xDEADBEEF, 4) is False

    def test_macos_aslr_range_is_pointer(self):
        """64-bit value in macOS ASLR range (0x1X_XXXX_XXXX)."""
        val = 0x10000001000  # (val >> 40) == 0x1
        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.getseg",
            return_value=None,
        ):
            assert _looks_like_pointer(val, 8) is True

    def test_linux_user_space_7_is_pointer(self):
        """64-bit value in Linux user-space range (top nibble 0x7)."""
        val = 0x7FFF00000000
        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.getseg",
            return_value=None,
        ):
            assert _looks_like_pointer(val, 8) is True

    def test_linux_user_space_5_is_pointer(self):
        """64-bit value in Linux user-space range (top nibble 0x5)."""
        val = 0x5FFF00000000
        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.getseg",
            return_value=None,
        ):
            assert _looks_like_pointer(val, 8) is True

    def test_normal_constant_not_pointer(self):
        """A regular 8-byte constant should not be flagged as pointer."""
        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.getseg",
            return_value=None,
        ):
            assert _looks_like_pointer(0x12345678, 8) is False

    def test_small_8byte_constant_not_pointer(self):
        """A small 8-byte value should not look like a pointer."""
        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.getseg",
            return_value=None,
        ):
            assert _looks_like_pointer(42, 8) is False


# ====================================================================== #
# Tests for _replace_with_immediate                                       #
# ====================================================================== #


class TestReplaceWithImmediate:
    """Tests for the _replace_with_immediate helper."""

    def test_opcode_set_to_mov(self):
        insn = mock.MagicMock()
        insn.opcode = _ida_hexrays.m_ldx  # starts as ldx
        insn.l = mock.MagicMock()
        insn.r = mock.MagicMock()
        _replace_with_immediate(insn, 0x42, 4)
        assert insn.opcode == _ida_hexrays.m_mov

    def test_l_operand_set_to_number(self):
        insn = mock.MagicMock()
        insn.opcode = _ida_hexrays.m_mov
        insn.l = mock.MagicMock()
        insn.r = mock.MagicMock()
        _replace_with_immediate(insn, 0xBEEF, 2)
        insn.l.make_number.assert_called_once_with(0xBEEF, 2)

    def test_r_operand_erased(self):
        insn = mock.MagicMock()
        insn.opcode = _ida_hexrays.m_ldx
        insn.l = mock.MagicMock()
        insn.r = mock.MagicMock()
        _replace_with_immediate(insn, 0x1234, 4)
        insn.r.erase.assert_called_once()


# ====================================================================== #
# Tests for GlobalConstantInliner.optimize (integration-like)             #
# ====================================================================== #


class TestGlobalConstantInlinerOptimize:
    """Tests for the optimize() method with mocked blocks."""

    def _make_rule(self) -> GlobalConstantInliner:
        return GlobalConstantInliner()

    def test_skip_non_mov_ldx_instructions(self):
        """Instructions other than m_mov/m_ldx should be skipped."""
        rule = self._make_rule()

        insn = mock.MagicMock()
        insn.opcode = 0xFF  # some other opcode
        insn.next = None

        blk = mock.MagicMock()
        blk.head = insn
        blk.mba = mock.MagicMock()

        result = rule.optimize(blk)
        assert result == 0

    def test_skip_when_no_instructions(self):
        """Empty block should return 0 changes."""
        rule = self._make_rule()

        blk = mock.MagicMock()
        blk.head = None
        blk.mba = mock.MagicMock()

        result = rule.optimize(blk)
        assert result == 0

    def test_skip_oversized_operand(self):
        """Operands larger than 8 bytes should be skipped."""
        rule = self._make_rule()

        insn = mock.MagicMock()
        insn.opcode = _ida_hexrays.m_mov
        insn.l.t = _ida_hexrays.mop_v
        insn.l.g = 0x1000
        insn.l.size = 16  # too large
        insn.next = None

        blk = mock.MagicMock()
        blk.head = insn

        result = rule.optimize(blk)
        assert result == 0

    def test_skip_code_address(self):
        """Addresses that point to code should be skipped."""
        rule = self._make_rule()

        insn = mock.MagicMock()
        insn.opcode = _ida_hexrays.m_mov
        insn.l.t = _ida_hexrays.mop_v
        insn.l.g = 0x1000
        insn.l.size = 4
        insn.next = None

        blk = mock.MagicMock()
        blk.head = insn

        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_bytes.get_flags",
            return_value=0,
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_bytes.is_code",
            return_value=True,
        ):
            result = rule.optimize(blk)
            assert result == 0


# ====================================================================== #
# Issue A3: optimize() happy-path (success) tests                         #
# ====================================================================== #


class TestOptimizeSuccessPath:
    """Tests verifying optimize() succeeds when conditions are met."""

    def _make_rule(self) -> GlobalConstantInliner:
        return GlobalConstantInliner()

    def _rodata_patches(self, ea: int = 0x1000, value: int = 0xDEAD, size: int = 4):
        """Return a context manager that patches all IDA helpers for a
        successful inlining of a m_mov with mop_v pointing to .rodata."""
        seg = _MockSegment(".rodata", perm=0x4)
        return [
            mock.patch(
                "d810.optimizers.microcode.flow.global_const_inline.ida_bytes.get_flags",
                return_value=0,
            ),
            mock.patch(
                "d810.optimizers.microcode.flow.global_const_inline.ida_bytes.is_code",
                return_value=False,
            ),
            mock.patch(
                "d810.optimizers.microcode.flow.global_const_inline.ida_segment.getseg",
                side_effect=lambda a: seg if a == ea else None,
            ),
            mock.patch(
                "d810.optimizers.microcode.flow.global_const_inline.ida_segment.get_segm_name",
                return_value=".rodata",
            ),
            mock.patch(
                "d810.optimizers.microcode.flow.global_const_inline.idaapi.get_dword",
                return_value=value,
            ),
            mock.patch(
                "d810.optimizers.microcode.flow.global_const_inline.idaapi.get_word",
                return_value=value,
            ),
            mock.patch(
                "d810.optimizers.microcode.flow.global_const_inline.idaapi.get_byte",
                return_value=value,
            ),
            mock.patch(
                "d810.optimizers.microcode.flow.global_const_inline.idaapi.get_qword",
                return_value=value,
            ),
        ]

    def test_mov_mop_v_rodata_inlines_successfully(self):
        """m_mov with mop_v pointing to .rodata constant -> inlines."""
        rule = self._make_rule()
        ea = 0x1000
        value = 0xDEAD
        size = 4

        insn = mock.MagicMock()
        insn.opcode = _ida_hexrays.m_mov
        insn.l.t = _ida_hexrays.mop_v
        insn.l.g = ea
        insn.l.size = size
        insn.next = None

        blk = mock.MagicMock()
        blk.head = insn

        patches = self._rodata_patches(ea=ea, value=value, size=size)
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
             patches[5], patches[6], patches[7]:
            result = rule.optimize(blk)
            assert result == 1

    def test_mov_success_calls_make_number_with_correct_args(self):
        """On success, make_number is called with (value, size)."""
        rule = self._make_rule()
        ea = 0x2000
        value = 0x42
        size = 4

        insn = mock.MagicMock()
        insn.opcode = _ida_hexrays.m_mov
        insn.l.t = _ida_hexrays.mop_v
        insn.l.g = ea
        insn.l.size = size
        insn.next = None

        blk = mock.MagicMock()
        blk.head = insn

        patches = self._rodata_patches(ea=ea, value=value, size=size)
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
             patches[5], patches[6], patches[7]:
            rule.optimize(blk)
            insn.l.make_number.assert_called_once_with(value, size)

    def test_mov_success_calls_mark_lists_dirty(self):
        """On success, blk.mark_lists_dirty() is called exactly once."""
        rule = self._make_rule()
        ea = 0x3000
        value = 0xBEEF
        size = 4

        insn = mock.MagicMock()
        insn.opcode = _ida_hexrays.m_mov
        insn.l.t = _ida_hexrays.mop_v
        insn.l.g = ea
        insn.l.size = size
        insn.next = None

        blk = mock.MagicMock()
        blk.head = insn

        patches = self._rodata_patches(ea=ea, value=value, size=size)
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
             patches[5], patches[6], patches[7]:
            rule.optimize(blk)
            blk.mark_lists_dirty.assert_called_once()

    def test_no_success_does_not_call_mark_lists_dirty(self):
        """When optimize returns 0, mark_lists_dirty is NOT called."""
        rule = self._make_rule()

        insn = mock.MagicMock()
        insn.opcode = 0xFF  # not m_mov or m_ldx
        insn.next = None

        blk = mock.MagicMock()
        blk.head = insn

        result = rule.optimize(blk)
        assert result == 0
        blk.mark_lists_dirty.assert_not_called()

    def test_mov_success_returns_1(self):
        """Successful single inlining returns 1."""
        rule = self._make_rule()
        ea = 0x4000
        value = 0x99
        size = 2

        insn = mock.MagicMock()
        insn.opcode = _ida_hexrays.m_mov
        insn.l.t = _ida_hexrays.mop_v
        insn.l.g = ea
        insn.l.size = size
        insn.next = None

        blk = mock.MagicMock()
        blk.head = insn

        patches = self._rodata_patches(ea=ea, value=value, size=size)
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
             patches[5], patches[6], patches[7]:
            result = rule.optimize(blk)
            assert result == 1


# ====================================================================== #
# Issue D4: m_ldx pattern tests                                           #
# ====================================================================== #


class TestOptimizeLdxPath:
    """Tests specifically for the m_ldx code path in optimize()."""

    def _make_rule(self) -> GlobalConstantInliner:
        return GlobalConstantInliner()

    def _rodata_patches_for_ldx(self, ea: int = 0x5000, value: int = 0xCAFE, size: int = 4):
        """Patches for successful m_ldx inlining."""
        seg = _MockSegment(".rodata", perm=0x4)
        return [
            mock.patch(
                "d810.optimizers.microcode.flow.global_const_inline.ida_bytes.get_flags",
                return_value=0,
            ),
            mock.patch(
                "d810.optimizers.microcode.flow.global_const_inline.ida_bytes.is_code",
                return_value=False,
            ),
            mock.patch(
                "d810.optimizers.microcode.flow.global_const_inline.ida_segment.getseg",
                side_effect=lambda a: seg if a == ea else None,
            ),
            mock.patch(
                "d810.optimizers.microcode.flow.global_const_inline.ida_segment.get_segm_name",
                return_value=".rodata",
            ),
            mock.patch(
                "d810.optimizers.microcode.flow.global_const_inline.idaapi.get_dword",
                return_value=value,
            ),
            mock.patch(
                "d810.optimizers.microcode.flow.global_const_inline.idaapi.get_word",
                return_value=value,
            ),
            mock.patch(
                "d810.optimizers.microcode.flow.global_const_inline.idaapi.get_byte",
                return_value=value,
            ),
            mock.patch(
                "d810.optimizers.microcode.flow.global_const_inline.idaapi.get_qword",
                return_value=value,
            ),
        ]

    def test_ldx_uses_insn_d_size_not_l_size(self):
        """For m_ldx, size comes from insn.d.size, not insn.l.size."""
        rule = self._make_rule()
        ea = 0x5000
        value = 0xCAFE
        d_size = 2  # destination size
        l_size = 8  # segment operand size (should be ignored)

        insn = mock.MagicMock()
        insn.opcode = _ida_hexrays.m_ldx
        insn.r.t = _ida_hexrays.mop_v
        insn.r.g = ea
        insn.l.size = l_size  # this should NOT be used
        insn.d.size = d_size  # this SHOULD be used
        insn.next = None

        blk = mock.MagicMock()
        blk.head = insn

        patches = self._rodata_patches_for_ldx(ea=ea, value=value, size=d_size)
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
             patches[5], patches[6], patches[7]:
            result = rule.optimize(blk)
            assert result == 1
            # Verify make_number was called with d_size (2), not l_size (8)
            insn.l.make_number.assert_called_once_with(value, d_size)

    def test_ldx_uses_insn_r_g_for_address(self):
        """For m_ldx, global address comes from insn.r.g, not insn.l.g."""
        rule = self._make_rule()
        ea = 0x6000
        value = 0xAB
        size = 1

        insn = mock.MagicMock()
        insn.opcode = _ida_hexrays.m_ldx
        insn.r.t = _ida_hexrays.mop_v
        insn.r.g = ea
        insn.l.g = 0xBAD  # should NOT be used
        insn.d.size = size
        insn.next = None

        blk = mock.MagicMock()
        blk.head = insn

        patches = self._rodata_patches_for_ldx(ea=ea, value=value, size=size)
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
             patches[5], patches[6], patches[7]:
            result = rule.optimize(blk)
            assert result == 1

    def test_ldx_becomes_mov(self):
        """After inlining, m_ldx instruction becomes m_mov."""
        rule = self._make_rule()
        ea = 0x7000
        value = 0xFE
        size = 4

        insn = mock.MagicMock()
        insn.opcode = _ida_hexrays.m_ldx
        insn.r.t = _ida_hexrays.mop_v
        insn.r.g = ea
        insn.d.size = size
        insn.next = None

        blk = mock.MagicMock()
        blk.head = insn

        patches = self._rodata_patches_for_ldx(ea=ea, value=value, size=size)
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
             patches[5], patches[6], patches[7]:
            rule.optimize(blk)
            assert insn.opcode == _ida_hexrays.m_mov

    def test_ldx_l_operand_overwritten(self):
        """For m_ldx, the segment operand (l) is overwritten with the constant."""
        rule = self._make_rule()
        ea = 0x8000
        value = 0x1234
        size = 4

        insn = mock.MagicMock()
        insn.opcode = _ida_hexrays.m_ldx
        insn.r.t = _ida_hexrays.mop_v
        insn.r.g = ea
        insn.d.size = size
        insn.next = None

        blk = mock.MagicMock()
        blk.head = insn

        patches = self._rodata_patches_for_ldx(ea=ea, value=value, size=size)
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
             patches[5], patches[6], patches[7]:
            rule.optimize(blk)
            insn.l.make_number.assert_called_once_with(value, size)
            insn.r.erase.assert_called_once()

    def test_ldx_r_operand_not_mop_v_skipped(self):
        """m_ldx where r operand is NOT mop_v should be skipped."""
        rule = self._make_rule()

        insn = mock.MagicMock()
        insn.opcode = _ida_hexrays.m_ldx
        insn.r.t = _ida_hexrays.mop_r  # register, not global
        insn.next = None

        blk = mock.MagicMock()
        blk.head = insn

        result = rule.optimize(blk)
        assert result == 0


# ====================================================================== #
# Issue D5: Size boundary tests                                           #
# ====================================================================== #


class TestSizeBoundaries:
    """Tests for size boundary validation in optimize()."""

    def _make_rule(self) -> GlobalConstantInliner:
        return GlobalConstantInliner()

    def test_size_zero_rejected(self):
        """size=0 should be rejected (size <= 0 check)."""
        rule = self._make_rule()

        insn = mock.MagicMock()
        insn.opcode = _ida_hexrays.m_mov
        insn.l.t = _ida_hexrays.mop_v
        insn.l.g = 0x1000
        insn.l.size = 0  # zero size
        insn.next = None

        blk = mock.MagicMock()
        blk.head = insn

        result = rule.optimize(blk)
        assert result == 0

    def test_size_8_accepted(self):
        """size=8 should be accepted (boundary: <= _MAX_INLINE_SIZE)."""
        rule = self._make_rule()
        ea = 0x9000
        value = 0x0123456789ABCDEF

        insn = mock.MagicMock()
        insn.opcode = _ida_hexrays.m_mov
        insn.l.t = _ida_hexrays.mop_v
        insn.l.g = ea
        insn.l.size = 8  # exactly at boundary
        insn.next = None

        blk = mock.MagicMock()
        blk.head = insn

        seg = _MockSegment(".rodata", perm=0x4)
        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_bytes.get_flags",
            return_value=0,
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_bytes.is_code",
            return_value=False,
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.getseg",
            side_effect=lambda a: seg if a == ea else None,
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.get_segm_name",
            return_value=".rodata",
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.idaapi.get_qword",
            return_value=value,
        ):
            result = rule.optimize(blk)
            assert result == 1

    def test_size_9_rejected(self):
        """size=9 should be rejected (> _MAX_INLINE_SIZE)."""
        rule = self._make_rule()

        insn = mock.MagicMock()
        insn.opcode = _ida_hexrays.m_mov
        insn.l.t = _ida_hexrays.mop_v
        insn.l.g = 0x1000
        insn.l.size = 9  # over boundary
        insn.next = None

        blk = mock.MagicMock()
        blk.head = insn

        result = rule.optimize(blk)
        assert result == 0


# ====================================================================== #
# Issue: Multi-instruction blocks                                         #
# ====================================================================== #


class TestMultiInstructionBlocks:
    """Tests for blocks with multiple instructions."""

    def _make_rule(self) -> GlobalConstantInliner:
        return GlobalConstantInliner()

    def _make_eligible_insn(self, ea: int, size: int = 4):
        """Create a mock instruction eligible for inlining (m_mov with mop_v)."""
        insn = mock.MagicMock()
        insn.opcode = _ida_hexrays.m_mov
        insn.l.t = _ida_hexrays.mop_v
        insn.l.g = ea
        insn.l.size = size
        return insn

    def _make_non_eligible_insn(self):
        """Create a mock instruction NOT eligible for inlining."""
        insn = mock.MagicMock()
        insn.opcode = 0xFF  # not m_mov or m_ldx
        return insn

    def test_three_insns_first_and_third_eligible_returns_2(self):
        """Block: eligible, not-eligible, eligible -> returns 2."""
        rule = self._make_rule()

        insn1 = self._make_eligible_insn(ea=0xA000)
        insn2 = self._make_non_eligible_insn()
        insn3 = self._make_eligible_insn(ea=0xB000)

        # Chain: insn1 -> insn2 -> insn3 -> None
        insn1.next = insn2
        insn2.next = insn3
        insn3.next = None

        blk = mock.MagicMock()
        blk.head = insn1

        seg = _MockSegment(".rodata", perm=0x4)
        value = 0x42

        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_bytes.get_flags",
            return_value=0,
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_bytes.is_code",
            return_value=False,
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.getseg",
            side_effect=lambda a: seg if a in (0xA000, 0xB000) else None,
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.get_segm_name",
            return_value=".rodata",
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.idaapi.get_dword",
            return_value=value,
        ):
            result = rule.optimize(blk)
            assert result == 2
            blk.mark_lists_dirty.assert_called_once()

    def test_no_eligible_instructions_returns_0(self):
        """Block with no eligible instructions -> returns 0."""
        rule = self._make_rule()

        insn1 = self._make_non_eligible_insn()
        insn2 = self._make_non_eligible_insn()
        insn3 = self._make_non_eligible_insn()

        insn1.next = insn2
        insn2.next = insn3
        insn3.next = None

        blk = mock.MagicMock()
        blk.head = insn1

        result = rule.optimize(blk)
        assert result == 0
        blk.mark_lists_dirty.assert_not_called()

    def test_all_instructions_visited(self):
        """Verify all instructions in the block are visited, not just the first."""
        rule = self._make_rule()

        # 3 non-eligible, then 1 eligible at the end
        insn1 = self._make_non_eligible_insn()
        insn2 = self._make_non_eligible_insn()
        insn3 = self._make_non_eligible_insn()
        insn4 = self._make_eligible_insn(ea=0xC000)
        insn4.next = None

        insn1.next = insn2
        insn2.next = insn3
        insn3.next = insn4

        blk = mock.MagicMock()
        blk.head = insn1

        seg = _MockSegment(".rodata", perm=0x4)
        value = 0x77

        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_bytes.get_flags",
            return_value=0,
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_bytes.is_code",
            return_value=False,
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.getseg",
            side_effect=lambda a: seg if a == 0xC000 else None,
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.get_segm_name",
            return_value=".rodata",
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.idaapi.get_dword",
            return_value=value,
        ):
            result = rule.optimize(blk)
            assert result == 1
            insn4.l.make_number.assert_called_once_with(value, 4)


# ====================================================================== #
# Issue: Pointer rejection in end-to-end flow                             #
# ====================================================================== #


class TestPointerRejectionEndToEnd:
    """Test that pointer-like values are rejected in the full optimize() flow."""

    def _make_rule(self) -> GlobalConstantInliner:
        return GlobalConstantInliner()

    def test_value_looks_like_pointer_not_inlined(self):
        """Value passes _is_constant_global and _read_constant_value but
        fails _looks_like_pointer -> returns 0, make_number NOT called."""
        rule = self._make_rule()
        ea = 0xD000
        pointer_value = 0x401000  # will look like pointer (falls in segment)
        size = 4

        insn = mock.MagicMock()
        insn.opcode = _ida_hexrays.m_mov
        insn.l.t = _ida_hexrays.mop_v
        insn.l.g = ea
        insn.l.size = size
        insn.next = None

        blk = mock.MagicMock()
        blk.head = insn

        seg_rodata = _MockSegment(".rodata", perm=0x4)
        seg_text = _MockSegment(".text", perm=0x5)

        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_bytes.get_flags",
            return_value=0,
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_bytes.is_code",
            return_value=False,
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.getseg",
            side_effect=lambda a: seg_rodata if a == ea else (seg_text if a == pointer_value else None),
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.get_segm_name",
            return_value=".rodata",
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.idaapi.get_dword",
            return_value=pointer_value,
        ):
            result = rule.optimize(blk)
            assert result == 0
            insn.l.make_number.assert_not_called()
            blk.mark_lists_dirty.assert_not_called()


# ====================================================================== #
# Issue C3: End-to-end optimize() integration test                        #
# ====================================================================== #


class TestEndToEndIntegration:
    """Full integration test: detect mov with global -> validate read-only ->
    read value -> check not pointer -> replace."""

    def _make_rule(self) -> GlobalConstantInliner:
        return GlobalConstantInliner()

    def test_full_flow_mov_rodata(self):
        """Full e2e: m_mov with mop_v in .rodata, non-pointer value -> inlined."""
        rule = self._make_rule()
        ea = 0xE000
        value = 0xDEADBEEF
        size = 4

        # Build a realistic instruction mock
        insn = mock.MagicMock()
        insn.opcode = _ida_hexrays.m_mov
        insn.l.t = _ida_hexrays.mop_v
        insn.l.g = ea
        insn.l.size = size
        insn.next = None

        blk = mock.MagicMock()
        blk.head = insn

        seg = _MockSegment(".rodata", perm=0x4)

        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_bytes.get_flags",
            return_value=0,
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_bytes.is_code",
            return_value=False,
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.getseg",
            side_effect=lambda a: seg if a == ea else None,
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.get_segm_name",
            return_value=".rodata",
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.idaapi.get_dword",
            return_value=value,
        ):
            result = rule.optimize(blk)

            # 1. Return value should be 1 (one inlined)
            assert result == 1

            # 2. Instruction should now be m_mov
            assert insn.opcode == _ida_hexrays.m_mov

            # 3. l operand should have make_number called with correct args
            insn.l.make_number.assert_called_once_with(value, size)

            # 4. r operand should be erased
            insn.r.erase.assert_called_once()

            # 5. Block should be marked dirty
            blk.mark_lists_dirty.assert_called_once()

    def test_full_flow_ldx_rodata(self):
        """Full e2e: m_ldx with mop_v in .rodata -> becomes m_mov with immediate."""
        rule = self._make_rule()
        ea = 0xF000
        value = 0xCAFEBABE
        size = 4

        insn = mock.MagicMock()
        insn.opcode = _ida_hexrays.m_ldx
        insn.r.t = _ida_hexrays.mop_v
        insn.r.g = ea
        insn.d.size = size
        insn.next = None

        blk = mock.MagicMock()
        blk.head = insn

        seg = _MockSegment(".rodata", perm=0x4)

        with mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_bytes.get_flags",
            return_value=0,
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_bytes.is_code",
            return_value=False,
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.getseg",
            side_effect=lambda a: seg if a == ea else None,
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.ida_segment.get_segm_name",
            return_value=".rodata",
        ), mock.patch(
            "d810.optimizers.microcode.flow.global_const_inline.idaapi.get_dword",
            return_value=value,
        ):
            result = rule.optimize(blk)

            # 1. Return value should be 1
            assert result == 1

            # 2. Instruction should now be m_mov (was m_ldx)
            assert insn.opcode == _ida_hexrays.m_mov

            # 3. l operand gets the constant
            insn.l.make_number.assert_called_once_with(value, size)

            # 4. r operand erased (was the address operand)
            insn.r.erase.assert_called_once()

            # 5. Block marked dirty
            blk.mark_lists_dirty.assert_called_once()
