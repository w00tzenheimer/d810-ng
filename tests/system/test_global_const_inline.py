"""System tests for the GlobalConstantInliner flow optimization rule.

These tests run without IDA Pro by mocking the required IDA modules.
They verify the pure-logic helpers (_is_constant_global, _read_constant_value,
_looks_like_pointer, _replace_with_immediate) as well as the class attributes
and initialization of GlobalConstantInliner.

All IDA module stubs are injected via a module-scoped pytest fixture
(``_ida_stubs``) that properly saves and restores ``sys.modules``
so that stubs do not leak into other test modules.
"""

from __future__ import annotations

import sys
import types
from typing import Optional
from unittest import mock
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# Stub helpers
# ---------------------------------------------------------------------------

class _AutoIntModule(types.ModuleType):
    """Module stub that auto-generates attributes on access.

    * Names ending in ``_t`` (class names like ``vd_printer_t``,
      ``mop_t``) get a proper class so subclassing / ``@register`` works.
    * Integer-looking names (``m_*``, ``mop_*``, ``BLT_*``, ``MMAT_*``,
      ``MBL_*``, ``MFL_*``) get a unique negative integer.
    * Everything else gets a ``MagicMock`` so attribute access chains
      silently succeed.
    """

    _COUNTER = -2000  # separate range from test_indirect_branch

    _INT_PREFIXES = ("m_", "mop_", "BLT_", "MMAT_", "MBL_", "MFL_")

    def __getattr__(self, name: str):
        if name.startswith("_"):
            raise AttributeError(name)

        # Class-like names -> produce an empty base class
        if name.endswith("_t"):
            cls = type(name, (), {})
            setattr(self, name, cls)
            return cls

        # Opcode / constant names -> unique integer
        if any(name.startswith(pfx) for pfx in self._INT_PREFIXES):
            _AutoIntModule._COUNTER -= 1
            val = _AutoIntModule._COUNTER
            setattr(self, name, val)
            return val

        # Fallback: MagicMock (allows arbitrary chaining)
        val = MagicMock()
        setattr(self, name, val)
        return val


# IDA module names that this test file needs to mock.
IDA_MODULES = [
    "ida_bytes",
    "ida_hexrays",
    "ida_segment",
    "ida_xref",
    "idaapi",
    "idc",
    "ida_diskio",
]


def _create_ida_stubs() -> dict[str, types.ModuleType]:
    """Create fresh IDA module stubs (does NOT inject into sys.modules)."""
    stubs: dict[str, types.ModuleType] = {}

    # --- ida_hexrays (auto-stub with explicit overrides) ---
    ida_hexrays = _AutoIntModule("ida_hexrays")
    # Maturity constants (exact values used by test assertions)
    ida_hexrays.MMAT_ZERO = 0
    ida_hexrays.MMAT_GENERATED = 1
    ida_hexrays.MMAT_PREOPTIMIZED = 2
    ida_hexrays.MMAT_LOCOPT = 3
    ida_hexrays.MMAT_CALLS = 4
    ida_hexrays.MMAT_GLBOPT1 = 5
    ida_hexrays.MMAT_GLBOPT2 = 6
    ida_hexrays.MMAT_GLBOPT3 = 0
    ida_hexrays.MMAT_LVARS = 7
    ida_hexrays.CMAT_FINAL = 8
    # Operand types (exact values used by test assertions)
    ida_hexrays.mop_z = 0
    ida_hexrays.mop_n = 1
    ida_hexrays.mop_r = 2
    ida_hexrays.mop_v = 6
    ida_hexrays.mop_S = 5
    ida_hexrays.mop_l = 7
    # Opcodes that matter for this module (unique values)
    ida_hexrays.m_mov = 0x10
    ida_hexrays.m_ldx = 0x11
    ida_hexrays.m_ldc = 0x12
    # Type stubs used as base classes or with @register
    ida_hexrays.minsn_t = MagicMock
    ida_hexrays.mop_t = MagicMock
    ida_hexrays.mblock_t = MagicMock
    ida_hexrays.mba_t = MagicMock
    ida_hexrays.mbl_array_t = MagicMock
    ida_hexrays.get_mreg_name = MagicMock(return_value="reg")
    ida_hexrays.is_mcode_jcond = MagicMock(return_value=False)
    stubs["ida_hexrays"] = ida_hexrays

    # --- idaapi (auto-stub with explicit overrides) ---
    idaapi_mod = _AutoIntModule("idaapi")
    idaapi_mod.BADADDR = 0xFFFFFFFFFFFFFFFF
    idaapi_mod.SEGPERM_WRITE = 0x2
    idaapi_mod.SEGPERM_READ = 0x4
    idaapi_mod.SEGPERM_EXEC = 0x1
    idaapi_mod.XREF_DATA = 0x1F
    idaapi_mod.dr_W = 2
    idaapi_mod.IDA_SDK_VERSION = 900
    idaapi_mod.get_byte = lambda ea: 0
    idaapi_mod.get_word = lambda ea: 0
    idaapi_mod.get_dword = lambda ea: 0
    idaapi_mod.get_qword = lambda ea: 0
    idaapi_mod.getseg = lambda ea: None
    idaapi_mod.is_loaded = lambda ea: False
    idaapi_mod.set_cmt = MagicMock()
    stubs["idaapi"] = idaapi_mod

    # --- ida_segment ---
    ida_segment = types.ModuleType("ida_segment")
    ida_segment.getseg = lambda ea: None
    ida_segment.get_segm_name = lambda seg: ""
    stubs["ida_segment"] = ida_segment

    # --- ida_bytes ---
    ida_bytes = types.ModuleType("ida_bytes")
    ida_bytes.get_bytes = lambda ea, size: None
    ida_bytes.get_flags = lambda ea: 0
    ida_bytes.is_code = lambda flags: False
    stubs["ida_bytes"] = ida_bytes

    # --- ida_xref ---
    ida_xref = types.ModuleType("ida_xref")
    ida_xref.XREF_ALL = 0
    ida_xref.dr_W = 2
    ida_xref.xrefblk_t = type("xrefblk_t", (), {"__init__": lambda self, *a, **kw: None})
    stubs["ida_xref"] = ida_xref

    # --- idc ---
    idc = types.ModuleType("idc")
    idc.get_func_name = MagicMock(return_value="mock_func")
    stubs["idc"] = idc

    # --- ida_diskio ---
    ida_diskio = types.ModuleType("ida_diskio")
    ida_diskio.get_user_idadir = MagicMock(return_value="/tmp")
    stubs["ida_diskio"] = ida_diskio

    return stubs


# ---------------------------------------------------------------------------
# Module-scoped fixture: inject stubs, yield, then restore sys.modules.
# Follows the same pattern as test_indirect_branch.py / test_indirect_call.py.
# ---------------------------------------------------------------------------

# Module-level references populated by the fixture.
_ida_hexrays = None
_idaapi = None
_ida_segment = None
_ida_bytes_mod = None
_ida_xref = None
GlobalConstantInliner = None
_is_constant_global = None
_looks_like_pointer = None
_read_constant_value = None
_replace_with_immediate = None


@pytest.fixture(scope="module", autouse=True)
def _ida_stubs():
    """Inject IDA stubs into sys.modules for the duration of this module's tests."""
    global _ida_hexrays, _idaapi, _ida_segment, _ida_bytes_mod, _ida_xref
    global GlobalConstantInliner, _is_constant_global, _looks_like_pointer
    global _read_constant_value, _replace_with_immediate

    stubs = _create_ida_stubs()

    # Snapshot the complete set of IDA + d810 modules before we touch anything.
    saved: dict[str, types.ModuleType | None] = {}
    for name in list(sys.modules):
        if (
            name in stubs
            or name == "d810" or name.startswith("d810.")
        ):
            saved[name] = sys.modules.get(name)

    # Inject mock IDA modules.
    for name, mod in stubs.items():
        sys.modules[name] = mod

    # Evict cached d810 modules so they re-import with the mocked IDA stubs.
    for mod_name in sorted(sys.modules, reverse=True):
        if mod_name == "d810" or mod_name.startswith("d810."):
            del sys.modules[mod_name]

    # Now safe to import d810 modules under the stubs.
    from d810.optimizers.microcode.flow.global_const_inline import (
        GlobalConstantInliner as _GlobalConstantInliner,
        _is_constant_global as _is_constant_global_fn,
        _looks_like_pointer as _looks_like_pointer_fn,
        _read_constant_value as _read_constant_value_fn,
        _replace_with_immediate as _replace_with_immediate_fn,
    )

    # Publish to module globals so test code can reference them.
    _ida_hexrays = stubs["ida_hexrays"]
    _idaapi = stubs["idaapi"]
    _ida_segment = stubs["ida_segment"]
    _ida_bytes_mod = stubs["ida_bytes"]
    _ida_xref = stubs["ida_xref"]
    GlobalConstantInliner = _GlobalConstantInliner
    _is_constant_global = _is_constant_global_fn
    _looks_like_pointer = _looks_like_pointer_fn
    _read_constant_value = _read_constant_value_fn
    _replace_with_immediate = _replace_with_immediate_fn

    yield stubs

    # --- Teardown: restore the pre-fixture module state exactly. ---

    # 1. Remove any d810/IDA modules that were (re-)imported during the tests.
    for mod_name in list(sys.modules):
        if (
            mod_name == "d810" or mod_name.startswith("d810.")
            or mod_name in stubs
        ):
            sys.modules.pop(mod_name, None)

    # 2. Restore every saved entry.
    for name, orig in saved.items():
        if orig is not None:
            sys.modules[name] = orig
        else:
            sys.modules.pop(name, None)


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
