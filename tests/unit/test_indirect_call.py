"""Unit tests for IndirectCallResolver (Chernobog Phase 6).

These tests run without IDA Pro by mocking the ida_* modules and exercising
the pure-Python logic of indirect call detection, sub-offset extraction,
target computation, and instruction iteration.
"""
from __future__ import annotations

import pathlib
import sys
import types
from typing import Optional
from unittest import mock

import pytest

# ---------------------------------------------------------------------------
# Ensure that the project ``src/`` directory is on sys.path so that d810
# modules can be found.
# ---------------------------------------------------------------------------
_PROJECT_SRC = str(pathlib.Path(__file__).resolve().parent.parent.parent / "src")
if _PROJECT_SRC not in sys.path:
    sys.path.insert(0, _PROJECT_SRC)


# ---------------------------------------------------------------------------
# IDA module stubs -- injected before any d810 import that touches IDA.
# ---------------------------------------------------------------------------

class _AutoIntModule(types.ModuleType):
    """Module stub that auto-generates attributes on access.

    * Integer-looking names (``m_*``, ``mop_*``, ``BLT_*``, ``MMAT_*``,
      ``MBL_*``) get a unique negative integer so that
      ``hexrays_helpers.OPCODES_INFO`` builds correctly.
    * Names ending in ``_t`` (class names like ``vd_printer_t``,
      ``switch_info_t``) get a proper class so subclassing works.
    * Everything else gets a ``MagicMock`` so attribute access chains
      (e.g. ``ida_hexrays.something.foo``) silently succeed.
    """

    _COUNTER = -1000
    # Prefixes that should resolve to unique integers (opcode/constant IDs)
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
        val = mock.MagicMock()
        setattr(self, name, val)
        return val


def _create_ida_stubs():
    """Create minimal IDA module stubs (does NOT inject into sys.modules)."""
    stubs = {}

    # --- ida_bytes ---
    ida_bytes = types.ModuleType("ida_bytes")
    ida_bytes.get_bytes = mock.MagicMock(return_value=None)
    ida_bytes.get_flags = mock.MagicMock(return_value=0)
    ida_bytes.is_code = mock.MagicMock(return_value=False)
    stubs["ida_bytes"] = ida_bytes

    # --- ida_hexrays (opcodes + constants) ---
    ida_hexrays = _AutoIntModule("ida_hexrays")
    # Opcodes we care about -- explicit values
    ida_hexrays.m_ijmp = 0x40
    ida_hexrays.m_goto = 0x41
    ida_hexrays.m_mov = 0x01
    ida_hexrays.m_ldx = 0x02
    ida_hexrays.m_xor = 0x03
    ida_hexrays.m_neg = 0x04
    ida_hexrays.m_add = 0x05
    ida_hexrays.m_and = 0x06
    ida_hexrays.m_low = 0x07
    ida_hexrays.m_sub = 0x08
    ida_hexrays.m_nop = 0x00
    ida_hexrays.m_call = 0x09
    ida_hexrays.m_icall = 0x0A
    ida_hexrays.m_mul = 0x0B
    ida_hexrays.m_jnz = 0x10
    ida_hexrays.m_jz = 0x11
    ida_hexrays.m_jae = 0x12
    ida_hexrays.m_jb = 0x13
    ida_hexrays.m_ja = 0x14
    ida_hexrays.m_jbe = 0x15
    ida_hexrays.m_jg = 0x16
    ida_hexrays.m_jge = 0x17
    ida_hexrays.m_jl = 0x18
    ida_hexrays.m_jle = 0x19
    # Operand types
    ida_hexrays.mop_r = 1
    ida_hexrays.mop_n = 2
    ida_hexrays.mop_v = 3
    ida_hexrays.mop_d = 4
    ida_hexrays.mop_a = 5
    ida_hexrays.mop_b = 6
    ida_hexrays.mop_S = 7
    ida_hexrays.mop_f = 8
    ida_hexrays.mop_z = 0
    # Block types
    ida_hexrays.BLT_NONE = 0
    ida_hexrays.BLT_STOP = 1
    ida_hexrays.BLT_0WAY = 2
    ida_hexrays.BLT_1WAY = 3
    ida_hexrays.BLT_2WAY = 4
    ida_hexrays.BLT_NWAY = 5
    ida_hexrays.BLT_XTRN = 6
    # Maturities
    ida_hexrays.MMAT_ZERO = 0
    ida_hexrays.MMAT_GENERATED = 1
    ida_hexrays.MMAT_PREOPTIMIZED = 2
    ida_hexrays.MMAT_LOCOPT = 3
    ida_hexrays.MMAT_CALLS = 4
    ida_hexrays.MMAT_GLBOPT1 = 5
    ida_hexrays.MMAT_GLBOPT2 = 6
    ida_hexrays.MMAT_GLBOPT3 = 7
    ida_hexrays.MMAT_LVARS = 8
    # Block flags
    ida_hexrays.MBL_GOTO = 0x01
    # Classes (stubs)
    ida_hexrays.minsn_t = mock.MagicMock
    ida_hexrays.mop_t = mock.MagicMock
    ida_hexrays.mblock_t = mock.MagicMock
    ida_hexrays.mba_t = mock.MagicMock
    ida_hexrays.mbl_array_t = mock.MagicMock
    ida_hexrays.mcallinfo_t = mock.MagicMock
    ida_hexrays.get_mreg_name = mock.MagicMock(return_value="reg")
    ida_hexrays.is_mcode_jcond = mock.MagicMock(return_value=False)
    stubs["ida_hexrays"] = ida_hexrays

    # --- ida_nalt ---
    ida_nalt = types.ModuleType("ida_nalt")
    ida_nalt.switch_info_t = mock.MagicMock
    ida_nalt.get_switch_info = mock.MagicMock(return_value=0)
    stubs["ida_nalt"] = ida_nalt

    # --- ida_name ---
    ida_name = types.ModuleType("ida_name")
    ida_name.get_name_ea = mock.MagicMock(return_value=0xFFFFFFFFFFFFFFFF)
    ida_name.get_name = mock.MagicMock(return_value="")
    stubs["ida_name"] = ida_name

    # --- ida_funcs ---
    ida_funcs = types.ModuleType("ida_funcs")
    ida_funcs.get_func = mock.MagicMock(return_value=None)
    ida_funcs.add_func = mock.MagicMock(return_value=False)
    stubs["ida_funcs"] = ida_funcs

    # --- ida_typeinf ---
    ida_typeinf = types.ModuleType("ida_typeinf")
    ida_typeinf.tinfo_t = mock.MagicMock
    ida_typeinf.get_tinfo = mock.MagicMock(return_value=False)
    ida_typeinf.CM_CC_FASTCALL = 0x0C
    ida_typeinf.BT_VOID = 0x01
    stubs["ida_typeinf"] = ida_typeinf

    # --- idaapi ---
    idaapi_mod = _AutoIntModule("idaapi")
    idaapi_mod.set_cmt = mock.MagicMock()
    idaapi_mod.BADADDR = 0xFFFFFFFFFFFFFFFF
    idaapi_mod.IDA_SDK_VERSION = 900
    stubs["idaapi"] = idaapi_mod

    # --- idc ---
    idc = types.ModuleType("idc")
    idc.get_func_name = mock.MagicMock(return_value="mock_func")
    stubs["idc"] = idc

    # --- ida_diskio ---
    ida_diskio = types.ModuleType("ida_diskio")
    ida_diskio.get_user_idadir = mock.MagicMock(return_value="/tmp")
    stubs["ida_diskio"] = ida_diskio

    return stubs


# ---------------------------------------------------------------------------
# Module-level globals populated by the ``_ida_stubs`` fixture below.
# They are set once (module scope) before any test in this file executes.
# ---------------------------------------------------------------------------
_stubs: dict = {}
IndirectCallResolver = None  # type: ignore[assignment]
DEFAULT_ENTRY_SIZE = None
MAX_TABLE_ENTRIES = None
MIN_SUB_OFFSET = None
MAX_SUB_OFFSET = None


@pytest.fixture(scope="module")
def _ida_stubs():
    """Inject IDA stubs into sys.modules for the duration of this module's tests."""
    global _stubs, IndirectCallResolver, DEFAULT_ENTRY_SIZE
    global MAX_TABLE_ENTRIES, MIN_SUB_OFFSET, MAX_SUB_OFFSET

    stubs = _create_ida_stubs()

    # Snapshot the complete set of IDA + d810 modules before we touch anything.
    saved: dict[str, types.ModuleType | None] = {}
    for name in list(sys.modules):
        if (
            name in stubs
            or name == "d810" or name.startswith("d810.")
            or name.startswith("ida") or name == "idc" or name == "idaapi"
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
    from d810.optimizers.microcode.flow.indirect_call import (
        DEFAULT_ENTRY_SIZE as _DEFAULT_ENTRY_SIZE,
        IndirectCallResolver as _IndirectCallResolver,
        MAX_SUB_OFFSET as _MAX_SUB_OFFSET,
        MAX_TABLE_ENTRIES as _MAX_TABLE_ENTRIES,
        MIN_SUB_OFFSET as _MIN_SUB_OFFSET,
    )

    # Publish to module globals so test code can reference them.
    _stubs.update(stubs)
    IndirectCallResolver = _IndirectCallResolver
    DEFAULT_ENTRY_SIZE = _DEFAULT_ENTRY_SIZE
    MAX_TABLE_ENTRIES = _MAX_TABLE_ENTRIES
    MIN_SUB_OFFSET = _MIN_SUB_OFFSET
    MAX_SUB_OFFSET = _MAX_SUB_OFFSET

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

    # 3. Clear module globals.
    _stubs.clear()


@pytest.fixture(autouse=True)
def _use_ida_stubs(_ida_stubs):
    """Auto-use wrapper so every test in this module gets IDA stubs."""
    return _ida_stubs


# ===========================================================================
# Helper: build mock microcode structures
# ===========================================================================

class MockNnn:
    """Stands in for mop_t.nnn (number info)."""
    def __init__(self, value: int) -> None:
        self.value = value


class MockStkvar:
    """Stands in for mop_t.s (stack variable info)."""
    def __init__(self, off: int) -> None:
        self.off = off


class MockMop:
    """Minimal mop_t mock."""
    def __init__(
        self,
        t: int = 0,
        r: int = 0,
        g: int = 0,
        nnn: Optional[MockNnn] = None,
        d: object = None,
        a: object = None,
        b: int = 0,
        f: object = None,
        s: Optional[MockStkvar] = None,
        size: int = 0,
    ) -> None:
        self.t = t
        self.r = r
        self.g = g
        self.nnn = nnn
        self.d = d
        self.a = a
        self.b = b
        self.f = f
        self.s = s
        self.size = size

    def erase(self) -> None:
        pass

    def empty(self) -> bool:
        return self.t == 0


class MockInsn:
    """Minimal minsn_t mock."""
    def __init__(
        self,
        opcode: int = 0,
        ea: int = 0,
        l: Optional[MockMop] = None,
        r: Optional[MockMop] = None,
        d: Optional[MockMop] = None,
    ) -> None:
        self.opcode = opcode
        self.ea = ea
        self.l = l or MockMop()
        self.r = r or MockMop()
        self.d = d or MockMop()
        self.next: Optional[MockInsn] = None
        self.prev: Optional[MockInsn] = None


class MockBlock:
    """Minimal mblock_t mock."""
    def __init__(
        self,
        serial: int = 0,
        start: int = 0,
        end: int = 0,
        head: Optional[MockInsn] = None,
        tail: Optional[MockInsn] = None,
    ) -> None:
        self.serial = serial
        self.start = start
        self.end = end
        self.head = head
        self.tail = tail
        self.mba: Optional[MockMba] = None

    def mark_lists_dirty(self) -> None:
        pass


class MockMba:
    """Minimal mba_t mock."""
    def __init__(self, blocks: Optional[list[MockBlock]] = None) -> None:
        self.blocks = blocks or []
        self.qty = len(self.blocks)
        self.entry_ea = 0x1000
        self.maturity = _stubs["ida_hexrays"].MMAT_CALLS
        for blk in self.blocks:
            blk.mba = self

    def get_mblock(self, idx: int) -> Optional[MockBlock]:
        if 0 <= idx < len(self.blocks):
            return self.blocks[idx]
        return None

    def mark_chains_dirty(self) -> None:
        pass


def _build_chain(*insns: MockInsn) -> tuple[MockInsn, MockInsn]:
    """Link a list of instructions into a doubly-linked chain.  Returns (head, tail)."""
    for i in range(len(insns) - 1):
        insns[i].next = insns[i + 1]
        insns[i + 1].prev = insns[i]
    return insns[0], insns[-1]


def _make_resolver() -> IndirectCallResolver:
    """Create a resolver instance using the dummy base."""
    return IndirectCallResolver()


# ===========================================================================
# Tests: Class Attributes
# ===========================================================================

class TestClassAttributes:
    """Verify class-level constants and metadata."""

    def test_name(self) -> None:
        assert IndirectCallResolver.NAME == "indirect_call_resolver"

    def test_description(self) -> None:
        assert "indirect call" in IndirectCallResolver.DESCRIPTION.lower()

    def test_safe_maturities(self) -> None:
        # In test environment, SAFE_MATURITIES is empty because _IDA_AVAILABLE is False
        # during class definition. But the values should correspond to MMAT_CALLS
        # and MMAT_GLBOPT1.
        assert isinstance(IndirectCallResolver.SAFE_MATURITIES, list)

    def test_uses_deferred_cfg_is_false(self) -> None:
        assert IndirectCallResolver.USES_DEFERRED_CFG is False

    def test_max_table_entries(self) -> None:
        assert IndirectCallResolver.MAX_TABLE_ENTRIES == 512

    def test_default_entry_size(self) -> None:
        assert IndirectCallResolver.DEFAULT_ENTRY_SIZE == 8

    def test_min_sub_offset(self) -> None:
        assert IndirectCallResolver.MIN_SUB_OFFSET == 0x10000

    def test_max_sub_offset(self) -> None:
        assert IndirectCallResolver.MAX_SUB_OFFSET == 0x1000000


# ===========================================================================
# Tests: _is_indirect_call
# ===========================================================================

class TestIsIndirectCall:
    """Test detection of indirect call instructions."""

    def test_m_icall_detected(self) -> None:
        """m_icall is always an indirect call."""
        resolver = _make_resolver()
        insn = MockInsn(opcode=_stubs["ida_hexrays"].m_icall)
        assert resolver._is_indirect_call(insn) is True

    def test_m_call_with_mop_r_detected(self) -> None:
        """m_call with register target (mop_r) is an indirect call."""
        resolver = _make_resolver()
        insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_call,
            l=MockMop(t=_stubs["ida_hexrays"].mop_r, r=1),
        )
        assert resolver._is_indirect_call(insn) is True

    def test_m_call_with_mop_d_detected(self) -> None:
        """m_call with computed target (mop_d) is an indirect call."""
        resolver = _make_resolver()
        insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_call,
            l=MockMop(t=_stubs["ida_hexrays"].mop_d),
        )
        assert resolver._is_indirect_call(insn) is True

    def test_m_call_with_mop_v_skipped(self) -> None:
        """m_call with direct target (mop_v) is NOT an indirect call."""
        resolver = _make_resolver()
        insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_call,
            l=MockMop(t=_stubs["ida_hexrays"].mop_v, g=0x401000),
        )
        assert resolver._is_indirect_call(insn) is False

    def test_non_call_opcode_skipped(self) -> None:
        """Non-call opcodes should not be detected as indirect calls."""
        resolver = _make_resolver()
        insn = MockInsn(opcode=_stubs["ida_hexrays"].m_mov)
        assert resolver._is_indirect_call(insn) is False

    def test_nop_skipped(self) -> None:
        """m_nop should not be detected as an indirect call."""
        resolver = _make_resolver()
        insn = MockInsn(opcode=_stubs["ida_hexrays"].m_nop)
        assert resolver._is_indirect_call(insn) is False

    def test_m_ijmp_skipped(self) -> None:
        """m_ijmp (indirect jump) is not an indirect call."""
        resolver = _make_resolver()
        insn = MockInsn(opcode=_stubs["ida_hexrays"].m_ijmp)
        assert resolver._is_indirect_call(insn) is False


# ===========================================================================
# Tests: _extract_sub_offset
# ===========================================================================

class TestExtractSubOffset:
    """Test extraction of large constants from m_sub instructions."""

    def test_large_constant_found(self) -> None:
        """A constant in the valid range should be extracted."""
        resolver = _make_resolver()
        sub_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_sub,
            r=MockMop(t=_stubs["ida_hexrays"].mop_n, nnn=MockNnn(0x80000)),
        )
        head, tail = _build_chain(sub_insn)
        blk = MockBlock(head=head, tail=tail)
        MockMba([blk])

        result = resolver._extract_sub_offset(blk, sub_insn)
        assert result == 0x80000

    def test_too_small_constant_rejected(self) -> None:
        """Constants <= MIN_SUB_OFFSET should be rejected."""
        resolver = _make_resolver()
        sub_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_sub,
            r=MockMop(t=_stubs["ida_hexrays"].mop_n, nnn=MockNnn(0x100)),
        )
        head, tail = _build_chain(sub_insn)
        blk = MockBlock(head=head, tail=tail)
        MockMba([blk])

        result = resolver._extract_sub_offset(blk, sub_insn)
        assert result == 0

    def test_too_large_constant_rejected(self) -> None:
        """Constants >= MAX_SUB_OFFSET should be rejected."""
        resolver = _make_resolver()
        sub_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_sub,
            r=MockMop(t=_stubs["ida_hexrays"].mop_n, nnn=MockNnn(0x2000000)),
        )
        head, tail = _build_chain(sub_insn)
        blk = MockBlock(head=head, tail=tail)
        MockMba([blk])

        result = resolver._extract_sub_offset(blk, sub_insn)
        assert result == 0

    def test_no_m_sub_returns_zero(self) -> None:
        """When no m_sub exists in the block, offset should be 0."""
        resolver = _make_resolver()
        nop_insn = MockInsn(opcode=_stubs["ida_hexrays"].m_nop)
        head, tail = _build_chain(nop_insn)
        blk = MockBlock(head=head, tail=tail)
        MockMba([blk])

        result = resolver._extract_sub_offset(blk, nop_insn)
        assert result == 0

    def test_non_immediate_operand_returns_zero(self) -> None:
        """m_sub with non-immediate right operand should return 0."""
        resolver = _make_resolver()
        sub_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_sub,
            r=MockMop(t=_stubs["ida_hexrays"].mop_r, r=1),
        )
        head, tail = _build_chain(sub_insn)
        blk = MockBlock(head=head, tail=tail)
        MockMba([blk])

        result = resolver._extract_sub_offset(blk, sub_insn)
        assert result == 0

    def test_boundary_min_offset(self) -> None:
        """Exactly MIN_SUB_OFFSET (0x10000) should be rejected (not strictly greater)."""
        resolver = _make_resolver()
        sub_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_sub,
            r=MockMop(t=_stubs["ida_hexrays"].mop_n, nnn=MockNnn(0x10000)),
        )
        result = resolver._extract_sub_offset_from_insn(sub_insn)
        assert result == 0

    def test_boundary_just_above_min(self) -> None:
        """MIN_SUB_OFFSET + 1 should be accepted."""
        resolver = _make_resolver()
        sub_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_sub,
            r=MockMop(t=_stubs["ida_hexrays"].mop_n, nnn=MockNnn(0x10001)),
        )
        result = resolver._extract_sub_offset_from_insn(sub_insn)
        assert result == 0x10001


# ===========================================================================
# Tests: _compute_target
# ===========================================================================

class TestComputeTarget:
    """Test target computation from table entries."""

    def test_basic_computation(self) -> None:
        """table[index] - offset should produce the correct target."""
        resolver = _make_resolver()
        # Mock reading an 8-byte value from table
        table_ea = 0x100000
        index = 3
        offset = 0x50000
        entry_val = 0x451000  # table[3]
        expected_target = entry_val - offset  # 0x401000

        _stubs["ida_bytes"].get_bytes.return_value = entry_val.to_bytes(
            8, byteorder="little",
        )
        _stubs["ida_bytes"].is_code.return_value = True

        result = resolver._compute_target(table_ea, index, offset, 8)
        assert result == expected_target

    def test_bad_table_address(self) -> None:
        """BADADDR as table_ea should return None."""
        resolver = _make_resolver()
        result = resolver._compute_target(0xFFFFFFFFFFFFFFFF, 0, 0, 8)
        assert result is None

    def test_negative_index(self) -> None:
        """Negative index should return None."""
        resolver = _make_resolver()
        result = resolver._compute_target(0x100000, -1, 0, 8)
        assert result is None

    def test_read_failure(self) -> None:
        """When get_bytes returns None, should return None."""
        resolver = _make_resolver()
        _stubs["ida_bytes"].get_bytes.return_value = None
        result = resolver._compute_target(0x100000, 0, 0, 8)
        assert result is None

    def test_zero_offset(self) -> None:
        """With zero offset, target == table entry value."""
        resolver = _make_resolver()
        entry_val = 0x401000

        _stubs["ida_bytes"].get_bytes.return_value = entry_val.to_bytes(
            8, byteorder="little",
        )
        _stubs["ida_bytes"].is_code.return_value = True

        result = resolver._compute_target(0x100000, 0, 0, 8)
        assert result == entry_val


# ===========================================================================
# Tests: optimize() iteration -- all instructions checked
# ===========================================================================

class TestOptimizeIteration:
    """Verify that optimize() checks ALL instructions, not just tail."""

    def test_iterates_all_instructions(self) -> None:
        """optimize() should check every instruction in the block, not just tail."""
        resolver = _make_resolver()

        # Build a chain: nop -> icall -> nop
        nop1 = MockInsn(opcode=_stubs["ida_hexrays"].m_nop, ea=0x1000)
        icall = MockInsn(
            opcode=_stubs["ida_hexrays"].m_icall,
            ea=0x1008,
            l=MockMop(t=_stubs["ida_hexrays"].mop_r, r=1),
        )
        nop2 = MockInsn(opcode=_stubs["ida_hexrays"].m_nop, ea=0x1010)
        head, tail = _build_chain(nop1, icall, nop2)

        blk = MockBlock(serial=0, head=head, tail=tail)
        mba = MockMba([blk])

        # The icall is in the middle, not at the tail.
        # optimize() should still find it.  It will return 0 because
        # _resolve_indirect_call will fail (no table), but we can verify
        # the detection by patching _resolve_indirect_call.
        with mock.patch.object(
            resolver, "_resolve_indirect_call", return_value=True,
        ) as mock_resolve:
            result = resolver.optimize(blk)

        # Should have been called once for the m_icall
        assert mock_resolve.call_count == 1
        assert result == 1

    def test_multiple_indirect_calls(self) -> None:
        """optimize() should find multiple indirect calls in one block."""
        resolver = _make_resolver()

        icall1 = MockInsn(
            opcode=_stubs["ida_hexrays"].m_icall, ea=0x1000,
        )
        icall2 = MockInsn(
            opcode=_stubs["ida_hexrays"].m_icall, ea=0x1010,
        )
        head, tail = _build_chain(icall1, icall2)

        blk = MockBlock(serial=0, head=head, tail=tail)
        MockMba([blk])

        with mock.patch.object(
            resolver, "_resolve_indirect_call", return_value=True,
        ) as mock_resolve:
            result = resolver.optimize(blk)

        assert mock_resolve.call_count == 2
        assert result == 2

    def test_no_indirect_calls(self) -> None:
        """Block with no indirect calls should return 0."""
        resolver = _make_resolver()

        nop = MockInsn(opcode=_stubs["ida_hexrays"].m_nop)
        mov = MockInsn(opcode=_stubs["ida_hexrays"].m_mov)
        head, tail = _build_chain(nop, mov)

        blk = MockBlock(serial=0, head=head, tail=tail)
        MockMba([blk])

        result = resolver.optimize(blk)
        assert result == 0

    def test_empty_block(self) -> None:
        """Block with no instructions should return 0."""
        resolver = _make_resolver()

        blk = MockBlock(serial=0, head=None, tail=None)
        MockMba([blk])

        result = resolver.optimize(blk)
        assert result == 0


# ===========================================================================
# Tests: _extract_sub_offset_from_insn (static method)
# ===========================================================================

class TestExtractSubOffsetFromInsn:
    """Test the static per-instruction sub-offset extraction."""

    def test_valid_sub(self) -> None:
        insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_sub,
            r=MockMop(t=_stubs["ida_hexrays"].mop_n, nnn=MockNnn(0x80000)),
        )
        assert IndirectCallResolver._extract_sub_offset_from_insn(insn) == 0x80000

    def test_not_sub_opcode(self) -> None:
        insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_add,
            r=MockMop(t=_stubs["ida_hexrays"].mop_n, nnn=MockNnn(0x80000)),
        )
        assert IndirectCallResolver._extract_sub_offset_from_insn(insn) == 0

    def test_sub_with_register_operand(self) -> None:
        insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_sub,
            r=MockMop(t=_stubs["ida_hexrays"].mop_r, r=2),
        )
        assert IndirectCallResolver._extract_sub_offset_from_insn(insn) == 0


# ===========================================================================
# Tests: Module-level constants
# ===========================================================================

class TestModuleConstants:
    """Verify module-level constants have expected values."""

    def test_max_table_entries(self) -> None:
        assert MAX_TABLE_ENTRIES == 512

    def test_default_entry_size(self) -> None:
        assert DEFAULT_ENTRY_SIZE == 8

    def test_min_sub_offset(self) -> None:
        assert MIN_SUB_OFFSET == 0x10000

    def test_max_sub_offset(self) -> None:
        assert MAX_SUB_OFFSET == 0x1000000


# ===========================================================================
# Tests: _replace_call (Issue A2 -- most critical function)
# ===========================================================================

class TestReplaceCall:
    """Test _replace_call: mcallinfo manipulation, opcode conversion, dirty marking."""

    def test_m_icall_with_existing_mcallinfo(self) -> None:
        """m_icall with d.t == mop_f: should update callee, set type, convert to m_call."""
        resolver = _make_resolver()

        # Build mcallinfo mock
        mci = mock.MagicMock()
        mci.callee = 0

        target_ea = 0x401000

        insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_icall,
            ea=0x2000,
            l=MockMop(t=_stubs["ida_hexrays"].mop_r, r=1),
            d=MockMop(t=_stubs["ida_hexrays"].mop_f, f=mci),
        )

        blk = MockBlock(serial=0, head=insn, tail=insn)
        mba = MockMba([blk])

        # Mock type info retrieval
        _stubs["ida_typeinf"].get_tinfo = mock.MagicMock(return_value=True)
        _stubs["ida_typeinf"].tinfo_t = mock.MagicMock

        result = resolver._replace_call(insn, target_ea, blk)

        assert result is True
        assert mci.callee == target_ea
        assert insn.opcode == _stubs["ida_hexrays"].m_call
        assert insn.l.t == _stubs["ida_hexrays"].mop_v
        assert insn.l.g == target_ea

    def test_m_icall_without_mcallinfo(self) -> None:
        """m_icall with d.empty(): should create new mcallinfo_t and convert."""
        resolver = _make_resolver()

        target_ea = 0x401000

        # d has mop_z (empty type) and f=None
        insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_icall,
            ea=0x2000,
            l=MockMop(t=_stubs["ida_hexrays"].mop_r, r=1),
            d=MockMop(t=_stubs["ida_hexrays"].mop_z),
        )

        blk = MockBlock(serial=0, head=insn, tail=insn)
        mba = MockMba([blk])

        # Mock type info (fail to find type)
        _stubs["ida_typeinf"].get_tinfo = mock.MagicMock(return_value=False)
        _stubs["ida_typeinf"].tinfo_t = mock.MagicMock
        _stubs["ida_hexrays"].mcallinfo_t = mock.MagicMock

        result = resolver._replace_call(insn, target_ea, blk)

        assert result is True
        assert insn.opcode == _stubs["ida_hexrays"].m_call
        assert insn.l.t == _stubs["ida_hexrays"].mop_v
        assert insn.l.g == target_ea
        assert insn.d.t == _stubs["ida_hexrays"].mop_f
        assert insn.d.f is not None

    def test_m_call_update_path(self) -> None:
        """m_call with existing mcallinfo: updates callee and target."""
        resolver = _make_resolver()

        mci = mock.MagicMock()
        mci.callee = 0xBAD

        target_ea = 0x402000

        insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_call,
            ea=0x3000,
            l=MockMop(t=_stubs["ida_hexrays"].mop_r, r=2),
            d=MockMop(t=_stubs["ida_hexrays"].mop_f, f=mci),
        )

        blk = MockBlock(serial=0, head=insn, tail=insn)
        mba = MockMba([blk])

        result = resolver._replace_call(insn, target_ea, blk)

        assert result is True
        assert mci.callee == target_ea
        assert insn.l.t == _stubs["ida_hexrays"].mop_v
        assert insn.l.g == target_ea

    def test_marks_block_dirty(self) -> None:
        """After replacement, block and mba should be marked dirty."""
        resolver = _make_resolver()

        mci = mock.MagicMock()
        target_ea = 0x401000

        insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_icall,
            ea=0x2000,
            d=MockMop(t=_stubs["ida_hexrays"].mop_f, f=mci),
        )

        blk = MockBlock(serial=0, head=insn, tail=insn)
        blk.mark_lists_dirty = mock.MagicMock()
        mba = MockMba([blk])
        mba.mark_chains_dirty = mock.MagicMock()

        _stubs["ida_typeinf"].get_tinfo = mock.MagicMock(return_value=True)
        _stubs["ida_typeinf"].tinfo_t = mock.MagicMock

        resolver._replace_call(insn, target_ea, blk)

        blk.mark_lists_dirty.assert_called_once()
        mba.mark_chains_dirty.assert_called_once()

    def test_annotation_fallback_for_non_function_start(self) -> None:
        """_annotate_call should set a comment without modifying the instruction."""
        resolver = _make_resolver()

        insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_icall,
            ea=0x5000,
        )
        target_ea = 0x401234

        _stubs["ida_name"].get_name = mock.MagicMock(return_value="sub_401234")
        _stubs["idaapi"].set_cmt = mock.MagicMock()

        resolver._annotate_call(insn, target_ea)

        _stubs["idaapi"].set_cmt.assert_called_once()
        args = _stubs["idaapi"].set_cmt.call_args[0]
        assert args[0] == insn.ea
        assert "0x401234" in args[1]
        assert "sub_401234" in args[1]
        # Instruction should NOT have been modified
        assert insn.opcode == _stubs["ida_hexrays"].m_icall

    def test_unsupported_opcode_returns_false(self) -> None:
        """_replace_call on an unsupported opcode (e.g., m_mov) returns False."""
        resolver = _make_resolver()

        insn = MockInsn(opcode=_stubs["ida_hexrays"].m_mov, ea=0x6000)
        blk = MockBlock(serial=0, head=insn, tail=insn)
        MockMba([blk])

        result = resolver._replace_call(insn, 0x401000, blk)
        assert result is False


# ===========================================================================
# Tests: _find_call_table (Issue B7)
# ===========================================================================

class TestFindCallTable:
    """Test _find_call_table: Strategy 1 (find_table_reference) and
    Strategy 2 (Hikari mov+sub pattern)."""

    def test_strategy1_find_table_reference(self) -> None:
        """Strategy 1: finds table via find_table_reference (m_ldx)."""
        resolver = _make_resolver()

        # Build block with an m_ldx referencing a global
        ldx_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_ldx,
            ea=0x1000,
            l=MockMop(t=_stubs["ida_hexrays"].mop_v, g=0xDEAD0000),
        )
        icall_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_icall,
            ea=0x1010,
        )
        head, tail = _build_chain(ldx_insn, icall_insn)

        blk = MockBlock(serial=0, head=head, tail=tail)
        MockMba([blk])

        result = resolver._find_call_table(blk, icall_insn)
        assert result == 0xDEAD0000

    def test_strategy2_hikari_pattern(self) -> None:
        """Strategy 2: finds Hikari pattern (m_mov with mop_a + global)."""
        resolver = _make_resolver()

        # Build a mock mop_a operand that has .a.t == mop_v and .a.g set
        mock_a = MockMop(t=_stubs["ida_hexrays"].mop_v, g=0xCAFE0000)
        mov_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_mov,
            ea=0x1000,
            l=MockMop(t=_stubs["ida_hexrays"].mop_a, a=mock_a),
        )
        icall_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_icall,
            ea=0x1010,
        )
        head, tail = _build_chain(mov_insn, icall_insn)

        blk = MockBlock(serial=0, head=head, tail=tail)
        MockMba([blk])

        # Mock find_table_reference to return None (so Strategy 1 fails)
        # Mock read_global_value and validate_code_target for Strategy 2
        with mock.patch(
            "d810.optimizers.microcode.flow.indirect_call.find_table_reference",
            return_value=None,
        ), mock.patch(
            "d810.optimizers.microcode.flow.indirect_call.read_global_value",
            return_value=0x401000,
        ), mock.patch(
            "d810.optimizers.microcode.flow.indirect_call.validate_code_target",
            return_value=True,
        ):
            result = resolver._find_call_table(blk, icall_insn)

        assert result == 0xCAFE0000

    def test_returns_none_when_both_strategies_fail(self) -> None:
        """Returns None when neither strategy finds a table."""
        resolver = _make_resolver()

        nop_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_nop,
            ea=0x1000,
        )
        icall_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_icall,
            ea=0x1010,
        )
        head, tail = _build_chain(nop_insn, icall_insn)

        blk = MockBlock(serial=0, head=head, tail=tail)
        MockMba([blk])

        with mock.patch(
            "d810.optimizers.microcode.flow.indirect_call.find_table_reference",
            return_value=None,
        ):
            result = resolver._find_call_table(blk, icall_insn)

        assert result is None


# ===========================================================================
# Tests: _trace_call_target (Issue B8)
# ===========================================================================

class TestTraceCallTarget:
    """Test _trace_call_target: register tracking, stack var tracking,
    LDX index extraction, SUB offset extraction."""

    def test_register_value_tracking_via_mov(self) -> None:
        """Track register values via m_mov of immediates, then LDX index."""
        resolver = _make_resolver()

        table_ea = 0x100000

        # mov #40, reg5  (40 = 5 * 8, so index should be 5)
        mov_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_mov,
            ea=0x1000,
            l=MockMop(t=_stubs["ida_hexrays"].mop_n, nnn=MockNnn(40)),
            d=MockMop(t=_stubs["ida_hexrays"].mop_r, r=5),
        )
        # ldx seg, reg5 -> reg6  (uses register value as index)
        ldx_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_ldx,
            ea=0x1008,
            l=MockMop(t=_stubs["ida_hexrays"].mop_v, g=table_ea),
            r=MockMop(t=_stubs["ida_hexrays"].mop_r, r=5),
            d=MockMop(t=_stubs["ida_hexrays"].mop_r, r=6),
        )
        head, tail = _build_chain(mov_insn, ldx_insn)

        blk = MockBlock(serial=0, head=head, tail=tail)
        MockMba([blk])

        with mock.patch(
            "d810.optimizers.microcode.flow.indirect_call.find_xor_with_globals",
            return_value=[],
        ):
            result = resolver._trace_call_target(blk, ldx_insn, table_ea)

        assert result is not None
        index, offset = result
        assert index == 5  # 40 / 8
        assert offset == 0

    def test_stack_variable_tracking(self) -> None:
        """Track stack variable values via m_mov of immediates to stack."""
        resolver = _make_resolver()

        table_ea = 0x100000

        # mov #24, stkvar(off=16)  (24 = 3 * 8, index = 3)
        mov_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_mov,
            ea=0x1000,
            l=MockMop(t=_stubs["ida_hexrays"].mop_n, nnn=MockNnn(24)),
            d=MockMop(t=_stubs["ida_hexrays"].mop_S, s=MockStkvar(16)),
        )
        # ldx seg, stkvar(off=16)
        ldx_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_ldx,
            ea=0x1008,
            l=MockMop(t=_stubs["ida_hexrays"].mop_v, g=table_ea),
            r=MockMop(t=_stubs["ida_hexrays"].mop_S, s=MockStkvar(16)),
            d=MockMop(t=_stubs["ida_hexrays"].mop_r, r=7),
        )
        head, tail = _build_chain(mov_insn, ldx_insn)

        blk = MockBlock(serial=0, head=head, tail=tail)
        MockMba([blk])

        with mock.patch(
            "d810.optimizers.microcode.flow.indirect_call.find_xor_with_globals",
            return_value=[],
        ):
            result = resolver._trace_call_target(blk, ldx_insn, table_ea)

        assert result is not None
        index, offset = result
        assert index == 3  # 24 / 8
        assert offset == 0

    def test_ldx_index_extraction(self) -> None:
        """LDX with immediate index operand."""
        resolver = _make_resolver()

        table_ea = 0x100000

        # ldx with immediate offset: 16 / 8 = index 2
        ldx_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_ldx,
            ea=0x1000,
            l=MockMop(t=_stubs["ida_hexrays"].mop_v, g=table_ea),
            r=MockMop(t=_stubs["ida_hexrays"].mop_n, nnn=MockNnn(16)),
            d=MockMop(t=_stubs["ida_hexrays"].mop_r, r=8),
        )
        head, tail = _build_chain(ldx_insn)

        blk = MockBlock(serial=0, head=head, tail=tail)
        MockMba([blk])

        with mock.patch(
            "d810.optimizers.microcode.flow.indirect_call.find_xor_with_globals",
            return_value=[],
        ):
            result = resolver._trace_call_target(blk, ldx_insn, table_ea)

        assert result is not None
        index, offset = result
        assert index == 2  # 16 / 8
        assert offset == 0

    def test_sub_offset_extraction(self) -> None:
        """SUB with large constant extracts offset."""
        resolver = _make_resolver()

        table_ea = 0x100000

        # ldx with immediate: index = 0 (value 0 is NOT > 0, so won't resolve from ldx)
        # We need to supply a valid index. Use immediate value = 8 -> index = 1
        ldx_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_ldx,
            ea=0x1000,
            l=MockMop(t=_stubs["ida_hexrays"].mop_v, g=table_ea),
            r=MockMop(t=_stubs["ida_hexrays"].mop_n, nnn=MockNnn(8)),
            d=MockMop(t=_stubs["ida_hexrays"].mop_r, r=8),
        )
        # sub reg, #0x80000
        sub_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_sub,
            ea=0x1010,
            r=MockMop(t=_stubs["ida_hexrays"].mop_n, nnn=MockNnn(0x80000)),
        )
        head, tail = _build_chain(ldx_insn, sub_insn)

        blk = MockBlock(serial=0, head=head, tail=tail)
        MockMba([blk])

        with mock.patch(
            "d810.optimizers.microcode.flow.indirect_call.find_xor_with_globals",
            return_value=[],
        ):
            result = resolver._trace_call_target(blk, sub_insn, table_ea)

        assert result is not None
        index, offset = result
        assert index == 1  # 8 / 8
        assert offset == 0x80000

    def test_returns_none_when_no_strategy_succeeds(self) -> None:
        """Returns None when no index can be resolved."""
        resolver = _make_resolver()

        table_ea = 0x100000

        # Block with only a nop -- no mov, no ldx, no sub
        nop_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_nop,
            ea=0x1000,
        )
        head, tail = _build_chain(nop_insn)

        blk = MockBlock(serial=0, head=head, tail=tail)
        MockMba([blk])

        with mock.patch(
            "d810.optimizers.microcode.flow.indirect_call.find_xor_with_globals",
            return_value=[],
        ):
            result = resolver._trace_call_target(blk, nop_insn, table_ea)

        assert result is None


# ===========================================================================
# Tests: _extract_ldx_index (MEDIUM)
# ===========================================================================

class TestExtractLdxIndex:
    """Test _extract_ldx_index: stack var, register, and immediate index sources."""

    def test_index_from_stack_variable(self) -> None:
        """Index from stack variable with tracked value in stkvar_values."""
        ldx_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_ldx,
            ea=0x1000,
            r=MockMop(t=_stubs["ida_hexrays"].mop_S, s=MockStkvar(8)),
        )
        # stkvar at offset 8 holds value 32 -> 32/8 = index 4
        stkvar_values = {8: 32}
        reg_values = {}

        result = IndirectCallResolver._extract_ldx_index(ldx_insn, reg_values, stkvar_values)
        assert result == 4

    def test_index_from_register(self) -> None:
        """Index from register with tracked value in reg_values."""
        ldx_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_ldx,
            ea=0x1000,
            r=MockMop(t=_stubs["ida_hexrays"].mop_r, r=3),
        )
        # Register 3 holds value 48 -> 48/8 = index 6
        reg_values = {3: 48}
        stkvar_values = {}

        result = IndirectCallResolver._extract_ldx_index(ldx_insn, reg_values, stkvar_values)
        assert result == 6

    def test_index_from_immediate(self) -> None:
        """Index from immediate constant in the operand."""
        ldx_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_ldx,
            ea=0x1000,
            r=MockMop(t=_stubs["ida_hexrays"].mop_n, nnn=MockNnn(56)),
        )
        # 56 / 8 = 7
        result = IndirectCallResolver._extract_ldx_index(ldx_insn, {}, {})
        assert result == 7

    def test_division_by_entry_size(self) -> None:
        """Values are divided by 8 (entry size) to get the index."""
        ldx_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_ldx,
            ea=0x1000,
            r=MockMop(t=_stubs["ida_hexrays"].mop_n, nnn=MockNnn(64)),
        )
        result = IndirectCallResolver._extract_ldx_index(ldx_insn, {}, {})
        assert result == 8  # 64 / 8

    def test_non_ldx_returns_none(self) -> None:
        """Non-m_ldx instruction returns None."""
        mov_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_mov,
            ea=0x1000,
            r=MockMop(t=_stubs["ida_hexrays"].mop_n, nnn=MockNnn(16)),
        )
        result = IndirectCallResolver._extract_ldx_index(mov_insn, {}, {})
        assert result is None

    def test_immediate_zero_returns_zero(self) -> None:
        """Immediate value 0 should return index 0 (0 / 8 = 0, and >= 0)."""
        ldx_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_ldx,
            ea=0x1000,
            r=MockMop(t=_stubs["ida_hexrays"].mop_n, nnn=MockNnn(0)),
        )
        result = IndirectCallResolver._extract_ldx_index(ldx_insn, {}, {})
        assert result == 0


# ===========================================================================
# Tests: _extract_mul8_index (MEDIUM)
# ===========================================================================

class TestExtractMul8Index:
    """Test _extract_mul8_index: add(base, mul(index, 8)) patterns."""

    def _make_mul_inner(self, left_mop, right_mop):
        """Create a mock mul instruction embedded in a mop_d operand."""
        mul_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_mul,
            l=left_mop,
            r=right_mop,
        )
        return MockMop(t=_stubs["ida_hexrays"].mop_d, d=mul_insn)

    def test_add_base_mul_index_8_left(self) -> None:
        """add(base, mul(index, 8)) with mul on LEFT operand."""
        # mul(3, 8) on left side of add
        mul_op = self._make_mul_inner(
            MockMop(t=_stubs["ida_hexrays"].mop_n, nnn=MockNnn(3)),
            MockMop(t=_stubs["ida_hexrays"].mop_n, nnn=MockNnn(8)),
        )
        add_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_add,
            ea=0x1000,
            l=mul_op,
            r=MockMop(t=_stubs["ida_hexrays"].mop_v, g=0x100000),
        )

        result = IndirectCallResolver._extract_mul8_index(add_insn, {})
        assert result == 3

    def test_add_mul_8_index_base_right(self) -> None:
        """add(mul(8, index), base) with mul on RIGHT operand."""
        # mul(8, 5) on right side of add
        mul_op = self._make_mul_inner(
            MockMop(t=_stubs["ida_hexrays"].mop_n, nnn=MockNnn(8)),
            MockMop(t=_stubs["ida_hexrays"].mop_n, nnn=MockNnn(5)),
        )
        add_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_add,
            ea=0x1000,
            l=MockMop(t=_stubs["ida_hexrays"].mop_v, g=0x100000),
            r=mul_op,
        )

        result = IndirectCallResolver._extract_mul8_index(add_insn, {})
        assert result == 5

    def test_mul_index_from_register(self) -> None:
        """mul(reg, 8) where reg has tracked value."""
        mul_op = self._make_mul_inner(
            MockMop(t=_stubs["ida_hexrays"].mop_r, r=2),
            MockMop(t=_stubs["ida_hexrays"].mop_n, nnn=MockNnn(8)),
        )
        add_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_add,
            ea=0x1000,
            l=mul_op,
            r=MockMop(t=_stubs["ida_hexrays"].mop_v, g=0x100000),
        )

        result = IndirectCallResolver._extract_mul8_index(add_insn, {2: 7})
        assert result == 7

    def test_no_mul_returns_none(self) -> None:
        """add without mul sub-expression returns None."""
        add_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_add,
            ea=0x1000,
            l=MockMop(t=_stubs["ida_hexrays"].mop_r, r=1),
            r=MockMop(t=_stubs["ida_hexrays"].mop_n, nnn=MockNnn(100)),
        )

        result = IndirectCallResolver._extract_mul8_index(add_insn, {})
        assert result is None


# ===========================================================================
# Tests: _extract_sub_offset (block-level) (MEDIUM)
# ===========================================================================

class TestExtractSubOffsetBlock:
    """Test block-level _extract_sub_offset scanning."""

    def test_scan_block_for_m_sub_with_large_constant(self) -> None:
        """Should find the largest large constant in m_sub instructions."""
        resolver = _make_resolver()

        sub1 = MockInsn(
            opcode=_stubs["ida_hexrays"].m_sub,
            r=MockMop(t=_stubs["ida_hexrays"].mop_n, nnn=MockNnn(0x20000)),
        )
        sub2 = MockInsn(
            opcode=_stubs["ida_hexrays"].m_sub,
            r=MockMop(t=_stubs["ida_hexrays"].mop_n, nnn=MockNnn(0x90000)),
        )
        head, tail = _build_chain(sub1, sub2)

        blk = MockBlock(head=head, tail=tail)
        MockMba([blk])

        result = resolver._extract_sub_offset(blk, sub1)
        assert result == 0x90000  # the larger one

    def test_rejects_constants_outside_valid_range(self) -> None:
        """Constants outside MIN_SUB_OFFSET..MAX_SUB_OFFSET are rejected."""
        resolver = _make_resolver()

        # Too small
        sub_small = MockInsn(
            opcode=_stubs["ida_hexrays"].m_sub,
            r=MockMop(t=_stubs["ida_hexrays"].mop_n, nnn=MockNnn(0x100)),
        )
        # Too large
        sub_large = MockInsn(
            opcode=_stubs["ida_hexrays"].m_sub,
            r=MockMop(t=_stubs["ida_hexrays"].mop_n, nnn=MockNnn(0x2000000)),
        )
        head, tail = _build_chain(sub_small, sub_large)

        blk = MockBlock(head=head, tail=tail)
        MockMba([blk])

        result = resolver._extract_sub_offset(blk, sub_small)
        assert result == 0


# ===========================================================================
# Tests: End-to-end optimize() flow (Issue C2)
# ===========================================================================

class TestOptimizeEndToEnd:
    """Integration test: full flow icall -> find table -> trace target -> replace call."""

    def test_full_flow_resolve_and_replace(self) -> None:
        """Full end-to-end: detect icall, find table, trace target, replace call."""
        resolver = _make_resolver()

        target_ea = 0x401000
        table_ea = 0x200000
        entry_val = target_ea + 0x80000  # target = entry_val - offset

        # Build block:
        # 1. mov #8, reg5  (index byte offset = 8 -> index 1)
        # 2. ldx table_ea, reg5 -> reg6
        # 3. sub reg6, #0x80000
        # 4. icall reg6  (with mcallinfo)
        mov_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_mov,
            ea=0x1000,
            l=MockMop(t=_stubs["ida_hexrays"].mop_n, nnn=MockNnn(8)),
            d=MockMop(t=_stubs["ida_hexrays"].mop_r, r=5),
        )
        ldx_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_ldx,
            ea=0x1008,
            l=MockMop(t=_stubs["ida_hexrays"].mop_v, g=table_ea),
            r=MockMop(t=_stubs["ida_hexrays"].mop_r, r=5),
            d=MockMop(t=_stubs["ida_hexrays"].mop_r, r=6),
        )
        sub_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_sub,
            ea=0x1010,
            r=MockMop(t=_stubs["ida_hexrays"].mop_n, nnn=MockNnn(0x80000)),
            d=MockMop(t=_stubs["ida_hexrays"].mop_r, r=6),
        )
        mci = mock.MagicMock()
        mci.callee = 0
        icall_insn = MockInsn(
            opcode=_stubs["ida_hexrays"].m_icall,
            ea=0x1018,
            l=MockMop(t=_stubs["ida_hexrays"].mop_r, r=6),
            d=MockMop(t=_stubs["ida_hexrays"].mop_f, f=mci),
        )

        head, tail = _build_chain(mov_insn, ldx_insn, sub_insn, icall_insn)
        blk = MockBlock(serial=0, head=head, tail=tail)
        blk.mark_lists_dirty = mock.MagicMock()
        mba = MockMba([blk])
        mba.mark_chains_dirty = mock.MagicMock()

        # Mock the external dependencies
        mock_func = mock.MagicMock()
        mock_func.start_ea = target_ea

        with mock.patch(
            "d810.optimizers.microcode.flow.indirect_call.find_table_reference",
            return_value=table_ea,
        ), mock.patch(
            "d810.optimizers.microcode.flow.indirect_call.find_xor_with_globals",
            return_value=[],
        ), mock.patch(
            "d810.optimizers.microcode.flow.indirect_call.read_global_value",
            return_value=entry_val,
        ), mock.patch(
            "d810.optimizers.microcode.flow.indirect_call.validate_code_target",
            return_value=True,
        ), mock.patch(
            "d810.optimizers.microcode.flow.indirect_call.ida_funcs"
        ) as mock_ida_funcs, mock.patch(
            "d810.optimizers.microcode.flow.indirect_call.ida_typeinf"
        ) as mock_ida_typeinf, mock.patch(
            "d810.optimizers.microcode.flow.indirect_call.ida_name"
        ) as mock_ida_name, mock.patch(
            "d810.optimizers.microcode.flow.indirect_call.idaapi"
        ) as mock_idaapi:
            mock_ida_funcs.get_func.return_value = mock_func
            mock_ida_typeinf.tinfo_t = mock.MagicMock
            mock_ida_typeinf.get_tinfo = mock.MagicMock(return_value=True)
            mock_ida_name.get_name.return_value = "target_func"

            result = resolver.optimize(blk)

        # The icall should have been resolved
        assert result == 1
        assert icall_insn.opcode == _stubs["ida_hexrays"].m_call
        assert icall_insn.l.t == _stubs["ida_hexrays"].mop_v
        assert icall_insn.l.g == target_ea
        assert mci.callee == target_ea
        blk.mark_lists_dirty.assert_called_once()
        mba.mark_chains_dirty.assert_called_once()
