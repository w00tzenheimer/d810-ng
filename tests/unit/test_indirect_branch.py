"""Unit tests for IndirectBranchResolver (Chernobog Phase 5).

These tests run without IDA Pro by mocking the ida_* modules and exercising
the pure-Python logic of table decoding, index-bound tracing, and the
single-vs-multiple target decision path.

All IDA module stubs are injected via a module-scoped pytest fixture
(``_mock_ida_modules``) that properly saves and restores ``sys.modules``
so that stubs do not leak into other test modules.
"""
from __future__ import annotations

import pathlib
import sys
import types
from typing import Optional
from unittest import mock
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Ensure that the worktree's ``src/`` directory takes priority over any
# editable install of d810 from the main repo.
# ---------------------------------------------------------------------------
_WORKTREE_SRC = str(pathlib.Path(__file__).resolve().parent.parent.parent / "src")
if _WORKTREE_SRC not in sys.path:
    sys.path.insert(0, _WORKTREE_SRC)


# ---------------------------------------------------------------------------
# IDA module stubs -- created by the fixture, NOT at module level.
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
        val = MagicMock()
        setattr(self, name, val)
        return val


def _create_ida_stubs():
    """Create IDA module stubs (does NOT inject into sys.modules)."""
    stubs = {}

    # --- ida_bytes ---
    ida_bytes = types.ModuleType("ida_bytes")
    ida_bytes.get_bytes = MagicMock(return_value=None)
    ida_bytes.get_flags = MagicMock(return_value=0)
    ida_bytes.is_code = MagicMock(return_value=False)
    stubs["ida_bytes"] = ida_bytes

    # --- ida_hexrays (opcodes + constants) ---
    ida_hexrays = _AutoIntModule("ida_hexrays")
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
    ida_hexrays.mop_r = 1
    ida_hexrays.mop_n = 2
    ida_hexrays.mop_v = 3
    ida_hexrays.mop_d = 4
    ida_hexrays.mop_a = 5
    ida_hexrays.mop_b = 6
    ida_hexrays.mop_S = 7
    ida_hexrays.BLT_NONE = 0
    ida_hexrays.BLT_STOP = 1
    ida_hexrays.BLT_0WAY = 2
    ida_hexrays.BLT_1WAY = 3
    ida_hexrays.BLT_2WAY = 4
    ida_hexrays.BLT_NWAY = 5
    ida_hexrays.BLT_XTRN = 6
    ida_hexrays.MMAT_ZERO = 0
    ida_hexrays.MMAT_GENERATED = 1
    ida_hexrays.MMAT_PREOPTIMIZED = 2
    ida_hexrays.MMAT_LOCOPT = 3
    ida_hexrays.MMAT_CALLS = 4
    ida_hexrays.MMAT_GLBOPT1 = 5
    ida_hexrays.MMAT_GLBOPT2 = 6
    ida_hexrays.MMAT_GLBOPT3 = 7
    ida_hexrays.MMAT_LVARS = 8
    ida_hexrays.MBL_GOTO = 0x01
    ida_hexrays.minsn_t = MagicMock
    ida_hexrays.mop_t = MagicMock
    ida_hexrays.mblock_t = MagicMock
    ida_hexrays.mba_t = MagicMock
    ida_hexrays.mbl_array_t = MagicMock
    ida_hexrays.get_mreg_name = MagicMock(return_value="reg")
    ida_hexrays.is_mcode_jcond = MagicMock(return_value=False)
    stubs["ida_hexrays"] = ida_hexrays

    # --- ida_nalt ---
    ida_nalt = types.ModuleType("ida_nalt")
    ida_nalt.switch_info_t = MagicMock
    ida_nalt.get_switch_info = MagicMock(return_value=0)
    stubs["ida_nalt"] = ida_nalt

    # --- ida_name ---
    ida_name = types.ModuleType("ida_name")
    ida_name.get_name_ea = MagicMock(return_value=0xFFFFFFFFFFFFFFFF)
    ida_name.get_name = MagicMock(return_value="")
    stubs["ida_name"] = ida_name

    # --- ida_funcs ---
    ida_funcs = types.ModuleType("ida_funcs")
    ida_funcs.get_func = MagicMock(return_value=None)
    stubs["ida_funcs"] = ida_funcs

    # --- idaapi ---
    idaapi_mod = _AutoIntModule("idaapi")
    idaapi_mod.set_cmt = MagicMock()
    idaapi_mod.BADADDR = 0xFFFFFFFFFFFFFFFF
    idaapi_mod.IDA_SDK_VERSION = 900
    stubs["idaapi"] = idaapi_mod

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
# Follows the same pattern as test_block_merge.py.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def _ida_stubs():
    """Inject IDA stubs into sys.modules for the duration of this module's tests."""
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


@pytest.fixture(autouse=True)
def _use_ida_stubs(_ida_stubs):
    """Auto-use wrapper so every test in this module gets IDA stubs."""
    return _ida_stubs


# ===========================================================================
# Helper: build mock microcode blocks
# ===========================================================================

class MockNnn:
    """Stands in for mop_t.nnn (number info)."""
    def __init__(self, value: int) -> None:
        self.value = value


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
    ) -> None:
        self.t = t
        self.r = r
        self.g = g
        self.nnn = nnn
        self.d = d
        self.a = a
        self.b = b

    def make_blkref(self, serial: int) -> None:
        self.b = serial

    def erase(self) -> None:
        pass


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


class MockSuccset:
    """Minimal succset/predset mock."""
    def __init__(self, items: Optional[list[int]] = None) -> None:
        self._items = list(items) if items else []

    def __iter__(self):
        return iter(self._items)

    def __getitem__(self, idx):
        return self._items[idx]

    def __len__(self):
        return len(self._items)

    def push_back(self, val: int) -> None:
        self._items.append(val)

    def _del(self, val: int) -> None:
        if val in self._items:
            self._items.remove(val)

    def _del_all(self) -> None:
        self._items.clear()


class MockBlock:
    """Minimal mblock_t mock."""
    def __init__(
        self,
        serial: int = 0,
        start: int = 0,
        end: int = 0,
        head: Optional[MockInsn] = None,
        tail: Optional[MockInsn] = None,
        blk_type: int = 3,  # BLT_1WAY
    ) -> None:
        self.serial = serial
        self.start = start
        self.end = end
        self.head = head
        self.tail = tail
        self.type = blk_type
        self.flags = 0
        self.succset = MockSuccset()
        self.predset = MockSuccset()
        self.mba: Optional[MockMba] = None
        self.nextb: Optional[MockBlock] = None

    def nsucc(self) -> int:
        return len(self.succset)

    def npred(self) -> int:
        return len(self.predset)

    def succ(self, idx: int) -> int:
        return self.succset[idx]

    def pred(self, idx: int) -> int:
        return self.predset[idx]

    def mark_lists_dirty(self) -> None:
        pass


class MockMba:
    """Minimal mba_t mock."""
    def __init__(self, blocks: Optional[list[MockBlock]] = None, stubs=None) -> None:
        self.blocks = blocks or []
        self.qty = len(self.blocks)
        self.entry_ea = 0x1000
        # Use MMAT_LOCOPT value (3) directly to avoid stubs dependency
        self.maturity = 3
        for blk in self.blocks:
            blk.mba = self

    def get_mblock(self, idx: int) -> Optional[MockBlock]:
        if 0 <= idx < len(self.blocks):
            return self.blocks[idx]
        return None

    def mark_chains_dirty(self) -> None:
        pass

    def verify(self, _: bool = True) -> None:
        pass


def _build_chain(*insns: MockInsn) -> tuple[MockInsn, MockInsn]:
    """Link a list of instructions into a doubly-linked chain.  Returns (head, tail)."""
    for i in range(len(insns) - 1):
        insns[i].next = insns[i + 1]
        insns[i + 1].prev = insns[i]
    return insns[0], insns[-1]


# ===========================================================================
# Helper imports -- must be called at test time, after fixture injects stubs
# ===========================================================================

def _import_resolver():
    from d810.optimizers.microcode.flow.indirect_branch import IndirectBranchResolver
    return IndirectBranchResolver

def _import_table_utils():
    from d810.hexrays.table_utils import (
        TableEncoding,
        decode_table_entry,
        read_table_entries,
    )
    return TableEncoding, decode_table_entry, read_table_entries

def _get_stubs():
    """Return the current IDA stubs from sys.modules."""
    return {
        "ida_hexrays": sys.modules["ida_hexrays"],
        "ida_bytes": sys.modules["ida_bytes"],
        "ida_nalt": sys.modules["ida_nalt"],
        "ida_name": sys.modules["ida_name"],
        "ida_funcs": sys.modules["ida_funcs"],
        "idaapi": sys.modules["idaapi"],
        "idc": sys.modules["idc"],
        "ida_diskio": sys.modules["ida_diskio"],
    }


# ===========================================================================
# Tests: decode_table_entry
# ===========================================================================

class TestDecodeTableEntry:
    """Test the pure-Python decode_table_entry function."""

    def test_direct(self) -> None:
        TableEncoding, decode_table_entry, _ = _import_table_utils()
        assert decode_table_entry(0xDEAD, TableEncoding.DIRECT) == 0xDEAD

    def test_offset(self) -> None:
        TableEncoding, decode_table_entry, _ = _import_table_utils()
        assert decode_table_entry(0x100, TableEncoding.OFFSET, base=0x4000) == 0x4100

    def test_xor(self) -> None:
        TableEncoding, decode_table_entry, _ = _import_table_utils()
        assert decode_table_entry(0xFF00, TableEncoding.XOR, key=0x00FF) == 0xFFFF

    def test_offset_xor(self) -> None:
        TableEncoding, decode_table_entry, _ = _import_table_utils()
        # (0xFF00 ^ 0x00FF) + 0x1000 = 0xFFFF + 0x1000 = 0x10FFF
        result = decode_table_entry(0xFF00, TableEncoding.OFFSET_XOR, key=0x00FF, base=0x1000)
        assert result == 0x10FFF

    def test_roundtrip_xor(self) -> None:
        """Encoding + decoding with XOR should produce the original address."""
        TableEncoding, decode_table_entry, _ = _import_table_utils()
        original = 0x401000
        key = 0xCAFEBABE
        encoded = original ^ key
        decoded = decode_table_entry(encoded, TableEncoding.XOR, key=key)
        assert decoded == original

    def test_roundtrip_offset(self) -> None:
        TableEncoding, decode_table_entry, _ = _import_table_utils()
        original = 0x401000
        base = 0x400000
        encoded = original - base
        decoded = decode_table_entry(encoded, TableEncoding.OFFSET, base=base)
        assert decoded == original


# ===========================================================================
# Tests: _trace_index_bounds (via IndirectBranchResolver)
# ===========================================================================

class TestTraceIndexBounds:
    """Test index-bound detection from block instructions."""

    def _make_resolver(self):
        Cls = _import_resolver()
        return Cls()

    def test_and_mask(self) -> None:
        """AND with 0xFF mask should yield 256 entries."""
        stubs = _get_stubs()
        resolver = self._make_resolver()

        and_insn = MockInsn(
            opcode=stubs["ida_hexrays"].m_and,
            l=MockMop(t=stubs["ida_hexrays"].mop_r, r=1),
            r=MockMop(t=stubs["ida_hexrays"].mop_n, nnn=MockNnn(0xFF)),
        )
        ijmp_insn = MockInsn(opcode=stubs["ida_hexrays"].m_ijmp)
        head, tail = _build_chain(and_insn, ijmp_insn)

        blk = MockBlock(head=head, tail=tail)
        result = resolver._trace_index_bounds(blk)
        assert result == 256  # 0xFF + 1

    def test_and_mask_small(self) -> None:
        """AND with 0x0F mask should yield 16 entries."""
        stubs = _get_stubs()
        resolver = self._make_resolver()

        and_insn = MockInsn(
            opcode=stubs["ida_hexrays"].m_and,
            l=MockMop(t=stubs["ida_hexrays"].mop_r, r=1),
            r=MockMop(t=stubs["ida_hexrays"].mop_n, nnn=MockNnn(0x0F)),
        )
        ijmp_insn = MockInsn(opcode=stubs["ida_hexrays"].m_ijmp)
        head, tail = _build_chain(and_insn, ijmp_insn)

        blk = MockBlock(head=head, tail=tail)
        result = resolver._trace_index_bounds(blk)
        assert result == 16

    def test_low_byte_extraction(self) -> None:
        """m_low instruction should yield 256 entries."""
        stubs = _get_stubs()
        resolver = self._make_resolver()

        low_insn = MockInsn(
            opcode=stubs["ida_hexrays"].m_low,
            l=MockMop(t=stubs["ida_hexrays"].mop_r, r=1),
        )
        ijmp_insn = MockInsn(opcode=stubs["ida_hexrays"].m_ijmp)
        head, tail = _build_chain(low_insn, ijmp_insn)

        blk = MockBlock(head=head, tail=tail)
        result = resolver._trace_index_bounds(blk)
        assert result == 256

    def test_no_bound_defaults_to_max(self) -> None:
        """Without bounding ops, should default to MAX_TABLE_ENTRIES."""
        stubs = _get_stubs()
        resolver = self._make_resolver()

        from d810.optimizers.microcode.flow.indirect_branch import MAX_TABLE_ENTRIES

        nop_insn = MockInsn(opcode=stubs["ida_hexrays"].m_nop)
        ijmp_insn = MockInsn(opcode=stubs["ida_hexrays"].m_ijmp)
        head, tail = _build_chain(nop_insn, ijmp_insn)

        blk = MockBlock(head=head, tail=tail)
        result = resolver._trace_index_bounds(blk)
        assert result == MAX_TABLE_ENTRIES


# ===========================================================================
# Tests: optimize() decision logic
# ===========================================================================

class TestOptimizeDecision:
    """Test the optimize() method's detection and decision branches."""

    def _make_resolver(self):
        Cls = _import_resolver()
        return Cls()

    def test_skip_non_ijmp(self) -> None:
        """Blocks not ending in m_ijmp should return 0 immediately."""
        stubs = _get_stubs()
        resolver = self._make_resolver()
        blk = MockBlock(tail=MockInsn(opcode=stubs["ida_hexrays"].m_goto))
        assert resolver.optimize(blk) == 0

    def test_skip_no_tail(self) -> None:
        """Blocks with no tail instruction should return 0."""
        resolver = self._make_resolver()
        blk = MockBlock(tail=None)
        assert resolver.optimize(blk) == 0


# ===========================================================================
# Tests: _resolve_target_blocks
# ===========================================================================

class TestResolveTargetBlocks:
    """Test mapping of target EAs to block serial numbers."""

    def _make_resolver(self):
        Cls = _import_resolver()
        return Cls()

    def test_single_block(self) -> None:
        resolver = self._make_resolver()
        blk0 = MockBlock(serial=0, start=0x1000, end=0x1010)
        blk1 = MockBlock(serial=1, start=0x1010, end=0x1020)
        blk2 = MockBlock(serial=2, start=0x1020, end=0x1030)
        mba = MockMba([blk0, blk1, blk2])

        result = resolver._resolve_target_blocks(mba, [0x1015])
        assert result == [1]

    def test_multiple_targets_same_block(self) -> None:
        resolver = self._make_resolver()
        blk0 = MockBlock(serial=0, start=0x1000, end=0x1020)
        mba = MockMba([blk0])

        result = resolver._resolve_target_blocks(mba, [0x1000, 0x1010, 0x1018])
        assert result == [0, 0, 0]

    def test_target_outside_all_blocks(self) -> None:
        resolver = self._make_resolver()
        blk0 = MockBlock(serial=0, start=0x1000, end=0x1010)
        mba = MockMba([blk0])

        result = resolver._resolve_target_blocks(mba, [0x9999])
        assert result == [None]


# ===========================================================================
# Tests: table_utils helpers (non-IDA)
# ===========================================================================

class TestTableEncodingEnum:
    """Verify TableEncoding enum values match Chernobog's C++ enum."""

    def test_values(self) -> None:
        TableEncoding, _, _ = _import_table_utils()
        assert TableEncoding.DIRECT == 0
        assert TableEncoding.OFFSET == 1
        assert TableEncoding.XOR == 2
        assert TableEncoding.OFFSET_XOR == 3


class TestReadTableEntries:
    """Test read_table_entries with a mock IDA environment."""

    def test_reads_entries(self) -> None:
        """Should read entries until read_global_value returns None."""
        stubs = _get_stubs()
        _, _, read_table_entries = _import_table_utils()
        stubs["ida_bytes"].get_bytes.side_effect = [
            b"\x00\x10\x40\x00\x00\x00\x00\x00",  # 0x401000
            b"\x00\x20\x40\x00\x00\x00\x00\x00",  # 0x402000
            None,  # read failure -> stop
        ]
        entries = read_table_entries(0x5000, count=5, entry_size=8)
        assert len(entries) == 2
        assert entries[0] == 0x401000
        assert entries[1] == 0x402000

    def test_empty_on_immediate_failure(self) -> None:
        stubs = _get_stubs()
        _, _, read_table_entries = _import_table_utils()
        stubs["ida_bytes"].get_bytes.side_effect = None
        stubs["ida_bytes"].get_bytes.return_value = None
        entries = read_table_entries(0x5000, count=5, entry_size=8)
        assert entries == []

    def test_respects_count_limit(self) -> None:
        stubs = _get_stubs()
        _, _, read_table_entries = _import_table_utils()
        stubs["ida_bytes"].get_bytes.side_effect = [
            b"\x01\x00\x00\x00\x00\x00\x00\x00",
            b"\x02\x00\x00\x00\x00\x00\x00\x00",
            b"\x03\x00\x00\x00\x00\x00\x00\x00",
        ]
        entries = read_table_entries(0x5000, count=2, entry_size=8)
        assert len(entries) == 2


# ===========================================================================
# Tests: Constants
# ===========================================================================

class TestConstants:
    """Verify module-level constants have expected values."""

    def test_max_table_entries(self) -> None:
        from d810.optimizers.microcode.flow.indirect_branch import MAX_TABLE_ENTRIES
        assert MAX_TABLE_ENTRIES == 512

    def test_max_consecutive_invalid(self) -> None:
        from d810.optimizers.microcode.flow.indirect_branch import MAX_CONSECUTIVE_INVALID
        assert MAX_CONSECUTIVE_INVALID == 5

    def test_default_entry_size(self) -> None:
        from d810.optimizers.microcode.flow.indirect_branch import DEFAULT_TABLE_ENTRY_SIZE
        assert DEFAULT_TABLE_ENTRY_SIZE == 8


# ===========================================================================
# Issue A1: _convert_to_goto() tests (CFG modification)
# ===========================================================================

class TestConvertToGoto:
    """Test _convert_to_goto() with mocked cfg_utils helpers."""

    def _make_resolver(self):
        Cls = _import_resolver()
        return Cls()

    def test_0way_block_uses_change_0way(self) -> None:
        """When blk.nsucc() == 0, should call change_0way_block_successor."""
        stubs = _get_stubs()
        resolver = self._make_resolver()

        ijmp_insn = MockInsn(opcode=stubs["ida_hexrays"].m_ijmp, ea=0x1000)
        blk = MockBlock(serial=1, start=0x1000, tail=ijmp_insn)
        blk0 = MockBlock(serial=0, start=0x900)
        blk2 = MockBlock(serial=2, start=0x2000)
        mba = MockMba([blk0, blk, blk2])

        with mock.patch(
            "d810.optimizers.microcode.flow.indirect_branch.change_0way_block_successor",
            return_value=True,
        ) as mock_0way:
            result = resolver._convert_to_goto(blk, 2)

        assert result == 1
        mock_0way.assert_called_once_with(blk, 2)

    def test_1way_block_uses_change_1way(self) -> None:
        """When blk.nsucc() == 1, should call change_1way_block_successor."""
        stubs = _get_stubs()
        resolver = self._make_resolver()

        ijmp_insn = MockInsn(opcode=stubs["ida_hexrays"].m_ijmp, ea=0x1000)
        blk = MockBlock(serial=1, start=0x1000, tail=ijmp_insn)
        blk.succset.push_back(3)
        blk0 = MockBlock(serial=0, start=0x900)
        blk2 = MockBlock(serial=2, start=0x2000)
        mba = MockMba([blk0, blk, blk2])

        with mock.patch(
            "d810.optimizers.microcode.flow.indirect_branch.change_1way_block_successor",
            return_value=True,
        ) as mock_1way:
            result = resolver._convert_to_goto(blk, 2)

        assert result == 1
        mock_1way.assert_called_once_with(blk, 2)

    def test_returns_0_when_helper_returns_false(self) -> None:
        """Should return 0 when the cfg_utils helper returns False."""
        stubs = _get_stubs()
        resolver = self._make_resolver()

        ijmp_insn = MockInsn(opcode=stubs["ida_hexrays"].m_ijmp, ea=0x1000)
        blk = MockBlock(serial=1, start=0x1000, tail=ijmp_insn)
        blk.succset.push_back(3)
        blk0 = MockBlock(serial=0, start=0x900)
        mba = MockMba([blk0, blk])

        with mock.patch(
            "d810.optimizers.microcode.flow.indirect_branch.change_1way_block_successor",
            return_value=False,
        ):
            result = resolver._convert_to_goto(blk, 0)

        assert result == 0

    def test_catches_runtime_error_returns_0(self) -> None:
        """Should catch RuntimeError from mba.verify() and return 0."""
        stubs = _get_stubs()
        resolver = self._make_resolver()

        ijmp_insn = MockInsn(opcode=stubs["ida_hexrays"].m_ijmp, ea=0x1000)
        blk = MockBlock(serial=1, start=0x1000, tail=ijmp_insn)
        blk.succset.push_back(3)
        blk0 = MockBlock(serial=0, start=0x900)
        mba = MockMba([blk0, blk])

        with mock.patch(
            "d810.optimizers.microcode.flow.indirect_branch.change_1way_block_successor",
            side_effect=RuntimeError("verify failed: error 50357"),
        ):
            result = resolver._convert_to_goto(blk, 0)

        assert result == 0


# ===========================================================================
# Issue B5: _find_table_by_switch_info() tests
# ===========================================================================

class TestFindTableBySwitchInfo:
    """Test _find_table_by_switch_info() with mocked ida_nalt."""

    def _make_resolver(self):
        Cls = _import_resolver()
        return Cls()

    def setup_method(self) -> None:
        """Save original ida_nalt stubs so we can restore after each test."""
        stubs = _get_stubs()
        self._orig_switch_info_t = stubs["ida_nalt"].switch_info_t
        self._orig_get_switch_info = stubs["ida_nalt"].get_switch_info

    def teardown_method(self) -> None:
        """Restore original ida_nalt stubs to prevent test pollution."""
        stubs = _get_stubs()
        stubs["ida_nalt"].switch_info_t = self._orig_switch_info_t
        stubs["ida_nalt"].get_switch_info = self._orig_get_switch_info
        if hasattr(stubs["ida_nalt"].get_switch_info, "side_effect"):
            stubs["ida_nalt"].get_switch_info.side_effect = None

    def test_finds_switch_info_at_blk_start(self) -> None:
        """Should return si.jumps when get_switch_info succeeds at blk.start."""
        stubs = _get_stubs()
        resolver = self._make_resolver()

        ijmp_insn = MockInsn(opcode=stubs["ida_hexrays"].m_ijmp, ea=0x2000)
        blk = MockBlock(serial=1, start=0x1000, tail=ijmp_insn)

        mock_si = MagicMock()
        mock_si.jumps = 0x5000
        stubs["ida_nalt"].switch_info_t = MagicMock(return_value=mock_si)

        stubs["ida_nalt"].get_switch_info = MagicMock(
            side_effect=lambda si, ea: 1 if ea == 0x1000 else 0
        )

        result = resolver._find_table_by_switch_info(blk)
        assert result == 0x5000

    def test_falls_back_to_tail_ea(self) -> None:
        """Should try blk.tail.ea when blk.start fails."""
        stubs = _get_stubs()
        resolver = self._make_resolver()

        ijmp_insn = MockInsn(opcode=stubs["ida_hexrays"].m_ijmp, ea=0x2000)
        blk = MockBlock(serial=1, start=0x1000, tail=ijmp_insn)

        mock_si = MagicMock()
        mock_si.jumps = 0x6000
        stubs["ida_nalt"].switch_info_t = MagicMock(return_value=mock_si)

        stubs["ida_nalt"].get_switch_info = MagicMock(
            side_effect=lambda si, ea: 1 if ea == 0x2000 else 0
        )

        result = resolver._find_table_by_switch_info(blk)
        assert result == 0x6000

    def test_returns_none_when_both_fail(self) -> None:
        """Should return None when get_switch_info fails at both addresses."""
        stubs = _get_stubs()
        resolver = self._make_resolver()

        ijmp_insn = MockInsn(opcode=stubs["ida_hexrays"].m_ijmp, ea=0x2000)
        blk = MockBlock(serial=1, start=0x1000, tail=ijmp_insn)

        stubs["ida_nalt"].switch_info_t = MagicMock(return_value=MagicMock())

        stubs["ida_nalt"].get_switch_info = MagicMock(
            side_effect=lambda si, ea: 0
        )

        result = resolver._find_table_by_switch_info(blk)
        assert result is None


# ===========================================================================
# Issue B6: _find_table_by_known_names() tests
# ===========================================================================

class TestFindTableByKnownNames:
    """Test _find_table_by_known_names() with mocked ida_name."""

    def _make_resolver(self):
        Cls = _import_resolver()
        return Cls()

    def teardown_method(self) -> None:
        """Reset get_name_ea mock to prevent test pollution."""
        stubs = _get_stubs()
        stubs["ida_name"].get_name_ea.side_effect = None
        stubs["ida_name"].get_name_ea.return_value = 0xFFFFFFFFFFFFFFFF

    def test_finds_hikari_table_by_first_name(self) -> None:
        """Should return EA when first known name resolves."""
        stubs = _get_stubs()
        resolver = self._make_resolver()
        from d810.optimizers.microcode.flow.indirect_branch import BADADDR

        stubs["ida_name"].get_name_ea.side_effect = lambda seg, name: (
            0x7000 if name == "IndirectBranchingGlobalTable" else BADADDR
        )

        result = resolver._find_table_by_known_names()
        assert result == 0x7000

    def test_tries_all_names_succeeds_on_last(self) -> None:
        """Should try all 3 names and succeed on the last one."""
        stubs = _get_stubs()
        resolver = self._make_resolver()
        from d810.optimizers.microcode.flow.indirect_branch import BADADDR

        stubs["ida_name"].get_name_ea.side_effect = lambda seg, name: (
            0x8000 if name == "IndirectBranchTable" else BADADDR
        )

        result = resolver._find_table_by_known_names()
        assert result == 0x8000

    def test_returns_none_when_all_fail(self) -> None:
        """Should return None when all known names resolve to BADADDR."""
        stubs = _get_stubs()
        resolver = self._make_resolver()
        from d810.optimizers.microcode.flow.indirect_branch import BADADDR

        stubs["ida_name"].get_name_ea.side_effect = None
        stubs["ida_name"].get_name_ea.return_value = BADADDR

        result = resolver._find_table_by_known_names()
        assert result is None


# ===========================================================================
# Issue D2: "5 consecutive invalid targets" stop condition
# ===========================================================================

class TestConsecutiveInvalidTargets:
    """Test the consecutive invalid target stop condition in optimize()."""

    def _make_resolver(self):
        Cls = _import_resolver()
        return Cls()

    def _setup_optimize_mocks(self, raw_entries, code_valid_eas=None):
        """Set up all mocks needed for optimize() to reach the table scanning loop."""
        TableEncoding, _, _ = _import_table_utils()
        if code_valid_eas is None:
            code_valid_eas = set()

        patches = {}
        patches["find_table_ref"] = mock.patch(
            "d810.optimizers.microcode.flow.indirect_branch.find_table_reference",
            return_value=0x5000,
        )
        patches["analyze_enc"] = mock.patch(
            "d810.optimizers.microcode.flow.indirect_branch.analyze_table_encoding",
            return_value=(TableEncoding.DIRECT, 0, 0),
        )
        patches["read_entries"] = mock.patch(
            "d810.optimizers.microcode.flow.indirect_branch.read_table_entries",
            return_value=raw_entries,
        )
        patches["validate"] = mock.patch(
            "d810.optimizers.microcode.flow.indirect_branch.validate_code_target",
            side_effect=lambda ea, *a: ea in code_valid_eas,
        )
        patches["func_bounds"] = mock.patch.object(
            type(self._make_resolver()), "_get_function_bounds",
            return_value=(0x1000, 0x9000),
        )
        return patches

    def test_stops_after_5_consecutive_invalid(self) -> None:
        """Should stop scanning after 5 consecutive invalid (non-zero) targets."""
        stubs = _get_stubs()
        resolver = self._make_resolver()
        from d810.optimizers.microcode.flow.indirect_branch import MAX_CONSECUTIVE_INVALID

        raw_entries = [0x2000, 0x3000, 0xDEAD, 0xDEAD, 0xDEAD, 0xDEAD, 0xDEAD, 0x4000]
        valid_eas = {0x2000, 0x3000, 0x4000}

        ijmp_insn = MockInsn(opcode=stubs["ida_hexrays"].m_ijmp, ea=0x1050)
        blk = MockBlock(serial=1, start=0x1000, tail=ijmp_insn, head=ijmp_insn)
        blk0 = MockBlock(serial=0, start=0x900, end=0x1000)
        blk2 = MockBlock(serial=2, start=0x2000, end=0x5000)
        mba = MockMba([blk0, blk, blk2])

        patches = self._setup_optimize_mocks(raw_entries, valid_eas)

        with (
            patches["find_table_ref"],
            patches["analyze_enc"],
            patches["read_entries"],
            patches["validate"],
            patches["func_bounds"],
            mock.patch.object(
                type(resolver), "_convert_to_goto", return_value=1,
            ) as mock_convert,
        ):
            result = resolver.optimize(blk)

        assert result == 1
        mock_convert.assert_called_once_with(blk, 2)

    def test_resets_counter_on_valid_target(self) -> None:
        """Counter should reset to 0 when a valid target appears between invalids."""
        stubs = _get_stubs()
        resolver = self._make_resolver()

        raw_entries = [
            0x2000,   # valid
            0xDEAD, 0xDEAD, 0xDEAD, 0xDEAD,  # 4 invalid
            0x3000,   # valid (resets counter)
            0xDEAD, 0xDEAD, 0xDEAD, 0xDEAD,  # 4 invalid
            0x4000,   # valid (resets counter)
        ]
        valid_eas = {0x2000, 0x3000, 0x4000}

        ijmp_insn = MockInsn(opcode=stubs["ida_hexrays"].m_ijmp, ea=0x1050)
        blk = MockBlock(serial=1, start=0x1000, tail=ijmp_insn, head=ijmp_insn)
        blk0 = MockBlock(serial=0, start=0x900, end=0x1000)
        blk2 = MockBlock(serial=2, start=0x2000, end=0x5000)
        mba = MockMba([blk0, blk, blk2])

        patches = self._setup_optimize_mocks(raw_entries, valid_eas)

        with (
            patches["find_table_ref"],
            patches["analyze_enc"],
            patches["read_entries"],
            patches["validate"],
            patches["func_bounds"],
            mock.patch.object(
                type(resolver), "_convert_to_goto", return_value=1,
            ) as mock_convert,
        ):
            result = resolver.optimize(blk)

        assert mock_convert.called
        assert result == 1

    def test_max_table_entries_limit(self) -> None:
        """Should not read more than MAX_TABLE_ENTRIES entries."""
        stubs = _get_stubs()
        resolver = self._make_resolver()
        from d810.optimizers.microcode.flow.indirect_branch import MAX_TABLE_ENTRIES

        raw_entries = [0x2000 + i for i in range(MAX_TABLE_ENTRIES + 10)]
        valid_eas = set(raw_entries)

        ijmp_insn = MockInsn(opcode=stubs["ida_hexrays"].m_ijmp, ea=0x1050)
        blk = MockBlock(serial=1, start=0x1000, tail=ijmp_insn, head=ijmp_insn)
        blk0 = MockBlock(serial=0, start=0x900, end=0x1000)
        blk2 = MockBlock(serial=2, start=0x1000, end=0xFFFFF)
        mba = MockMba([blk0, blk, blk2])

        patches = self._setup_optimize_mocks(raw_entries, valid_eas)

        with (
            patches["find_table_ref"],
            patches["analyze_enc"],
            patches["read_entries"] as mock_read,
            patches["validate"],
            patches["func_bounds"],
            mock.patch.object(
                type(resolver), "_convert_to_goto", return_value=1,
            ),
        ):
            resolver.optimize(blk)

        mock_read.assert_called_once()
        call_args = mock_read.call_args
        assert call_args[0][1] == MAX_TABLE_ENTRIES


# ===========================================================================
# Issue D3: Multi-target annotation path
# ===========================================================================

class TestAnnotateTargets:
    """Test _annotate_targets() IDB comment generation."""

    def _make_resolver(self):
        Cls = _import_resolver()
        return Cls()

    def teardown_method(self) -> None:
        """Reset ida_name.get_name mock to prevent test pollution."""
        stubs = _get_stubs()
        stubs["ida_name"].get_name.side_effect = None
        stubs["ida_name"].get_name.return_value = ""

    def test_annotate_targets_adds_comment(self) -> None:
        """Should call idaapi.set_cmt with formatted target list."""
        stubs = _get_stubs()
        resolver = self._make_resolver()

        blk = MockBlock(serial=1, start=0x1000)

        targets = [0x2000, 0x3000, 0x4000]

        stubs["ida_name"].get_name.side_effect = lambda ea: (
            "target_func" if ea == 0x2000 else ""
        )

        stubs["idaapi"].set_cmt.reset_mock()
        resolver._annotate_targets(blk, targets)

        stubs["idaapi"].set_cmt.assert_called_once()
        call_args = stubs["idaapi"].set_cmt.call_args
        comment = call_args[0][1]

        assert "3 targets" in comment
        assert "0x2000" in comment
        assert "target_func" in comment
        assert "0x3000" in comment
        assert "0x4000" in comment

    def test_annotate_truncates_at_20_targets(self) -> None:
        """Should truncate the target list at 20 entries with a '... and N more' note."""
        stubs = _get_stubs()
        resolver = self._make_resolver()

        blk = MockBlock(serial=1, start=0x1000)

        targets = [0x2000 + i * 0x10 for i in range(30)]

        stubs["ida_name"].get_name.return_value = ""
        stubs["idaapi"].set_cmt.reset_mock()

        resolver._annotate_targets(blk, targets)

        stubs["idaapi"].set_cmt.assert_called_once()
        call_args = stubs["idaapi"].set_cmt.call_args
        comment = call_args[0][1]

        assert "30 targets" in comment
        assert "... and 10 more" in comment
        assert "[19]" in comment
        assert "[20]" not in comment


# ===========================================================================
# Issue C1: End-to-end optimize() flow
# ===========================================================================

class TestOptimizeEndToEnd:
    """Integration test: detect ijmp -> find table -> resolve -> convert to goto."""

    def _make_resolver(self):
        Cls = _import_resolver()
        return Cls()

    def test_full_flow_single_target_block(self) -> None:
        """Full flow: ijmp block with table resolving to single block -> goto conversion."""
        stubs = _get_stubs()
        TableEncoding, _, _ = _import_table_utils()
        resolver = self._make_resolver()

        ijmp_insn = MockInsn(opcode=stubs["ida_hexrays"].m_ijmp, ea=0x1050)
        blk = MockBlock(serial=1, start=0x1000, end=0x1060, tail=ijmp_insn, head=ijmp_insn)
        blk.succset.push_back(2)

        blk0 = MockBlock(serial=0, start=0x900, end=0x1000)
        blk2 = MockBlock(serial=2, start=0x2000, end=0x3000)
        mba = MockMba([blk0, blk, blk2])

        raw_entries = [0x2000, 0x2100, 0x2200]

        with (
            mock.patch(
                "d810.optimizers.microcode.flow.indirect_branch.find_table_reference",
                return_value=0x5000,
            ),
            mock.patch(
                "d810.optimizers.microcode.flow.indirect_branch.analyze_table_encoding",
                return_value=(TableEncoding.DIRECT, 0, 0),
            ),
            mock.patch(
                "d810.optimizers.microcode.flow.indirect_branch.read_table_entries",
                return_value=raw_entries,
            ),
            mock.patch(
                "d810.optimizers.microcode.flow.indirect_branch.validate_code_target",
                return_value=True,
            ),
            mock.patch.object(
                type(resolver), "_get_function_bounds",
                return_value=(0x900, 0x9000),
            ),
            mock.patch(
                "d810.optimizers.microcode.flow.indirect_branch.change_1way_block_successor",
                return_value=True,
            ) as mock_change,
        ):
            result = resolver.optimize(blk)

        assert result == 1
        mock_change.assert_called_once_with(blk, 2)
