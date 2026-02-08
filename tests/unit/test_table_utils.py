"""Unit tests for d810.hexrays.table_utils.

These tests exercise the pure-logic functions (enum, dataclass,
decode_table_entry) without requiring IDA Pro.  IDA-dependent functions
are tested with mocked ``ida_bytes``.
"""
from __future__ import annotations

import sys
import types
from unittest import mock

import pytest


# ---------------------------------------------------------------------------
# Provide stub IDA modules so the module can be imported outside IDA.
# ---------------------------------------------------------------------------

def _ensure_ida_stubs():
    """Inject minimal IDA stubs into ``sys.modules`` if not already present."""
    stub_modules = [
        "ida_bytes", "ida_hexrays", "idaapi", "idc",
        "ida_diskio", "ida_funcs", "ida_ida",
    ]
    created = {}
    for name in stub_modules:
        if name not in sys.modules:
            mod = types.ModuleType(name)
            sys.modules[name] = mod
            created[name] = mod

    # ida_bytes stubs
    ida_bytes = sys.modules["ida_bytes"]
    if not hasattr(ida_bytes, "get_bytes"):
        ida_bytes.get_bytes = lambda ea, size: None  # type: ignore[attr-defined]
    if not hasattr(ida_bytes, "get_flags"):
        ida_bytes.get_flags = lambda ea: 0  # type: ignore[attr-defined]
    if not hasattr(ida_bytes, "is_code"):
        ida_bytes.is_code = lambda flags: False  # type: ignore[attr-defined]

    # ida_hexrays stubs -- opcode constants
    hx = sys.modules["ida_hexrays"]
    opcodes = {
        "m_mov": 0x01, "m_ldx": 0x02, "m_xor": 0x03,
        "m_neg": 0x04, "m_add": 0x05, "m_nop": 0x00,
        "mop_r": 1, "mop_n": 2, "mop_v": 3, "mop_a": 4,
        "mop_d": 5, "mop_z": 0,
    }
    for attr, val in opcodes.items():
        if not hasattr(hx, attr):
            setattr(hx, attr, val)

    return created


_stubs_created = _ensure_ida_stubs()

# Now we can safely import the module under test
from d810.hexrays.table_utils import (  # noqa: E402
    TableEncoding,
    XorKeyInfo,
    analyze_table_encoding,
    decode_table_entry,
    find_table_reference,
    find_xor_with_globals,
    read_global_value,
    read_table_entries,
    validate_code_target,
)

def _get_ida_hexrays():
    """Return the current ida_hexrays module from sys.modules.

    Must be called at test time, not at import time, because when IDA Pro
    is installed, test_pxd_equivalence.py can replace the stub module with
    the real one during pytest collection.
    """
    return sys.modules["ida_hexrays"]


def _ida_available_ctx():
    """Context manager that ensures table_utils sees IDA as available.

    Patches ``_IDA_AVAILABLE`` **and** ``ida_hexrays`` so the functions
    work correctly regardless of import order (which matters when the full
    test suite runs and another module triggers an early import of
    table_utils before stubs exist, or when the real IDA module replaces
    the stub).
    """
    return mock.patch.multiple(
        "d810.hexrays.table_utils",
        _IDA_AVAILABLE=True,
        ida_hexrays=_get_ida_hexrays(),
    )


# ===================================================================
# TableEncoding enum
# ===================================================================
class TestTableEncoding:
    def test_values(self):
        assert int(TableEncoding.DIRECT) == 0
        assert int(TableEncoding.OFFSET) == 1
        assert int(TableEncoding.XOR) == 2
        assert int(TableEncoding.OFFSET_XOR) == 3

    def test_members(self):
        assert set(TableEncoding.__members__.keys()) == {
            "DIRECT", "OFFSET", "XOR", "OFFSET_XOR",
        }

    def test_from_int(self):
        assert TableEncoding(0) is TableEncoding.DIRECT
        assert TableEncoding(3) is TableEncoding.OFFSET_XOR


# ===================================================================
# XorKeyInfo dataclass
# ===================================================================
class TestXorKeyInfo:
    def test_creation(self):
        info = XorKeyInfo(xor_key=0xDEAD, is_negated=False, source_ea=0x1000, reg=5)
        assert info.xor_key == 0xDEAD
        assert info.is_negated is False
        assert info.source_ea == 0x1000
        assert info.reg == 5

    def test_negated(self):
        info = XorKeyInfo(xor_key=0xBEEF, is_negated=True, source_ea=0x2000, reg=3)
        assert info.is_negated is True

    def test_equality(self):
        a = XorKeyInfo(xor_key=1, is_negated=False, source_ea=0, reg=0)
        b = XorKeyInfo(xor_key=1, is_negated=False, source_ea=0, reg=0)
        assert a == b

    def test_repr(self):
        info = XorKeyInfo(xor_key=0xFF, is_negated=False, source_ea=0x100, reg=2)
        r = repr(info)
        assert "XorKeyInfo" in r
        assert "255" in r or "0xff" in r.lower()


# ===================================================================
# decode_table_entry
# ===================================================================
class TestDecodeTableEntry:
    def test_direct(self):
        assert decode_table_entry(0x401000, TableEncoding.DIRECT) == 0x401000

    def test_offset(self):
        result = decode_table_entry(0x100, TableEncoding.OFFSET, base=0x400000)
        assert result == 0x400100

    def test_xor(self):
        result = decode_table_entry(0xDEADBEEF, TableEncoding.XOR, key=0xFF00FF00)
        assert result == 0xDEADBEEF ^ 0xFF00FF00

    def test_offset_xor(self):
        raw = 0xABCD
        key = 0xFF00
        base = 0x100000
        result = decode_table_entry(raw, TableEncoding.OFFSET_XOR, key=key, base=base)
        assert result == base + (raw ^ key)

    def test_direct_ignores_key_and_base(self):
        result = decode_table_entry(42, TableEncoding.DIRECT, key=99, base=100)
        assert result == 42

    def test_offset_zero_base(self):
        result = decode_table_entry(0x500, TableEncoding.OFFSET, base=0)
        assert result == 0x500

    def test_xor_zero_key(self):
        result = decode_table_entry(0x1234, TableEncoding.XOR, key=0)
        assert result == 0x1234

    def test_offset_xor_identity(self):
        """XOR with zero key and zero base is identity."""
        result = decode_table_entry(0xCAFE, TableEncoding.OFFSET_XOR, key=0, base=0)
        assert result == 0xCAFE


# ===================================================================
# read_global_value (mocked ida_bytes)
# ===================================================================
class TestReadGlobalValue:
    def test_read_4_bytes(self):
        # 0x78563412 in little-endian
        raw = b"\x12\x34\x56\x78"
        with mock.patch("d810.hexrays.table_utils.ida_bytes") as mb:
            mb.get_bytes = mock.Mock(return_value=raw)
            # Ensure the module thinks IDA is available
            with mock.patch("d810.hexrays.table_utils._IDA_AVAILABLE", True):
                result = read_global_value(0x1000, 4)
        assert result == 0x78563412

    def test_read_8_bytes(self):
        raw = b"\x01\x00\x00\x00\x02\x00\x00\x00"
        with mock.patch("d810.hexrays.table_utils.ida_bytes") as mb:
            mb.get_bytes = mock.Mock(return_value=raw)
            with mock.patch("d810.hexrays.table_utils._IDA_AVAILABLE", True):
                result = read_global_value(0x2000, 8)
        assert result == 0x0000000200000001

    def test_read_1_byte(self):
        raw = b"\xAB"
        with mock.patch("d810.hexrays.table_utils.ida_bytes") as mb:
            mb.get_bytes = mock.Mock(return_value=raw)
            with mock.patch("d810.hexrays.table_utils._IDA_AVAILABLE", True):
                result = read_global_value(0x3000, 1)
        assert result == 0xAB

    def test_read_2_bytes(self):
        raw = b"\xCD\xAB"
        with mock.patch("d810.hexrays.table_utils.ida_bytes") as mb:
            mb.get_bytes = mock.Mock(return_value=raw)
            with mock.patch("d810.hexrays.table_utils._IDA_AVAILABLE", True):
                result = read_global_value(0x4000, 2)
        assert result == 0xABCD

    def test_badaddr_returns_none(self):
        with mock.patch("d810.hexrays.table_utils._IDA_AVAILABLE", True):
            result = read_global_value(0xFFFFFFFFFFFFFFFF, 4)
        assert result is None

    def test_read_failure_returns_none(self):
        with mock.patch("d810.hexrays.table_utils.ida_bytes") as mb:
            mb.get_bytes = mock.Mock(return_value=None)
            with mock.patch("d810.hexrays.table_utils._IDA_AVAILABLE", True):
                result = read_global_value(0x5000, 4)
        assert result is None

    def test_short_read_returns_none(self):
        with mock.patch("d810.hexrays.table_utils.ida_bytes") as mb:
            mb.get_bytes = mock.Mock(return_value=b"\x01\x02")  # only 2 of 4
            with mock.patch("d810.hexrays.table_utils._IDA_AVAILABLE", True):
                result = read_global_value(0x6000, 4)
        assert result is None

    def test_no_ida_returns_none(self):
        with mock.patch("d810.hexrays.table_utils._IDA_AVAILABLE", False):
            result = read_global_value(0x7000, 4)
        assert result is None


# ===================================================================
# read_table_entries (mocked ida_bytes)
# ===================================================================
class TestReadTableEntries:
    def test_reads_all_entries(self):
        """Read 3 entries of 4 bytes each."""
        def fake_get_bytes(ea, size):
            table = {
                0x1000: b"\x01\x00\x00\x00",
                0x1004: b"\x02\x00\x00\x00",
                0x1008: b"\x03\x00\x00\x00",
            }
            return table.get(ea)

        with mock.patch("d810.hexrays.table_utils.ida_bytes") as mb:
            mb.get_bytes = mock.Mock(side_effect=fake_get_bytes)
            with mock.patch("d810.hexrays.table_utils._IDA_AVAILABLE", True):
                entries = read_table_entries(0x1000, 3, entry_size=4)

        assert entries == [1, 2, 3]

    def test_stops_on_read_failure(self):
        """Stop early when a read returns None."""
        call_count = 0

        def fake_get_bytes(ea, size):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return b"\xFF" * size
            return None

        with mock.patch("d810.hexrays.table_utils.ida_bytes") as mb:
            mb.get_bytes = mock.Mock(side_effect=fake_get_bytes)
            with mock.patch("d810.hexrays.table_utils._IDA_AVAILABLE", True):
                entries = read_table_entries(0x2000, 10, entry_size=8)

        assert len(entries) == 2

    def test_empty_on_immediate_failure(self):
        with mock.patch("d810.hexrays.table_utils.ida_bytes") as mb:
            mb.get_bytes = mock.Mock(return_value=None)
            with mock.patch("d810.hexrays.table_utils._IDA_AVAILABLE", True):
                entries = read_table_entries(0x3000, 5)
        assert entries == []


# ===================================================================
# validate_code_target (mocked ida_bytes)
# ===================================================================
class TestValidateCodeTarget:
    def test_is_code(self):
        with mock.patch("d810.hexrays.table_utils.ida_bytes") as mb:
            mb.get_flags = mock.Mock(return_value=0x600)
            mb.is_code = mock.Mock(return_value=True)
            with mock.patch("d810.hexrays.table_utils._IDA_AVAILABLE", True):
                assert validate_code_target(0x401000) is True

    def test_not_code_but_in_func(self):
        with mock.patch("d810.hexrays.table_utils.ida_bytes") as mb:
            mb.get_flags = mock.Mock(return_value=0)
            mb.is_code = mock.Mock(return_value=False)
            with mock.patch("d810.hexrays.table_utils._IDA_AVAILABLE", True):
                result = validate_code_target(0x401050, func_start=0x401000, func_end=0x402000)
        assert result is True

    def test_not_code_outside_func(self):
        with mock.patch("d810.hexrays.table_utils.ida_bytes") as mb:
            mb.get_flags = mock.Mock(return_value=0)
            mb.is_code = mock.Mock(return_value=False)
            with mock.patch("d810.hexrays.table_utils._IDA_AVAILABLE", True):
                result = validate_code_target(0x500000, func_start=0x401000, func_end=0x402000)
        assert result is False

    def test_no_func_bounds(self):
        with mock.patch("d810.hexrays.table_utils.ida_bytes") as mb:
            mb.get_flags = mock.Mock(return_value=0)
            mb.is_code = mock.Mock(return_value=False)
            with mock.patch("d810.hexrays.table_utils._IDA_AVAILABLE", True):
                result = validate_code_target(0x401000)
        assert result is False

    def test_no_ida(self):
        with mock.patch("d810.hexrays.table_utils._IDA_AVAILABLE", False):
            assert validate_code_target(0x401000) is False


# ===================================================================
# Mock microcode helpers
# ===================================================================

# Opcode and operand type accessors.
# These MUST be looked up dynamically from the current ida_hexrays module,
# because when IDA Pro is installed, pytest may collect test_pxd_equivalence.py
# which replaces the stub module with the real one during collection.
# Using lazy lookups ensures our mock objects use the same constant values
# the implementation sees at test execution time.

def _M_NOP(): return _get_ida_hexrays().m_nop  # noqa: E302
def _M_MOV(): return _get_ida_hexrays().m_mov  # noqa: E302
def _M_LDX(): return _get_ida_hexrays().m_ldx  # noqa: E302
def _M_XOR(): return _get_ida_hexrays().m_xor  # noqa: E302
def _M_NEG(): return _get_ida_hexrays().m_neg  # noqa: E302
def _M_ADD(): return _get_ida_hexrays().m_add  # noqa: E302

def _MOP_Z(): return _get_ida_hexrays().mop_z  # noqa: E302
def _MOP_R(): return _get_ida_hexrays().mop_r  # noqa: E302
def _MOP_N(): return _get_ida_hexrays().mop_n  # noqa: E302
def _MOP_V(): return _get_ida_hexrays().mop_v  # noqa: E302
def _MOP_A(): return _get_ida_hexrays().mop_a  # noqa: E302
def _MOP_D(): return _get_ida_hexrays().mop_d  # noqa: E302


class MockNnn:
    """Mock for mop_t.nnn -- an immediate number container."""
    def __init__(self, value: int):
        self.value = value


class MockMop:
    """Mock for mop_t -- a microcode operand.

    Supports register (mop_r), immediate (mop_n), global (mop_v),
    address (mop_a), and sub-instruction (mop_d) operand types.
    """
    def __init__(self, t: int = 0, *, r: int = 0, nnn: MockNnn = None,
                 g: int = 0, a=None, d=None):
        self.t = t
        self.r = r       # register number (for mop_r)
        self.nnn = nnn   # immediate value (for mop_n)
        self.g = g       # global EA (for mop_v)
        self.a = a       # nested operand (for mop_a)
        self.d = d       # sub-instruction (for mop_d)

    @classmethod
    def reg(cls, reg_num: int) -> "MockMop":
        return cls(t=_MOP_R(), r=reg_num)

    @classmethod
    def imm(cls, value: int) -> "MockMop":
        return cls(t=_MOP_N(), nnn=MockNnn(value))

    @classmethod
    def glob(cls, ea: int) -> "MockMop":
        return cls(t=_MOP_V(), g=ea)

    @classmethod
    def addr(cls, inner_mop: "MockMop") -> "MockMop":
        return cls(t=_MOP_A(), a=inner_mop)

    @classmethod
    def sub(cls, sub_ins: "MockInsn") -> "MockMop":
        return cls(t=_MOP_D(), d=sub_ins)


class MockInsn:
    """Mock for minsn_t -- a microcode instruction."""
    def __init__(self, opcode: int, l: MockMop = None, r: MockMop = None,
                 d: MockMop = None):
        self.opcode = opcode
        self.l = l or MockMop()
        self.r = r or MockMop()
        self.d = d or MockMop()
        self.next = None


def _make_instruction_chain(*instructions: MockInsn) -> MockInsn:
    """Link instructions into a forward-linked list (head->next->next...).

    Returns the head of the chain.
    """
    if not instructions:
        return None
    for i in range(len(instructions) - 1):
        instructions[i].next = instructions[i + 1]
    instructions[-1].next = None
    return instructions[0]


class MockBlock:
    """Mock for mblock_t -- a microcode basic block."""
    def __init__(self, head: MockInsn = None):
        self.head = head


# ===================================================================
# Issue B1: find_xor_with_globals tests
# ===================================================================
class TestFindXorWithGlobals:
    """Tests for find_xor_with_globals() -- Issue B1."""

    def test_empty_block_returns_empty_list(self):
        """An empty block (no instructions) should return no results."""
        blk = MockBlock(head=None)
        with _ida_available_ctx():
            result = find_xor_with_globals(blk)
        assert result == []

    def test_none_block_returns_empty_list(self):
        """None block should return empty list."""
        with _ida_available_ctx():
            result = find_xor_with_globals(None)
        assert result == []

    def test_no_ida_returns_empty_list(self):
        """Without IDA, should return empty list."""
        blk = MockBlock(head=None)
        with mock.patch("d810.hexrays.table_utils._IDA_AVAILABLE", False):
            result = find_xor_with_globals(blk)
        assert result == []

    def test_mov_immediate_to_register_tracking(self):
        """m_mov #imm -> reg should be tracked, but without XOR no results."""
        # mov #0xDEAD, r1
        ins = MockInsn(
            opcode=_M_MOV(),
            l=MockMop.imm(0xDEAD),
            d=MockMop.reg(1),
        )
        blk = MockBlock(head=_make_instruction_chain(ins))
        with _ida_available_ctx():
            result = find_xor_with_globals(blk)
        # No XOR instruction -> no results
        assert result == []

    def test_mov_global_to_register_tracking(self):
        """m_mov [global] -> reg should be tracked, but without XOR no results."""
        # mov [0x5000], r2
        ins = MockInsn(
            opcode=_M_MOV(),
            l=MockMop.glob(0x5000),
            d=MockMop.reg(2),
        )
        blk = MockBlock(head=_make_instruction_chain(ins))
        with _ida_available_ctx():
            result = find_xor_with_globals(blk)
        assert result == []

    def test_xor_immediate_and_global_direct(self):
        """m_xor #imm, global -> reg should detect XOR pattern.

        Pattern: xor #0xAA, [0x6000] -> r3
        Global at 0x6000 contains 0x55.
        Expected key: 0xAA ^ 0x55 = 0xFF
        """
        ins = MockInsn(
            opcode=_M_XOR(),
            l=MockMop.imm(0xAA),
            r=MockMop.glob(0x6000),
            d=MockMop.reg(3),
        )
        blk = MockBlock(head=_make_instruction_chain(ins))
        with _ida_available_ctx():
            with mock.patch("d810.hexrays.table_utils.ida_bytes") as mb:
                mb.get_bytes = mock.Mock(return_value=b"\x55\x00\x00\x00")
                result = find_xor_with_globals(blk)
        assert len(result) == 1
        assert result[0].xor_key == 0xAA ^ 0x55
        assert result[0].source_ea == 0x6000
        assert result[0].reg == 3
        assert result[0].is_negated is False

    def test_xor_global_and_immediate_direct(self):
        """m_xor global, #imm -> reg (reversed operand order)."""
        ins = MockInsn(
            opcode=_M_XOR(),
            l=MockMop.glob(0x7000),
            r=MockMop.imm(0xBB),
            d=MockMop.reg(4),
        )
        blk = MockBlock(head=_make_instruction_chain(ins))
        with _ida_available_ctx():
            with mock.patch("d810.hexrays.table_utils.ida_bytes") as mb:
                mb.get_bytes = mock.Mock(return_value=b"\x11\x00\x00\x00")
                result = find_xor_with_globals(blk)
        assert len(result) == 1
        assert result[0].xor_key == 0xBB ^ 0x11

    def test_xor_via_register_tracking(self):
        """mov #imm -> r1; mov [global] -> r2; xor r1, r2 -> r3.

        Registers r1 and r2 are tracked by the mov instructions, then the
        xor r1, r2 pattern should be detected.
        """
        mov_imm = MockInsn(
            opcode=_M_MOV(),
            l=MockMop.imm(0xCC),
            d=MockMop.reg(1),
        )
        mov_glob = MockInsn(
            opcode=_M_MOV(),
            l=MockMop.glob(0x8000),
            d=MockMop.reg(2),
        )
        xor_ins = MockInsn(
            opcode=_M_XOR(),
            l=MockMop.reg(1),  # holds immediate
            r=MockMop.reg(2),  # holds global
            d=MockMop.reg(3),
        )
        blk = MockBlock(head=_make_instruction_chain(mov_imm, mov_glob, xor_ins))
        with _ida_available_ctx():
            with mock.patch("d810.hexrays.table_utils.ida_bytes") as mb:
                mb.get_bytes = mock.Mock(return_value=b"\x33\x00\x00\x00")
                result = find_xor_with_globals(blk)
        assert len(result) == 1
        assert result[0].xor_key == 0xCC ^ 0x33
        assert result[0].reg == 3

    def test_neg_marks_value_as_negated(self):
        """m_neg after XOR should mark the result as negated.

        xor #0x10, [0x9000] -> r5  (global=0x20, key=0x10^0x20=0x30)
        neg r5 -> r5
        Expected: is_negated=True, key = (-0x30) & 0xFFFFFFFFFFFFFFFF
        """
        xor_ins = MockInsn(
            opcode=_M_XOR(),
            l=MockMop.imm(0x10),
            r=MockMop.glob(0x9000),
            d=MockMop.reg(5),
        )
        neg_ins = MockInsn(
            opcode=_M_NEG(),
            l=MockMop.reg(5),
            d=MockMop.reg(5),
        )
        blk = MockBlock(head=_make_instruction_chain(xor_ins, neg_ins))
        with _ida_available_ctx():
            with mock.patch("d810.hexrays.table_utils.ida_bytes") as mb:
                mb.get_bytes = mock.Mock(return_value=b"\x20\x00\x00\x00")
                result = find_xor_with_globals(blk)
        assert len(result) == 1
        assert result[0].is_negated is True
        original_key = 0x10 ^ 0x20
        expected_negated = (-original_key) & 0xFFFFFFFFFFFFFFFF
        assert result[0].xor_key == expected_negated

    def test_multiple_xor_operations(self):
        """Multiple XOR instructions should produce multiple results."""
        xor1 = MockInsn(
            opcode=_M_XOR(),
            l=MockMop.imm(0xAA),
            r=MockMop.glob(0xA000),
            d=MockMop.reg(1),
        )
        xor2 = MockInsn(
            opcode=_M_XOR(),
            l=MockMop.imm(0xBB),
            r=MockMop.glob(0xB000),
            d=MockMop.reg(2),
        )
        blk = MockBlock(head=_make_instruction_chain(xor1, xor2))
        with _ida_available_ctx():
            with mock.patch("d810.hexrays.table_utils.ida_bytes") as mb:
                def fake_get_bytes(ea, size):
                    if ea == 0xA000:
                        return b"\x11\x00\x00\x00"
                    elif ea == 0xB000:
                        return b"\x22\x00\x00\x00"
                    return None
                mb.get_bytes = mock.Mock(side_effect=fake_get_bytes)
                result = find_xor_with_globals(blk)
        assert len(result) == 2
        assert result[0].xor_key == 0xAA ^ 0x11
        assert result[0].source_ea == 0xA000
        assert result[1].xor_key == 0xBB ^ 0x22
        assert result[1].source_ea == 0xB000

    def test_register_invalidation_on_non_mov_xor_neg_write(self):
        """Writing to a register via an unrelated opcode should invalidate tracking.

        mov #0xCC -> r1; add r1, r1 -> r1; xor r1, [0xC000] -> r2
        The add to r1 should invalidate the immediate tracking, so
        the xor should NOT match.
        """
        mov_imm = MockInsn(
            opcode=_M_MOV(),
            l=MockMop.imm(0xCC),
            d=MockMop.reg(1),
        )
        # add r1, r1 -> r1 (modifies r1 without being mov/xor/neg)
        add_ins = MockInsn(
            opcode=_M_ADD(),
            l=MockMop.reg(1),
            r=MockMop.reg(1),
            d=MockMop.reg(1),
        )
        xor_ins = MockInsn(
            opcode=_M_XOR(),
            l=MockMop.reg(1),  # was invalidated by add
            r=MockMop.glob(0xC000),
            d=MockMop.reg(2),
        )
        blk = MockBlock(head=_make_instruction_chain(mov_imm, add_ins, xor_ins))
        with _ida_available_ctx():
            with mock.patch("d810.hexrays.table_utils.ida_bytes") as mb:
                mb.get_bytes = mock.Mock(return_value=b"\x44\x00\x00\x00")
                result = find_xor_with_globals(blk)
        # The register was invalidated, so the reg-reg XOR pattern should not match.
        # However, the xor has one operand as a direct global (mop_v on r),
        # but the left is mop_r without a tracked value -- so no match.
        assert result == []

    def test_xor_reg_holding_imm_with_direct_global(self):
        """xor reg(imm), global_operand -> should match directly.

        This tests the pattern: xor r1, [global] where r1 holds immediate
        and global is a direct mop_v operand.
        """
        mov_imm = MockInsn(
            opcode=_M_MOV(),
            l=MockMop.imm(0x42),
            d=MockMop.reg(7),
        )
        xor_ins = MockInsn(
            opcode=_M_XOR(),
            l=MockMop.reg(7),
            r=MockMop.glob(0xD000),
            d=MockMop.reg(8),
        )
        blk = MockBlock(head=_make_instruction_chain(mov_imm, xor_ins))
        with _ida_available_ctx():
            with mock.patch("d810.hexrays.table_utils.ida_bytes") as mb:
                mb.get_bytes = mock.Mock(return_value=b"\x24\x00\x00\x00")
                result = find_xor_with_globals(blk)
        assert len(result) == 1
        assert result[0].xor_key == 0x42 ^ 0x24


# ===================================================================
# Issue B2: analyze_table_encoding tests
# ===================================================================
class TestAnalyzeTableEncoding:
    """Tests for analyze_table_encoding() -- Issue B2."""

    def test_none_block_returns_direct(self):
        """None block should return (DIRECT, 0, 0)."""
        with _ida_available_ctx():
            result = analyze_table_encoding(None)
        assert result == (TableEncoding.DIRECT, 0, 0)

    def test_empty_block_returns_direct(self):
        """Block with no instructions should return (DIRECT, 0, 0)."""
        blk = MockBlock(head=None)
        with _ida_available_ctx():
            result = analyze_table_encoding(blk)
        assert result == (TableEncoding.DIRECT, 0, 0)

    def test_no_ida_returns_direct(self):
        """Without IDA, should return (DIRECT, 0, 0)."""
        blk = MockBlock(head=None)
        with mock.patch("d810.hexrays.table_utils._IDA_AVAILABLE", False):
            result = analyze_table_encoding(blk)
        assert result == (TableEncoding.DIRECT, 0, 0)

    def test_block_with_xor_constant_returns_xor_encoding(self):
        """Block with m_xor using immediate operand -> (XOR, key, 0)."""
        xor_ins = MockInsn(
            opcode=_M_XOR(),
            l=MockMop.imm(0xDEAD),
            r=MockMop.reg(1),
            d=MockMop.reg(2),
        )
        blk = MockBlock(head=_make_instruction_chain(xor_ins))
        with _ida_available_ctx():
            result = analyze_table_encoding(blk)
        assert result == (TableEncoding.XOR, 0xDEAD, 0)

    def test_block_with_xor_right_constant(self):
        """XOR with immediate on right operand."""
        xor_ins = MockInsn(
            opcode=_M_XOR(),
            l=MockMop.reg(1),
            r=MockMop.imm(0xBEEF),
            d=MockMop.reg(2),
        )
        blk = MockBlock(head=_make_instruction_chain(xor_ins))
        with _ida_available_ctx():
            result = analyze_table_encoding(blk)
        assert result == (TableEncoding.XOR, 0xBEEF, 0)

    def test_block_with_add_global_returns_offset_encoding(self):
        """Block with m_add using global operand -> (OFFSET, 0, base)."""
        add_ins = MockInsn(
            opcode=_M_ADD(),
            l=MockMop.glob(0x400000),
            r=MockMop.reg(1),
            d=MockMop.reg(2),
        )
        blk = MockBlock(head=_make_instruction_chain(add_ins))
        with _ida_available_ctx():
            result = analyze_table_encoding(blk)
        assert result == (TableEncoding.OFFSET, 0, 0x400000)

    def test_block_with_add_global_right(self):
        """ADD with global address on right operand."""
        add_ins = MockInsn(
            opcode=_M_ADD(),
            l=MockMop.reg(1),
            r=MockMop.glob(0x500000),
            d=MockMop.reg(2),
        )
        blk = MockBlock(head=_make_instruction_chain(add_ins))
        with _ida_available_ctx():
            result = analyze_table_encoding(blk)
        assert result == (TableEncoding.OFFSET, 0, 0x500000)

    def test_block_with_xor_and_add_returns_offset_xor(self):
        """Block with both XOR + ADD -> (OFFSET_XOR, key, base)."""
        xor_ins = MockInsn(
            opcode=_M_XOR(),
            l=MockMop.imm(0xCAFE),
            r=MockMop.reg(1),
            d=MockMop.reg(2),
        )
        add_ins = MockInsn(
            opcode=_M_ADD(),
            l=MockMop.glob(0x600000),
            r=MockMop.reg(2),
            d=MockMop.reg(3),
        )
        blk = MockBlock(head=_make_instruction_chain(xor_ins, add_ins))
        with _ida_available_ctx():
            result = analyze_table_encoding(blk)
        assert result == (TableEncoding.OFFSET_XOR, 0xCAFE, 0x600000)

    def test_block_with_neither_returns_direct(self):
        """Block with unrelated instructions -> (DIRECT, 0, 0)."""
        mov_ins = MockInsn(
            opcode=_M_MOV(),
            l=MockMop.imm(42),
            d=MockMop.reg(1),
        )
        blk = MockBlock(head=_make_instruction_chain(mov_ins))
        with _ida_available_ctx():
            result = analyze_table_encoding(blk)
        assert result == (TableEncoding.DIRECT, 0, 0)

    def test_xor_with_global_reads_value(self):
        """XOR with a global operand should read the global value as key."""
        xor_ins = MockInsn(
            opcode=_M_XOR(),
            l=MockMop.glob(0xE000),
            r=MockMop.reg(1),
            d=MockMop.reg(2),
        )
        blk = MockBlock(head=_make_instruction_chain(xor_ins))
        with _ida_available_ctx():
            with mock.patch("d810.hexrays.table_utils.ida_bytes") as mb:
                mb.get_bytes = mock.Mock(return_value=b"\x99\x00\x00\x00")
                result = analyze_table_encoding(blk)
        assert result == (TableEncoding.XOR, 0x99, 0)


# ===================================================================
# Issue B3: find_table_reference tests
# ===================================================================
class TestFindTableReference:
    """Tests for find_table_reference() -- Issue B3."""

    def test_none_block_returns_none(self):
        """None block should return None."""
        with _ida_available_ctx():
            result = find_table_reference(None)
        assert result is None

    def test_no_ida_returns_none(self):
        """Without IDA should return None."""
        blk = MockBlock(head=None)
        with mock.patch("d810.hexrays.table_utils._IDA_AVAILABLE", False):
            result = find_table_reference(blk)
        assert result is None

    def test_empty_block_returns_none(self):
        """Block with no instructions returns None."""
        blk = MockBlock(head=None)
        with _ida_available_ctx():
            result = find_table_reference(blk)
        assert result is None

    def test_no_ldx_returns_none(self):
        """Block without m_ldx returns None."""
        mov_ins = MockInsn(
            opcode=_M_MOV(),
            l=MockMop.imm(42),
            d=MockMop.reg(1),
        )
        blk = MockBlock(head=_make_instruction_chain(mov_ins))
        with _ida_available_ctx():
            result = find_table_reference(blk)
        assert result is None

    def test_ldx_with_direct_global_left(self):
        """m_ldx with global address as left operand -> returns EA."""
        ldx_ins = MockInsn(
            opcode=_M_LDX(),
            l=MockMop.glob(0x401000),
            r=MockMop.reg(1),
            d=MockMop.reg(2),
        )
        blk = MockBlock(head=_make_instruction_chain(ldx_ins))
        with _ida_available_ctx():
            result = find_table_reference(blk)
        assert result == 0x401000

    def test_ldx_with_nested_add_left_global(self):
        """m_ldx with nested add instruction containing global on left."""
        # sub-instruction: add [0x500000], r3 -> (result)
        sub_add = MockInsn(
            opcode=_M_ADD(),
            l=MockMop.glob(0x500000),
            r=MockMop.reg(3),
            d=MockMop.reg(4),
        )
        ldx_ins = MockInsn(
            opcode=_M_LDX(),
            l=MockMop.sub(sub_add),
            r=MockMop.reg(1),
            d=MockMop.reg(2),
        )
        blk = MockBlock(head=_make_instruction_chain(ldx_ins))
        with _ida_available_ctx():
            result = find_table_reference(blk)
        assert result == 0x500000

    def test_ldx_with_nested_add_right_global(self):
        """m_ldx with nested add instruction containing global on right."""
        sub_add = MockInsn(
            opcode=_M_ADD(),
            l=MockMop.reg(3),
            r=MockMop.glob(0x600000),
            d=MockMop.reg(4),
        )
        ldx_ins = MockInsn(
            opcode=_M_LDX(),
            l=MockMop.sub(sub_add),
            r=MockMop.reg(1),
            d=MockMop.reg(2),
        )
        blk = MockBlock(head=_make_instruction_chain(ldx_ins))
        with _ida_available_ctx():
            result = find_table_reference(blk)
        assert result == 0x600000

    def test_ldx_with_right_global(self):
        """m_ldx with global as right operand -> returns EA."""
        ldx_ins = MockInsn(
            opcode=_M_LDX(),
            l=MockMop.reg(1),
            r=MockMop.glob(0x700000),
            d=MockMop.reg(2),
        )
        blk = MockBlock(head=_make_instruction_chain(ldx_ins))
        with _ida_available_ctx():
            result = find_table_reference(blk)
        assert result == 0x700000


# ===================================================================
# Issue D9: decode_table_entry overflow tests
# ===================================================================
class TestDecodeTableEntryOverflow:
    """Tests for decode_table_entry with large / overflow values -- Issue D9."""

    def test_offset_64bit_overflow(self):
        """OFFSET encoding with values that overflow 64 bits.

        Python ints do not overflow, so base + raw_value may exceed 2**64.
        Document whether truncation happens (currently: it does NOT).
        """
        raw = 0xFFFFFFFFFFFFFFFF
        base = 1
        result = decode_table_entry(raw, TableEncoding.OFFSET, base=base)
        # Python integer arithmetic: no truncation, result > 2**64
        assert result == 0xFFFFFFFFFFFFFFFF + 1
        assert result == 2**64

    def test_large_xor_key(self):
        """XOR with maximum 64-bit key."""
        raw = 0x0000000000000001
        key = 0xFFFFFFFFFFFFFFFF
        result = decode_table_entry(raw, TableEncoding.XOR, key=key)
        assert result == raw ^ key
        assert result == 0xFFFFFFFFFFFFFFFE

    def test_offset_xor_large_values(self):
        """OFFSET_XOR with large values that may overflow."""
        raw = 0xFFFFFFFFFFFFFFFF
        key = 0xFFFFFFFFFFFFFFFF
        base = 0x1000
        result = decode_table_entry(raw, TableEncoding.OFFSET_XOR, key=key, base=base)
        # raw ^ key = 0, so result = base + 0 = 0x1000
        assert result == 0x1000

    def test_offset_xor_no_truncation(self):
        """Verify Python int semantics: no 64-bit truncation in OFFSET_XOR."""
        raw = 0xFFFFFFFFFFFFFFFE
        key = 0x0000000000000001
        base = 0xFFFFFFFFFFFFFFFF
        # raw ^ key = 0xFFFFFFFFFFFFFFFF
        # result = base + 0xFFFFFFFFFFFFFFFF
        result = decode_table_entry(raw, TableEncoding.OFFSET_XOR, key=key, base=base)
        expected = 0xFFFFFFFFFFFFFFFF + 0xFFFFFFFFFFFFFFFF
        assert result == expected
        # This is 2 * (2^64 - 1) which exceeds 64 bits
        assert result > 2**64


# ===================================================================
# Issue D10: validate_code_target boundary tests
# ===================================================================
class TestValidateCodeTargetBoundaries:
    """Tests for validate_code_target boundary conditions -- Issue D10."""

    def test_ea_equals_func_end_is_false(self):
        """ea == func_end should be False (half-open range [start, end))."""
        with mock.patch("d810.hexrays.table_utils.ida_bytes") as mb:
            mb.get_flags = mock.Mock(return_value=0)
            mb.is_code = mock.Mock(return_value=False)
            with mock.patch("d810.hexrays.table_utils._IDA_AVAILABLE", True):
                result = validate_code_target(
                    0x402000,
                    func_start=0x401000,
                    func_end=0x402000,
                )
        assert result is False

    def test_ea_equals_func_start_is_true(self):
        """ea == func_start should be True (inclusive lower bound)."""
        with mock.patch("d810.hexrays.table_utils.ida_bytes") as mb:
            mb.get_flags = mock.Mock(return_value=0)
            mb.is_code = mock.Mock(return_value=False)
            with mock.patch("d810.hexrays.table_utils._IDA_AVAILABLE", True):
                result = validate_code_target(
                    0x401000,
                    func_start=0x401000,
                    func_end=0x402000,
                )
        assert result is True

    def test_func_start_zero_func_end_zero_no_bounds_check(self):
        """When func_start=0 and func_end=0, no bounds check is performed.

        The function should rely only on is_code(), which returns False here.
        """
        with mock.patch("d810.hexrays.table_utils.ida_bytes") as mb:
            mb.get_flags = mock.Mock(return_value=0)
            mb.is_code = mock.Mock(return_value=False)
            with mock.patch("d810.hexrays.table_utils._IDA_AVAILABLE", True):
                result = validate_code_target(0x401000, func_start=0, func_end=0)
        assert result is False

    def test_ea_one_before_func_end_is_true(self):
        """ea == func_end - 1 should be True."""
        with mock.patch("d810.hexrays.table_utils.ida_bytes") as mb:
            mb.get_flags = mock.Mock(return_value=0)
            mb.is_code = mock.Mock(return_value=False)
            with mock.patch("d810.hexrays.table_utils._IDA_AVAILABLE", True):
                result = validate_code_target(
                    0x401FFF,
                    func_start=0x401000,
                    func_end=0x402000,
                )
        assert result is True
