"""Unit tests for opaque table folding -- making MopTracker resolve mop_v globals.

The hardened OLLVM pattern computes state transitions like:

    state = (g_opaque_table[N] ^ K1) + K2

where g_opaque_table is a volatile DWORD array in a writable .data segment.
MopTracker backward search hits these mop_v (global variable) operands and
marks them as memory_unresolved_ins_mops, causing is_resolved() to return
False.

These tests verify:
1. fetch_idb_value reads concrete values from IDB
2. MopTracker can auto-resolve mop_v operands via try_resolve_memory_mops
3. Emulator eval() reads mop_v from writable segments with no write xrefs
4. FoldReadonlyDataRule with fold_writable_constants=True folds such globals

These tests do NOT require IDA Pro -- all IDA types are mocked.
"""
from __future__ import annotations

import pathlib
import sys
import types
from unittest import mock
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Ensure the project src/ is on sys.path.
# ---------------------------------------------------------------------------
_PROJECT_SRC = str(pathlib.Path(__file__).resolve().parents[3] / "src")
if _PROJECT_SRC not in sys.path:
    sys.path.insert(0, _PROJECT_SRC)


# ---------------------------------------------------------------------------
# Build a strict mock for ida_hexrays that controls dir() output.
# This follows the pattern from test_block_merge.py.
# hexrays_helpers.py iterates dir(ida_hexrays) looking for attributes
# prefixed with MMAT_, m_, mop_ and uses them as dict keys at module level.
# MagicMock auto-creates attributes on access, so we need __dir__ to return
# only the names we explicitly set.
# ---------------------------------------------------------------------------

def _build_ida_hexrays_mock() -> MagicMock:
    """Return a MagicMock for ida_hexrays with ALL required constants."""
    # Opcode constants -- every opcode referenced by OPCODES_INFO in hexrays_helpers.py
    opcodes = {
        "m_nop": 0x00, "m_stx": 0x01, "m_ldx": 0x02, "m_ldc": 0x03,
        "m_mov": 0x04, "m_neg": 0x05, "m_lnot": 0x06, "m_bnot": 0x07,
        "m_xds": 0x08, "m_xdu": 0x09, "m_low": 0x0A, "m_high": 0x0B,
        "m_add": 0x0C, "m_sub": 0x0D, "m_mul": 0x0E,
        "m_udiv": 0x0F, "m_sdiv": 0x10, "m_umod": 0x11, "m_smod": 0x12,
        "m_or": 0x13, "m_and": 0x14, "m_xor": 0x15,
        "m_shl": 0x16, "m_shr": 0x17, "m_sar": 0x18,
        "m_cfadd": 0x19, "m_ofadd": 0x1A,
        "m_cfshl": 0x1B, "m_cfshr": 0x1C,
        "m_sets": 0x1D, "m_seto": 0x1E, "m_setp": 0x1F,
        "m_setnz": 0x20, "m_setz": 0x21,
        "m_seta": 0x22, "m_setae": 0x23, "m_setb": 0x24, "m_setbe": 0x25,
        "m_setg": 0x26, "m_setge": 0x27, "m_setl": 0x28, "m_setle": 0x29,
        "m_jcnd": 0x30, "m_jnz": 0x31, "m_jz": 0x32,
        "m_jae": 0x33, "m_jb": 0x34, "m_ja": 0x35, "m_jbe": 0x36,
        "m_jg": 0x37, "m_jge": 0x38, "m_jl": 0x39, "m_jle": 0x3A,
        "m_jtbl": 0x3B, "m_ijmp": 0x3C,
        "m_goto": 0x40, "m_call": 0x41, "m_icall": 0x42,
        "m_ret": 0x43, "m_push": 0x44, "m_pop": 0x45,
        "m_und": 0x46, "m_ext": 0x47,
        "m_f2i": 0x48, "m_f2u": 0x49, "m_i2f": 0x4A, "m_u2f": 0x4B,
        "m_f2f": 0x4C, "m_fneg": 0x4D, "m_fadd": 0x4E, "m_fsub": 0x4F,
        "m_fmul": 0x50, "m_fdiv": 0x51,
    }

    # Operand type constants
    mop_types = {
        "mop_z": 0, "mop_r": 1, "mop_n": 2, "mop_str": 3,
        "mop_d": 4, "mop_S": 5, "mop_v": 6, "mop_b": 7,
        "mop_f": 8, "mop_l": 9, "mop_a": 10, "mop_h": 11,
        "mop_c": 12, "mop_fn": 13, "mop_p": 14, "mop_sc": 15,
    }

    # Maturity levels
    maturities = {
        "MMAT_ZERO": 0,
        "MMAT_GENERATED": 10,
        "MMAT_PREOPTIMIZED": 15,
        "MMAT_LOCOPT": 20,
        "MMAT_CALLS": 25,
        "MMAT_GLBOPT1": 30,
        "MMAT_GLBOPT2": 35,
        "MMAT_GLBOPT3": 40,
        "MMAT_LVARS": 45,
    }

    # Access flags
    access_flags = {
        "MUST_ACCESS": 1,
        "MAY_ACCESS": 2,
        "FULL_XDSU": 4,
    }

    # Block type constants
    block_types = {
        "BLT_NONE": 0, "BLT_STOP": 1, "BLT_0WAY": 2,
        "BLT_1WAY": 3, "BLT_2WAY": 4, "BLT_NWAY": 5, "BLT_XTRN": 6,
    }

    attrs: dict[str, object] = {}
    attrs.update(opcodes)
    attrs.update(mop_types)
    attrs.update(maturities)
    attrs.update(access_flags)
    attrs.update(block_types)

    mock_mod = MagicMock()
    for name, value in attrs.items():
        setattr(mock_mod, name, value)

    # Override __dir__ so dir(ida_hexrays) only returns our attrs
    all_attr_names = list(attrs.keys())

    # is_mcode_jcond stub
    jcond_set = {
        opcodes["m_jcnd"], opcodes["m_jnz"], opcodes["m_jz"],
        opcodes["m_jae"], opcodes["m_jb"], opcodes["m_ja"], opcodes["m_jbe"],
        opcodes["m_jg"], opcodes["m_jge"], opcodes["m_jl"], opcodes["m_jle"],
    }
    mock_mod.is_mcode_jcond = lambda op: op in jcond_set
    mock_mod.get_mreg_name = MagicMock(return_value="eax")

    # Create real classes for isinstance / type checks
    _mop_v_val = mop_types["mop_v"]
    _mop_z_val = mop_types["mop_z"]
    _mop_n_val = mop_types["mop_n"]
    _mop_S_val = mop_types["mop_S"]
    _mop_r_val = mop_types["mop_r"]

    class _mock_mop_t:
        def __init__(self, other=None):
            self.t = _mop_z_val
            self.size = 0
            self.g = 0
            self.r = 0
            self.nnn = None
            self.d = None
            self.a = None
            self.s = None
            self.b = 0
            self.helper = ""
            if other is not None:
                self.assign(other)

        def erase(self):
            self.t = _mop_z_val
            self.size = 0

        def assign(self, other):
            self.t = other.t
            self.size = other.size
            self.g = getattr(other, 'g', 0)
            self.r = getattr(other, 'r', 0)
            self.nnn = getattr(other, 'nnn', None)
            self.d = getattr(other, 'd', None)
            self.a = getattr(other, 'a', None)
            self.s = getattr(other, 's', None)
            self.b = getattr(other, 'b', 0)
            self.helper = getattr(other, 'helper', "")

        def make_number(self, value, size):
            self.t = _mop_n_val
            self.size = size
            self.nnn = types.SimpleNamespace(value=value)

        def _make_stkvar(self, mba, offset):
            self.t = _mop_S_val
            self.s = types.SimpleNamespace(off=offset, start_ea=offset)

    class _mock_mop_visitor_t:
        def __init__(self):
            pass
        def visit_mop(self, op, op_type, is_target):
            return 0

    class _mock_minsn_t:
        def __init__(self, ea=0):
            self.ea = ea
            self.opcode = opcodes["m_nop"]
            self.l = _mock_mop_t()
            self.r = _mock_mop_t()
            self.d = _mock_mop_t()
            self.next = None
            self.prev = None

        def for_all_ops(self, visitor):
            pass

    class _mock_mlist_t:
        def __init__(self):
            self._items = []
        def has_common(self, other):
            return False

    class _mock_mblock_t:
        def __init__(self, serial=0):
            self.serial = serial
            self.head = None
            self.tail = None
            self.mba = None
            self.nextb = None
            self.predset = []
        def npred(self):
            return len(self.predset)
        def nsucc(self):
            return 0
        def append_use_list(self, ml, mop, access_type):
            pass
        def build_def_list(self, ins, flags):
            return _mock_mlist_t()

    class _mock_mba_t:
        def __init__(self):
            self._blocks = {}
        def get_mblock(self, serial):
            return self._blocks.get(serial)

    mock_mod.mop_t = _mock_mop_t
    mock_mod.mop_visitor_t = _mock_mop_visitor_t
    mock_mod.minsn_t = _mock_minsn_t
    mock_mod.mlist_t = _mock_mlist_t
    mock_mod.mblock_t = _mock_mblock_t
    mock_mod.mba_t = _mock_mba_t

    # Add class names to __dir__
    class_names = ["mop_t", "mop_visitor_t", "minsn_t", "mlist_t", "mblock_t", "mba_t",
                   "is_mcode_jcond", "get_mreg_name"]
    all_attr_names += class_names
    mock_mod.__dir__ = lambda self=None: all_attr_names  # noqa: ARG005

    return mock_mod


@pytest.fixture(scope="module", autouse=True)
def _mock_ida_modules():
    """Inject mock IDA modules so we can import d810 modules without IDA.

    Follows the same pattern as test_block_merge.py: snapshot all modules,
    inject mocks, evict cached d810 modules, and restore on teardown.
    """
    mock_ida_hexrays = _build_ida_hexrays_mock()

    # Other IDA modules that d810 may import transitively
    mock_idc = MagicMock()
    mock_idaapi = MagicMock()
    # Set up idaapi constants needed by emulator.py and ida_utils.py
    mock_idaapi.SEGPERM_READ = 4
    mock_idaapi.SEGPERM_WRITE = 2
    mock_idaapi.SEGPERM_EXEC = 1
    mock_idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    mock_idaapi.getseg = MagicMock(return_value=None)
    mock_idaapi.get_byte = MagicMock(return_value=0)
    mock_idaapi.get_word = MagicMock(return_value=0)
    mock_idaapi.get_dword = MagicMock(return_value=0)
    mock_idaapi.get_qword = MagicMock(return_value=0)
    mock_idaapi.is_loaded = MagicMock(return_value=False)
    mock_idaapi.XREF_DATA = 1
    mock_idaapi.dr_W = 2
    mock_idaapi.segment_t = type("segment_t", (), {})

    class _xrefblk_t:
        type = 0
        def first_to(self, addr, flags):
            return False
        def next_to(self):
            return False
    mock_idaapi.xrefblk_t = _xrefblk_t

    mock_ida_kernwin = MagicMock()
    mock_ida_diskio = MagicMock()
    mock_ida_diskio.get_user_idadir.return_value = "/tmp/mock_idadir"
    mock_ida_segment = MagicMock()
    mock_ida_segment.getseg = MagicMock(return_value=None)

    modules_to_mock = {
        "ida_hexrays": mock_ida_hexrays,
        "idc": mock_idc,
        "idaapi": mock_idaapi,
        "ida_kernwin": mock_ida_kernwin,
        "ida_diskio": mock_ida_diskio,
        "ida_segment": mock_ida_segment,
    }

    # Snapshot the complete set of IDA + d810 modules before we touch anything.
    saved: dict[str, types.ModuleType | None] = {}
    for name in list(sys.modules):
        if name in modules_to_mock or name == "d810" or name.startswith("d810."):
            saved[name] = sys.modules.get(name)

    # Inject mocks
    for name, mock_mod in modules_to_mock.items():
        sys.modules[name] = mock_mod

    # Evict cached d810 modules so they re-import with the mocked IDA stubs.
    for mod_name in sorted(sys.modules, reverse=True):
        if mod_name == "d810" or mod_name.startswith("d810."):
            del sys.modules[mod_name]

    yield {
        "ida_hexrays": mock_ida_hexrays,
        "idaapi": mock_idaapi,
        "ida_segment": mock_ida_segment,
    }

    # --- Teardown: restore the pre-fixture module state exactly. ---

    # 1. Remove any d810 modules that were (re-)imported during the tests.
    for mod_name in sorted(sys.modules, reverse=True):
        if mod_name == "d810" or mod_name.startswith("d810."):
            del sys.modules[mod_name]

    # 2. Restore every saved entry (IDA stubs + d810 modules).
    for name, orig in saved.items():
        if orig is not None:
            sys.modules[name] = orig
        else:
            sys.modules.pop(name, None)


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------

def _make_mop_v(address: int, size: int = 4):
    """Create a mop_v (global variable) operand."""
    import ida_hexrays
    mop = ida_hexrays.mop_t()
    mop.t = ida_hexrays.mop_v
    mop.g = address
    mop.size = size
    return mop


def _make_mop_n(value: int, size: int = 4):
    """Create a mop_n (constant) operand."""
    import ida_hexrays
    mop = ida_hexrays.mop_t()
    mop.make_number(value, size)
    return mop


def _make_mop_r(reg: int, size: int = 4):
    """Create a mop_r (register) operand."""
    import ida_hexrays
    mop = ida_hexrays.mop_t()
    mop.t = ida_hexrays.mop_r
    mop.r = reg
    mop.size = size
    return mop


def _make_segment(perm: int):
    """Create a mock segment with given permissions."""
    return types.SimpleNamespace(perm=perm)


# ===================================================================
# Test: fetch_idb_value reads concrete values
# ===================================================================
class TestFetchIdbValue:
    """Test that fetch_idb_value reads correct sized values."""

    def test_read_4_bytes(self, _mock_ida_modules):
        from d810.expr.emulator import fetch_idb_value
        with mock.patch("d810.expr.emulator.idaapi") as m_idaapi:
            m_idaapi.get_dword = mock.Mock(return_value=0xDEADBEEF)
            result = fetch_idb_value(0x1000, 4)
        assert result == 0xDEADBEEF

    def test_read_1_byte(self, _mock_ida_modules):
        from d810.expr.emulator import fetch_idb_value
        with mock.patch("d810.expr.emulator.idaapi") as m_idaapi:
            m_idaapi.get_byte = mock.Mock(return_value=0xAB)
            result = fetch_idb_value(0x1000, 1)
        assert result == 0xAB

    def test_read_2_bytes(self, _mock_ida_modules):
        from d810.expr.emulator import fetch_idb_value
        with mock.patch("d810.expr.emulator.idaapi") as m_idaapi:
            m_idaapi.get_word = mock.Mock(return_value=0xBEEF)
            result = fetch_idb_value(0x1000, 2)
        assert result == 0xBEEF

    def test_read_8_bytes(self, _mock_ida_modules):
        from d810.expr.emulator import fetch_idb_value
        with mock.patch("d810.expr.emulator.idaapi") as m_idaapi:
            m_idaapi.get_qword = mock.Mock(return_value=0x123456789ABCDEF0)
            result = fetch_idb_value(0x1000, 8)
        assert result == 0x123456789ABCDEF0

    def test_unsupported_size_returns_none(self, _mock_ida_modules):
        from d810.expr.emulator import fetch_idb_value
        result = fetch_idb_value(0x1000, 3)
        assert result is None

    def test_zero_size_returns_none(self, _mock_ida_modules):
        from d810.expr.emulator import fetch_idb_value
        result = fetch_idb_value(0x1000, 0)
        assert result is None

    def test_negative_size_returns_none(self, _mock_ida_modules):
        from d810.expr.emulator import fetch_idb_value
        result = fetch_idb_value(0x1000, -1)
        assert result is None


# ===================================================================
# Test: Emulator reads mop_v from writable segment with no write xrefs
# ===================================================================
class TestEmulatorMopVWritableNoXrefs:
    """Test that MicroCodeInterpreter.eval() reads mop_v from writable
    segments when is_never_written_var() returns True.
    """

    def test_eval_mop_v_readonly_segment(self, _mock_ida_modules):
        """mop_v in a readonly segment should be read from IDB."""
        from d810.expr.emulator import MicroCodeEnvironment, MicroCodeInterpreter

        mop = _make_mop_v(0x401000, size=4)
        ro_seg = _make_segment(perm=4)  # SEGPERM_READ only

        interp = MicroCodeInterpreter()
        env = MicroCodeEnvironment()

        with mock.patch("d810.expr.emulator.idaapi") as m_idaapi:
            m_idaapi.getseg = mock.Mock(return_value=ro_seg)
            m_idaapi.SEGPERM_WRITE = 2
            m_idaapi.get_qword = mock.Mock(return_value=0xCAFEBABE)
            result = interp.eval(mop, env)

        assert result == 0xCAFEBABE & 0xFFFFFFFF

    def test_eval_mop_v_writable_never_written(self, _mock_ida_modules):
        """mop_v in a writable segment with no write xrefs should be read."""
        from d810.expr.emulator import MicroCodeEnvironment, MicroCodeInterpreter

        mop = _make_mop_v(0x601000, size=4)
        wr_seg = _make_segment(perm=6)  # SEGPERM_READ | SEGPERM_WRITE

        interp = MicroCodeInterpreter()
        env = MicroCodeEnvironment()

        with mock.patch("d810.expr.emulator.idaapi") as m_idaapi, \
             mock.patch("d810.expr.emulator.is_never_written_var") as m_inw:
            m_idaapi.getseg = mock.Mock(return_value=wr_seg)
            m_idaapi.SEGPERM_WRITE = 2
            m_inw.return_value = True
            m_idaapi.get_dword = mock.Mock(return_value=0x12345678)
            result = interp.eval(mop, env)

        assert result == 0x12345678

    def test_eval_mop_v_writable_has_write_xrefs_raises(self, _mock_ida_modules):
        """mop_v in a writable segment WITH write xrefs should raise."""
        from d810.errors import EmulationException
        from d810.expr.emulator import MicroCodeEnvironment, MicroCodeInterpreter

        mop = _make_mop_v(0x601000, size=4)
        wr_seg = _make_segment(perm=6)  # SEGPERM_READ | SEGPERM_WRITE

        interp = MicroCodeInterpreter()
        env = MicroCodeEnvironment()

        with mock.patch("d810.expr.emulator.idaapi") as m_idaapi, \
             mock.patch("d810.expr.emulator.is_never_written_var") as m_inw:
            m_idaapi.getseg = mock.Mock(return_value=wr_seg)
            m_idaapi.SEGPERM_WRITE = 2
            m_inw.return_value = False  # Has write xrefs
            with pytest.raises(EmulationException):
                interp.eval(mop, env)


# ===================================================================
# Test: MopTracker resolves mop_v globals concretely
# ===================================================================
class TestMopTrackerResolvesGlobals:
    """Test that MopTracker.try_resolve_memory_mops() resolves
    mop_v operands by reading concrete values from the IDB.
    """

    def test_tracker_with_only_memory_unresolved_is_not_resolved(self, _mock_ida_modules):
        """A tracker with only memory_unresolved_mops should NOT be resolved."""
        from d810.hexrays.tracker import MopTracker

        mop = _make_mop_v(0x601000, size=4)
        tracker = MopTracker([mop])
        assert len(tracker._memory_unresolved_mops) == 1
        assert len(tracker._unresolved_mops) == 0
        assert tracker.is_resolved() is False

    def test_tracker_try_resolve_memory_mops_readonly(self, _mock_ida_modules):
        """After try_resolve_memory_mops, mop_v in a readonly segment
        should be resolved.
        """
        from d810.hexrays.tracker import MopTracker

        mop = _make_mop_v(0x401000, size=4)
        tracker = MopTracker([mop])
        assert tracker.is_resolved() is False

        ro_seg = _make_segment(perm=4)  # SEGPERM_READ only

        with mock.patch("d810.hexrays.tracker.idaapi") as m_idaapi, \
             mock.patch("d810.hexrays.tracker.is_never_written_var") as m_inw, \
             mock.patch("d810.hexrays.tracker.fetch_idb_value") as m_fetch:
            m_idaapi.getseg = mock.Mock(return_value=ro_seg)
            m_idaapi.SEGPERM_WRITE = 2
            m_fetch.return_value = 0xDEADBEEF
            m_inw.return_value = True

            tracker.try_resolve_memory_mops()

        assert tracker.is_resolved() is True
        assert len(tracker._memory_unresolved_mops) == 0

    def test_tracker_try_resolve_memory_mops_writable_no_xrefs(self, _mock_ida_modules):
        """After try_resolve_memory_mops, mop_v in a writable segment
        with no write xrefs should be resolved.
        """
        from d810.hexrays.tracker import MopTracker

        mop = _make_mop_v(0x601000, size=4)
        tracker = MopTracker([mop])
        assert tracker.is_resolved() is False

        wr_seg = _make_segment(perm=6)  # SEGPERM_READ | SEGPERM_WRITE

        with mock.patch("d810.hexrays.tracker.idaapi") as m_idaapi, \
             mock.patch("d810.hexrays.tracker.is_never_written_var") as m_inw, \
             mock.patch("d810.hexrays.tracker.fetch_idb_value") as m_fetch:
            m_idaapi.getseg = mock.Mock(return_value=wr_seg)
            m_idaapi.SEGPERM_WRITE = 2
            m_fetch.return_value = 0x12345678
            m_inw.return_value = True  # Never written

            tracker.try_resolve_memory_mops()

        assert tracker.is_resolved() is True
        assert len(tracker._memory_unresolved_mops) == 0

    def test_tracker_try_resolve_memory_mops_writable_has_xrefs(self, _mock_ida_modules):
        """mop_v in a writable segment WITH write xrefs stays unresolved."""
        from d810.hexrays.tracker import MopTracker

        mop = _make_mop_v(0x601000, size=4)
        tracker = MopTracker([mop])
        assert tracker.is_resolved() is False

        wr_seg = _make_segment(perm=6)  # SEGPERM_READ | SEGPERM_WRITE

        with mock.patch("d810.hexrays.tracker.idaapi") as m_idaapi, \
             mock.patch("d810.hexrays.tracker.is_never_written_var") as m_inw:
            m_idaapi.getseg = mock.Mock(return_value=wr_seg)
            m_idaapi.SEGPERM_WRITE = 2
            m_inw.return_value = False  # Has write xrefs

            tracker.try_resolve_memory_mops()

        assert tracker.is_resolved() is False
        assert len(tracker._memory_unresolved_mops) == 1

    def test_tracker_try_resolve_multiple_mops(self, _mock_ida_modules):
        """Multiple mop_v operands: some resolve, some don't."""
        from d810.hexrays.tracker import MopTracker

        mop_a = _make_mop_v(0x601000, size=4)  # resolvable
        mop_b = _make_mop_v(0x601004, size=4)  # not resolvable (has xrefs)
        mop_c = _make_mop_v(0x401000, size=4)  # resolvable (readonly)

        tracker = MopTracker([mop_a, mop_b, mop_c])
        assert len(tracker._memory_unresolved_mops) == 3

        ro_seg = _make_segment(perm=4)
        wr_seg = _make_segment(perm=6)

        def fake_getseg(addr):
            if addr == 0x401000:
                return ro_seg
            return wr_seg

        def fake_is_never_written(addr):
            if addr == 0x601004:
                return False  # This one has write xrefs
            return True

        def fake_fetch(addr, size):
            return {0x601000: 0xAAAA, 0x401000: 0xBBBB}.get(addr, 0)

        with mock.patch("d810.hexrays.tracker.idaapi") as m_idaapi, \
             mock.patch("d810.hexrays.tracker.is_never_written_var") as m_inw, \
             mock.patch("d810.hexrays.tracker.fetch_idb_value") as m_fetch:
            m_idaapi.getseg = mock.Mock(side_effect=fake_getseg)
            m_idaapi.SEGPERM_WRITE = 2
            m_fetch.side_effect = fake_fetch
            m_inw.side_effect = fake_is_never_written

            tracker.try_resolve_memory_mops()

        # Only mop_b (0x601004) should remain unresolved
        assert len(tracker._memory_unresolved_mops) == 1
        assert tracker._memory_unresolved_mops[0].g == 0x601004
        assert tracker.is_resolved() is False


# ===================================================================
# Test: FoldReadonlyDataRule with fold_writable_constants
# ===================================================================
class TestFoldReadonlyDataRuleWritableConstants:
    """Test that FoldReadonlyDataRule._is_foldable_address() returns True
    for writable segments when fold_writable_constants is enabled.
    """

    def test_foldable_when_fold_writable_enabled_and_no_xrefs(self, _mock_ida_modules):
        """With fold_writable_constants=True and no write xrefs,
        a writable address should be foldable.
        """
        from d810.optimizers.microcode.instructions.peephole.fold_readonlydata import (
            FoldReadonlyDataRule,
        )

        rule = FoldReadonlyDataRule()
        rule._fold_writable_constants = True

        wr_seg = _make_segment(perm=6)

        with mock.patch(
            "d810.optimizers.microcode.instructions.peephole.fold_readonlydata.ida_segment"
        ) as m_seg, \
             mock.patch(
            "d810.optimizers.microcode.instructions.peephole.fold_readonlydata.is_never_written_var"
        ) as m_inw, \
             mock.patch(
            "d810.optimizers.microcode.instructions.peephole.fold_readonlydata.idaapi"
        ) as m_idaapi:
            m_seg.getseg = mock.Mock(return_value=wr_seg)
            m_idaapi.SEGPERM_READ = 4
            m_idaapi.SEGPERM_WRITE = 2
            m_idaapi.SEGPERM_EXEC = 1
            m_inw.return_value = True

            assert rule._is_foldable_address(0x601000) is True

    def test_not_foldable_when_fold_writable_disabled(self, _mock_ida_modules):
        """With fold_writable_constants=False, writable addresses
        should NOT be foldable even without write xrefs.
        """
        from d810.optimizers.microcode.instructions.peephole.fold_readonlydata import (
            FoldReadonlyDataRule,
        )

        rule = FoldReadonlyDataRule()
        rule._fold_writable_constants = False

        wr_seg = _make_segment(perm=6)

        with mock.patch(
            "d810.optimizers.microcode.instructions.peephole.fold_readonlydata.ida_segment"
        ) as m_seg, \
             mock.patch(
            "d810.optimizers.microcode.instructions.peephole.fold_readonlydata.idaapi"
        ) as m_idaapi:
            m_seg.getseg = mock.Mock(return_value=wr_seg)
            m_idaapi.SEGPERM_READ = 4
            m_idaapi.SEGPERM_WRITE = 2
            m_idaapi.SEGPERM_EXEC = 1

            assert rule._is_foldable_address(0x601000) is False

    def test_configure_sets_fold_writable_constants(self, _mock_ida_modules):
        """configure() should set _fold_writable_constants from kwargs."""
        from d810.optimizers.microcode.instructions.peephole.fold_readonlydata import (
            FoldReadonlyDataRule,
        )

        rule = FoldReadonlyDataRule()
        assert rule._fold_writable_constants is False

        rule.configure({"fold_writable_constants": True})
        assert rule._fold_writable_constants is True

    def test_configure_sets_allow_executable(self, _mock_ida_modules):
        """configure() should set _allow_executable from kwargs."""
        from d810.optimizers.microcode.instructions.peephole.fold_readonlydata import (
            FoldReadonlyDataRule,
        )

        rule = FoldReadonlyDataRule()
        assert rule._allow_executable is False

        rule.configure({"allow_executable_readonly": True})
        assert rule._allow_executable is True
