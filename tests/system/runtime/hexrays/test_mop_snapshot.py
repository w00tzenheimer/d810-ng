"""Tests for MopSnapshot — requires IDA runtime for module import."""
import pytest

from d810.hexrays.mop_snapshot import MopSnapshot


@pytest.mark.ida_required
class TestMopSnapshot:
    """Test MopSnapshot dataclass behavior."""

    def test_frozen_immutable(self):
        snap = MopSnapshot(t=2, size=4, value=42)
        with pytest.raises(AttributeError):
            snap.t = 99

    def test_equality(self):
        a = MopSnapshot(t=2, size=4, value=42)
        b = MopSnapshot(t=2, size=4, value=42)
        assert a == b

    def test_inequality_different_value(self):
        a = MopSnapshot(t=2, size=4, value=42)
        b = MopSnapshot(t=2, size=4, value=99)
        assert a != b

    def test_hashable(self):
        snap = MopSnapshot(t=2, size=4, value=42)
        d = {snap: "found"}
        assert d[snap] == "found"

    def test_to_cache_key_deterministic(self):
        snap = MopSnapshot(t=2, size=4, value=42, valnum=7)
        key1 = snap.to_cache_key()
        key2 = snap.to_cache_key()
        assert key1 == key2
        assert isinstance(key1, tuple)

    def test_to_cache_key_includes_all_fields(self):
        snap = MopSnapshot(t=1, size=8, reg=3, valnum=5)
        key = snap.to_cache_key()
        assert 1 in key   # t
        assert 8 in key   # size
        assert 3 in key   # reg
        assert 5 in key   # valnum

    def test_register_snapshot(self):
        snap = MopSnapshot(t=1, size=4, reg=16)
        assert snap.reg == 16
        assert snap.value is None

    def test_constant_snapshot(self):
        snap = MopSnapshot(t=2, size=4, value=0xDEADBEEF)
        assert snap.value == 0xDEADBEEF
        assert snap.reg is None

    def test_stack_var_snapshot(self):
        snap = MopSnapshot(t=5, size=8, stkoff=-0x28)
        assert snap.stkoff == -0x28

    def test_global_addr_snapshot(self):
        snap = MopSnapshot(t=6, size=8, gaddr=0x140001000)
        assert snap.gaddr == 0x140001000

    def test_helper_snapshot(self):
        snap = MopSnapshot(t=11, size=0, helper_name="memcpy")
        assert snap.helper_name == "memcpy"

    def test_default_valnum_zero(self):
        snap = MopSnapshot(t=0, size=0)
        assert snap.valnum == 0

    def test_empty_operand(self):
        snap = MopSnapshot(t=0, size=0)
        assert snap.value is None
        assert snap.reg is None


@pytest.mark.ida_required
class TestMopSnapshotProperties:
    """Test is_constant and is_register properties using real ida_hexrays constants."""

    def test_is_constant(self):
        import ida_hexrays
        snap = MopSnapshot(t=ida_hexrays.mop_n, size=4, value=42)
        assert snap.is_constant is True

    def test_is_constant_false(self):
        import ida_hexrays
        snap = MopSnapshot(t=ida_hexrays.mop_r, size=4, reg=0)
        assert snap.is_constant is False

    def test_is_register(self):
        import ida_hexrays
        snap = MopSnapshot(t=ida_hexrays.mop_r, size=4, reg=16)
        assert snap.is_register is True

    def test_is_register_false(self):
        import ida_hexrays
        snap = MopSnapshot(t=ida_hexrays.mop_n, size=4, value=42)
        assert snap.is_register is False


@pytest.mark.ida_required
class TestMopSnapshotToMop:
    """Test that to_mop() reconstructs a real mop_t from a snapshot.

    The mop_v branch in particular must work on Hex-Rays 9.x SDKs where
    ``mop_t.make_global`` is not exposed (issue #44). Other branches are
    sanity-checked to guard against the same class of SDK drift.
    """

    def test_to_mop_global_reconstructs_mop_v(self):
        """mop_v branch — guards against missing mop_t.make_global (#44)."""
        import ida_hexrays
        snap = MopSnapshot(
            t=ida_hexrays.mop_v, size=8, gaddr=0x140001000
        )
        m = snap.to_mop()
        assert isinstance(m, ida_hexrays.mop_t)
        assert m.t == ida_hexrays.mop_v
        assert m.g == 0x140001000
        assert m.size == 8

    def test_to_mop_number_reconstructs_mop_n(self):
        import ida_hexrays
        snap = MopSnapshot(t=ida_hexrays.mop_n, size=4, value=0xDEADBEEF)
        m = snap.to_mop()
        assert m.t == ida_hexrays.mop_n
        assert m.size == 4
        assert m.nnn.value == 0xDEADBEEF

    def test_to_mop_register_reconstructs_mop_r(self):
        import ida_hexrays
        snap = MopSnapshot(t=ida_hexrays.mop_r, size=8, reg=16)
        m = snap.to_mop()
        assert m.t == ida_hexrays.mop_r
        assert m.size == 8
        assert m.r == 16

    def test_to_mop_helper_reconstructs_mop_h(self):
        import ida_hexrays
        snap = MopSnapshot(t=ida_hexrays.mop_h, size=0, helper_name="memcpy")
        m = snap.to_mop()
        assert m.t == ida_hexrays.mop_h
        assert m.helper == "memcpy"

    def test_to_mop_blkref_reconstructs_mop_b(self):
        import ida_hexrays
        snap = MopSnapshot(t=ida_hexrays.mop_b, size=0, block_num=7)
        m = snap.to_mop()
        assert m.t == ida_hexrays.mop_b
        assert m.b == 7
