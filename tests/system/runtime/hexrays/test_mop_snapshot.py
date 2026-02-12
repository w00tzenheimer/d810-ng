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
