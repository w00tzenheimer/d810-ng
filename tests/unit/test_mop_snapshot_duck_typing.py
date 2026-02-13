"""Test MopSnapshot duck-typing layer for mop_t attribute compatibility.

Verifies that MopSnapshot provides property aliases and proxy objects
so it can be used transparently wherever mop_t is expected.
"""
import pytest
from d810.hexrays.mop_snapshot import MopSnapshot


class TestPropertyAliases:
    """Test Category A: Simple property aliases."""

    def test_r_alias_for_reg(self):
        """Property .r should return .reg value."""
        snap = MopSnapshot(t=1, size=4, reg=5)
        assert snap.r == 5
        assert snap.r == snap.reg

    def test_r_returns_none_when_reg_none(self):
        """Property .r should return None when .reg is None."""
        snap = MopSnapshot(t=1, size=4)
        assert snap.r is None
        assert snap.reg is None

    def test_g_alias_for_gaddr(self):
        """Property .g should return .gaddr value."""
        snap = MopSnapshot(t=1, size=8, gaddr=0x401000)
        assert snap.g == 0x401000
        assert snap.g == snap.gaddr

    def test_g_returns_none_when_gaddr_none(self):
        """Property .g should return None when .gaddr is None."""
        snap = MopSnapshot(t=1, size=8)
        assert snap.g is None
        assert snap.gaddr is None

    def test_b_alias_for_block_num(self):
        """Property .b should return .block_num value."""
        snap = MopSnapshot(t=1, size=0, block_num=42)
        assert snap.b == 42
        assert snap.b == snap.block_num

    def test_b_returns_none_when_block_num_none(self):
        """Property .b should return None when .block_num is None."""
        snap = MopSnapshot(t=1, size=0)
        assert snap.b is None
        assert snap.block_num is None

    def test_helper_alias_for_helper_name(self):
        """Property .helper should return .helper_name value."""
        snap = MopSnapshot(t=1, size=4, helper_name="__aullshr")
        assert snap.helper == "__aullshr"
        assert snap.helper == snap.helper_name

    def test_helper_returns_none_when_helper_name_none(self):
        """Property .helper should return None when .helper_name is None."""
        snap = MopSnapshot(t=1, size=4)
        assert snap.helper is None
        assert snap.helper_name is None

    def test_cstr_alias_for_const_str(self):
        """Property .cstr should return .const_str value."""
        snap = MopSnapshot(t=1, size=4, const_str="hello")
        assert snap.cstr == "hello"
        assert snap.cstr == snap.const_str

    def test_cstr_returns_none_when_const_str_none(self):
        """Property .cstr should return None when .const_str is None."""
        snap = MopSnapshot(t=1, size=4)
        assert snap.cstr is None
        assert snap.const_str is None


class TestNnnProxy:
    """Test Category B: _NnnProxy for .nnn.value access."""

    def test_nnn_returns_proxy_when_value_set(self):
        """Property .nnn should return _NnnProxy when .value is set."""
        snap = MopSnapshot(t=1, size=4, value=0x1234)
        nnn = snap.nnn
        assert nnn is not None
        assert nnn.value == 0x1234

    def test_nnn_returns_none_when_value_none(self):
        """Property .nnn should return None when .value is None."""
        snap = MopSnapshot(t=1, size=4)
        assert snap.nnn is None

    def test_nnn_proxy_is_truthy(self):
        """_NnnProxy should be truthy when present."""
        snap = MopSnapshot(t=1, size=4, value=0)
        nnn = snap.nnn
        assert nnn is not None
        assert bool(nnn) is True

    def test_nnn_proxy_equality(self):
        """_NnnProxy instances with same value should be equal."""
        snap1 = MopSnapshot(t=1, size=4, value=100)
        snap2 = MopSnapshot(t=1, size=4, value=100)
        assert snap1.nnn == snap2.nnn

    def test_nnn_proxy_inequality(self):
        """_NnnProxy instances with different values should not be equal."""
        snap1 = MopSnapshot(t=1, size=4, value=100)
        snap2 = MopSnapshot(t=1, size=4, value=200)
        assert snap1.nnn != snap2.nnn

    def test_nnn_proxy_hashable(self):
        """_NnnProxy should be hashable."""
        snap = MopSnapshot(t=1, size=4, value=0x1234)
        nnn = snap.nnn
        assert hash(nnn) == hash(0x1234)

    def test_nnn_proxy_in_set(self):
        """_NnnProxy should work in sets."""
        snap1 = MopSnapshot(t=1, size=4, value=100)
        snap2 = MopSnapshot(t=1, size=4, value=100)
        snap3 = MopSnapshot(t=1, size=4, value=200)
        nnn_set = {snap1.nnn, snap2.nnn, snap3.nnn}
        # snap1.nnn and snap2.nnn are equal, so set should have 2 items
        assert len(nnn_set) == 2


class TestStkvarProxy:
    """Test Category B: _StkvarProxy for .s.off access."""

    def test_s_returns_proxy_when_stkoff_set(self):
        """Property .s should return _StkvarProxy when .stkoff is set."""
        snap = MopSnapshot(t=1, size=4, stkoff=0x10)
        s = snap.s
        assert s is not None
        assert s.off == 0x10

    def test_s_returns_none_when_stkoff_none(self):
        """Property .s should return None when .stkoff is None."""
        snap = MopSnapshot(t=1, size=4)
        assert snap.s is None

    def test_s_proxy_start_ea_returns_none(self):
        """_StkvarProxy.start_ea should return None (not available in snapshot)."""
        snap = MopSnapshot(t=1, size=4, stkoff=0x10)
        s = snap.s
        assert s.start_ea is None

    def test_s_proxy_mba_returns_none(self):
        """_StkvarProxy.mba should return None (not available in snapshot)."""
        snap = MopSnapshot(t=1, size=4, stkoff=0x10)
        s = snap.s
        assert s.mba is None

    def test_s_proxy_equality(self):
        """_StkvarProxy instances with same offset should be equal."""
        snap1 = MopSnapshot(t=1, size=4, stkoff=0x10)
        snap2 = MopSnapshot(t=1, size=4, stkoff=0x10)
        assert snap1.s == snap2.s

    def test_s_proxy_inequality(self):
        """_StkvarProxy instances with different offsets should not be equal."""
        snap1 = MopSnapshot(t=1, size=4, stkoff=0x10)
        snap2 = MopSnapshot(t=1, size=4, stkoff=0x20)
        assert snap1.s != snap2.s

    def test_s_proxy_hashable(self):
        """_StkvarProxy should be hashable."""
        snap = MopSnapshot(t=1, size=4, stkoff=0x10)
        s = snap.s
        assert hash(s) == hash(0x10)

    def test_s_proxy_in_dict(self):
        """_StkvarProxy should work as dict key."""
        snap1 = MopSnapshot(t=1, size=4, stkoff=0x10)
        snap2 = MopSnapshot(t=1, size=4, stkoff=0x20)
        d = {snap1.s: "first", snap2.s: "second"}
        assert len(d) == 2
        assert d[snap1.s] == "first"


class TestLvarProxy:
    """Test Category B: _LvarProxy for .l.idx/.l.off access."""

    def test_l_returns_proxy_when_lvar_set(self):
        """Property .l should return _LvarProxy when lvar_idx and lvar_off are set."""
        snap = MopSnapshot(t=1, size=4, lvar_idx=5, lvar_off=0)
        lvar = snap.l
        assert lvar is not None
        assert lvar.idx == 5
        assert lvar.off == 0

    def test_l_returns_none_when_lvar_idx_none(self):
        """Property .l should return None when lvar_idx is None."""
        snap = MopSnapshot(t=1, size=4, lvar_off=0)
        assert snap.l is None

    def test_l_returns_none_when_lvar_off_none(self):
        """Property .l should return None when lvar_off is None."""
        snap = MopSnapshot(t=1, size=4, lvar_idx=5)
        assert snap.l is None

    def test_l_returns_none_when_both_none(self):
        """Property .l should return None when both lvar_idx and lvar_off are None."""
        snap = MopSnapshot(t=1, size=4)
        assert snap.l is None

    def test_l_proxy_equality(self):
        """_LvarProxy instances with same idx/off should be equal."""
        snap1 = MopSnapshot(t=1, size=4, lvar_idx=5, lvar_off=0)
        snap2 = MopSnapshot(t=1, size=4, lvar_idx=5, lvar_off=0)
        assert snap1.l == snap2.l

    def test_l_proxy_inequality_different_idx(self):
        """_LvarProxy instances with different idx should not be equal."""
        snap1 = MopSnapshot(t=1, size=4, lvar_idx=5, lvar_off=0)
        snap2 = MopSnapshot(t=1, size=4, lvar_idx=6, lvar_off=0)
        assert snap1.l != snap2.l

    def test_l_proxy_inequality_different_off(self):
        """_LvarProxy instances with different off should not be equal."""
        snap1 = MopSnapshot(t=1, size=4, lvar_idx=5, lvar_off=0)
        snap2 = MopSnapshot(t=1, size=4, lvar_idx=5, lvar_off=4)
        assert snap1.l != snap2.l

    def test_l_proxy_hashable(self):
        """_LvarProxy should be hashable."""
        snap = MopSnapshot(t=1, size=4, lvar_idx=5, lvar_off=0)
        lvar = snap.l
        assert hash(lvar) == hash((5, 0))

    def test_l_proxy_in_set(self):
        """_LvarProxy should work in sets."""
        snap1 = MopSnapshot(t=1, size=4, lvar_idx=5, lvar_off=0)
        snap2 = MopSnapshot(t=1, size=4, lvar_idx=5, lvar_off=0)
        snap3 = MopSnapshot(t=1, size=4, lvar_idx=6, lvar_off=0)
        lvar_set = {snap1.l, snap2.l, snap3.l}
        # snap1.l and snap2.l are equal, so set should have 2 items
        assert len(lvar_set) == 2


class TestGetAttrFallback:
    """Test Category C: __getattr__ fallback for complex types."""

    def test_getattr_raises_when_owned_mop_none(self):
        """__getattr__ should raise AttributeError when owned_mop is None."""
        snap = MopSnapshot(t=1, size=4)
        with pytest.raises(AttributeError, match="no owned_mop"):
            _ = snap.nonexistent_attr

    def test_getattr_raises_for_private_attrs(self):
        """__getattr__ should raise for private attributes starting with _."""
        snap = MopSnapshot(t=1, size=4)
        with pytest.raises(AttributeError):
            _ = snap._private_attr

    def test_getattr_does_not_interfere_with_existing_attrs(self):
        """__getattr__ should not interfere with normal attribute access."""
        snap = MopSnapshot(t=1, size=4, value=100, reg=5)
        # These should use normal attribute lookup, not __getattr__
        assert snap.t == 1
        assert snap.size == 4
        assert snap.value == 100
        assert snap.reg == 5

    def test_getattr_does_not_interfere_with_properties(self):
        """__getattr__ should not interfere with property access."""
        snap = MopSnapshot(t=1, size=4, reg=5, value=100)
        # These should use property lookup, not __getattr__
        assert snap.r == 5
        assert snap.nnn.value == 100


class TestIntegration:
    """Integration tests: verify duck-typing works end-to-end."""

    def test_snapshot_can_be_used_like_mop_t_for_number(self):
        """MopSnapshot for mop_n should provide .nnn.value access."""
        snap = MopSnapshot(t=1, size=4, value=0x1234)
        # Code expecting mop_t can now do: mop.nnn.value
        assert snap.nnn.value == 0x1234

    def test_snapshot_can_be_used_like_mop_t_for_register(self):
        """MopSnapshot for mop_r should provide .r access."""
        snap = MopSnapshot(t=1, size=4, reg=5)
        # Code expecting mop_t can now do: mop.r
        assert snap.r == 5

    def test_snapshot_can_be_used_like_mop_t_for_stkvar(self):
        """MopSnapshot for mop_S should provide .s.off access."""
        snap = MopSnapshot(t=1, size=4, stkoff=0x10)
        # Code expecting mop_t can now do: mop.s.off
        assert snap.s.off == 0x10

    def test_snapshot_can_be_used_like_mop_t_for_lvar(self):
        """MopSnapshot for mop_l should provide .l.idx/.l.off access."""
        snap = MopSnapshot(t=1, size=4, lvar_idx=5, lvar_off=0)
        # Code expecting mop_t can now do: mop.l.idx, mop.l.off
        assert snap.l.idx == 5
        assert snap.l.off == 0

    def test_snapshot_can_be_used_like_mop_t_for_global(self):
        """MopSnapshot for mop_v should provide .g access."""
        snap = MopSnapshot(t=1, size=8, gaddr=0x401000)
        # Code expecting mop_t can now do: mop.g
        assert snap.g == 0x401000

    def test_snapshot_can_be_used_like_mop_t_for_block(self):
        """MopSnapshot for mop_b should provide .b access."""
        snap = MopSnapshot(t=1, size=0, block_num=42)
        # Code expecting mop_t can now do: mop.b
        assert snap.b == 42

    def test_snapshot_can_be_used_like_mop_t_for_helper(self):
        """MopSnapshot for mop_h should provide .helper access."""
        snap = MopSnapshot(t=1, size=4, helper_name="__aullshr")
        # Code expecting mop_t can now do: mop.helper
        assert snap.helper == "__aullshr"

    def test_snapshot_can_be_used_like_mop_t_for_string(self):
        """MopSnapshot for mop_str should provide .cstr access."""
        snap = MopSnapshot(t=1, size=4, const_str="hello")
        # Code expecting mop_t can now do: mop.cstr
        assert snap.cstr == "hello"
