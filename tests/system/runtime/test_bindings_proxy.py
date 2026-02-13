"""Unit tests for BindingsProxy adapter.

These tests verify that BindingsProxy correctly exposes MatchBindings
in the interface expected by update_leafs_mop() and get_replacement().
"""

import pytest

from d810.hexrays.mop_snapshot import MopSnapshot
from d810.optimizers.microcode.instructions.pattern_matching.pattern_speedups import (
    BindingsProxy,
    MatchBinding,
    MatchBindings,
)


class MockMopSnapshot:
    """Mock MopSnapshot for testing (avoids IDA dependency)."""
    def __init__(self, value=None, size=4):
        self.value = value
        self.size = size
        self.t = 0  # mop_n
        self.is_constant = True


class TestBindingsProxy:
    """Test suite for BindingsProxy adapter."""

    def test_proxy_exposes_leafs_by_name(self):
        """Verify leafs_by_name dict maps names to objects with .mop attribute."""
        bindings = MatchBindings()
        # Manually create bindings to bypass MopSnapshot.from_mop
        binding1 = MatchBinding("x_0", None)
        binding1.mop = MockMopSnapshot(42)
        binding2 = MatchBinding("y_0", None)
        binding2.mop = MockMopSnapshot(99)
        bindings.bindings = [binding1, binding2]
        bindings.count = 2

        proxy = BindingsProxy(bindings)

        assert "x_0" in proxy.leafs_by_name
        assert "y_0" in proxy.leafs_by_name
        assert proxy.leafs_by_name["x_0"].mop.value == 42
        assert proxy.leafs_by_name["y_0"].mop.value == 99

    def test_proxy_copies_root_metadata(self):
        """Verify ea, dst_mop, dest_size, mop are copied from bindings."""
        bindings = MatchBindings()
        bindings.root_ea = 0x401000
        bindings.root_dst_mop = MockMopSnapshot(123)
        bindings.root_dest_size = 8
        bindings.root_mop = MockMopSnapshot(456)

        proxy = BindingsProxy(bindings)

        assert proxy.ea == 0x401000
        assert proxy.dst_mop.value == 123
        assert proxy.dest_size == 8
        assert proxy.mop.value == 456

    def test_proxy_is_candidate_ok_defaults_true(self):
        """Verify is_candidate_ok is always True (equality check passed)."""
        bindings = MatchBindings()
        # Manually create binding
        binding = MatchBinding("x_0", None)
        binding.mop = MockMopSnapshot(42)
        bindings.bindings = [binding]
        bindings.count = 1

        proxy = BindingsProxy(bindings)

        assert proxy.is_candidate_ok is True

    def test_proxy_compatible_with_update_leafs_mop(self):
        """Verify proxy can be used with update_leafs_mop pattern."""
        # This test verifies the interface contract without importing IDA modules
        bindings = MatchBindings()

        # Manually create bindings
        binding1 = MatchBinding("a_0", None, dest_size=4, ea=0x401000)
        binding1.mop = MockMopSnapshot(10, size=4)
        binding2 = MatchBinding("b_0", None, dest_size=4, ea=0x401000)
        binding2.mop = MockMopSnapshot(20, size=4)

        bindings.bindings = [binding1, binding2]
        bindings.count = 2
        bindings.root_ea = 0x401000
        bindings.root_dst_mop = MockMopSnapshot(30)
        bindings.root_dest_size = 4
        bindings.root_mop = MockMopSnapshot(40)

        proxy = BindingsProxy(bindings)

        # Verify interface matches what update_leafs_mop expects
        assert hasattr(proxy, "leafs_by_name")
        assert isinstance(proxy.leafs_by_name, dict)

        # Verify each binding in leafs_by_name has the required attributes
        for name, binding in proxy.leafs_by_name.items():
            assert hasattr(binding, "mop")
            assert hasattr(binding, "dest_size")
            assert hasattr(binding, "ea")
            assert binding.name == name

        # Verify root metadata is accessible
        assert proxy.ea == 0x401000
        assert proxy.dst_mop.value == 30
        assert proxy.dest_size == 4
        assert proxy.mop.value == 40

    def test_proxy_empty_bindings(self):
        """Verify proxy works with empty bindings."""
        bindings = MatchBindings()

        proxy = BindingsProxy(bindings)

        assert proxy.leafs_by_name == {}
        assert proxy.ea is None
        assert proxy.dst_mop is None
        assert proxy.dest_size is None
        assert proxy.mop is None
        assert proxy.is_candidate_ok is True

    def test_proxy_multiple_bindings_same_name(self):
        """Verify proxy handles bindings dict correctly (last wins)."""
        bindings = MatchBindings()

        # Manually create duplicate bindings
        binding1 = MatchBinding("x_0", None)
        binding1.mop = MockMopSnapshot(1)
        binding2 = MatchBinding("x_0", None)
        binding2.mop = MockMopSnapshot(2)

        bindings.bindings = [binding1, binding2]
        bindings.count = 2

        proxy = BindingsProxy(bindings)

        # get_leafs_by_name returns last binding for duplicates
        leafs = proxy.leafs_by_name
        assert "x_0" in leafs
        # The dict will have the last binding with that name
        assert leafs["x_0"].mop.value == 2


# =========================================================================
# Test: BindingsProxy integration with real ASTs (requires IDA)
# =========================================================================


class TestBindingsProxyRealIntegration:
    """Test BindingsProxy works with real AST matching and update_leafs_mop bridge."""

    @pytest.mark.ida_required
    def test_proxy_works_with_real_replacement(self, real_asts, populated_storages):
        """Verify BindingsProxy can feed into the replacement pipeline."""
        from d810.optimizers.microcode.instructions.pattern_matching.engine import (
            match_pattern_nomut,
            MatchBindings,
        )
        from d810.optimizers.microcode.instructions.pattern_matching.pattern_speedups import (
            BindingsProxy,
        )

        # Get storage from fixture
        new_storage = populated_storages["new"]

        bindings = MatchBindings()
        tested = 0

        for ast, _ in real_asts[:20]:
            if not ast.is_node():
                continue

            candidates = new_storage.get_candidates(ast)
            for entry in candidates[:3]:
                bindings.reset()
                if match_pattern_nomut(entry.pattern, ast, bindings):
                    proxy = BindingsProxy(bindings)

                    # Verify proxy has valid leafs_by_name
                    assert len(proxy.leafs_by_name) > 0, (
                        "Successful match should produce leaf bindings"
                    )

                    # Verify each leaf binding has required attributes for update_leafs_mop
                    for name, binding in proxy.leafs_by_name.items():
                        assert binding.mop is not None, f"Leaf {name} has no mop"
                        assert hasattr(binding, "dest_size"), f"Leaf {name} missing dest_size"
                        assert hasattr(binding, "ea"), f"Leaf {name} missing ea"
                        assert binding.name == name, f"Leaf name mismatch: {binding.name} != {name}"

                    # Verify root metadata is present
                    assert proxy.ea is not None or proxy.mop is not None, (
                        "Proxy should have root metadata from successful match"
                    )

                    tested += 1
                    break  # Found a match for this AST

            if tested >= 5:
                break

        assert tested > 0, "Expected to test at least one successful match with proxy"
        print(f"\n  Tested {tested} BindingsProxy instances with real AST matches")
