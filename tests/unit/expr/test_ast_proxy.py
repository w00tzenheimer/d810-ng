"""Unit tests for AstProxy clone-on-write and attribute forwarding.

These tests use a minimal standalone implementation that replicates the
core AstProxy/AstLeaf/AstConstant behavior without requiring IDA imports.
This validates the proxy pattern works correctly for clone-on-write semantics.
"""

import unittest


# =============================================================================
# Minimal standalone AST classes for testing (mirrors d810.expr.p_ast)
# =============================================================================


class MockAstBase:
    """Minimal AstBase for testing proxy behavior."""

    mop = None
    dest_size = None
    ea = None
    ast_index = None

    @property
    def is_frozen(self) -> bool:
        raise NotImplementedError

    def clone(self):
        raise NotImplementedError

    def freeze(self) -> None:
        raise NotImplementedError


class MockAstLeaf(MockAstBase):
    """Minimal AstLeaf implementation for testing."""

    def __init__(self, name: str):
        self.name = name
        self.ast_index = None
        self.mop = None
        self.dest_size = None
        self.ea = None
        self._is_frozen = False

    @property
    def is_frozen(self) -> bool:
        return self._is_frozen

    def freeze(self):
        self._is_frozen = True

    def clone(self):
        new_leaf = MockAstLeaf(self.name)
        new_leaf.ast_index = self.ast_index
        new_leaf.mop = self.mop
        new_leaf.dest_size = self.dest_size
        new_leaf.ea = self.ea
        new_leaf._is_frozen = False  # Clones start mutable
        return new_leaf

    @property
    def size(self):
        return self.mop.size if self.mop else 0

    @property
    def dst_mop(self):
        return self.mop

    @dst_mop.setter
    def dst_mop(self, mop):
        self.mop = mop

    @property
    def value(self):
        if self.mop is not None and hasattr(self.mop, "nnn"):
            return self.mop.nnn.value
        return None


class MockAstConstant(MockAstLeaf):
    """Minimal AstConstant implementation for testing."""

    def __init__(self, name: str, expected_value=None, expected_size=None):
        super().__init__(name)
        self.expected_value = expected_value
        self.expected_size = expected_size

    @property
    def value(self):
        if self.mop is not None and hasattr(self.mop, "nnn"):
            return self.mop.nnn.value
        return self.expected_value

    def clone(self):
        new_const = MockAstConstant(self.name, self.expected_value, self.expected_size)
        new_const.ast_index = self.ast_index
        new_const.mop = self.mop
        new_const.dest_size = self.dest_size
        new_const.ea = self.ea
        new_const._is_frozen = False
        return new_const


class MockAstProxy(MockAstBase):
    """Minimal AstProxy implementation that mirrors d810.expr.p_ast.AstProxy.

    This implements clone-on-write semantics: when writing to a proxy that
    wraps a frozen target, the target is cloned first.
    """

    mop = None  # Class-level defaults to test __getattribute__ override
    dest_size = None
    ea = None
    ast_index = None

    def __init__(self, target_ast: MockAstBase):
        self._target = target_ast

    def _ensure_mutable(self):
        """Clone target if frozen."""
        if self._target.is_frozen:
            self._target = self._target.clone()

    def __getattr__(self, name):
        """Forward read access to target."""
        return getattr(self._target, name)

    def __setattr__(self, name, value):
        """Handle write access with clone-on-write."""
        if name == "_target":
            self.__dict__["_target"] = value
            return
        self._ensure_mutable()
        setattr(self._target, name, value)

    def __getattribute__(self, name):
        """Forward all attribute access, handling None placeholders."""
        if name.startswith("_"):
            return super().__getattribute__(name)

        try:
            val = super().__getattribute__(name)
        except AttributeError:
            return getattr(super().__getattribute__("_target"), name)

        if val is None:
            target = super().__getattribute__("_target")
            return getattr(target, name)
        return val

    @property
    def is_frozen(self) -> bool:
        return self._target.is_frozen

    def clone(self):
        return MockAstProxy(self._target.clone())

    def freeze(self) -> None:
        self._target.freeze()

    # Explicit property forwarders (mirrors p_ast.AstProxy)
    @property
    def mop(self):
        return self._target.mop

    @mop.setter
    def mop(self, value):
        self._ensure_mutable()
        self._target.mop = value

    @property
    def dest_size(self):
        return self._target.dest_size

    @dest_size.setter
    def dest_size(self, value):
        self._ensure_mutable()
        self._target.dest_size = value

    @property
    def ea(self):
        return self._target.ea

    @ea.setter
    def ea(self, value):
        self._ensure_mutable()
        self._target.ea = value

    @property
    def ast_index(self):
        return self._target.ast_index

    @ast_index.setter
    def ast_index(self, value):
        self._ensure_mutable()
        self._target.ast_index = value


class MockMop:
    """Mock mop_t object for testing."""

    def __init__(self, value: int, size: int):
        self.size = size
        self.t = 1  # mop_n (constant type)
        self.nnn = type("nnn", (), {"value": value})()


# =============================================================================
# Test Cases
# =============================================================================


class TestAstProxyForwarding(unittest.TestCase):
    """Validate that AstProxy correctly forwards attribute access and implements clone-on-write."""

    def setUp(self):
        """Set up test fixtures."""
        # Create a constant leaf 0x42 (8-bit)
        self.leaf = MockAstLeaf("const_42")
        self.leaf.mop = MockMop(0x42, 1)
        self.leaf.dest_size = 1
        self.leaf.ea = 0x1000
        self.leaf.ast_index = 7

        # Freeze to force clone-on-write later
        self.leaf.freeze()
        self.proxy = MockAstProxy(self.leaf)

    def test_attribute_forwarding(self):
        """Read access through proxy should match underlying leaf."""
        self.assertIs(self.proxy.mop, self.leaf.mop)
        self.assertEqual(self.proxy.dest_size, self.leaf.dest_size)
        self.assertEqual(self.proxy.ea, self.leaf.ea)
        self.assertEqual(self.proxy.ast_index, self.leaf.ast_index)

    def test_clone_on_write(self):
        """Writing through proxy must not mutate the frozen original object."""
        # Mutate via proxy
        self.proxy.dest_size = 2
        self.proxy.ea = 0x2000

        # Original leaf stays untouched
        self.assertEqual(self.leaf.dest_size, 1)
        self.assertEqual(self.leaf.ea, 0x1000)

        # Proxy now points to a distinct, mutable clone
        self.assertEqual(self.proxy.dest_size, 2)
        self.assertEqual(self.proxy.ea, 0x2000)
        self.assertIsNot(self.proxy._target, self.leaf)

    def test_size_and_dst_mop(self):
        """Verify size and dst_mop forwarding and mutability."""
        orig_size = self.proxy.size
        self.assertEqual(orig_size, 1)

        # dst_mop is alias of mop on AstLeaf; check getter
        self.assertIs(self.proxy.dst_mop, self.proxy.mop)

        # Change via setter and ensure reflected
        new_mop = MockMop(0x55, 1)
        self.proxy.dst_mop = new_mop
        self.assertIs(self.proxy.mop, new_mop)
        self.assertIs(self.proxy.dst_mop, new_mop)

    def test_value_forwarding_for_constant(self):
        """AstProxy should expose the .value property of an AstConstant leaf."""
        const_leaf = MockAstConstant("cst", expected_value=0x99, expected_size=1)
        const_leaf.mop = MockMop(0x99, 1)
        const_leaf.freeze()

        proxy = MockAstProxy(const_leaf)
        self.assertEqual(proxy.value, 0x99)


class TestAstProxyFrozenBehavior(unittest.TestCase):
    """Test frozen state handling in AstProxy."""

    def test_proxy_to_mutable_does_not_clone(self):
        """Writing to a proxy of a mutable target should not trigger cloning."""
        leaf = MockAstLeaf("mutable_leaf")
        leaf.dest_size = 4
        leaf.ea = 0x3000
        # Do NOT freeze - leaf remains mutable

        proxy = MockAstProxy(leaf)

        # Write through proxy
        proxy.dest_size = 8

        # Should modify the original since it's mutable
        self.assertEqual(leaf.dest_size, 8)
        self.assertIs(proxy._target, leaf)

    def test_multiple_writes_through_proxy(self):
        """Multiple writes through proxy should all go to the same cloned target."""
        leaf = MockAstLeaf("frozen_leaf")
        leaf.dest_size = 1
        leaf.ea = 0x1000
        leaf.ast_index = 1
        leaf.freeze()

        proxy = MockAstProxy(leaf)

        # First write triggers clone
        proxy.dest_size = 2
        cloned_target = proxy._target

        # Second write should use same cloned target
        proxy.ea = 0x2000
        self.assertIs(proxy._target, cloned_target)
        self.assertIsNot(cloned_target, leaf)

        # Verify all changes are on the clone
        self.assertEqual(proxy.dest_size, 2)
        self.assertEqual(proxy.ea, 0x2000)

        # Original unchanged
        self.assertEqual(leaf.dest_size, 1)
        self.assertEqual(leaf.ea, 0x1000)


class TestAstProxyClone(unittest.TestCase):
    """Test cloning behavior of AstProxy."""

    def test_proxy_clone_creates_new_proxy(self):
        """Cloning a proxy should create a new proxy with a cloned target."""
        leaf = MockAstLeaf("original")
        leaf.dest_size = 4
        leaf.freeze()

        proxy = MockAstProxy(leaf)
        cloned_proxy = proxy.clone()

        # The cloned proxy should be a different object
        self.assertIsNot(cloned_proxy, proxy)

        # The cloned proxy's target should also be different (not frozen)
        self.assertIsNot(cloned_proxy._target, proxy._target)

        # The cloned target should be mutable
        self.assertFalse(cloned_proxy._target.is_frozen)

    def test_proxy_freeze_freezes_target(self):
        """Freezing a proxy should freeze the underlying target."""
        leaf = MockAstLeaf("to_freeze")
        proxy = MockAstProxy(leaf)

        self.assertFalse(leaf.is_frozen)
        proxy.freeze()
        self.assertTrue(leaf.is_frozen)


if __name__ == "__main__":
    unittest.main()
