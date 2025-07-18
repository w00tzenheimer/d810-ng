import unittest

from d810.expr.ast import AstConstant, AstLeaf, AstProxy, get_constant_mop


class TestAstProxyForwarding(unittest.TestCase):
    """Validate that AstProxy correctly forwards attribute access and implements clone-on-write."""

    def setUp(self):
        # Create a constant leaf 0x42 (8-bit)
        self.leaf = AstLeaf("const_42")
        const_mop = get_constant_mop(0x42, 1)
        self.leaf.mop = const_mop
        self.leaf.dest_size = 1
        self.leaf.ea = 0x1000
        self.leaf.ast_index = 7

        # Freeze to force clone-on-write later
        self.leaf.freeze()
        self.proxy = AstProxy(self.leaf)

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
        new_mop = get_constant_mop(0x55, 1)
        self.proxy.dst_mop = new_mop
        self.assertIs(self.proxy.mop, new_mop)
        self.assertIs(self.proxy.dst_mop, new_mop)

    def test_value_forwarding_for_constant(self):
        """AstProxy should expose the .value property of an AstConstant leaf."""

        const_leaf = AstConstant("cst", expected_value=0x99, expected_size=1)
        const_leaf.mop = get_constant_mop(0x99, 1)
        const_leaf.freeze()

        proxy = AstProxy(const_leaf)
        self.assertEqual(proxy.value, 0x99)


if __name__ == "__main__":
    unittest.main()
