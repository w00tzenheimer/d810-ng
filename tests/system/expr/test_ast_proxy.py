import unittest

from d810.expr.ast import AstLeaf, AstProxy, get_constant_mop


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


if __name__ == "__main__":
    unittest.main()
