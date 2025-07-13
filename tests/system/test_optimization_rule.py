import unittest

from d810.optimizers.handler import OptimizationRule

import ida_hexrays


class TestOptimizationRule(unittest.TestCase):
    """Basic tests for the OptimizationRule class."""

    def test_name_and_description_defaults(self):
        rule = OptimizationRule()
        # Default name comes from class name
        self.assertEqual(rule.name, "OptimizationRule")
        # No DESCRIPTION set => fallback message
        self.assertEqual(rule.description, "No description available")

    def test_set_log_dir(self):
        rule = OptimizationRule()
        rule.set_log_dir("/tmp/logs")
        self.assertEqual(rule.log_dir, "/tmp/logs")

    def test_configure_none(self):
        rule = OptimizationRule()
        rule.configure(None)
        # No maturities => default empty
        self.assertEqual(rule.config, {})
        self.assertEqual(rule.maturities, [])

    def test_configure_empty_dict(self):
        rule = OptimizationRule()
        rule.configure({})
        self.assertEqual(rule.config, {})
        self.assertEqual(rule.maturities, [])

    def test_configure_with_maturities(self):
        rule = OptimizationRule()
        config = {"maturities": ["LOCOPT", "CALLS"]}
        rule.configure(config)
        # Config stored
        self.assertEqual(rule.config, config)
        # Maturities converted to Hex-Rays constants
        expected = [ida_hexrays.MMAT_LOCOPT, ida_hexrays.MMAT_CALLS]
        self.assertEqual(rule.maturities, expected)


if __name__ == "__main__":  # for standalone runs
    unittest.main()
