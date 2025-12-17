import logging
import unittest

from d810.core import LoggerConfigurator, getLogger


class TestLoggerConfigurator(unittest.TestCase):
    def setUp(self):
        # Ensure a test logger exists under our D810 prefix
        self.prefix = "D810"
        self.test_logger_name = f"{self.prefix}.testunit"
        # Create and reset the test logger
        self.logger = getLogger(self.test_logger_name)
        self.logger.setLevel(logging.WARNING)
        # Also ensure the root prefix logger exists
        self.root_logger = logging.getLogger(self.prefix)
        self.root_logger.setLevel(logging.WARNING)

    def test_available_loggers_with_prefix(self):
        names = LoggerConfigurator.available_loggers(self.prefix)
        # The test logger and root prefix should be listed
        self.assertIn(self.test_logger_name, names)
        self.assertIn(self.prefix, names)

    def test_available_loggers_without_prefix(self):
        names = LoggerConfigurator.available_loggers()
        # At minimum, core D810 logger should appear
        self.assertIn("D810", names)

    def test_set_level_changes_level(self):
        # Change to DEBUG and verify
        LoggerConfigurator.set_level(self.test_logger_name, "DEBUG")
        self.assertEqual(self.logger.level, logging.DEBUG)

    def test_set_level_invalid_raises(self):
        with self.assertRaises(ValueError):
            LoggerConfigurator.set_level(self.test_logger_name, "NOTALEVEL")

    def test_mdc_maturity_update(self):
        """Ensure that the maturity value is carried via the MDC and accessible."""
        maturity_val = "LOCOPT"
        log = getLogger(self.test_logger_name)
        log.update_maturity(maturity_val)
        self.assertEqual(log.get_mdc("maturity"), maturity_val)


if __name__ == "__main__":
    unittest.main()
