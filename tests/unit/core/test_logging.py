import logging
import os
import subprocess
import sys
import textwrap
import unittest

from d810.core import LoggerConfigurator, getLogger


class TestModuleLoggerLevelAfterConfigure(unittest.TestCase):
    """`d810.*` module loggers must not inherit root's DEBUG level.

    Every module does ``logger = getLogger(__name__)`` at import time, i.e.
    *before* ``configure_loggers`` runs. ``dictConfig`` resets existing loggers
    that are children of a *named* logger back to ``NOTSET`` -- and "d810" is a
    named logger, so all 133 of them qualify. If the parent chain is intact they
    then inherit "d810" (INFO). If it is broken they inherit ``root``, which is
    DEBUG, and every ``logger.debug()`` in the codebase starts emitting.

    That is not a cosmetic difference: it took d810.log from 14 MB to 3.2 GB
    (229x) on a single system-suite run, which slowed the suite 2.1x and
    exhausted memory mid-decompilation.

    Run in a subprocess because logging state is process-global -- an in-process
    version would be contaminated by whatever configured logging first.
    """

    SCRIPT = textwrap.dedent(
        """
        import json, logging, tempfile

        # Mimic real import order: the module logger is created first...
        from d810.core import getLogger
        getLogger("d810.hexrays.expr.p_ast")

        # ...and only later does the app configure logging.
        from d810.core.logging import configure_loggers
        configure_loggers(tempfile.mkdtemp())

        lg = logging.getLogger("d810.hexrays.expr.p_ast")
        print(json.dumps({
            "effective": lg.getEffectiveLevel(),
            "debug_enabled": lg.isEnabledFor(logging.DEBUG),
            "parent": lg.parent.name if lg.parent else None,
        }))
        """
    )

    def _probe(self) -> dict:
        import json

        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(sys.path)
        env.pop("D810_DEBUG_LOGGING", None)
        proc = subprocess.run(
            [sys.executable, "-c", self.SCRIPT],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout.strip().splitlines()[-1])

    def test_module_logger_is_not_debug_after_configure(self):
        result = self._probe()
        self.assertFalse(
            result["debug_enabled"],
            "d810.* module loggers must not emit DEBUG by default; "
            f"got effective level {logging.getLevelName(result['effective'])} "
            f"inherited via parent {result['parent']!r}",
        )
        self.assertEqual(result["effective"], logging.INFO)

    def test_module_logger_parents_to_d810_not_root(self):
        """The chain itself, so a future refactor can't silently re-break it."""
        self.assertEqual(self._probe()["parent"], "d810")


class TestUiLevelChangePropagates(unittest.TestCase):
    """Raising a parent's level from the UI must reach its children.

    ``LoggerConfigurator.set_level`` is what the D810 logger panel calls. It
    goes through ``getLogger``, which builds a *new* D810Logger and swaps it
    into ``loggerDict``. Children still hold a reference to the object it
    replaced, so without re-linking they keep resolving against a stale parent
    and the level change silently does nothing -- the same object-identity flaw
    that broke the parent chain in configure_loggers, just with the opposite
    symptom (nothing happens instead of everything happens).

    Selecting DEBUG on "d810" is the obvious way to turn debug logging on. If
    it no-ops, the missing output looks exactly like code that never ran.
    """

    SCRIPT = textwrap.dedent(
        """
        import json, logging, tempfile
        from d810.core import getLogger, LoggerConfigurator
        NAME = "d810.hexrays.expr.p_ast"
        getLogger(NAME)
        from d810.core.logging import configure_loggers
        configure_loggers(tempfile.mkdtemp())

        before = logging.getLogger(NAME).getEffectiveLevel()
        LoggerConfigurator.set_level("d810", "DEBUG")
        after_debug = logging.getLogger(NAME).getEffectiveLevel()
        LoggerConfigurator.set_level("d810", "INFO")
        after_info = logging.getLogger(NAME).getEffectiveLevel()

        print(json.dumps({
            "before": before,
            "after_debug": after_debug,
            "after_info": after_info,
        }))
        """
    )

    def _probe(self) -> dict:
        import json

        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(sys.path)
        env.pop("D810_DEBUG_LOGGING", None)
        proc = subprocess.run(
            [sys.executable, "-c", self.SCRIPT],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout.strip().splitlines()[-1])

    def test_setting_parent_level_reaches_children(self):
        result = self._probe()
        self.assertEqual(result["before"], logging.INFO)
        self.assertEqual(
            result["after_debug"],
            logging.DEBUG,
            "setting d810 -> DEBUG from the UI must reach child loggers",
        )
        self.assertEqual(
            result["after_info"],
            logging.INFO,
            "and setting it back must restore them",
        )


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
