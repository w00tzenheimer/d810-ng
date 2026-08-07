"""CoBRA must be optional: absent is a result, never an exception.

d810 ships as prebuilt wheels; a developer or CI image without a CoBRA build
must behave exactly like one where the feature is switched off.  The only
exception is an explicit opt-in (``D810_REQUIRE_COBRA=1``) so CI can assert the
binary really is present when it is supposed to be.
"""

from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

from d810.backends.cobra.probe import (
    COBRA_CLI_ENV,
    COBRA_REQUIRED_ENV,
    COBRA_ROOT_ENV,
    CobraStatus,
    find_cobra_cli,
)


class _CleanEnv(unittest.TestCase):
    """Neutralise the CoBRA env vars and PATH so tests are hermetic."""

    def setUp(self) -> None:
        self._saved = {
            k: os.environ.pop(k, None)
            for k in (COBRA_CLI_ENV, COBRA_ROOT_ENV, COBRA_REQUIRED_ENV, "PATH")
        }
        os.environ["PATH"] = ""

    def tearDown(self) -> None:
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class TestFindCobraCli(_CleanEnv):
    def test_missing_binary_is_skipped_not_raised(self):
        probe = find_cobra_cli()
        self.assertIs(probe.status, CobraStatus.SKIPPED)
        self.assertFalse(probe.available)
        self.assertIsNone(probe.path)

    def test_skip_reason_names_the_remedy(self):
        reason = find_cobra_cli().reason
        for expected in (COBRA_CLI_ENV, COBRA_ROOT_ENV, "PATH"):
            self.assertIn(expected, reason)

    def test_explicit_env_var_is_used(self):
        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp) / "cobra-cli"
            exe.write_text("#!/bin/sh\n")
            exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
            os.environ[COBRA_CLI_ENV] = str(exe)

            probe = find_cobra_cli()
            self.assertIs(probe.status, CobraStatus.AVAILABLE)
            self.assertEqual(probe.path, exe)

    def test_build_tree_layout_is_discovered_from_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp) / "build" / "tools" / "cobra-cli" / "cobra-cli"
            exe.parent.mkdir(parents=True)
            exe.write_text("#!/bin/sh\n")
            exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
            os.environ[COBRA_ROOT_ENV] = tmp

            self.assertTrue(find_cobra_cli().available)

    def test_non_executable_file_does_not_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp) / "cobra-cli"
            exe.write_text("not executable")
            exe.chmod(0o644)
            os.environ[COBRA_CLI_ENV] = str(exe)

            self.assertIs(find_cobra_cli().status, CobraStatus.SKIPPED)

    def test_required_flag_turns_absence_into_an_error(self):
        os.environ[COBRA_REQUIRED_ENV] = "1"
        with self.assertRaises(RuntimeError) as ctx:
            find_cobra_cli()
        self.assertIn(COBRA_REQUIRED_ENV, str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
