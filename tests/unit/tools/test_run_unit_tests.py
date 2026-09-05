"""Dry-run coverage for tools/scripts/run_unit_tests.sh.

Ticket d81-4tsd, review 1 (C1): the wrapper aborted with an "unbound
variable" error under macOS's bash 3.2 (/bin/bash) for every
argument-free invocation, including the documented serial command,
because it referenced an empty EXTRA_ARGS array directly under
`set -u`. These tests invoke the script through its own shebang (no
explicit `bash ...` prefix), so they exercise whatever interpreter the
shebang actually selects on this host, and assert on the exact resolved
`pytest` command via --dry-run rather than running the (expensive) suite
itself.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "tools" / "scripts" / "run_unit_tests.sh"


def _dry_run(*args: str) -> subprocess.CompletedProcess[str]:
    if not SCRIPT.is_file():
        pytest.fail(f"wrapper missing: {SCRIPT}")
    # Drop any PYTHONPATH inherited from the outer pytest process (this
    # test file is itself normally run with PYTHONPATH=src:tests set) so
    # the resolved command asserted below does not depend on how this
    # test was invoked -- the script appends its own "src:tests" ahead of
    # whatever PYTHONPATH it is handed.
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    return subprocess.run(
        [str(SCRIPT), *args, "--dry-run"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def test_no_args_resolves_to_serial_tests_unit() -> None:
    """The documented "serial behaviour is unchanged" invocation."""
    result = _dry_run()
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == (
        "PYTHONPATH=src:tests pyenv exec python -m pytest "
        "-p no:cacheprovider tests/unit"
    )


def test_n4_resolves_to_dist_load_with_tests_unit() -> None:
    result = _dry_run("-n", "4")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == (
        "PYTHONPATH=src:tests pyenv exec python -m pytest "
        "-p no:cacheprovider tests/unit -n 4 --dist load"
    )


def test_positional_path_replaces_tests_unit_default() -> None:
    """A caller-named target must not be unioned with tests/unit."""
    result = _dry_run("tests/unit/core/test_plugins.py")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == (
        "PYTHONPATH=src:tests pyenv exec python -m pytest "
        "-p no:cacheprovider tests/unit/core/test_plugins.py"
    )
