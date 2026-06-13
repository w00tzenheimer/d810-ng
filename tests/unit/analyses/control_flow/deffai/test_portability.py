"""Portability guard for the DEFFAI core (acceptance criterion #4).

Importing the DEFFAI subpackage must pull in **no** ``ida_*`` module -- it is the
``portable-core-no-ida`` layer (it runs on the portable :class:`FlowGraph`,
exactly as DEFFAI runs on LLVM bitcode).  This makes the portability guarantee a
CI-enforced unit test rather than a manual check.
"""
from __future__ import annotations

import subprocess
import sys

_PROBE = (
    "import sys; "
    "import d810.analyses.control_flow.deffai; "
    "leaked = sorted(m for m in sys.modules if m.split('.')[0].startswith('ida')); "
    "print('LEAKED:' + ','.join(leaked)); "
    "sys.exit(1 if leaked else 0)"
)


def _run_probe() -> subprocess.CompletedProcess:
    """Import the DEFFAI package in a FRESH interpreter and report ida leakage.

    A fresh subprocess is required because the in-process ``sys.modules`` may
    already hold IDA stubs loaded by sibling tests, which would mask a real
    transitive ida import behind the import cache.
    """
    return subprocess.run(
        [sys.executable, "-c", _PROBE],
        capture_output=True,
        text=True,
    )


def test_deffai_package_import_pulls_in_no_ida():
    result = _run_probe()
    assert result.returncode == 0, (
        "DEFFAI import is not portable -- it loaded IDA modules.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "LEAKED:" in result.stdout
    assert result.stdout.strip().endswith("LEAKED:")  # empty leak list
