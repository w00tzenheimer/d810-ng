"""Register the diag-replay ``DiagSourceLifter`` for the collector diag-source
tests (E opt-4).

These tests build offline diag snapshot targets and run portable fact
collectors over them.  Post opt-4 the collectors have no inline diag branch:
a diag source must be lifted to a canonical ``FlowGraph`` by the registered
``DiagSourceLifter`` (``d810.backends.hexrays.diag_lifter``) before ``from_block``
projects it.  These suites live under ``tests/system/runtime`` (not
``tests/unit``) because they import that backend lifter; it is pure-Python
(no ``ida_*``), so they still run offline without a live IDA.
"""

import pytest

from d810.backends.hexrays.diag_lifter import ensure_diag_lifter_registered


@pytest.fixture(autouse=True)
def _register_diag_lifter():
    ensure_diag_lifter_registered()
    yield
