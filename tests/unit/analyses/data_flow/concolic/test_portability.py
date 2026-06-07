"""S1 portability gate: the concolic domain imports + runs with no IDA / no z3.

Subprocess so the import graph is clean; the IDA modules are masked to ``None`` so
any reach raises ``ImportError`` (the airtight proof -- execution, not static
analysis), and z3 is asserted absent from ``sys.modules`` after exercising the
domain (ticket llr-xvkt acceptance: "No ida_* / z3 import").
"""
from __future__ import annotations

import subprocess
import sys


def test_concolic_loads_and_runs_without_ida_or_z3() -> None:
    script = (
        "import sys\n"
        "for m in ('ida_hexrays', 'idaapi', 'idc', 'ida_bytes', 'ida_funcs'):\n"
        "    sys.modules[m] = None\n"
        "import d810.analyses.data_flow.concolic as C\n"
        "v = C.ConcolicValue.of(5, 8)\n"
        "assert v.status is C.PrecisionStatus.CONCRETE and v.symbolic is None\n"
        "j = C.ConcolicValue.of(1, 8).join(C.ConcolicValue.of(2, 8))\n"
        "assert j.status is C.PrecisionStatus.ABSTRACT\n"
        "loc = C.LocationRef.stack(0x10, 8)\n"
        "s = C.ConcolicStore().assign(loc, v)\n"
        "assert s.is_concrete_enough([loc])\n"
        "leaked = [m for m in ('ida_hexrays', 'idaapi', 'z3') "
        "if sys.modules.get(m) is not None]\n"
        "assert not leaked, leaked\n"
        "print('CONCOLIC_PORTABLE_OK')\n"
    )
    r = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
    assert r.returncode == 0, f"rc={r.returncode}\nstderr:\n{r.stderr}\nstdout:\n{r.stdout}"
    assert "CONCOLIC_PORTABLE_OK" in r.stdout, r.stdout
