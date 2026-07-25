"""idalib worker system test for `d810cli.py fixture` (ticket d81-rtfh).

Requires the dac.dll ``.i64`` sample (user-supplied, not in the tracked corpus),
so it SKIPs unless ``DAC_IDB`` points at it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
WORKER = REPO / "samples/scripts/fixture_idb_worker.py"
IDB = os.environ.get("DAC_IDB")  # e.g. /path/to/dac.dll.i64

pytestmark = pytest.mark.requires_ida


@pytest.mark.skipif(
    not IDB or not Path(IDB).exists(), reason="set DAC_IDB to the dac.dll .i64 to run"
)
def test_extract_and_resolve_rand(tmp_path):
    out = tmp_path / "sub_1815C8C30.asm"
    env = {**os.environ, "PYTHONPATH": str(REPO / "src")}
    r = subprocess.run(
        [
            sys.executable,
            str(WORKER),
            "extract",
            "--idb",
            IDB,
            "--func",
            "sub_1815C8C30",
            "--out",
            str(out),
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    assert r.returncode == 0, r.stderr
    assert out.exists() and out.stat().st_size > 0
    meta = json.loads(r.stdout.strip().splitlines()[-1])
    assert meta["function"] == "sub_1815C8C30"

    # rand folds at VA 0x181803620 in dac.dll
    r2 = subprocess.run(
        [sys.executable, str(WORKER), "resolve", "--idb", IDB, "--vas", "0x181803620"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert r2.returncode == 0, r2.stderr
    res = json.loads(r2.stdout.strip().splitlines()[-1])
    entry = res[str(0x181803620)]
    assert entry["name"] == "rand"
    assert entry["retargetable"] is True
