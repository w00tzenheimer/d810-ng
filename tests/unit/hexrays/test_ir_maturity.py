from __future__ import annotations

import importlib
import json
import sys
from types import SimpleNamespace


def test_hexrays_maturity_envelope_json_includes_portable_and_provider_fields(
    monkeypatch,
) -> None:
    fake_ida_hexrays = SimpleNamespace(
        MMAT_ZERO=-1,
        MMAT_GENERATED=0,
        MMAT_PREOPTIMIZED=1,
        MMAT_LOCOPT=2,
        MMAT_CALLS=3,
        MMAT_GLBOPT1=4,
        MMAT_GLBOPT2=5,
        MMAT_GLBOPT3=6,
        MMAT_LVARS=7,
    )
    monkeypatch.setitem(sys.modules, "ida_hexrays", fake_ida_hexrays)
    sys.modules.pop("d810.hexrays.ir_maturity", None)
    try:
        ir_maturity = importlib.import_module("d810.hexrays.ir_maturity")
        payload = json.loads(ir_maturity.hexrays_maturity_envelope_json(4))
    finally:
        sys.modules.pop("d810.hexrays.ir_maturity", None)

    assert payload == {
        "ir": "GLOBAL_ANALYZED",
        "snapshot_form": "OPTIMIZED_IR",
        "provider": "hexrays",
        "provider_id": 4,
        "provider_name": "MMAT_GLBOPT1",
    }
