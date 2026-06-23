from __future__ import annotations

import dataclasses
import importlib
import json
import sys
from types import SimpleNamespace

import pytest


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
        native_maturity = ir_maturity.HexRaysMaturity.MMAT_GLBOPT1
        envelope = ir_maturity.hexrays_maturity_envelope(4)
        payload = envelope.to_dict()
    finally:
        sys.modules.pop("d810.hexrays.ir_maturity", None)

    assert native_maturity.value == 4
    assert ir_maturity.HexRaysMaturity.from_id(4) is native_maturity
    assert ir_maturity.HexRaysMaturity.from_name("GLBOPT1") is native_maturity
    assert dataclasses.is_dataclass(envelope)
    with pytest.raises(dataclasses.FrozenInstanceError):
        envelope.provider_name = "MMAT_CALLS"  # type: ignore[misc]
    assert envelope.to_record() == payload
    assert envelope.dump() == payload
    assert json.loads(envelope.dumps()) == payload
    assert json.loads(ir_maturity.hexrays_maturity_envelope_json(4)) == payload
    assert ir_maturity.HexRaysMaturityEnvelope.load(payload) == envelope
    assert ir_maturity.HexRaysMaturityEnvelope.loads(envelope.dumps()) == envelope
    assert payload == {
        "ir": "GLOBAL_ANALYZED",
        "snapshot_form": "OPTIMIZED_IR",
        "provider": "hexrays",
        "provider_id": 4,
        "provider_name": "MMAT_GLBOPT1",
    }


def test_ir_maturity_order_and_fact_collection_sets() -> None:
    from d810.ir.maturity import (
        EARLY_FACT_COLLECTION_IR_MATURITIES,
        IRMaturity,
        LOCAL_FACT_COLLECTION_IR_MATURITIES,
        ir_maturity_rank,
    )

    assert ir_maturity_rank(IRMaturity.LIFTED) == 0
    assert ir_maturity_rank(IRMaturity.GLOBAL_ANALYZED) > ir_maturity_rank(
        IRMaturity.CALL_MODELED
    )
    assert EARLY_FACT_COLLECTION_IR_MATURITIES == frozenset(
        {
            IRMaturity.CANONICAL,
            IRMaturity.LOCAL_OPTIMIZED,
            IRMaturity.CALL_MODELED,
            IRMaturity.GLOBAL_ANALYZED,
        }
    )
    assert LOCAL_FACT_COLLECTION_IR_MATURITIES == frozenset(
        {
            IRMaturity.CANONICAL,
            IRMaturity.LOCAL_OPTIMIZED,
        }
    )
