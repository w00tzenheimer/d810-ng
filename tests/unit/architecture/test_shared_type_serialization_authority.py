from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.pure_python

ROOT = Path(__file__).resolve().parents[3]
SHARED = ROOT / "src/d810/backends/ida/type_serialization.py"
CONSUMERS = (
    ROOT / "src/d810/backends/hexrays/global_const_annotation.py",
    ROOT / "src/d810/backends/ida/native_patch/capture.py",
    ROOT / "src/d810/backends/ida/native_patch/reanalysis.py",
    ROOT / "src/d810/backends/ida/idb_preparation/type_metadata.py",
)


def test_only_shared_adapter_serializes_or_deserializes_tinfo() -> None:
    assert ".serialize(" in SHARED.read_text(encoding="utf-8")
    assert ".deserialize(" in SHARED.read_text(encoding="utf-8")

    for consumer in CONSUMERS:
        source = consumer.read_text(encoding="utf-8")
        assert ".serialize(" not in source, consumer
        assert ".deserialize(" not in source, consumer


def test_hexrays_const_annotation_never_writes_types_directly() -> None:
    source = CONSUMERS[0].read_text(encoding="utf-8")
    assert "apply_tinfo(" not in source
    assert "del_tinfo(" not in source
