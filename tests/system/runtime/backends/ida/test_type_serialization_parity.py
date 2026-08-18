from __future__ import annotations

import pytest

pytestmark = [pytest.mark.requires_ida, pytest.mark.runtime]

ida_typeinf = pytest.importorskip("ida_typeinf")
ida_name = pytest.importorskip("ida_name")
idaapi = pytest.importorskip("idaapi")

from d810.backends.hexrays.global_const_annotation import (  # noqa: E402
    referenced_global_items,
)
from d810.backends.ida.idb_preparation.type_metadata import IdaTypeMetadata  # noqa: E402
from d810.backends.ida.type_serialization import (  # noqa: E402
    apply_serialized_tinfo,
    capture_serialized_tinfo,
    serialize_tinfo,
)


def _snapshot_tuple(snapshot):
    return snapshot.parts


def _parts_tuple(parts):
    if parts is None:
        return None
    return (parts.type_bytes, parts.field_bytes, parts.field_comment_bytes)


def _scalar():
    tif = ida_typeinf.tinfo_t()
    tif.create_simple_type(ida_typeinf.BTF_UINT32)
    assert not tif.empty()
    return tif


def _array():
    element = _scalar()
    tif = ida_typeinf.tinfo_t()
    assert tif.create_array(element, 8, 0)
    return tif


def _struct():
    tif = ida_typeinf.tinfo_t()
    assert ida_typeinf.parse_decl(
        tif,
        None,
        "struct d810_type_parity_probe { unsigned int value; unsigned char tag; };",
        ida_typeinf.PT_SIL,
    )
    return tif


def test_shared_and_preparation_capture_are_byte_identical_for_type_shapes(
    copy_of_idb,
) -> None:
    function_ea = int(ida_name.get_name_ea(idaapi.BADADDR, "global_const_rva_guard"))
    if function_ea == idaapi.BADADDR:
        pytest.skip("global_const_rva_guard not found")
    items = referenced_global_items(function_ea)
    if not items:
        pytest.skip("fixture has no referenced global data item")
    item_ea = int(items[0].evidence.item_head)
    original = capture_serialized_tinfo(item_ea)
    adapter = IdaTypeMetadata()
    try:
        assert apply_serialized_tinfo(item_ea, None)
        assert adapter.capture(item_ea).present is False
        assert capture_serialized_tinfo(item_ea) is None

        for tif in (_scalar(), _array(), _struct()):
            parts = serialize_tinfo(tif)
            assert apply_serialized_tinfo(item_ea, parts)
            assert _snapshot_tuple(adapter.capture(item_ea)) == _parts_tuple(
                capture_serialized_tinfo(item_ea)
            )
    finally:
        assert apply_serialized_tinfo(item_ea, original)
