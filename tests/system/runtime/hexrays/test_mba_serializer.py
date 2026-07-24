"""Runtime contracts for canonical MBA snapshot serialization."""

from __future__ import annotations

import ida_hexrays
import pytest

from d810.hexrays import mba_serializer


@pytest.mark.parametrize(
    ("opcode", "expected_name"),
    (
        (ida_hexrays.m_goto, "m_goto"),
        (ida_hexrays.m_jcnd, "m_jcnd"),
        (ida_hexrays.m_jnz, "m_jnz"),
        (ida_hexrays.m_ret, "m_ret"),
    ),
)
def test_serializer_uses_canonical_sdk_opcode_names(
    opcode: int,
    expected_name: str,
) -> None:
    mba_serializer._OPCODE_NAME_CACHE.clear()

    assert mba_serializer._opcode_name(opcode) == expected_name
