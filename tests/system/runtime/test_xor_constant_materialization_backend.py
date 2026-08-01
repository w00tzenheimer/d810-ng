from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.hexrays.mutation.semantic_fragment_backend import (
    SemanticFragmentBackendRejected,
    _require_xor_absolute_envelope,
)
from d810.transforms.fragment_plan import FragmentConstantPublicationEnvelope


def _materialization() -> SimpleNamespace:
    return SimpleNamespace(
        materialization_id="constant:rhad-xor-absolute@0x40C322",
        instruction_ea=0x40C322,
        data_ea=0x48AEC8,
        source_width_bits=8,
        destination_width_bits=8,
        destination_storage=SimpleNamespace(offset=8),
        publication_envelope=(
            FragmentConstantPublicationEnvelope.IMPORTED_GLOBAL_BYTE_XOR
        ),
    )


def _xor_fact(
    *,
    writes_condition_codes: bool = False,
    global_on_left: bool = True,
) -> SimpleNamespace:
    global_operand = (int(ida_hexrays.mop_v), 1, ("global", 0x48AEC8))
    register_operand = (int(ida_hexrays.mop_r), 1, ("register", 8))
    return SimpleNamespace(
        opcode=int(ida_hexrays.m_xor),
        operand_shape=(
            global_operand if global_on_left else register_operand,
            register_operand if global_on_left else global_operand,
            register_operand,
        ),
        writes_condition_codes=writes_condition_codes,
    )


def test_xor_constant_preflight_accepts_exact_left_global_byte_envelope() -> None:
    _require_xor_absolute_envelope(
        _materialization(),
        (_xor_fact(),),
    )


def test_xor_constant_preflight_rejects_swapped_global_operand() -> None:
    with pytest.raises(
        SemanticFragmentBackendRejected,
        match="data flow differs",
    ) as exc_info:
        _require_xor_absolute_envelope(
            _materialization(),
            (_xor_fact(global_on_left=False),),
        )

    assert exc_info.value.reason_code == "constant_materialization_dataflow_mismatch"
