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


def _xor_fact(*, writes_condition_codes: bool) -> SimpleNamespace:
    return SimpleNamespace(
        opcode=int(ida_hexrays.m_xor),
        operand_shape=(
            (int(ida_hexrays.mop_r), 1, ("register", 8)),
            (int(ida_hexrays.mop_v), 1, ("global", 0x48AEC8)),
            (int(ida_hexrays.mop_r), 1, ("register", 8)),
        ),
        writes_condition_codes=writes_condition_codes,
    )


def test_xor_constant_preflight_accepts_exact_right_global_byte_envelope() -> None:
    _require_xor_absolute_envelope(
        _materialization(),
        (_xor_fact(writes_condition_codes=True),),
    )


def test_xor_constant_preflight_rejects_missing_flag_producer() -> None:
    with pytest.raises(
        SemanticFragmentBackendRejected,
        match="data flow differs",
    ) as exc_info:
        _require_xor_absolute_envelope(
            _materialization(),
            (_xor_fact(writes_condition_codes=False),),
        )

    assert exc_info.value.reason_code == "constant_materialization_dataflow_mismatch"
