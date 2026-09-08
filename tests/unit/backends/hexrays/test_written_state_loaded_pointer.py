"""State-only no-escape provenance; arbitrary operand stores still clobber."""

from types import SimpleNamespace
import pytest
from d810.analyses.control_flow.computed_state_writer import StorageKey
from d810.backends.hexrays.evidence import condition_chain_analysis as cca
from tests.unit.backends.hexrays.test_computed_state_write_adapter import (
    _VOCABULARY as V,
    _microcode_vocabulary as _microcode_vocabulary,
    _sub_insn,
    _reg,
    _stk,
    _num,
    _insn,
    _block,
    _Mba,
)


def _address(mop):
    return SimpleNamespace(t=V.mop_a, a=mop, size=8)


def _loaded_pointer():
    result = _sub_insn(V.m_ldx, _reg(100, 2), _stk(552, 8))
    result.size = 8
    return result


def _offset(mop):
    result = _sub_insn(V.m_add, mop, _num(0xF8, 8))
    result.size = 8
    return result


def _receipt(address):
    return cca._collect_written_state_set(
        _Mba(
            {
                0: _block(
                    _insn(V.m_mov, _num(0x12345678), None, _stk(48)),
                    _insn(V.m_stx, _num(0xDEADBEEF), _reg(100, 2), address),
                )
            }
        ),
        48,
    )


@pytest.mark.parametrize("shape", ["observed", "nested_load", "cast"])
def test_loaded_pointer_result_preserves_private_state_receipt(shape):
    address = _loaded_pointer()
    if shape == "nested_load":
        address = _sub_insn(V.m_ldx, _reg(100, 2), address)
    elif shape == "cast":
        address = _sub_insn(70, address)  # value-preserving cast-shaped expression
    receipt = _receipt(_offset(address))
    assert receipt.complete
    assert receipt.constants == frozenset({0x12345678})


def test_explicit_state_address_sibling_of_load_remains_unknown():
    assert not _receipt(
        _sub_insn(V.m_add, _address(_stk(48)), _loaded_pointer())
    ).complete


def test_deep_explicit_address_remains_unknown():
    address = _address(_stk(48))
    for _ in range(5):
        address = _offset(address)
    assert not _receipt(address).complete


def test_malformed_composite_is_not_proof_of_disjointness():
    assert not _receipt(SimpleNamespace(t=V.mop_d, d=None, size=8)).complete


@pytest.mark.parametrize("kind", ["S", "l"])
def test_loaded_pointer_store_still_kills_arbitrary_operand_binding(kind):
    operand = (
        _stk(80)
        if kind == "S"
        else SimpleNamespace(t=V.mop_l, l=SimpleNamespace(idx=0), size=4)
    )
    block = _block(
        _insn(V.m_mov, _num(0x100), None, operand),
        _insn(V.m_stx, _reg(40), _reg(100, 2), _offset(_loaded_pointer())),
    )
    definition = cca._read_storage_definition(
        block, StorageKey(kind, 80 if kind == "S" else 0)
    )
    assert definition.written
    assert definition.value is None


def test_missing_load_opcode_metadata_is_not_an_opaque_load(monkeypatch):
    monkeypatch.delattr(V, "m_ldx")
    address = _sub_insn(None, _reg(100, 2), _stk(552, 8))
    assert not _receipt(address).complete
