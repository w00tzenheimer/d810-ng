"""Written-state closure must account for SDK stores and overlapping aliases."""

from types import SimpleNamespace

import pytest

from d810.analyses.control_flow.route_exactness import is_exact_route_interval
from d810.backends.hexrays import condition_chain_runtime
from d810.backends.hexrays.evidence import condition_chain_analysis as cca
from tests.unit.backends.hexrays.test_computed_state_write_adapter import (
    _Mba,
    _STATE_STKOFF,
    _VOCABULARY,
    _block,
    _insn,
    _num,
    _reg,
    _stk,
)

_STATE = 0x12345678
_SECOND_STATE = 0x1234AA78
_OPERAND_OFF = 80
_STATE_REG = 16
_UNKNOWN_REG = 40


@pytest.fixture(autouse=True)
def _microcode_vocabulary(monkeypatch):
    monkeypatch.setattr(condition_chain_runtime, "_idaapi", lambda: _VOCABULARY)
    saved = (cca._maps_initialized, cca.OPCODE_MAP, cca.MOP_TYPE_MAP)
    cca._maps_initialized = False
    cca._init_constants()
    yield
    cca._maps_initialized, cca.OPCODE_MAP, cca.MOP_TYPE_MAP = saved


def _address(operand):
    return SimpleNamespace(t=_VOCABULARY.mop_a, a=operand, size=8)


def _lvar(index, size=4):
    return SimpleNamespace(t=_VOCABULARY.mop_l, l=SimpleNamespace(idx=index), size=size)


def _store(value, address):
    # SDK stx: l=data, r=segment, d=address. The segment is not the address.
    return _insn(_VOCABULARY.m_stx, value, _reg(100, size=2), address)


def _move(value, destination):
    return _insn(_VOCABULARY.m_mov, value, None, destination)


def _collect(mba, *, state_reg=None):
    return cca._collect_written_state_set(
        mba,
        None if state_reg is not None else _STATE_STKOFF,
        state_var_reg=state_reg,
    )


def _assert_range_refused(receipt):
    assert not is_exact_route_interval(
        lo=0x12340000,
        hi=0x12350000,
        state=_STATE,
        written_states=receipt,
    )


def test_sdk_store_to_state_address_adds_the_second_written_state():
    mba = _Mba(
        {
            0: _block(
                _move(_num(_STATE), _stk(_STATE_STKOFF)),
                _store(_num(_SECOND_STATE), _address(_stk(_STATE_STKOFF))),
            ),
        }
    )

    receipt = _collect(mba)

    assert receipt.complete
    assert receipt.constants == frozenset({_STATE, _SECOND_STATE})
    _assert_range_refused(receipt)


def test_sdk_store_to_unresolved_stack_address_withdraws_completeness():
    unresolved_stack = SimpleNamespace(
        t=_VOCABULARY.mop_S, s=SimpleNamespace(off=None), size=4
    )
    mba = _Mba(
        {
            0: _block(
                _move(_num(_STATE), _stk(_STATE_STKOFF)),
                _store(_num(_SECOND_STATE), _address(unresolved_stack)),
            ),
        }
    )

    receipt = _collect(mba)

    assert not receipt.complete
    assert receipt.reasons
    _assert_range_refused(receipt)


def test_sdk_store_to_disjoint_known_stack_slot_preserves_state_receipt():
    mba = _Mba(
        {
            0: _block(
                _move(_num(_STATE), _stk(_STATE_STKOFF)),
                _store(_num(_SECOND_STATE), _address(_stk(_OPERAND_OFF))),
            ),
        }
    )

    receipt = _collect(mba)

    assert receipt.complete
    assert receipt.constants == frozenset({_STATE})


@pytest.mark.parametrize("storage_kind", ["stack", "register"])
@pytest.mark.parametrize("offset", [0, 1], ids=["same-base", "interior-byte"])
@pytest.mark.parametrize("size", [1, 2], ids=["byte", "word"])
def test_partial_state_write_withdraws_complete_u32_receipt(storage_kind, offset, size):
    if storage_kind == "stack":
        whole = _stk(_STATE_STKOFF)
        partial = _stk(_STATE_STKOFF + offset, size=size)
        state_reg = None
    else:
        whole = _reg(_STATE_REG)
        partial = _reg(_STATE_REG + offset, size=size)
        state_reg = _STATE_REG
    mba = _Mba(
        {0: _block(_move(_num(_STATE), whole), _move(_num(0xAA, size=size), partial))}
    )

    receipt = _collect(mba, state_reg=state_reg)

    assert not receipt.complete
    assert receipt.reasons
    _assert_range_refused(receipt)


@pytest.mark.parametrize("location", ["predecessor", "writer-prefix"])
def test_addressed_operand_store_blocks_predecessor_constant_reuse(location):
    # The stored value is unknown: recovering the earlier constant is unsound,
    # and folding a replacement constant cannot legitimately discharge this test.
    overwrite = _store(_reg(_UNKNOWN_REG), _address(_stk(_OPERAND_OFF)))
    initial = _move(_num(0x100), _stk(_OPERAND_OFF))
    writer = _insn(_VOCABULARY.m_xor, _stk(_OPERAND_OFF), _num(1), _stk(_STATE_STKOFF))
    mba = _Mba(
        {
            0: _block(initial, *([overwrite] if location == "predecessor" else [])),
            1: _block(
                *([overwrite] if location == "writer-prefix" else []),
                writer,
                preds=(0,),
            ),
        }
    )

    resolution = cca._resolve_computed_state_write_in_block(
        mba.get_mblock(1), mba=mba, state_var_stkoff=_STATE_STKOFF
    )
    receipt = _collect(mba)

    assert not resolution.resolved
    assert not resolution.values
    assert not receipt.complete


@pytest.mark.parametrize("location", ["predecessor", "writer-prefix"])
@pytest.mark.parametrize("operand_kind", ["stack", "lvar"])
def test_mapped_stack_lvar_operand_alias_blocks_stale_binding(location, operand_kind):
    operand = _stk(_OPERAND_OFF) if operand_kind == "stack" else _lvar(0)
    alias = _lvar(0) if operand_kind == "stack" else _stk(_OPERAND_OFF)
    initial = _move(_num(0x100), operand)
    overwrite = _move(_reg(_UNKNOWN_REG), alias)
    writer = _insn(_VOCABULARY.m_xor, operand, _num(1), _stk(_STATE_STKOFF))
    mba = _Mba(
        {
            0: _block(initial, *([overwrite] if location == "predecessor" else [])),
            1: _block(
                *([overwrite] if location == "writer-prefix" else []),
                writer,
                preds=(0,),
            ),
        }
    )
    mba.vars = [
        SimpleNamespace(
            location=SimpleNamespace(
                is_stkoff=lambda: True, stkoff=lambda: _OPERAND_OFF
            )
        )
    ]

    resolution = cca._resolve_computed_state_write_in_block(
        mba.get_mblock(1), mba=mba, state_var_stkoff=_STATE_STKOFF
    )
    receipt = _collect(mba)

    assert not resolution.resolved
    assert not resolution.values
    assert not receipt.complete


def test_opaque_pointer_store_retains_private_state_no_escape_assumption():
    mba = _Mba(
        {
            0: _block(
                _move(_num(_STATE), _stk(_STATE_STKOFF)),
                _store(_reg(_UNKNOWN_REG), _reg(64, size=8)),
            ),
        }
    )

    receipt = _collect(mba)

    assert receipt.complete
    assert receipt.constants == frozenset({_STATE})


@pytest.mark.parametrize("location", ["predecessor", "writer-prefix"])
@pytest.mark.parametrize("operand_kind", ["stack", "lvar"])
def test_unresolved_indirect_store_blocks_computed_operand_reuse(
    location, operand_kind
):
    # The private-state no-escape assumption cannot certify arbitrary operands.
    operand = _stk(_OPERAND_OFF) if operand_kind == "stack" else _lvar(0)
    initial = _move(_num(0x100), operand)
    overwrite = _store(_reg(_UNKNOWN_REG), _reg(64, size=8))
    writer = _insn(_VOCABULARY.m_xor, operand, _num(1), _stk(_STATE_STKOFF))
    mba = _Mba(
        {
            0: _block(initial, *([overwrite] if location == "predecessor" else [])),
            1: _block(
                *([overwrite] if location == "writer-prefix" else []),
                writer,
                preds=(0,),
            ),
        }
    )
    mba.vars = [
        SimpleNamespace(
            location=SimpleNamespace(
                is_stkoff=lambda: True, stkoff=lambda: _OPERAND_OFF
            )
        )
    ]

    resolution = cca._resolve_computed_state_write_in_block(
        mba.get_mblock(1), mba=mba, state_var_stkoff=_STATE_STKOFF
    )
    receipt = _collect(mba)

    assert not resolution.resolved
    assert not resolution.values
    assert not receipt.complete
