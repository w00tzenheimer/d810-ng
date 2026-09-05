"""Computed state-write resolution over live-shaped microcode (ticket d81-czrc).

``sub_7FFB0E398850`` writes its dispatcher state 75 times, and 6 of those writes
are *computed* from registers assigned in the predecessor blocks rather than
written as a literal.  The literal scan (``_extract_state_from_block``) returns
``None`` for them and the intra-block fold (``_resolve_mop_value_in_block``)
cannot reach a definition that lives one hop up, so those states were simply
absent from the written-state set -- the one direction that is unsound for a
closed-world consumer, because "absent" is what a range row's exactness proof
reads as "no second state here".

These tests pin the adapter that closes the gap: it partitions by predecessor,
binds every operand on each incoming edge, folds once per partition, and either
proves the full constant set or abstains with a named reason.

The fakes are duck-typed microcode operands, not mocks of an ``ida_*`` module:
the vocabulary comes from the backend's own ``condition_chain_runtime`` shim,
exactly as ``test_written_state_receipt.py`` does.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.analyses.control_flow.computed_state_writer import AbstainReason
from d810.backends.hexrays import condition_chain_runtime
from d810.backends.hexrays.evidence import condition_chain_analysis as cca

_VOCABULARY = SimpleNamespace(
    m_mov=4,
    m_stx=62,
    m_add=28,
    m_sub=29,
    m_xor=31,
    m_and=21,
    m_or=22,
    m_mul=30,
    m_call=57,
    m_icall=58,
    m_goto=55,
    m_ldx=61,
    mop_r=1,
    mop_n=2,
    mop_S=5,
    mop_d=6,
    mop_a=8,
    mop_l=9,
)

_STATE_STKOFF = 48
# Register numbers are arbitrary identities; only distinctness matters.
_ECX, _EAX, _EDX, _R8D = 1, 2, 3, 4


@pytest.fixture(autouse=True)
def _microcode_vocabulary(monkeypatch):
    monkeypatch.setattr(condition_chain_runtime, "_idaapi", lambda: _VOCABULARY)
    saved = (cca._maps_initialized, cca.OPCODE_MAP, cca.MOP_TYPE_MAP)
    cca._maps_initialized = False
    cca._init_constants()
    yield
    cca._maps_initialized, cca.OPCODE_MAP, cca.MOP_TYPE_MAP = saved


def _num(value: int, size: int = 4):
    return SimpleNamespace(
        t=_VOCABULARY.mop_n, nnn=SimpleNamespace(value=value), size=size
    )


def _stk(offset: int, size: int = 4):
    return SimpleNamespace(t=_VOCABULARY.mop_S, s=SimpleNamespace(off=offset), size=size)


def _reg(register_id: int, size: int = 4):
    return SimpleNamespace(t=_VOCABULARY.mop_r, r=register_id, size=size)


def _sub_insn(opcode: int, left=None, right=None):
    """A nested ``mop_d`` operand wrapping a sub-instruction."""
    inner = SimpleNamespace(opcode=opcode, l=left, r=right, d=None, next=None)
    return SimpleNamespace(t=_VOCABULARY.mop_d, d=inner, size=4)


def _insn(opcode: int, left=None, right=None, dest=None):
    return SimpleNamespace(opcode=opcode, l=left, r=right, d=dest, next=None)


def _block(*insns, preds=()):
    head = None
    for insn in reversed(insns):
        insn.next = head
        head = insn
    return SimpleNamespace(head=head, predset=list(preds))


class _Mba:
    def __init__(self, blocks):
        self._blocks = dict(blocks)
        self.qty = (max(self._blocks) + 1) if self._blocks else 0
        self.vars = []

    def get_mblock(self, serial):
        return self._blocks.get(int(serial))


def _resolve(mba, serial):
    return cca._resolve_computed_state_write_in_block(
        mba.get_mblock(serial), mba=mba, state_var_stkoff=_STATE_STKOFF
    )


# --------------------------------------------------------------------------
# the real writer shapes
# --------------------------------------------------------------------------


def _xor_writer_mba(preds_consts):
    """blk2: ``xor ecx, eax -> statevar``, reached from two constant setters."""
    blocks = {
        2: _block(
            _insn(_VOCABULARY.m_xor, _reg(_ECX), _reg(_EAX), _stk(_STATE_STKOFF)),
            _insn(_VOCABULARY.m_goto),
            preds=tuple(preds_consts),
        )
    }
    for serial, (ecx, eax) in preds_consts.items():
        insns = []
        if ecx is not None:
            insns.append(_insn(_VOCABULARY.m_mov, _num(ecx), None, _reg(_ECX)))
        if eax is not None:
            insns.append(_insn(_VOCABULARY.m_mov, _num(eax), None, _reg(_EAX)))
        insns.append(_insn(_VOCABULARY.m_goto))
        blocks[serial] = _block(*insns, preds=())
    return _Mba(blocks)


def test_xor_of_two_registers_resolves_both_partitions():
    """The real blk136 constants: 0xA84A23E8^0xBA1637C8 and 0x5FDB1F09^0x1D431D66."""
    mba = _xor_writer_mba(
        {36: (0xA84A23E8, 0xBA1637C8), 135: (0x5FDB1F09, 0x1D431D66)}
    )
    res = _resolve(mba, 2)
    assert res.resolved, res.reason
    assert res.values == frozenset({0x125C1420, 0x4298026F})


def test_the_literal_scan_sees_nothing_for_the_same_block():
    """The discriminating pin: this is exactly what made the receipt incomplete."""
    mba = _xor_writer_mba(
        {36: (0xA84A23E8, 0xBA1637C8), 135: (0x5FDB1F09, 0x1D431D66)}
    )
    assert (
        cca._extract_state_from_block(mba.get_mblock(2), _STATE_STKOFF, mba=mba) is None
    )


def test_sub_of_two_registers_wraps_to_u32():
    """The real blk123 constants; the first partition borrows."""
    blocks = {
        2: _block(
            _insn(_VOCABULARY.m_sub, _reg(_EAX), _reg(_ECX), _stk(_STATE_STKOFF)),
            preds=(19, 122),
        ),
        19: _block(
            _insn(_VOCABULARY.m_mov, _num(0x149FBC10), None, _reg(_EAX)),
            _insn(_VOCABULARY.m_mov, _num(0xC39DF36E), None, _reg(_ECX)),
        ),
        122: _block(
            _insn(_VOCABULARY.m_mov, _num(0x515DD7EF), None, _reg(_EAX)),
            _insn(_VOCABULARY.m_mov, _num(0x1A147C74), None, _reg(_ECX)),
        ),
    }
    res = _resolve(_Mba(blocks), 2)
    assert res.resolved, res.reason
    assert res.values == frozenset({0x5101C8A2, 0x37495B7B})


def test_bare_register_mov_resolves_across_many_predecessors():
    """blk4's shape: ``mov ecx -> statevar`` with one constant per predecessor."""
    consts = {3: 0x62127A6B, 31: 0x770D420C, 46: 0x42CBD42C, 107: 0x0728280D}
    blocks = {
        2: _block(
            _insn(_VOCABULARY.m_mov, _reg(_ECX), None, _stk(_STATE_STKOFF)),
            preds=tuple(consts),
        )
    }
    for serial, value in consts.items():
        blocks[serial] = _block(
            _insn(_VOCABULARY.m_mov, _num(value), None, _reg(_ECX))
        )
    res = _resolve(_Mba(blocks), 2)
    assert res.resolved, res.reason
    assert res.values == frozenset(consts.values())


def test_last_definition_in_the_predecessor_wins():
    """blk46 rewrites ecx three times before its goto; only the last reaches."""
    blocks = {
        2: _block(
            _insn(_VOCABULARY.m_mov, _reg(_ECX), None, _stk(_STATE_STKOFF)),
            preds=(46,),
        ),
        46: _block(
            _insn(_VOCABULARY.m_mov, _num(0x11111111), None, _reg(_ECX)),
            _insn(_VOCABULARY.m_mov, _num(0x22222222), None, _reg(_ECX)),
            _insn(_VOCABULARY.m_mov, _num(0x42CBD42C), None, _reg(_ECX)),
        ),
    }
    res = _resolve(_Mba(blocks), 2)
    assert res.values == frozenset({0x42CBD42C})


def test_nested_mop_d_operand_tree_folds():
    """``sub((ecx ^ eax), edx) -> statevar`` -- three leaves, one partition."""
    blocks = {
        2: _block(
            _insn(
                _VOCABULARY.m_sub,
                _sub_insn(_VOCABULARY.m_xor, _reg(_ECX), _reg(_EAX)),
                _reg(_EDX),
                _stk(_STATE_STKOFF),
            ),
            preds=(9,),
        ),
        9: _block(
            _insn(_VOCABULARY.m_mov, _num(0xD778CBDF), None, _reg(_ECX)),
            _insn(_VOCABULARY.m_mov, _num(0x3D766243), None, _reg(_EAX)),
            _insn(_VOCABULARY.m_mov, _num(0xCD4068E9), None, _reg(_EDX)),
        ),
    }
    res = _resolve(_Mba(blocks), 2)
    assert res.resolved, res.reason
    assert res.values == frozenset({((0xD778CBDF ^ 0x3D766243) - 0xCD4068E9) & 0xFFFFFFFF})


def test_mixed_register_and_stack_operands_resolve():
    blocks = {
        2: _block(
            _insn(_VOCABULARY.m_xor, _reg(_EDX), _stk(0x80), _stk(_STATE_STKOFF)),
            preds=(10, 11),
        ),
        10: _block(
            _insn(_VOCABULARY.m_mov, _num(0xF054A9FE), None, _reg(_EDX)),
            _insn(_VOCABULARY.m_mov, _num(0xAECEB876), None, _stk(0x80)),
        ),
        11: _block(
            _insn(_VOCABULARY.m_mov, _num(0xCB62C29C), None, _reg(_EDX)),
            _insn(_VOCABULARY.m_mov, _num(0xCA4CCF17), None, _stk(0x80)),
        ),
    }
    res = _resolve(_Mba(blocks), 2)
    assert res.values == frozenset({0x5E9A1188, 0x012E0D8B})


def test_constant_is_found_one_hop_up_a_unique_predecessor_chain():
    blocks = {
        2: _block(
            _insn(_VOCABULARY.m_mov, _reg(_ECX), None, _stk(_STATE_STKOFF)),
            preds=(5,),
        ),
        5: _block(_insn(_VOCABULARY.m_goto), preds=(6,)),
        6: _block(_insn(_VOCABULARY.m_mov, _num(0x0AFBB178), None, _reg(_ECX))),
    }
    res = _resolve(_Mba(blocks), 2)
    assert res.values == frozenset({0x0AFBB178})


# --------------------------------------------------------------------------
# abstentions -- the negative controls
# --------------------------------------------------------------------------


def test_one_predecessor_without_the_operand_abstains():
    mba = _xor_writer_mba({36: (0xA84A23E8, 0xBA1637C8), 135: (0x5FDB1F09, None)})
    res = _resolve(mba, 2)
    assert not res.resolved
    assert res.reason == AbstainReason.UNRESOLVED_OPERAND
    assert res.values == frozenset()


def test_a_call_after_the_definition_clobbers_a_register_binding():
    """The ABI may destroy a scratch register across a call, so the binding dies."""
    blocks = {
        2: _block(
            _insn(_VOCABULARY.m_mov, _reg(_ECX), None, _stk(_STATE_STKOFF)),
            preds=(7,),
        ),
        7: _block(
            _insn(_VOCABULARY.m_mov, _num(0x62127A6B), None, _reg(_ECX)),
            _insn(_VOCABULARY.m_call),
        ),
    }
    res = _resolve(_Mba(blocks), 2)
    assert not res.resolved
    assert res.reason == AbstainReason.UNRESOLVED_OPERAND


def test_a_call_before_the_definition_does_not_clobber_it():
    blocks = {
        2: _block(
            _insn(_VOCABULARY.m_mov, _reg(_ECX), None, _stk(_STATE_STKOFF)),
            preds=(7,),
        ),
        7: _block(
            _insn(_VOCABULARY.m_call),
            _insn(_VOCABULARY.m_mov, _num(0x62127A6B), None, _reg(_ECX)),
        ),
    }
    res = _resolve(_Mba(blocks), 2)
    assert res.values == frozenset({0x62127A6B})


def test_a_call_does_not_clobber_a_stack_binding():
    blocks = {
        2: _block(
            _insn(_VOCABULARY.m_mov, _stk(0x80), None, _stk(_STATE_STKOFF)),
            preds=(7,),
        ),
        7: _block(
            _insn(_VOCABULARY.m_mov, _num(0x62127A6B), None, _stk(0x80)),
            _insn(_VOCABULARY.m_call),
        ),
    }
    res = _resolve(_Mba(blocks), 2)
    assert res.values == frozenset({0x62127A6B})


def test_a_fork_on_the_way_back_abstains_rather_than_guessing():
    """A join has no flow-sensitively unique constant, so the partition dies."""
    blocks = {
        2: _block(
            _insn(_VOCABULARY.m_mov, _reg(_ECX), None, _stk(_STATE_STKOFF)),
            preds=(5,),
        ),
        5: _block(_insn(_VOCABULARY.m_goto), preds=(6, 7)),
        6: _block(_insn(_VOCABULARY.m_mov, _num(0x11111111), None, _reg(_ECX))),
        7: _block(_insn(_VOCABULARY.m_mov, _num(0x22222222), None, _reg(_ECX))),
    }
    res = _resolve(_Mba(blocks), 2)
    assert not res.resolved
    assert res.reason == AbstainReason.UNRESOLVED_OPERAND


def test_a_nonconstant_definition_abstains():
    blocks = {
        2: _block(
            _insn(_VOCABULARY.m_mov, _reg(_ECX), None, _stk(_STATE_STKOFF)),
            preds=(7,),
        ),
        7: _block(_insn(_VOCABULARY.m_mov, _reg(_EAX), None, _reg(_ECX))),
    }
    res = _resolve(_Mba(blocks), 2)
    assert not res.resolved
    assert res.reason == AbstainReason.UNRESOLVED_OPERAND


def test_an_unsupported_opcode_abstains_instead_of_folding():
    blocks = {
        2: _block(
            _insn(_VOCABULARY.m_ldx, _reg(_ECX), _reg(_EAX), _stk(_STATE_STKOFF)),
            preds=(7,),
        ),
        7: _block(
            _insn(_VOCABULARY.m_mov, _num(1), None, _reg(_ECX)),
            _insn(_VOCABULARY.m_mov, _num(2), None, _reg(_EAX)),
        ),
    }
    res = _resolve(_Mba(blocks), 2)
    assert not res.resolved
    assert res.reason == AbstainReason.UNFOLDABLE_OPERATION


def test_a_block_with_no_predecessors_abstains():
    blocks = {
        2: _block(
            _insn(_VOCABULARY.m_mov, _reg(_ECX), None, _stk(_STATE_STKOFF)), preds=()
        )
    }
    res = _resolve(_Mba(blocks), 2)
    assert not res.resolved
    assert res.reason == AbstainReason.NO_PREDECESSORS


def test_a_purely_literal_write_is_left_to_the_literal_scan():
    blocks = {
        2: _block(
            _insn(_VOCABULARY.m_mov, _num(0x1CAFDDE5), None, _stk(_STATE_STKOFF)),
            preds=(7,),
        ),
        7: _block(_insn(_VOCABULARY.m_goto)),
    }
    res = _resolve(_Mba(blocks), 2)
    assert not res.resolved
    assert res.reason == AbstainReason.NO_STATE_WRITE
    assert (
        cca._extract_state_from_block(_Mba(blocks).get_mblock(2), _STATE_STKOFF)
        == 0x1CAFDDE5
    )


def test_a_block_that_never_touches_the_state_slot_abstains():
    blocks = {2: _block(_insn(_VOCABULARY.m_mov, _num(7), None, _stk(0x99)), preds=(7,))}
    res = _resolve(_Mba(blocks), 2)
    assert res.reason == AbstainReason.NO_STATE_WRITE
