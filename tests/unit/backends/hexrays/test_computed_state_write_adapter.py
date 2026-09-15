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
    MMAT_LVARS=9,
    m_mov=4,
    m_xdu=7,
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
# Microregister numbers are byte offsets; separate the four-byte operands.
_ECX, _EAX, _EDX, _R8D = 16, 24, 32, 40


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
    return SimpleNamespace(
        t=_VOCABULARY.mop_S, s=SimpleNamespace(off=offset), size=size
    )


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
        self.maturity = 9

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
    mba = _xor_writer_mba({36: (0xA84A23E8, 0xBA1637C8), 135: (0x5FDB1F09, 0x1D431D66)})
    res = _resolve(mba, 2)
    assert res.resolved, res.reason
    assert res.values == frozenset({0x125C1420, 0x4298026F})


def test_the_literal_scan_sees_nothing_for_the_same_block():
    """The discriminating pin: this is exactly what made the receipt incomplete."""
    mba = _xor_writer_mba({36: (0xA84A23E8, 0xBA1637C8), 135: (0x5FDB1F09, 0x1D431D66)})
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
        blocks[serial] = _block(_insn(_VOCABULARY.m_mov, _num(value), None, _reg(_ECX)))
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
    assert res.values == frozenset(
        {((0xD778CBDF ^ 0x3D766243) - 0xCD4068E9) & 0xFFFFFFFF}
    )


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


def test_deferred_register_expression_is_folded_per_incoming_path():
    """A shared store may consume a value computed in its predecessor block."""
    blocks = {
        2: _block(
            _insn(_VOCABULARY.m_mov, _reg(_EDX), None, _stk(_STATE_STKOFF)),
            preds=(3,),
        ),
        3: _block(
            _insn(_VOCABULARY.m_xor, _reg(_EAX), _reg(_EDX), _reg(_EDX)),
            _insn(_VOCABULARY.m_goto),
            preds=(7, 159),
        ),
        7: _block(
            _insn(_VOCABULARY.m_mov, _num(0x5D2FE549), None, _reg(_EAX)),
            _insn(_VOCABULARY.m_mov, _num(0x03604258), None, _reg(_EDX)),
        ),
        159: _block(
            _insn(_VOCABULARY.m_mov, _num(0x2C039622), None, _reg(_EAX)),
            _insn(_VOCABULARY.m_mov, _num(0x09705EB8), None, _reg(_EDX)),
        ),
    }

    res = _resolve(_Mba(blocks), 2)

    assert res.resolved, res.reason
    assert res.values == frozenset({0x5E4FA711, 0x2573C89A})
    assert {e.pred_serial for e in res.evidence} == {7, 159}


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


def test_a_call_cannot_preserve_a_stack_binding_without_effect_evidence():
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
    assert not res.resolved
    assert res.reason == AbstainReason.UNRESOLVED_OPERAND


def test_a_join_on_the_way_back_expands_into_correlated_partitions():
    """A pass-through join preserves one binding per incoming path."""
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
    assert res.resolved, res.reason
    assert res.values == frozenset({0x11111111, 0x22222222})
    assert {e.pred_serial for e in res.evidence} == {6, 7}


def test_join_frontier_keeps_two_operand_bindings_correlated():
    blocks = {
        2: _block(
            _insn(_VOCABULARY.m_xor, _reg(_ECX), _reg(_EAX), _stk(_STATE_STKOFF)),
            preds=(5,),
        ),
        5: _block(_insn(_VOCABULARY.m_goto), preds=(6, 7)),
        6: _block(
            _insn(_VOCABULARY.m_mov, _num(0x10), None, _reg(_ECX)),
            _insn(_VOCABULARY.m_mov, _num(0x01), None, _reg(_EAX)),
        ),
        7: _block(
            _insn(_VOCABULARY.m_mov, _num(0x20), None, _reg(_ECX)),
            _insn(_VOCABULARY.m_mov, _num(0x02), None, _reg(_EAX)),
        ),
    }

    res = _resolve(_Mba(blocks), 2)

    assert res.resolved, res.reason
    assert res.values == frozenset({0x11, 0x22})
    assert len(res.evidence) == 2


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
    blocks = {
        2: _block(_insn(_VOCABULARY.m_mov, _num(7), None, _stk(0x99)), preds=(7,))
    }
    res = _resolve(_Mba(blocks), 2)
    assert res.reason == AbstainReason.NO_STATE_WRITE


@pytest.mark.parametrize("overwrite", ["call", "mov", "arithmetic"])
@pytest.mark.parametrize("same_block", [False, True])
def test_overwrite_never_revives_an_older_predecessor_constant(overwrite, same_block):
    """A killed reaching definition must not close a written-state receipt."""
    seed = _insn(_VOCABULARY.m_mov, _num(0x62127A6B), None, _reg(_ECX))
    kill = {
        "call": _insn(_VOCABULARY.m_call),
        "mov": _insn(_VOCABULARY.m_mov, _reg(_EAX), None, _reg(_ECX)),
        "arithmetic": _insn(_VOCABULARY.m_xor, _reg(_ECX), _reg(_EAX), _reg(_ECX)),
    }[overwrite]
    blocks = {
        2: _block(
            _insn(_VOCABULARY.m_mov, _reg(_ECX), None, _stk(_STATE_STKOFF)),
            preds=(7,),
        ),
        7: _block(*([seed, kill] if same_block else [kill]), preds=(8,)),
        8: _block(seed) if not same_block else _block(),
    }
    res = _resolve(_Mba(blocks), 2)
    assert not res.resolved
    assert res.reason == AbstainReason.UNRESOLVED_OPERAND


@pytest.mark.parametrize("prefix_kind", ["call", "arithmetic"])
def test_writer_block_prefix_cannot_reuse_the_incoming_operand(prefix_kind):
    prefix = {
        "call": _insn(_VOCABULARY.m_call),
        "constant": _insn(_VOCABULARY.m_mov, _num(0x22222222), None, _reg(_ECX)),
        "arithmetic": _insn(_VOCABULARY.m_xor, _reg(_ECX), _reg(_EAX), _reg(_ECX)),
    }[prefix_kind]
    blocks = {
        2: _block(
            prefix,
            _insn(_VOCABULARY.m_mov, _reg(_ECX), None, _stk(_STATE_STKOFF)),
            preds=(7,),
        ),
        7: _block(_insn(_VOCABULARY.m_mov, _num(0x11111111), None, _reg(_ECX))),
    }
    res = _resolve(_Mba(blocks), 2)
    assert not res.resolved
    assert res.reason == AbstainReason.UNRESOLVED_OPERAND


def test_writer_block_literal_binding_combines_with_predecessor_binding():
    blocks = {
        2: _block(
            _insn(_VOCABULARY.m_mov, _num(0x22), None, _reg(_ECX)),
            _insn(_VOCABULARY.m_xor, _reg(_ECX), _reg(_EAX), _stk(_STATE_STKOFF)),
            preds=(7,),
        ),
        7: _block(_insn(_VOCABULARY.m_mov, _num(0x11), None, _reg(_EAX))),
    }

    res = _resolve(_Mba(blocks), 2)

    assert res.resolved, res.reason
    assert res.values == frozenset({0x33})


def test_writer_block_derived_register_is_folded_per_predecessor_path(monkeypatch):
    wide_r8 = _R8D - 8
    monkeypatch.setattr(
        cca,
        "_canonical_mreg_key",
        lambda mreg, width: wide_r8 if mreg in {wide_r8, _R8D} else mreg,
    )
    derived = _sub_insn(
        _VOCABULARY.m_add,
        _reg(_EAX),
        _sub_insn(_VOCABULARY.m_xor, _reg(_ECX), _reg(_R8D)),
    )
    blocks = {
        2: _block(
            _insn(_VOCABULARY.m_xdu, derived, None, _reg(wide_r8, size=8)),
            _insn(_VOCABULARY.m_mov, _reg(_R8D), None, _stk(_STATE_STKOFF)),
            preds=(6, 7),
        ),
        6: _block(
            _insn(_VOCABULARY.m_mov, _num(1), None, _reg(_EAX)),
            _insn(_VOCABULARY.m_mov, _num(2), None, _reg(_ECX)),
            _insn(_VOCABULARY.m_mov, _num(4), None, _reg(_R8D)),
        ),
        7: _block(
            _insn(_VOCABULARY.m_mov, _num(10), None, _reg(_EAX)),
            _insn(_VOCABULARY.m_mov, _num(20), None, _reg(_ECX)),
            _insn(_VOCABULARY.m_mov, _num(40), None, _reg(_R8D)),
        ),
    }

    res = _resolve(_Mba(blocks), 2)

    assert res.resolved, res.reason
    assert res.values == frozenset({1 + (2 ^ 4), 10 + (20 ^ 40)})


@pytest.mark.parametrize(
    ("narrow", "wide"),
    [("eax", "rax"), ("r8d", "r8"), ("r15w", "r15"), ("sil", "rsi")],
)
def test_x86_register_aliases_use_one_widest_family(narrow, wide):
    assert cca._x86_widest_register_name(narrow) == wide


def test_swig_instruction_wrappers_share_native_occurrence_identity():
    native_pointer = object()
    first_wrapper = SimpleNamespace(this=native_pointer)
    second_wrapper = SimpleNamespace(this=native_pointer)

    assert first_wrapper is not second_wrapper
    assert cca._same_instruction_occurrence(first_wrapper, second_wrapper)


def test_join_frontier_abstains_instead_of_truncating_over_partition_budget():
    leaves = tuple(range(10, 75))
    blocks = {
        2: _block(
            _insn(_VOCABULARY.m_mov, _reg(_ECX), None, _stk(_STATE_STKOFF)),
            preds=(5,),
        ),
        5: _block(_insn(_VOCABULARY.m_goto), preds=leaves),
    }
    for serial in leaves:
        blocks[serial] = _block(
            _insn(_VOCABULARY.m_mov, _num(serial), None, _reg(_ECX))
        )

    res = _resolve(_Mba(blocks), 2)

    assert not res.resolved
    assert res.reason == AbstainReason.PREDECESSOR_BUDGET_EXCEEDED


def test_narrow_operand_is_not_folded_as_an_untruncated_u32():
    blocks = {
        2: _block(
            _insn(_VOCABULARY.m_mov, _reg(_ECX, size=1), None, _stk(_STATE_STKOFF)),
            preds=(7,),
        ),
        7: _block(_insn(_VOCABULARY.m_mov, _num(0x12345678), None, _reg(_ECX))),
    }
    res = _resolve(_Mba(blocks), 2)
    assert not res.resolved


def test_overlapping_partial_register_write_kills_the_full_binding():
    blocks = {
        2: _block(
            _insn(_VOCABULARY.m_mov, _reg(16), None, _stk(_STATE_STKOFF)),
            preds=(7,),
        ),
        7: _block(
            _insn(_VOCABULARY.m_mov, _num(0x12345678), None, _reg(16)),
            _insn(_VOCABULARY.m_mov, _num(0xAB, size=1), None, _reg(17, size=1)),
        ),
    }
    assert not _resolve(_Mba(blocks), 2).resolved


@pytest.mark.parametrize("barrier", ["partial-register", "call", "stack-alias", "indirect-store"])
def test_in_block_state_receipt_cannot_revive_arithmetic_before_a_clobber(barrier):
    lvar = SimpleNamespace(t=_VOCABULARY.mop_l, l=SimpleNamespace(idx=0), size=4)
    operand = lvar if barrier in {"stack-alias", "indirect-store"} else _reg(_ECX)
    if barrier == "partial-register":
        overwrite = _insn(_VOCABULARY.m_mov, _num(0xAA, size=1), None, _reg(_ECX + 1, size=1))
    elif barrier == "call":
        overwrite = _insn(_VOCABULARY.m_call)
    elif barrier == "stack-alias":
        overwrite = _insn(_VOCABULARY.m_mov, _reg(_EDX), None, _stk(80))
    else:
        overwrite = _insn(_VOCABULARY.m_stx, _reg(_EDX), _reg(100, size=2), _reg(64, size=8))
    mba = _Mba({0: _block(
        _insn(_VOCABULARY.m_xor, _num(0x100), _num(1), operand),
        overwrite,
        _insn(_VOCABULARY.m_mov, operand, None, _stk(_STATE_STKOFF)),
    )})
    mba.vars = [SimpleNamespace(location=SimpleNamespace(is_stkoff=lambda: True, stkoff=lambda: 80))]

    receipt = cca._collect_written_state_set(mba, _STATE_STKOFF)

    assert not receipt.complete
    assert 0x101 not in receipt.constants


def test_in_block_state_receipt_preserves_unclobbered_arithmetic():
    mba = _Mba({0: _block(
        _insn(_VOCABULARY.m_xor, _num(0x100), _num(1), _reg(_ECX)),
        _insn(_VOCABULARY.m_mov, _num(0xAA), None, _reg(_EDX)),
        _insn(_VOCABULARY.m_mov, _reg(_ECX), None, _stk(_STATE_STKOFF)),
    )})

    receipt = cca._collect_written_state_set(mba, _STATE_STKOFF)

    assert receipt.complete
    assert receipt.constants == frozenset({0x101})


@pytest.mark.parametrize("barrier", ["register-write", "call"])
def test_unmapped_lvar_operand_cannot_survive_register_clobbers(barrier):
    local = SimpleNamespace(t=_VOCABULARY.mop_l, l=SimpleNamespace(idx=0), size=4)
    kill = (_insn(_VOCABULARY.m_call) if barrier == "call"
            else _insn(_VOCABULARY.m_mov, _reg(_EDX), None, _reg(_ECX)))
    mba = _Mba({
        0: _block(_insn(_VOCABULARY.m_mov, _num(0x100), None, local), kill),
        1: _block(_insn(_VOCABULARY.m_xor, local, _num(1), _stk(_STATE_STKOFF)), preds=(0,)),
    })
    assert not _resolve(mba, 1).resolved


def test_lvar_stack_mapping_requires_sdk_location_and_maturity_guards():
    invalid_accesses = []
    location = SimpleNamespace(is_stkoff=lambda: False,
                               stkoff=lambda: invalid_accesses.append("stkoff") or 80)
    mba = SimpleNamespace(maturity=9, vars=[SimpleNamespace(location=location)])
    assert cca._lvar_stkoff(mba, 0) is None
    local = SimpleNamespace(t=_VOCABULARY.mop_l, l=SimpleNamespace(idx=0), size=4)
    assert not cca._mop_matches_stkoff(local, 80, mba=mba)
    assert not invalid_accesses

    class EarlyMba:
        maturity = 0

        @property
        def vars(self):
            invalid_accesses.append("vars")
            return []

    assert cca._lvar_stkoff(EarlyMba(), 0) is None
    assert not invalid_accesses


def test_unknown_call_invalidates_computed_stack_operand():
    # Arbitrary computed operands do not inherit the state slot's no-escape
    # assumption: the callee may receive an address of this stack storage.
    mba = _Mba({
        0: _block(_insn(_VOCABULARY.m_mov, _num(0x100), None, _stk(80)),
                  _insn(_VOCABULARY.m_call)),
        1: _block(_insn(_VOCABULARY.m_xor, _stk(80), _num(1), _stk(_STATE_STKOFF)), preds=(0,)),
    })
    assert not _resolve(mba, 1).resolved
