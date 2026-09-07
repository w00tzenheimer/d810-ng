"""Unit tests for the computed state-writer resolver (d81-czrc).

IDA-free: the resolver core is a pure function of an operand list, a predecessor
list and two injected readers, so every shape below is expressed with plain
dicts.  The fixtures reproduce the three writer shapes measured on
``sub_7FFB0E398850`` (diag DB ``00007ffb0e398850_1788475193_277``, snapshot 5 =
``maturity_MMAT_GLBOPT1_pre_d810``):

* ``m_xor`` of two registers  (blk136 / blk160 / blk164),
* ``m_sub`` of two registers  (blk123 / blk141),
* a bare register ``m_mov``   (blk4, twelve predecessors),

plus the negative controls that must keep the resolver abstaining.
"""

from __future__ import annotations

import operator

import pytest

from d810.analyses.control_flow.computed_state_writer import (
    AbstainReason,
    ComputedWriteResolution,
    StorageKey,
    resolve_computed_write,
)
from d810.analyses.data_flow.abstract_value import TOP, Const, OneOf


U32 = 0xFFFFFFFF

REG_ECX = StorageKey("r", 1)
REG_EAX = StorageKey("r", 0)
REG_EDX = StorageKey("r", 2)
REG_R8D = StorageKey("r", 8)
STK_438 = StorageKey("S", 48)


def _reader(table):
    """``(pred, storage) -> const|None`` backed by a nested dict fixture."""

    def read(pred: int, storage: StorageKey):
        return table.get(pred, {}).get(storage)

    return read


def _binop(op, left: StorageKey, right: StorageKey):
    """``env -> folded u32`` for ``op(left, right)``; ``None`` when unbound."""

    def fold(env):
        a = env.get(left)
        b = env.get(right)
        if a is None or b is None:
            return None
        return op(int(a), int(b)) & U32

    return fold


def _passthrough(src: StorageKey):
    def fold(env):
        v = env.get(src)
        return None if v is None else int(v) & U32

    return fold


# --------------------------------------------------------------------------
# the three real writer shapes
# --------------------------------------------------------------------------


def test_xor_of_two_registers_resolves_both_partitions():
    """blk136: ``xor ecx, eax -> var_438``, preds 36 and 135 (real constants)."""
    table = {
        36: {REG_ECX: 0xA84A23E8, REG_EAX: 0xBA1637C8},
        135: {REG_ECX: 0x5FDB1F09, REG_EAX: 0x1D431D66},
    }
    res = resolve_computed_write(
        operands=(REG_ECX, REG_EAX),
        predecessors=(36, 135),
        const_reader=_reader(table),
        fold=_binop(operator.xor, REG_ECX, REG_EAX),
    )
    assert res.resolved
    assert res.reason is None
    assert res.values == frozenset({0x125C1420, 0x4298026F})


def test_sub_of_two_registers_resolves_with_u32_wraparound():
    """blk123: ``sub eax, ecx -> var_438``; the blk19 partition borrows."""
    table = {
        19: {REG_EAX: 0x149FBC10, REG_ECX: 0xC39DF36E},
        122: {REG_EAX: 0x515DD7EF, REG_ECX: 0x1A147C74},
    }
    res = resolve_computed_write(
        operands=(REG_EAX, REG_ECX),
        predecessors=(19, 122),
        const_reader=_reader(table),
        fold=_binop(operator.sub, REG_EAX, REG_ECX),
    )
    assert res.resolved
    # 0x149FBC10 - 0xC39DF36E is negative; the fold must wrap, not go negative.
    assert res.values == frozenset({0x5101C8A2, 0x37495B7B})
    assert all(0 <= v <= U32 for v in res.values)


def test_bare_register_mov_resolves_over_twelve_predecessors():
    """blk4: ``mov ecx -> var_438`` with the twelve real predecessor constants."""
    consts = [
        0x62127A6B,
        0x770D420C,
        0x42CBD42C,
        0x7D021312,
        0x0AFBB178,
        0x6C73B329,
        0x6F0199FE,
        0x68838EAE,
        0x4855A84B,
        0x6FB6D410,
        0x5FC63063,
        0x3B51BFB9,
    ]
    preds = (3, 31, 46, 84, 93, 107, 115, 120, 124, 125, 145, 156)
    table = {p: {REG_ECX: c} for p, c in zip(preds, consts)}
    res = resolve_computed_write(
        operands=(REG_ECX,),
        predecessors=preds,
        const_reader=_reader(table),
        fold=_passthrough(REG_ECX),
    )
    assert res.resolved
    assert res.values == frozenset(consts)
    assert len(res.evidence) == 12


def test_xor_of_register_and_stack_operand_is_storage_agnostic():
    """Mixed ``mop_r`` / ``mop_S`` operands resolve through the same core."""
    table = {
        10: {REG_EDX: 0xF054A9FE, STK_438: 0xAECEB876},
        11: {REG_EDX: 0xCB62C29C, STK_438: 0xCA4CCF17},
    }
    res = resolve_computed_write(
        operands=(REG_EDX, STK_438),
        predecessors=(10, 11),
        const_reader=_reader(table),
        fold=_binop(operator.xor, REG_EDX, STK_438),
    )
    assert res.resolved
    assert res.values == frozenset({0x5E9A1188, 0x012E0D8B})


# --------------------------------------------------------------------------
# evidence
# --------------------------------------------------------------------------


def test_evidence_names_every_partition_and_its_bindings():
    table = {
        36: {REG_ECX: 0xA84A23E8, REG_EAX: 0xBA1637C8},
        135: {REG_ECX: 0x5FDB1F09, REG_EAX: 0x1D431D66},
    }
    res = resolve_computed_write(
        operands=(REG_ECX, REG_EAX),
        predecessors=(36, 135),
        const_reader=_reader(table),
        fold=_binop(operator.xor, REG_ECX, REG_EAX),
    )
    by_pred = {e.pred_serial: e for e in res.evidence}
    assert set(by_pred) == {36, 135}
    assert dict(by_pred[36].bindings) == {REG_ECX: 0xA84A23E8, REG_EAX: 0xBA1637C8}
    assert by_pred[36].folded == 0x125C1420
    assert by_pred[135].folded == 0x4298026F


def test_evidence_order_follows_predecessor_order_and_is_deterministic():
    table = {p: {REG_ECX: p} for p in (7, 3, 9)}
    res = resolve_computed_write(
        operands=(REG_ECX,),
        predecessors=(7, 3, 9),
        const_reader=_reader(table),
        fold=_passthrough(REG_ECX),
    )
    assert [e.pred_serial for e in res.evidence] == [7, 3, 9]


# --------------------------------------------------------------------------
# abstain paths — the negative controls
# --------------------------------------------------------------------------


def test_one_unresolved_partition_abstains_and_yields_no_values():
    """blk160-shaped, but the second predecessor does not set r8d."""
    table = {
        101: {REG_EDX: 0xF054A9FE, REG_R8D: 0xAECEB876},
        159: {REG_EDX: 0xCB62C29C},  # r8d missing -> whole write abstains
    }
    res = resolve_computed_write(
        operands=(REG_EDX, REG_R8D),
        predecessors=(101, 159),
        const_reader=_reader(table),
        fold=_binop(operator.xor, REG_EDX, REG_R8D),
    )
    assert not res.resolved
    assert res.reason == AbstainReason.UNRESOLVED_OPERAND
    assert res.values == frozenset()
    # The resolvable partition is NOT leaked as a partial answer.
    assert res.evidence == ()


def test_no_predecessors_abstains():
    res = resolve_computed_write(
        operands=(REG_ECX,),
        predecessors=(),
        const_reader=_reader({}),
        fold=_passthrough(REG_ECX),
    )
    assert not res.resolved
    assert res.reason == AbstainReason.NO_PREDECESSORS


def test_no_operands_abstains():
    res = resolve_computed_write(
        operands=(),
        predecessors=(1,),
        const_reader=_reader({}),
        fold=lambda env: 0x1234,
    )
    assert not res.resolved
    assert res.reason == AbstainReason.NO_OPERANDS


def test_unfoldable_operation_abstains():
    """Operands all bind, but the fold itself declines (unsupported opcode)."""
    table = {1: {REG_ECX: 5}, 2: {REG_ECX: 6}}
    res = resolve_computed_write(
        operands=(REG_ECX,),
        predecessors=(1, 2),
        const_reader=_reader(table),
        fold=lambda env: None,
    )
    assert not res.resolved
    assert res.reason == AbstainReason.UNFOLDABLE_OPERATION


def test_predecessor_budget_exceeded_abstains():
    preds = tuple(range(40))
    table = {p: {REG_ECX: p} for p in preds}
    res = resolve_computed_write(
        operands=(REG_ECX,),
        predecessors=preds,
        const_reader=_reader(table),
        fold=_passthrough(REG_ECX),
        max_predecessors=32,
    )
    assert not res.resolved
    assert res.reason == AbstainReason.PREDECESSOR_BUDGET_EXCEEDED


def test_operand_budget_exceeded_abstains():
    ops = tuple(StorageKey("r", i) for i in range(12))
    res = resolve_computed_write(
        operands=ops,
        predecessors=(1,),
        const_reader=_reader({}),
        fold=lambda env: 0,
        max_operands=8,
    )
    assert not res.resolved
    assert res.reason == AbstainReason.OPERAND_BUDGET_EXCEEDED


def test_duplicate_predecessors_are_visited_once():
    """A block listed twice in ``predset`` must not double-count a partition."""
    table = {5: {REG_ECX: 0x11111111}, 6: {REG_ECX: 0x22222222}}
    res = resolve_computed_write(
        operands=(REG_ECX,),
        predecessors=(5, 6, 5),
        const_reader=_reader(table),
        fold=_passthrough(REG_ECX),
    )
    assert res.resolved
    assert [e.pred_serial for e in res.evidence] == [5, 6]


def test_fold_result_is_masked_to_u32():
    table = {1: {REG_ECX: 0x1_0000_00AB}}
    res = resolve_computed_write(
        operands=(REG_ECX,),
        predecessors=(1,),
        const_reader=_reader(table),
        fold=lambda env: env[REG_ECX],
    )
    assert res.values == frozenset({0xAB})


# --------------------------------------------------------------------------
# the receipt invariant + AbstractValue projection
# --------------------------------------------------------------------------


def test_resolution_rejects_a_reason_next_to_values():
    with pytest.raises(ValueError):
        ComputedWriteResolution(
            values=frozenset({1}), reason=AbstainReason.NO_OPERANDS, evidence=()
        )


def test_resolution_rejects_resolved_with_no_values():
    with pytest.raises(ValueError):
        ComputedWriteResolution(values=frozenset(), reason=None, evidence=())


def test_abstract_value_projection_matches_the_existing_seam():
    """Const for a singleton, OneOf for several, TOP for an abstain."""
    table = {1: {REG_ECX: 0x2A5E29F6}, 2: {REG_ECX: 0x2A5E29F6}}
    single = resolve_computed_write(
        operands=(REG_ECX,),
        predecessors=(1, 2),
        const_reader=_reader(table),
        fold=_passthrough(REG_ECX),
    )
    assert single.to_abstract_value() == Const(0x2A5E29F6, 4)

    table2 = {1: {REG_ECX: 0x41FB8FBB}, 2: {REG_ECX: 0x71E22BF3}}
    many = resolve_computed_write(
        operands=(REG_ECX,),
        predecessors=(1, 2),
        const_reader=_reader(table2),
        fold=_passthrough(REG_ECX),
    )
    assert many.to_abstract_value() == OneOf(frozenset({0x41FB8FBB, 0x71E22BF3}))

    abstained = resolve_computed_write(
        operands=(REG_ECX,),
        predecessors=(),
        const_reader=_reader({}),
        fold=_passthrough(REG_ECX),
    )
    assert abstained.to_abstract_value() is TOP


# --------------------------------------------------------------------------
# receipt completeness only flips when EVERY computed write resolves
# --------------------------------------------------------------------------


def _resolve_all(specs):
    from d810.analyses.control_flow.computed_state_writer import (
        resolve_computed_writes,
    )

    return resolve_computed_writes(specs)


def test_receipt_is_complete_only_when_every_write_resolves():
    from d810.analyses.control_flow.computed_state_writer import ComputedWriteRequest

    good = ComputedWriteRequest(
        site=136,
        operands=(REG_ECX, REG_EAX),
        predecessors=(36, 135),
        const_reader=_reader(
            {
                36: {REG_ECX: 0xA84A23E8, REG_EAX: 0xBA1637C8},
                135: {REG_ECX: 0x5FDB1F09, REG_EAX: 0x1D431D66},
            }
        ),
        fold=_binop(operator.xor, REG_ECX, REG_EAX),
    )
    bad = ComputedWriteRequest(
        site=160,
        operands=(REG_EDX, REG_R8D),
        predecessors=(101, 159),
        const_reader=_reader({101: {REG_EDX: 1, REG_R8D: 2}, 159: {REG_EDX: 3}}),
        fold=_binop(operator.xor, REG_EDX, REG_R8D),
    )

    all_good = _resolve_all((good,))
    assert all_good.complete
    assert all_good.reasons == ()
    assert all_good.values == frozenset({0x125C1420, 0x4298026F})

    mixed = _resolve_all((good, bad))
    assert not mixed.complete
    assert mixed.reasons == (AbstainReason.UNRESOLVED_OPERAND,)
    # The resolved sibling's constants are still contributed: enlarging the
    # written-state set can only refuse routes, never invent one, so keeping
    # them is the SAFE direction even while the receipt stays incomplete.
    assert mixed.values == frozenset({0x125C1420, 0x4298026F})
    assert mixed.unresolved_sites == (160,)


def test_empty_request_set_is_vacuously_complete():
    empty = _resolve_all(())
    assert empty.complete
    assert empty.values == frozenset()
    assert empty.reasons == ()
