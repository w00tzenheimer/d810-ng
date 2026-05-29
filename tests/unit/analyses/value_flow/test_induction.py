"""Tests for portable induction-variable analysis (LS8 S5). Pure-Python, no IDA.

Synthetic instruction views (SimpleNamespace) stand in for backend snapshot
rows. Includes the mandated loop-head-merge coverage: the optimistic union meet
must NOT wipe a body-block candidate at an empty loop head (LS6 bug class).
"""
from __future__ import annotations

from types import SimpleNamespace

from d810.analyses.value_flow.induction import (
    InductionVariableAnalysis,
    InductionVariableFact,
)


def _view(*, op, dest, l_off=None, l_val=None, r_off=None, r_val=None, block=0):
    return SimpleNamespace(
        block_serial=block,
        opcode_name=op,
        dest_stkoff=dest,
        src_l_stkoff=l_off,
        src_l_value=l_val,
        src_r_stkoff=r_off,
        src_r_value=r_val,
    )


def test_classify_add_right_operand_step() -> None:
    fact = InductionVariableAnalysis().classify_update(
        _view(op="m_add", dest=0x20, l_off=0x20, r_val=4)
    )
    assert fact == InductionVariableFact(0x20, 4, "right", 0)


def test_classify_add_left_operand_step() -> None:
    fact = InductionVariableAnalysis().classify_update(
        _view(op="m_add", dest=0x20, r_off=0x20, l_val=8)
    )
    assert fact == InductionVariableFact(0x20, 8, "left", 0)


def test_classify_sub_is_negative_step() -> None:
    fact = InductionVariableAnalysis().classify_update(
        _view(op="m_sub", dest=0x20, l_off=0x20, r_val=1)
    )
    assert fact is not None and fact.step == -1


def test_signed_step_handles_64bit_unsigned() -> None:
    fact = InductionVariableAnalysis().classify_update(
        _view(op="m_add", dest=0x20, l_off=0x20, r_val=0xFFFFFFFFFFFFFFFF)
    )
    assert fact is not None and fact.step == -1


def test_all_opcode_forms_classify() -> None:
    a = InductionVariableAnalysis()
    for op in ("m_add", "op_12", "ADD"):
        f = a.classify_update(_view(op=op, dest=0x20, l_off=0x20, r_val=1))
        assert f is not None and f.step == 1


def test_non_induction_returns_none() -> None:
    a = InductionVariableAnalysis()
    assert a.classify_update(_view(op="m_add", dest=None, l_off=0x20, r_val=1)) is None
    assert a.classify_update(_view(op="m_mov", dest=0x20, l_off=0x20, r_val=1)) is None
    # not a self-update: src offset differs from dest
    assert a.classify_update(_view(op="m_add", dest=0x20, l_off=0x30, r_val=1)) is None


def test_collect_block_keys_by_dest_stkoff() -> None:
    a = InductionVariableAnalysis()
    facts = a.collect_block(
        [
            _view(op="m_add", dest=0x20, l_off=0x20, r_val=1),
            _view(op="m_sub", dest=0x40, l_off=0x40, r_val=2),
            _view(op="m_mov", dest=0x60, l_off=0x60, r_val=3),  # ignored
        ]
    )
    assert set(facts) == {0x20, 0x40}


def test_loop_head_merge_keeps_body_candidate() -> None:
    # header (serial 0): no induction update; body (serial 1): x = x + 1.
    # Optimistic union must keep the body fact at the (empty) loop head.
    a = InductionVariableAnalysis()
    result = a.analyze_loop(
        {
            0: [_view(op="m_mov", dest=0x8, l_off=0x8, r_val=0, block=0)],
            1: [_view(op="m_add", dest=0x20, l_off=0x20, r_val=1, block=1)],
        }
    )
    assert 0x20 in result  # NOT wiped by the empty header
    assert result[0x20].step == 1 and result[0x20].block_serial == 1


def test_merge_is_union_not_intersection() -> None:
    a = InductionVariableAnalysis()
    fact = InductionVariableFact(0x20, 1, "right", 1)
    # An intersection meet would yield {} (candidate absent from the first state);
    # union keeps it.
    assert a.merge([{}, {0x20: fact}]) == {0x20: fact}
