from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

import d810.backends.llvm.emitter as llvm_emitter
from d810.backends.llvm import (
    LLVM_M1_PREFERRED_MATURITY,
    LlvmLiftResult,
    UnsupportedLiftKind,
    assess_flowgraph_maturity,
    emit_flowgraph_to_llvm,
)
from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.ir.instructions import Instruction
from d810.ir.maturity import IRMaturity
from d810.ir.semantics import CallKind, PredicateKind
from d810.ir.varnode import Space, Varnode


def _reg(register_id: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.REGISTER, reg=register_id, size=size)


def _stk(offset: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.STACK, stkoff=offset, size=size)


def _num(value: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.NUMBER, value=value, size=size)


def _case_list(
    cases: tuple[tuple[tuple[int, ...], int], ...],
) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.CASE_LIST, switch_cases=cases)


def _subinsn(
    sub_kind: InsnKind,
    sub_l: MopSnapshot | None,
    sub_r: MopSnapshot | None = None,
    *,
    size: int = 0,
) -> MopSnapshot:
    return MopSnapshot(
        kind=OperandKind.SUBINSN,
        size=size,
        sub_kind=sub_kind,
        sub_l=sub_l,
        sub_r=sub_r,
    )


def _semantic_subinsn(
    value_op_kind: ValueOpKind,
    sub_l: MopSnapshot | None,
    sub_r: MopSnapshot | None = None,
    *,
    size: int = 0,
) -> MopSnapshot:
    return MopSnapshot(
        kind=OperandKind.SUBINSN,
        size=size,
        sub_value_op_kind=value_op_kind,
        sub_l=sub_l,
        sub_r=sub_r,
    )


def _mov(src: MopSnapshot, dst: MopSnapshot, ea: int = 0x1000) -> InsnSnapshot:
    return InsnSnapshot(opcode=0x04, ea=ea, operands=(), kind=InsnKind.MOV, l=src, d=dst)


def _add(lhs: MopSnapshot, rhs: MopSnapshot, dst: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(opcode=0x12, ea=0x1004, operands=(), kind=InsnKind.ADD, l=lhs, r=rhs, d=dst)


def _sub(lhs: MopSnapshot, rhs: MopSnapshot, dst: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(opcode=0x13, ea=0x1008, operands=(), kind=InsnKind.SUB, l=lhs, r=rhs, d=dst)


def _and(lhs: MopSnapshot, rhs: MopSnapshot, dst: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(opcode=0x14, ea=0x100C, operands=(), kind=InsnKind.AND, l=lhs, r=rhs, d=dst)


def _value_op(
    operation: ValueOpKind,
    lhs: MopSnapshot,
    rhs: MopSnapshot,
    dst: MopSnapshot,
    *,
    raw_opcode_name: str | None = None,
) -> InsnSnapshot:
    attrs = {"raw_opcode_name": raw_opcode_name} if raw_opcode_name is not None else {}
    return InsnSnapshot(
        opcode=-1,
        raw_opcode=0x80,
        ea=0x1014,
        operands=(),
        kind=InsnKind.UNKNOWN,
        value_op_kind=operation,
        opcode_attrs=attrs,
        l=lhs,
        r=rhs,
        d=dst,
    )


def _unary_value_op(
    operation: ValueOpKind,
    src: MopSnapshot | None,
    dst: MopSnapshot | None,
    *,
    raw_opcode_name: str | None = None,
) -> InsnSnapshot:
    attrs = {"raw_opcode_name": raw_opcode_name} if raw_opcode_name is not None else {}
    return InsnSnapshot(
        opcode=-1,
        raw_opcode=0x81,
        ea=0x1018,
        operands=(),
        kind=InsnKind.UNKNOWN,
        value_op_kind=operation,
        opcode_attrs=attrs,
        l=src,
        d=dst,
    )


def _ret(value: MopSnapshot | None = None) -> InsnSnapshot:
    return InsnSnapshot(opcode=0x42, ea=0x1010, operands=(), kind=InsnKind.RET, l=value)


def _jcc(predicate: PredicateKind, lhs: MopSnapshot, rhs: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=0x2C,
        ea=0x2000,
        operands=(),
        kind=InsnKind.EQUALITY_JUMP,
        branch_predicate=predicate,
        l=lhs,
        r=rhs,
    )


def _jtbl(
    selector: MopSnapshot | None,
    cases: tuple[tuple[tuple[int, ...], int], ...],
) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=0x35,
        ea=0x2030,
        operands=(),
        kind=InsnKind.TABLE_JUMP,
        l=selector,
        r=_case_list(cases),
    )


def _setcc(
    predicate: PredicateKind,
    lhs: MopSnapshot | None,
    rhs: MopSnapshot | None,
    dst: MopSnapshot | None,
) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=0x2D,
        ea=0x2010,
        operands=(),
        kind=InsnKind.UNKNOWN,
        predicate_kind=predicate,
        l=lhs,
        r=rhs,
        d=dst,
    )


def _call(
    call_kind: CallKind,
    target: MopSnapshot | None,
    dst: MopSnapshot | None = None,
    *,
    arg: MopSnapshot | None = None,
) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=0x41,
        ea=0x3000,
        operands=(),
        kind=InsnKind.CALL,
        call_kind=call_kind,
        l=target,
        r=arg,
        d=dst,
    )


def _block(serial: int, succs: tuple[int, ...], insns: tuple[InsnSnapshot, ...]) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=0,
        succs=succs,
        preds=(),
        flags=0,
        start_ea=0x1000 + serial,
        insn_snapshots=insns,
    )


def _graph(
    *blocks: BlockSnapshot,
    entry: int = 0,
    metadata: dict[str, object] | None = None,
) -> FlowGraph:
    return FlowGraph(
        blocks={blk.serial: blk for blk in blocks},
        entry_serial=entry,
        func_ea=0x180000000,
        metadata=metadata or {},
    )


def _find_opt() -> Path | None:
    candidates = [
        os.environ.get("LLVM_OPT"),
        "/opt/homebrew/opt/llvm/bin/opt",
        shutil.which("opt"),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return path
    return None


def test_simple_arithmetic_emits_allocas_loads_and_stores():
    flow = _graph(
        _block(
            0,
            (),
            (
                _mov(_num(7), _stk(0x10)),
                _add(_stk(0x10), _num(5), _reg(0)),
                _sub(_reg(0), _num(2), _reg(1)),
                _and(_reg(1), _num(0xFF), _reg(2)),
                _ret(_reg(2)),
            ),
        )
    )

    result = emit_flowgraph_to_llvm(flow, function_name="m1a_arith")

    assert result.supported
    assert isinstance(result, LlvmLiftResult)
    assert "%S16_4 = alloca i32" in result.ir_text
    assert "%r0_4 = alloca i32" in result.ir_text
    assert "store i32 7, ptr %S16_4" in result.ir_text
    assert " = add i32 " in result.ir_text
    assert " = sub i32 " in result.ir_text
    assert " = and i32 " in result.ir_text
    assert "ret i32 %" in result.ir_text


@pytest.mark.parametrize(
    ("operation", "llvm_opcode"),
    (
        (ValueOpKind.OR, "or"),
        (ValueOpKind.XOR, "xor"),
        (ValueOpKind.MUL, "mul"),
    ),
)
def test_m1d_integer_binary_ops_emit_canonical_llvm_opcode(
    operation: ValueOpKind,
    llvm_opcode: str,
):
    flow = _graph(
        _block(
            0,
            (),
            (
                _value_op(operation, _reg(0), _num(0x55), _reg(1)),
                _ret(_reg(1)),
            ),
        )
    )

    result = emit_flowgraph_to_llvm(flow)

    assert result.supported
    assert f" = {llvm_opcode} i32 " in result.ir_text
    assert "ptr %r1_4" in result.ir_text


def test_xor_materialization_accepts_duplicate_compared_operands():
    flow = _graph(
        _block(
            0,
            (),
            (
                _value_op(ValueOpKind.XOR, _reg(0), _reg(0), _reg(1)),
                _ret(_reg(1)),
            ),
        )
    )

    result = emit_flowgraph_to_llvm(flow)

    assert result.supported
    assert " = xor i32 " in result.ir_text
    assert "XOR requires two inputs" not in {reason.reason for reason in result.unsupported}


def test_m1h_neg_emits_sub_from_zero():
    flow = _graph(
        _block(
            0,
            (),
            (
                _unary_value_op(ValueOpKind.NEG, _reg(0), _reg(1)),
                _ret(_reg(1)),
            ),
        )
    )

    result = emit_flowgraph_to_llvm(flow)

    assert result.supported
    assert " = sub i32 0, " in result.ir_text
    assert "ptr %r1_4" in result.ir_text


def test_m1h_zext_emits_width_increasing_cast():
    flow = _graph(
        _block(
            0,
            (),
            (
                _unary_value_op(ValueOpKind.ZEXT, _reg(0, size=1), _reg(1, size=4)),
                _ret(_reg(1)),
            ),
        )
    )

    result = emit_flowgraph_to_llvm(flow)

    assert result.supported
    assert " = zext i8 " in result.ir_text
    assert " to i32" in result.ir_text
    assert "ptr %r1_4" in result.ir_text


def test_one_way_cfg_edge_emits_branch_label():
    flow = _graph(
        _block(0, (2,), (_mov(_num(1), _reg(0)),)),
        _block(2, (), (_ret(_reg(0)),)),
    )

    result = emit_flowgraph_to_llvm(flow)

    assert result.supported
    assert "bb0:" in result.ir_text
    assert "  br label %bb2" in result.ir_text
    assert "bb2:" in result.ir_text


def test_conditional_branch_uses_instruction_control_not_raw_opcode_attrs():
    flow = _graph(
        _block(
            0,
            (1, 2),
            (
                _mov(_num(7), _reg(0)),
                _jcc(PredicateKind.EQ, _reg(0), _num(7)),
            ),
        ),
        _block(1, (), (_ret(_reg(0)),)),
        _block(2, (), (_ret(),)),
    )

    result = emit_flowgraph_to_llvm(flow)

    assert result.supported
    assert " = icmp eq i32 " in result.ir_text
    assert "br i1" in result.ir_text
    assert "label %bb1, label %bb2" in result.ir_text


def test_table_branch_emits_switch_from_portable_control_payload():
    cases = (((0,), 1), ((1, 2), 2), ((), 3))
    flow = _graph(
        _block(0, (1, 2, 3), (_jtbl(_stk(0x10), cases),)),
        _block(1, (), (_ret(_num(11)),)),
        _block(2, (), (_ret(_num(22)),)),
        _block(3, (), (_ret(_num(33)),)),
    )

    result = emit_flowgraph_to_llvm(flow)

    assert result.supported
    assert " = load i32, ptr %S16_4" in result.ir_text
    assert "switch i32 %t" in result.ir_text
    assert "label %bb3 [" in result.ir_text
    assert "i32 0, label %bb1" in result.ir_text
    assert "i32 1, label %bb2" in result.ir_text
    assert "i32 2, label %bb2" in result.ir_text


def test_conditional_branch_with_nested_and_emits_temp_then_two_input_icmp():
    nested = _subinsn(InsnKind.AND, _stk(0x10), _num(0x3F))
    flow = _graph(
        _block(0, (1, 2), (_jcc(PredicateKind.NE, nested, _num(0)),)),
        _block(1, (), (_ret(),)),
        _block(2, (), (_ret(),)),
    )

    result = emit_flowgraph_to_llvm(flow)

    assert result.supported
    assert " = and i32 " in result.ir_text
    assert " = icmp ne i32 " in result.ir_text
    assert "conditional branch requires two compared inputs" not in {
        reason.reason for reason in result.unsupported
    }


def test_value_op_with_nested_supported_operand_emits_temp_before_parent():
    nested = _subinsn(InsnKind.SUB, _stk(0x10), _num(1))
    flow = _graph(
        _block(
            0,
            (),
            (
                _add(nested, _num(7), _reg(0)),
                _ret(_reg(0)),
            ),
        )
    )

    result = emit_flowgraph_to_llvm(flow)

    assert result.supported
    assert " = sub i32 " in result.ir_text
    assert " = add i32 " in result.ir_text
    assert result.ir_text.index(" = sub i32 ") < result.ir_text.index(" = add i32 ")


def test_nested_extended_value_op_kind_emits_supported_temp():
    nested = _semantic_subinsn(ValueOpKind.XOR, _stk(0x10), _num(0xFF))
    flow = _graph(
        _block(0, (1, 2), (_jcc(PredicateKind.NE, nested, _num(0)),)),
        _block(1, (), (_ret(),)),
        _block(2, (), (_ret(),)),
    )

    result = emit_flowgraph_to_llvm(flow)

    assert result.supported
    assert " = xor i32 " in result.ir_text
    assert " = icmp ne i32 " in result.ir_text
    assert "nested_expression_unsupported" not in {
        reason.kind.value for reason in result.unsupported
    }


def test_raw_opcode_attrs_do_not_authorize_conditional_branch():
    fake_branch = InsnSnapshot(
        opcode=0x2C,
        ea=0x2000,
        operands=(),
        kind=InsnKind.UNKNOWN,
        opcode_attrs={"raw_opcode_name": "m_jz"},
    )
    flow = _graph(_block(0, (1, 2), (fake_branch,)), _block(1, (), ()), _block(2, (), ()))

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert result.ir_text == ""
    assert any(reason.reason == "multi-successor block needs conditional terminator" for reason in result.unsupported)
    assert any(
        reason.kind is UnsupportedLiftKind.BLOCK_TERMINATOR_MISSING
        for reason in result.unsupported
    )


def test_predicate_materialization_emits_icmp_zext_and_store_byte_result():
    flow = _graph(
        _block(
            0,
            (),
            (
                _mov(_num(7), _reg(0)),
                _setcc(PredicateKind.EQ, _reg(0), _num(7), _reg(1, size=1)),
                _ret(_reg(0)),
            ),
        )
    )

    result = emit_flowgraph_to_llvm(flow)

    assert result.supported
    assert "%r1_1 = alloca i8" in result.ir_text
    assert " = icmp eq i32 " in result.ir_text
    assert " = zext i1 %t" in result.ir_text
    assert " to i8" in result.ir_text
    assert "store i8 %t" in result.ir_text
    assert "ptr %r1_1" in result.ir_text


def test_predicate_materialization_accepts_duplicate_compared_operands():
    flow = _graph(
        _block(
            0,
            (),
            (
                _setcc(PredicateKind.EQ, _reg(0), _reg(0), _reg(1, size=1)),
                _ret(_reg(0)),
            ),
        )
    )

    result = emit_flowgraph_to_llvm(flow)

    assert result.supported
    assert " = icmp eq i32 " in result.ir_text
    assert "predicate materialization requires two compared inputs" not in {
        reason.reason for reason in result.unsupported
    }


def test_signed_predicate_materialization_uses_signed_icmp():
    flow = _graph(
        _block(
            0,
            (),
            (
                _setcc(PredicateKind.SLT, _reg(0), _reg(1), _reg(2, size=4)),
                _ret(_reg(0)),
            ),
        )
    )

    result = emit_flowgraph_to_llvm(flow)

    assert result.supported
    assert " = icmp slt i32 " in result.ir_text
    assert " = zext i1 %t" in result.ir_text
    assert " to i32" in result.ir_text


def test_raw_opcode_attrs_do_not_authorize_predicate_materialization():
    fake_setz = InsnSnapshot(
        opcode=0x2D,
        ea=0x2010,
        operands=(),
        kind=InsnKind.UNKNOWN,
        opcode_attrs={"raw_opcode_name": "m_setz"},
        l=_reg(0),
        r=_num(0),
        d=_reg(1, size=1),
    )
    flow = _graph(_block(0, (), (fake_setz, _ret(_reg(0)))))

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert result.ir_text == ""
    assert any(
        reason.operation == "vendor"
        and reason.kind is UnsupportedLiftKind.VALUE_OP_UNSUPPORTED
        and reason.reason == "value operation vendor is unsupported in M1a"
        for reason in result.unsupported
    )


def test_raw_opcode_attrs_do_not_authorize_xor_value_operation():
    fake_xor = InsnSnapshot(
        opcode=0x80,
        ea=0x2020,
        operands=(),
        kind=InsnKind.UNKNOWN,
        opcode_attrs={"raw_opcode_name": "m_xor"},
        l=_reg(0),
        r=_reg(1),
        d=_reg(2),
    )
    flow = _graph(_block(0, (), (fake_xor, _ret(_reg(0)))))

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert result.ir_text == ""
    assert any(
        reason.operation == "vendor"
        and reason.kind is UnsupportedLiftKind.VALUE_OP_UNSUPPORTED
        and reason.reason == "value operation vendor is unsupported in M1a"
        for reason in result.unsupported
    )


def test_raw_opcode_attrs_do_not_authorize_zext_value_operation():
    fake_zext = InsnSnapshot(
        opcode=0x81,
        ea=0x2024,
        operands=(),
        kind=InsnKind.UNKNOWN,
        opcode_attrs={"raw_opcode_name": "m_xdu"},
        l=_reg(0, size=1),
        d=_reg(1, size=4),
    )
    flow = _graph(_block(0, (), (fake_zext, _ret(_reg(0)))))

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert result.ir_text == ""
    assert any(
        reason.operation == "vendor"
        and reason.kind is UnsupportedLiftKind.VALUE_OP_UNSUPPORTED
        and reason.reason == "value operation vendor is unsupported in M1a"
        for reason in result.unsupported
    )


def test_raw_opcode_attrs_do_not_authorize_table_branch():
    fake_jtbl = InsnSnapshot(
        opcode=0x35,
        ea=0x2034,
        operands=(),
        kind=InsnKind.UNKNOWN,
        opcode_attrs={"raw_opcode_name": "m_jtbl"},
        l=_stk(0x10),
        r=_case_list((((0,), 1), ((), 2))),
    )
    flow = _graph(
        _block(0, (1, 2), (fake_jtbl,)),
        _block(1, (), (_ret(),)),
        _block(2, (), (_ret(),)),
    )

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert result.ir_text == ""
    assert any(
        reason.operation == "vendor"
        and reason.kind is UnsupportedLiftKind.VALUE_OP_UNSUPPORTED
        and reason.reason == "value operation vendor is unsupported in M1a"
        for reason in result.unsupported
    )


@pytest.mark.parametrize(
    ("insn", "expected_kind", "expected_reason"),
    (
        (
            _setcc(PredicateKind.EQ, _reg(0), _reg(1), None),
            UnsupportedLiftKind.PREDICATE_RESULT_MISSING,
            "predicate materialization has no result varnode",
        ),
        (
            _setcc(PredicateKind.EQ, _reg(0), _reg(1), _num(0, size=1)),
            UnsupportedLiftKind.PREDICATE_RESULT_CONST,
            "predicate materialization result cannot be const",
        ),
        (
            _setcc(PredicateKind.EQ, _reg(0), None, _reg(1, size=1)),
            UnsupportedLiftKind.PREDICATE_ARITY,
            "predicate materialization requires two compared inputs",
        ),
        (
            _setcc(PredicateKind.EQ, _reg(0, size=4), _reg(1, size=8), _reg(2, size=1)),
            UnsupportedLiftKind.PREDICATE_WIDTH_MISMATCH,
            "M1c requires predicate inputs to have matching widths",
        ),
        (
            _setcc(PredicateKind.TRUTHY, _reg(0), _num(0), _reg(1, size=1)),
            UnsupportedLiftKind.PREDICATE_UNSUPPORTED,
            "predicate truthy is unsupported for materialization in M1c",
        ),
    ),
)
def test_unsupported_predicate_materialization_cases_fail_closed(
    insn: InsnSnapshot,
    expected_kind: UnsupportedLiftKind,
    expected_reason: str,
):
    flow = _graph(_block(0, (), (insn, _ret(_reg(0)))))

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert result.ir_text == ""
    assert any(
        reason.kind is expected_kind and reason.reason == expected_reason
        for reason in result.unsupported
    )


def test_m1d_binary_op_mismatched_widths_fail_closed():
    flow = _graph(
        _block(
            0,
            (),
            (
                _value_op(ValueOpKind.MUL, _reg(0, size=4), _reg(1, size=8), _reg(2)),
                _ret(_reg(2)),
            ),
        )
    )

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert result.ir_text == ""
    assert any(
        reason.kind is UnsupportedLiftKind.VALUE_WIDTH_MISMATCH
        and reason.reason == "M1a requires value operands and result to have matching widths"
        for reason in result.unsupported
    )


@pytest.mark.parametrize(
    ("insn", "expected_kind", "expected_reason"),
    (
        (
            _mov(_num(1), None),
            UnsupportedLiftKind.VALUE_RESULT_MISSING,
            "value op has no result varnode",
        ),
        (
            _mov(_num(1), _num(0)),
            UnsupportedLiftKind.VALUE_RESULT_CONST,
            "value op result cannot be const",
        ),
        (
            _mov(_num(1), _reg(0, size=3)),
            UnsupportedLiftKind.VARNODE_WIDTH,
            "unsupported varnode width 3; expected 1/2/4/8 bytes",
        ),
        (
            _add(_reg(0), _reg(1), _reg(2, size=8)),
            UnsupportedLiftKind.VALUE_WIDTH_MISMATCH,
            "M1a requires value operands and result to have matching widths",
        ),
        (
            _value_op(ValueOpKind.XOR, _reg(0), _reg(1), _reg(2)),
            UnsupportedLiftKind.VALUE_ARITY,
            "XOR requires two inputs",
        ),
        (
            _unary_value_op(ValueOpKind.NEG, _reg(0), None),
            UnsupportedLiftKind.VALUE_RESULT_MISSING,
            "value op has no result varnode",
        ),
        (
            _unary_value_op(ValueOpKind.NEG, _reg(0), _reg(1, size=8)),
            UnsupportedLiftKind.VALUE_WIDTH_MISMATCH,
            "M1a requires value operands and result to have matching widths",
        ),
        (
            _unary_value_op(ValueOpKind.ZEXT, _reg(0, size=4), _reg(1, size=4)),
            UnsupportedLiftKind.VALUE_WIDTH_MISMATCH,
            "ZEXT requires input width to be narrower than result width",
        ),
    ),
)
def test_unsupported_value_cases_have_structured_kinds(
    insn: InsnSnapshot,
    expected_kind: UnsupportedLiftKind,
    expected_reason: str,
):
    if expected_reason == "XOR requires two inputs":
        insn = InsnSnapshot(
            opcode=-1,
            raw_opcode=0x80,
            ea=0x1014,
            operands=(),
            kind=InsnKind.UNKNOWN,
            value_op_kind=ValueOpKind.XOR,
            l=_reg(0),
            d=_reg(1),
        )
    flow = _graph(_block(0, (), (insn, _ret(_reg(0)))))

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert result.ir_text == ""
    assert any(
        reason.kind is expected_kind and reason.reason == expected_reason
        for reason in result.unsupported
    )


@pytest.mark.parametrize(
    ("insn", "succs", "expected_kind", "expected_reason"),
    (
        (
            _jtbl(None, (((0,), 1), ((), 2))),
            (1, 2),
            UnsupportedLiftKind.TABLE_ARITY,
            "table branch requires one selector input",
        ),
        (
            _jtbl(_stk(0x10), ()),
            (1, 2),
            UnsupportedLiftKind.TABLE_CASES_MISSING,
            "table branch requires switch cases",
        ),
        (
            _jtbl(_stk(0x10), (((0,), 1),)),
            (1,),
            UnsupportedLiftKind.TABLE_DEFAULT_MISSING,
            "table branch requires exactly one default case",
        ),
        (
            _jtbl(_stk(0x10), (((0,), 3), ((), 2))),
            (1, 2),
            UnsupportedLiftKind.TABLE_TARGET_UNSUPPORTED,
            "table branch case target is not a block successor",
        ),
        (
            _jtbl(_stk(0x10), (((1,), 1), ((1,), 2), ((), 3))),
            (1, 2, 3),
            UnsupportedLiftKind.TABLE_CASE_DUPLICATE,
            "table branch case values must be unique after selector-width canonicalization",
        ),
        (
            _jtbl(_stk(0x10, size=1), (((-1,), 1), ((255,), 2), ((), 3))),
            (1, 2, 3),
            UnsupportedLiftKind.TABLE_CASE_DUPLICATE,
            "table branch case values must be unique after selector-width canonicalization",
        ),
    ),
)
def test_unsupported_table_branch_cases_have_structured_kinds(
    insn: InsnSnapshot,
    succs: tuple[int, ...],
    expected_kind: UnsupportedLiftKind,
    expected_reason: str,
):
    flow = _graph(
        _block(0, succs, (insn,)),
        _block(1, (), (_ret(),)),
        _block(2, (), (_ret(),)),
        _block(3, (), (_ret(),)),
    )

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert result.ir_text == ""
    assert any(
        reason.kind is expected_kind and reason.reason == expected_reason
        for reason in result.unsupported
    )


def test_unknown_varnode_space_has_structured_kind(monkeypatch):
    unknown = Instruction(
        operation=ValueOpKind.MOVE,
        inputs=(Varnode(Space.UNKNOWN, 0, 4),),
        result=Varnode(Space.REGISTER, 0, 4),
    )
    monkeypatch.setattr(llvm_emitter, "project_instruction_sequence", lambda _insn: (unknown,))
    flow = _graph(_block(0, (), (_mov(_num(1), _reg(0)),)))

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert result.ir_text == ""
    assert any(
        reason.kind is UnsupportedLiftKind.VARNODE_SPACE
        and reason.reason == "unknown varnode space"
        for reason in result.unsupported
    )


def test_unsupported_nested_expression_has_structured_kind():
    nested = _subinsn(InsnKind.UNKNOWN, _stk(0x10), _num(1))
    flow = _graph(
        _block(0, (1, 2), (_jcc(PredicateKind.EQ, nested, _num(0)),)),
        _block(1, (), (_ret(),)),
        _block(2, (), (_ret(),)),
    )

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert result.ir_text == ""
    assert any(
        reason.kind is UnsupportedLiftKind.NESTED_EXPRESSION_UNSUPPORTED
        and reason.reason == "nested expression unknown is unsupported in M1f"
        for reason in result.unsupported
    )


def test_unsupported_nested_value_op_kind_fails_closed():
    nested = _semantic_subinsn(ValueOpKind.SHL, _stk(0x10), _num(1))
    flow = _graph(
        _block(0, (1, 2), (_jcc(PredicateKind.EQ, nested, _num(0)),)),
        _block(1, (), (_ret(),)),
        _block(2, (), (_ret(),)),
    )

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert result.ir_text == ""
    assert any(
        reason.kind is UnsupportedLiftKind.VALUE_OP_UNSUPPORTED
        and reason.reason == "value operation shl is unsupported in M1a"
        for reason in result.unsupported
    )


def test_store_effect_has_structured_unsupported_kind():
    store = InsnSnapshot(
        opcode=0x21,
        ea=0x5000,
        operands=(),
        kind=InsnKind.STORE,
        l=_reg(0),
        r=_reg(1),
        d=_stk(0x10),
    )
    flow = _graph(_block(0, (), (store, _ret(_reg(0)))))

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert any(reason.kind is UnsupportedLiftKind.EFFECT_UNSUPPORTED for reason in result.unsupported)


def test_raw_opcode_attrs_do_not_authorize_store_effect():
    fake_store = InsnSnapshot(
        opcode=0x21,
        ea=0x5004,
        operands=(),
        kind=InsnKind.UNKNOWN,
        opcode_attrs={"raw_opcode_name": "m_stx"},
        l=_reg(0),
        r=_reg(1),
        d=_stk(0x10),
    )
    flow = _graph(_block(0, (), (fake_store, _ret(_reg(0)))))

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert result.ir_text == ""
    assert any(
        reason.operation == "vendor"
        and reason.kind is UnsupportedLiftKind.VALUE_OP_UNSUPPORTED
        for reason in result.unsupported
    )


def test_unsupported_control_transfer_has_structured_kind():
    indirect = InsnSnapshot(
        opcode=0x31,
        ea=0x6000,
        operands=(),
        kind=InsnKind.INDIRECT_JUMP,
        l=_reg(0, size=8),
    )
    flow = _graph(_block(0, (), (indirect,)))

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert any(
        reason.kind is UnsupportedLiftKind.CONTROL_TRANSFER_UNSUPPORTED
        and reason.reason == "control transfer indirect_branch is unsupported in M1a"
        for reason in result.unsupported
    )


def test_conditional_truthy_branch_has_structured_predicate_kind():
    flow = _graph(
        _block(0, (1, 2), (_jcc(PredicateKind.TRUTHY, _reg(0), _num(0)),)),
        _block(1, (), (_ret(),)),
        _block(2, (), (_ret(),)),
    )

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert any(
        reason.kind is UnsupportedLiftKind.BRANCH_PREDICATE_UNSUPPORTED
        and reason.reason == "unsupported branch predicate"
        for reason in result.unsupported
    )


def test_return_with_successor_has_structured_kind():
    flow = _graph(_block(0, (1,), (_ret(_reg(0)),)), _block(1, (), (_ret(),)))

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert any(
        reason.kind is UnsupportedLiftKind.RETURN_SUCCESSOR
        and reason.reason == "return block must have zero succs"
        for reason in result.unsupported
    )


def test_goto_bad_successor_count_has_structured_kind():
    goto = InsnSnapshot(opcode=0x30, ea=0x7000, operands=(), kind=InsnKind.GOTO)
    flow = _graph(_block(0, (), (goto,)))

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert any(
        reason.kind is UnsupportedLiftKind.GOTO_SUCCESSOR_ARITY
        and reason.reason == "goto block needs one succ"
        for reason in result.unsupported
    )


def test_return_type_has_structured_kind():
    flow = _graph(_block(0, (), (_ret(_reg(0, size=8)),)))

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert any(
        reason.kind is UnsupportedLiftKind.RETURN_TYPE_UNSUPPORTED
        and reason.reason == "M1a function signature supports only i32 return values"
        for reason in result.unsupported
    )


def test_multiple_control_transfers_have_structured_malformed_kind():
    flow = _graph(_block(0, (), (_ret(_reg(0)), _ret(_reg(0)))))

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert any(
        reason.kind is UnsupportedLiftKind.MALFORMED_TERMINATOR
        and reason.reason == "block has multiple control-transfer instructions"
        for reason in result.unsupported
    )


def test_conditional_branch_successor_count_has_structured_kind():
    flow = _graph(_block(0, (1,), (_jcc(PredicateKind.NE, _reg(0), _num(0)),)))

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert any(
        reason.kind is UnsupportedLiftKind.BRANCH_SUCCESSOR_ARITY
        and reason.reason == "conditional block needs two succs"
        for reason in result.unsupported
    )


def test_conditional_branch_arity_has_structured_kind():
    jcc = InsnSnapshot(
        opcode=0x2C,
        ea=0x2000,
        operands=(),
        kind=InsnKind.EQUALITY_JUMP,
        branch_predicate=PredicateKind.NE,
        l=_reg(0),
    )
    flow = _graph(_block(0, (1, 2), (jcc,)), _block(1, (), (_ret(),)), _block(2, (), (_ret(),)))

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert any(
        reason.kind is UnsupportedLiftKind.BRANCH_ARITY
        and reason.reason == "conditional branch requires two compared inputs"
        for reason in result.unsupported
    )


def test_indirect_call_emits_opaque_side_effecting_call_with_result_store():
    flow = _graph(_block(0, (), (_call(CallKind.INDIRECT, _reg(5, size=8), _reg(0)), _ret())))

    result = emit_flowgraph_to_llvm(flow)

    assert result.supported
    assert "declare i32 @__d810_opaque_call_i32_i64(i64)" in result.ir_text
    assert " = load i64, ptr %r5_8, align 8" in result.ir_text
    assert " = call i32 @__d810_opaque_call_i32_i64(i64 %t" in result.ir_text
    assert "store i32 %t" in result.ir_text
    assert "ptr %r0_4, align 4" in result.ir_text
    assert not result.unsupported


def test_direct_call_without_result_emits_void_opaque_call():
    flow = _graph(_block(0, (), (_call(CallKind.DIRECT, _num(0x180010000, size=8)), _ret())))

    result = emit_flowgraph_to_llvm(flow)

    assert result.supported
    assert "declare void @__d810_opaque_call_void_i64(i64)" in result.ir_text
    assert "call void @__d810_opaque_call_void_i64(i64 6442516480)" in result.ir_text


def test_indirect_call_preserves_argument_multiplicity_when_arg_equals_target():
    flow = _graph(
        _block(
            0,
            (),
            (_call(CallKind.INDIRECT, _reg(5, size=8), arg=_reg(5, size=8)), _ret()),
        )
    )

    result = emit_flowgraph_to_llvm(flow)

    assert result.supported
    assert "declare void @__d810_opaque_call_void_i64_i64(i64, i64)" in result.ir_text
    assert result.ir_text.count(" = load i64, ptr %r5_8, align 8") == 2
    assert "call void @__d810_opaque_call_void_i64_i64(i64 %t0, i64 %t1)" in result.ir_text


def test_call_without_portable_target_fails_closed():
    flow = _graph(_block(0, (), (_call(CallKind.INDIRECT, None, _reg(0)), _ret())))

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert result.ir_text == ""
    assert any(
        reason.kind is UnsupportedLiftKind.CALL_PAYLOAD_UNSUPPORTED
        and reason.reason == "call requires a portable call target"
        for reason in result.unsupported
    )


def test_call_const_result_fails_closed():
    flow = _graph(_block(0, (), (_call(CallKind.INDIRECT, _reg(5, size=8), _num(0)), _ret())))

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert result.ir_text == ""
    assert any(
        reason.kind is UnsupportedLiftKind.CALL_RESULT_UNSUPPORTED
        and reason.reason == "call result cannot be const"
        for reason in result.unsupported
    )


def test_raw_opcode_attrs_do_not_authorize_call():
    fake_call = InsnSnapshot(
        opcode=0x41,
        ea=0x3004,
        operands=(),
        kind=InsnKind.UNKNOWN,
        opcode_attrs={"raw_opcode_name": "m_call"},
        l=_reg(5, size=8),
        d=_reg(0),
    )
    flow = _graph(_block(0, (), (fake_call, _ret())))

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert result.ir_text == ""
    assert any(
        reason.operation == "vendor"
        and reason.kind is UnsupportedLiftKind.VALUE_OP_UNSUPPORTED
        for reason in result.unsupported
    )


def test_unsupported_width_returns_diagnostic_and_no_ir():
    flow = _graph(_block(0, (), (_mov(_num(1, size=3), _reg(0, size=3)), _ret())))

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert result.ir_text == ""
    assert any(
        reason.kind is UnsupportedLiftKind.VARNODE_WIDTH
        and "unsupported varnode width 3" in reason.reason
        for reason in result.unsupported
    )


def test_non_tail_return_is_reported_not_asserted():
    flow = _graph(_block(0, (), (_ret(_reg(0)), _mov(_num(1), _reg(1)))))

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert result.ir_text == ""
    assert any(
        reason.operation == "return"
        and reason.kind is UnsupportedLiftKind.MALFORMED_TERMINATOR
        and reason.reason == "control-transfer instruction must be block tail"
        for reason in result.unsupported
    )


def test_non_tail_conditional_branch_is_reported_not_asserted():
    flow = _graph(
        _block(0, (1,), (_jcc(PredicateKind.NE, _reg(0), _num(0)), _mov(_num(1), _reg(1)))),
        _block(1, (), (_ret(),)),
    )

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert result.ir_text == ""
    assert any(
        reason.operation == "conditional_branch"
        and reason.kind is UnsupportedLiftKind.MALFORMED_TERMINATOR
        and reason.reason == "control-transfer instruction must be block tail"
        for reason in result.unsupported
    )


def test_tail_return_with_successor_is_reported_not_silently_emitted():
    flow = _graph(_block(0, (1,), (_ret(_reg(0)),)), _block(1, (), (_ret(),)))

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert result.ir_text == ""
    assert any(
        reason.operation == "return"
        and reason.kind is UnsupportedLiftKind.RETURN_SUCCESSOR
        and reason.reason == "return block must have zero succs"
        for reason in result.unsupported
    )


def test_opt_verify_accepts_supported_emission_when_opt_available(tmp_path):
    opt = _find_opt()
    if opt is None:
        pytest.skip("LLVM opt not found; set LLVM_OPT or install opt in PATH/Homebrew LLVM")
    flow = _graph(
        _block(
            0,
            (),
            (
                _mov(_num(7), _stk(0x10)),
                _add(_stk(0x10), _num(5), _reg(0)),
                _setcc(PredicateKind.NE, _reg(0), _num(0), _reg(1, size=1)),
                _ret(_reg(0)),
            ),
        )
    )
    result = emit_flowgraph_to_llvm(flow, function_name="verify_me")
    assert result.supported
    ir_path = tmp_path / "verify_me.ll"
    ir_path.write_text(result.ir_text, encoding="utf-8")

    proc = subprocess.run(
        [str(opt), "-S", "-passes=verify", str(ir_path), "-o", "-"],
        text=True,
        capture_output=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr or proc.stdout


def test_maturity_policy_accepts_preferred_portable_metadata():
    flow = _graph(
        _block(0, (), (_ret(),)),
        metadata={"ir_maturity": IRMaturity.GLOBAL_ANALYZED},
    )

    assessment = assess_flowgraph_maturity(flow)

    assert assessment.observed is LLVM_M1_PREFERRED_MATURITY
    assert assessment.accepted
    assert assessment.preferred
    assert "preferred" in assessment.reason


def test_maturity_policy_accepts_string_value_metadata():
    flow = _graph(
        _block(0, (), (_ret(),)),
        metadata={"ir_maturity": IRMaturity.CALL_MODELED.value},
    )

    assessment = assess_flowgraph_maturity(flow)

    assert assessment.observed is IRMaturity.CALL_MODELED
    assert assessment.accepted
    assert not assessment.preferred


def test_maturity_policy_rejects_missing_or_out_of_range_metadata():
    missing = assess_flowgraph_maturity(_graph(_block(0, (), (_ret(),))))
    early = assess_flowgraph_maturity(
        _graph(
            _block(0, (), (_ret(),)),
            metadata={"ir_maturity": IRMaturity.LOCAL_OPTIMIZED},
        )
    )

    assert missing.observed is None
    assert not missing.accepted
    assert "ir_maturity" in missing.reason
    assert early.observed is IRMaturity.LOCAL_OPTIMIZED
    assert not early.accepted
    assert "outside" in early.reason
