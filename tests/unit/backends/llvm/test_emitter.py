from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from d810.backends.llvm import (
    LLVM_M1_PREFERRED_MATURITY,
    LlvmLiftResult,
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
from d810.ir.maturity import IRMaturity
from d810.ir.semantics import CallKind, PredicateKind


def _reg(register_id: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.REGISTER, reg=register_id, size=size)


def _stk(offset: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.STACK, stkoff=offset, size=size)


def _num(value: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.NUMBER, value=value, size=size)


def _mov(src: MopSnapshot, dst: MopSnapshot, ea: int = 0x1000) -> InsnSnapshot:
    return InsnSnapshot(opcode=0x04, ea=ea, operands=(), kind=InsnKind.MOV, l=src, d=dst)


def _add(lhs: MopSnapshot, rhs: MopSnapshot, dst: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(opcode=0x12, ea=0x1004, operands=(), kind=InsnKind.ADD, l=lhs, r=rhs, d=dst)


def _sub(lhs: MopSnapshot, rhs: MopSnapshot, dst: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(opcode=0x13, ea=0x1008, operands=(), kind=InsnKind.SUB, l=lhs, r=rhs, d=dst)


def _and(lhs: MopSnapshot, rhs: MopSnapshot, dst: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(opcode=0x14, ea=0x100C, operands=(), kind=InsnKind.AND, l=lhs, r=rhs, d=dst)


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


def test_unsupported_call_returns_diagnostic_and_no_ir():
    call = InsnSnapshot(
        opcode=0x41,
        ea=0x3000,
        operands=(),
        kind=InsnKind.CALL,
        l=_reg(5, size=8),
        d=_reg(0, size=8),
        call_kind=CallKind.INDIRECT,
    )
    flow = _graph(_block(0, (), (call, _ret())))

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert result.ir_text == ""
    assert result.unsupported[0].block_serial == 0
    assert result.unsupported[0].ea == 0x3000
    assert result.unsupported[0].operation == "indirect"
    assert "calls are unsupported" in result.unsupported[0].reason


def test_unsupported_width_returns_diagnostic_and_no_ir():
    flow = _graph(_block(0, (), (_mov(_num(1, size=3), _reg(0, size=3)), _ret())))

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert result.ir_text == ""
    assert any("unsupported varnode width 3" in reason.reason for reason in result.unsupported)


def test_non_tail_return_is_reported_not_asserted():
    flow = _graph(_block(0, (), (_ret(_reg(0)), _mov(_num(1), _reg(1)))))

    result = emit_flowgraph_to_llvm(flow)

    assert not result.supported
    assert result.ir_text == ""
    assert any(
        reason.operation == "return"
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
